//! Key domains through actual arm64e image activation and personality entry.

use super::*;
use crate::isa::arm::aarch64::pauth::PauthKeyKind;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::pauth::UserPauth;
use crate::user::darwin::signal::{self, frame};
use crate::user::darwin::thread_state as ts;
use crate::user::darwin::thread_status;

const CODE: u64 = 0x1_0000_1000;
const TRAMP: u64 = CODE + 0x100;
const HANDLER: u64 = CODE + 0x200;

fn process() -> DarwinProcess {
    let mut image = super::exclusive_tests::image();
    let mut bytes = image.bytes.to_vec();
    bytes[8..12].copy_from_slice(&0x8000_0002u32.to_le_bytes());
    image.bytes = bytes.into();
    let mut config = DarwinConfig::embedded(
        "/exclusive-test",
        vec![b"/exclusive-test".to_vec()],
        Vec::new(),
        crate::user::supplied_fs::Files::new(BTreeMap::new()).unwrap(),
        crate::user::console::CapturedConsole::new(Vec::new(), 4096).unwrap(),
    );
    config.abi = Some(DarwinAbi::Arm64);
    config.seed = Some(0x19a64);
    config.arena_bytes = 64 << 20;
    DarwinProcess::spawn(config, image).unwrap()
}

fn raw_state(thread: &Thread) -> [u8; ts::ARM_THREAD_STATE64_SIZE] {
    let DarwinCpu::Arm64(cpu) = &thread.cpu else {
        unreachable!()
    };
    ts::arm64_thread_state(cpu, 0)
}

fn read64(proc: &Proc, address: u64) -> u64 {
    let mut bytes = [0u8; 8];
    proc.space.read(address, &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

fn signal_arguments(thread: &Thread) -> (u64, u64) {
    let DarwinCpu::Arm64(cpu) = &thread.cpu else {
        unreachable!()
    };
    (cpu.core().get_x(4), cpu.core().get_x(5))
}

#[test]
fn darwin_pauth_image_activation_and_new_threads_use_one_key_domain() {
    let mut process = process();
    assert!(frame::uses_ptrauth(&process.proc));
    let (_, mut thread) = process.proc.threads.pop_first().unwrap();
    let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
        unreachable!()
    };
    let keys = cpu.core().pauth_keys();
    assert_ne!(keys, Default::default());
    let auth = UserPauth::from_cpu(cpu);
    assert!(auth.enabled());
    let cloned = cpu.clone_thread();
    assert_eq!(cloned.core().pauth_keys(), keys);
    let DarwinCpu::Arm64(peer) = process.proc.new_thread_cpu() else {
        unreachable!()
    };
    assert_eq!(peer.core().pauth_keys(), keys);
    assert_eq!(peer.core().pauth_controls(), cpu.core().pauth_controls());

    // PACIA/AUTIA, PACIBSP/AUTIBSP and PACGA execute in real EL0 state.
    let words = [
        0xdac1_0020u32,
        0xdac1_1020,
        0xd503_237f,
        0xd503_23ff,
        0x9ac1_3002,
    ];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    process.proc.space.write_raw(CODE, &bytes).unwrap();
    cpu.core_mut().set_x(0, HANDLER);
    cpu.core_mut().set_x(1, 0x1234);
    cpu.core_mut().set_x(30, CODE + 0x40);
    assert_eq!(cpu.run(1), crate::user::cpu::aarch64::A64Exit::Yield);
    assert_eq!(
        cpu.core().get_x(0),
        auth.sign(HANDLER, PauthKeyKind::Ia, 0x1234)
    );
    assert_eq!(cpu.run(4), crate::user::cpu::aarch64::A64Exit::Yield);
    assert_eq!(cpu.core().get_x(0), HANDLER);
    assert_eq!(cpu.core().get_x(30), CODE + 0x40);
    assert_eq!(cpu.pc(), CODE + 20);
    assert_eq!(
        cpu.core().get_x(2) as u32,
        0,
        "PACGA's low 32 bits are zero"
    );
    assert_ne!(
        cpu.core().get_x(2),
        0,
        "fixed seeded inputs have a nonzero MAC"
    );
}

#[test]
fn darwin_pauth_nested_signals_round_trip_signed_state_and_uctx_tokens() {
    for ib_lr in [false, true] {
        let mut process = process();
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
            unreachable!()
        };
        for register in 0..31 {
            cpu.core_mut().set_x(register, 0x1000 + u64::from(register));
        }
        let frame_pointer = cpu.sp() - 0x100;
        cpu.core_mut().set_x(29, frame_pointer);
        let lr = if ib_lr {
            UserPauth::from_cpu(cpu).sign(CODE + 0x40, PauthKeyKind::Ib, cpu.sp())
        } else {
            CODE + 0x40
        };
        cpu.core_mut().set_x(30, lr);
        cpu.core_mut().set_nzcv_bits(0b1011);
        let initial = raw_state(&thread);
        process.proc.sigacts.tramp[signal::SIGUSR1 as usize] = TRAMP;
        frame::sendsig(
            &mut process.proc,
            &mut thread,
            HANDLER,
            signal::SIGUSR1,
            0,
            0,
        )
        .unwrap();
        let (outer_uctx, outer_token) = signal_arguments(&thread);
        assert_ne!(
            outer_token,
            outer_uctx ^ thread.sig.token,
            "uctx is signed before XOR"
        );
        let mctx = read64(&process.proc, outer_uctx + 48);
        assert_ne!(read64(&process.proc, mctx + 16 + 256), CODE);
        assert_ne!(
            read64(&process.proc, mctx + 16 + 248),
            u64::from_le_bytes(initial[248..256].try_into().unwrap())
        );
        assert_eq!(thread.cpu.pc(), TRAMP);
        let handler_state = raw_state(&thread);
        frame::sendsig(
            &mut process.proc,
            &mut thread,
            HANDLER,
            signal::SIGUSR1,
            0,
            0,
        )
        .unwrap();
        let (inner_uctx, inner_token) = signal_arguments(&thread);
        assert_eq!(thread.sig.pending_sigreturn, 2);
        assert!(
            frame::sigreturn(
                &mut process.proc,
                &mut thread,
                inner_uctx,
                frame::UC_TRAD,
                inner_token
            )
            .is_ok()
        );
        assert_eq!(&raw_state(&thread)[..268], &handler_state[..268]);
        assert_eq!(thread.sig.pending_sigreturn, 1);
        assert!(
            frame::sigreturn(
                &mut process.proc,
                &mut thread,
                outer_uctx,
                frame::UC_TRAD,
                outer_token
            )
            .is_ok()
        );
        assert_eq!(&raw_state(&thread)[..268], &initial[..268]);
        assert_eq!(thread.sig.pending_sigreturn, 0);
    }
}

#[test]
fn darwin_pauth_sigreturn_rejects_bad_argument_and_kernel_pointer_tokens() {
    let mut process = process();
    let (_, mut thread) = process.proc.threads.pop_first().unwrap();
    process.proc.sigacts.tramp[signal::SIGUSR1 as usize] = TRAMP;
    frame::sendsig(
        &mut process.proc,
        &mut thread,
        HANDLER,
        signal::SIGUSR1,
        0,
        0,
    )
    .unwrap();
    let (uctx, token) = signal_arguments(&thread);
    assert_eq!(
        frame::sigreturn(
            &mut process.proc,
            &mut thread,
            uctx,
            frame::UC_TRAD,
            token ^ 1
        ),
        Err(Errno::EINVAL)
    );
    assert_eq!(thread.cpu.pc(), TRAMP);
    assert_eq!(thread.sig.pending_sigreturn, 1);
    let mctx = read64(&process.proc, uctx + 48);
    let flags_address = mctx + 16 + 268;
    let mut flags = [0u8; 4];
    process.proc.space.read(flags_address, &mut flags).unwrap();
    let original_flags = u32::from_le_bytes(flags);
    process
        .proc
        .space
        .write(flags_address, &(original_flags ^ (1 << 16)).to_le_bytes())
        .unwrap();
    assert_eq!(
        frame::sigreturn(&mut process.proc, &mut thread, uctx, frame::UC_TRAD, token),
        Err(Errno::EINVAL)
    );
    assert_eq!(thread.cpu.pc(), TRAMP);
    process
        .proc
        .space
        .write(flags_address, &original_flags.to_le_bytes())
        .unwrap();
    assert!(frame::sigreturn(&mut process.proc, &mut thread, uctx, frame::UC_TRAD, token).is_ok());
    assert_eq!(thread.cpu.pc(), CODE);
}

#[test]
fn darwin_pauth_mach_thread_state_signs_and_authenticates_without_a_guest_aut_trap() {
    let mut process = process();
    let (_, mut thread) = process.proc.threads.pop_first().unwrap();
    let initial = raw_state(&thread);
    let view = thread_status::View {
        cpu: &thread.cpu,
        entry: &thread.sig.entry,
        debug: &[],
        ptrauth: true,
    };
    let mut state = thread_status::get(&view, thread_status::arm::THREAD_STATE64, 68).unwrap();
    assert_ne!(u64::from(state[64]) | (u64::from(state[65]) << 32), CODE);
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::arm::THREAD_STATE64,
        &state,
    )
    .unwrap();
    assert_eq!(&raw_state(&thread)[..268], &initial[..268]);
    state[65] ^= 1 << 16; // Corrupt PAC bit 48 of the exported PC.
    thread_status::set(
        &mut thread.cpu,
        &mut thread.mach.debug_state,
        thread_status::arm::THREAD_STATE64,
        &state,
    )
    .unwrap();
    assert_eq!((thread.cpu.pc() >> 61) & 3, 1, "XNU's IA poison code");
    assert_ne!(thread.cpu.pc(), CODE);
}

#[test]
fn darwin_pauth_registered_callbacks_authenticate_before_becoming_kernel_selected_pcs() {
    use crate::user::darwin::arch::Rv;
    use crate::user::darwin::syscall::{
        Ctx,
        bsd::{pthread, sig, thread as bsd_thread},
    };

    let mut process = process();
    let (_, mut thread) = process.proc.threads.pop_first().unwrap();
    let DarwinCpu::Arm64(cpu) = &thread.cpu else {
        unreachable!()
    };
    let auth = UserPauth::from_cpu(cpu);
    let keys = cpu.core().pauth_keys();
    let stack = thread.cpu.sp() - 0x4000;
    let thread_start = auth.sign(TRAMP, PauthKeyKind::Ia, 0);
    let workq_start = auth.sign(HANDLER, PauthKeyKind::Ia, 0);
    let signed_handler = auth.sign(HANDLER, PauthKeyKind::Ia, 0);
    let action_address = stack - 64;
    let mut action = [0u8; 24];
    action[..8].copy_from_slice(&signed_handler.to_le_bytes());
    action[8..16].copy_from_slice(&thread_start.to_le_bytes());
    process.proc.space.write(action_address, &action).unwrap();
    let mut ctx = Ctx {
        proc: &mut process.proc,
        thread: &mut thread,
        nr: 0,
        pc: CODE,
    };
    bsd_thread::bsdthread_register(&mut ctx, &[thread_start, workq_start, 0x400, 0, 0, 0, 0, 0])
        .unwrap();
    assert_eq!(ctx.proc.pthread.thread_start, TRAMP);
    assert_eq!(ctx.proc.pthread.wqthread_start, HANDLER);
    sig::sigaction(&mut ctx, signal::SIGUSR1, action_address, 0).unwrap();
    assert_eq!(ctx.proc.sigacts.tramp[signal::SIGUSR1 as usize], TRAMP);
    assert_eq!(
        ctx.proc.sigacts.get(signal::SIGUSR1).handler,
        signed_handler,
        "the handler remains signed for the user trampoline"
    );
    assert_eq!(
        pthread::bsdthread_create(
            &mut ctx,
            signed_handler,
            0x55,
            stack,
            stack + 0x100,
            0x0100_0000
        ),
        Ok(Rv::one(stack + 0x100))
    );
    let child = ctx.proc.threads.values().next().unwrap();
    assert_eq!(child.cpu.pc(), TRAMP);
    let DarwinCpu::Arm64(cpu) = &child.cpu else {
        unreachable!()
    };
    assert_eq!(cpu.core().pauth_keys(), keys);
    assert_eq!(
        cpu.core().get_x(2),
        signed_handler,
        "thread_start receives the signed user callback"
    );
}
