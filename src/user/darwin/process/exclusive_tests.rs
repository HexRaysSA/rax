//! Arm64 local-monitor lifetime through the Darwin scheduler and signal path.

use super::*;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::aarch64::A64Exit;
use crate::user::darwin::exception::{InFlight, Level, Raised};
use crate::user::image::macho::{
    ARM_THREAD_STATE64, ARM_THREAD_STATE64_COUNT, CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64,
    LC_SEGMENT_64, LC_UNIXTHREAD, MH_EXECUTE, MH_MAGIC_64, VM_PROT_EXECUTE, VM_PROT_READ,
};
use crate::user::mm::{Mapping, Perms};

const TEXT: u64 = 0x1_0000_0000;
const CODE: u64 = TEXT + 0x1000;
const OTHER: u64 = TEXT + 0x1100;
const HANDLER: u64 = TEXT + 0x1200;
const DATA: u64 = TEXT + 0x8000;
const STATUS: u64 = DATA + 8;
const PAGE: u64 = 0x4000;

const LDXR_X0_X1: u32 = 0xc85f_7c20;
const STXR_W2_X0_X1: u32 = 0xc802_7c20;
const STR_W2_X3: u32 = 0xb900_0062;
const MOVZ_X16_1: u32 = 0xd280_0030;
const MOVZ_X0_0: u32 = 0xd280_0000;
const SVC_0: u32 = 0xd400_0001;
const B_SELF: u32 = 0x1400_0000;
const LDXR_X8_X6: u32 = 0xc85f_7cc8;
const STXR_W9_X8_X6: u32 = 0xc809_7cc8;

fn command(kind: u32, body: &[u8]) -> Vec<u8> {
    let mut command = Vec::with_capacity(8 + body.len());
    command.extend_from_slice(&kind.to_le_bytes());
    command.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    command.extend_from_slice(body);
    command
}

fn segment(name: &[u8], address: u64, size: u64, file_size: u64, protection: u32) -> Vec<u8> {
    let mut body = vec![0u8; 16];
    body[..name.len()].copy_from_slice(name);
    for value in [address, size, 0, file_size] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [protection, protection, 0, 0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    command(LC_SEGMENT_64, &body)
}

/// A static arm64 Mach-O avoids host dyld/SDK dependencies in these tests.
fn image() -> ImageFile {
    let mut thread = Vec::new();
    thread.extend_from_slice(&ARM_THREAD_STATE64.to_le_bytes());
    thread.extend_from_slice(&ARM_THREAD_STATE64_COUNT.to_le_bytes());
    thread.resize(8 + ARM_THREAD_STATE64_COUNT as usize * 4, 0);
    // ARM_THREAD_STATE64: X0-X30, SP, PC, CPSR, pad.
    thread[8 + 32 * 8..8 + 33 * 8].copy_from_slice(&CODE.to_le_bytes());
    let commands = [
        segment(b"__PAGEZERO", 0, TEXT, 0, 0),
        segment(b"__TEXT", TEXT, PAGE, PAGE, VM_PROT_READ | VM_PROT_EXECUTE),
        command(LC_UNIXTHREAD, &thread),
    ];
    let size: usize = commands.iter().map(Vec::len).sum();
    let mut bytes = Vec::with_capacity(PAGE as usize);
    for value in [
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64_ALL,
        MH_EXECUTE,
        commands.len() as u32,
        size as u32,
        0,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for command in commands {
        bytes.extend(command);
    }
    bytes.resize(PAGE as usize, 0);
    ImageFile {
        path: "/exclusive-test".into(),
        host_path: "/exclusive-test".into(),
        vnode_path: "/exclusive-test".into(),
        bytes: bytes.into(),
        file_id: (0, 0),
        slice: None,
    }
}

fn write_words(process: &DarwinProcess, address: u64, words: &[u32]) {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    process.proc.space.write_raw(address, &bytes).unwrap();
}

fn process() -> DarwinProcess {
    let mut config = DarwinConfig::embedded(
        "/exclusive-test",
        vec![b"/exclusive-test".to_vec()],
        vec![],
        crate::user::supplied_fs::Files::new(BTreeMap::new()).unwrap(),
        crate::user::console::CapturedConsole::new(Vec::new(), 4096).unwrap(),
    );
    config.abi = Some(DarwinAbi::Arm64);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    config.slice_insns = 1;
    let mut process = DarwinProcess::spawn(config, image()).unwrap();
    process
        .proc
        .space
        .map(DATA, PAGE, Mapping::anonymous(Perms::READ | Perms::WRITE))
        .unwrap();
    process
        .proc
        .space
        .write(DATA, &0x55u64.to_le_bytes())
        .unwrap();
    process
        .proc
        .space
        .write(STATUS, &0xffu32.to_le_bytes())
        .unwrap();
    write_words(
        &process,
        CODE,
        &[
            LDXR_X0_X1,
            STXR_W2_X0_X1,
            STR_W2_X3,
            MOVZ_X16_1,
            MOVZ_X0_0,
            SVC_0,
        ],
    );
    let thread = process.proc.threads.values_mut().next().unwrap();
    let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
        unreachable!("arm64 image selected")
    };
    cpu.core_mut().set_x(1, DATA);
    cpu.core_mut().set_x(3, STATUS);
    cpu.core_mut().set_pc(CODE);
    process
}

fn status(process: &DarwinProcess) -> u32 {
    let mut bytes = [0u8; 4];
    process.proc.space.read(STATUS, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

#[derive(Clone, Copy)]
enum Peer {
    User,
    KernelOnly,
}

fn add_peer(process: &mut DarwinProcess, peer: Peer) -> u64 {
    let tid = *process.proc.threads.keys().next().unwrap() + 1;
    let kport = Port::new(KObject::Thread(tid));
    let port = process.proc.insert_send(&kport);
    let mut cpu = DarwinCpu::new(DarwinAbi::Arm64, &process.proc.space);
    cpu.set_pc(OTHER);
    let mut thread = Thread {
        tid,
        port,
        kport,
        cpu,
        sig: signal::ThreadSig::default(),
        wait: None,
        resume: None,
        pthread: 0,
        exited: false,
        woken: false,
        wake_event: false,
        mach: ThreadMach::default(),
        name: Vec::new(),
        pw: Default::default(),
        assumed: None,
    };
    match peer {
        Peer::User => write_words(process, OTHER, &[B_SELF]),
        Peer::KernelOnly => {
            thread.mach.exception = Some(InFlight {
                raised: Raised {
                    exception: 1,
                    codes: [0, 0],
                    ncodes: 2,
                    fatal: false,
                },
                level: Level::Thread,
                id: 0,
                stateful: false,
                reply: Port::new(KObject::None),
            });
        }
    }
    process.proc.threads.insert(tid, thread);
    tid
}

#[test]
fn same_tid_budget_slices_preserve_reservation_through_process_run() {
    let mut process = process();
    assert_eq!(process.run(), ExitStatus::Exited(0));
    assert_eq!(status(&process), 0, "STXR succeeds after same-TID yields");
}

#[test]
fn selecting_another_user_thread_clears_reservation_through_process_run() {
    let mut process = process();
    let peer = add_peer(&mut process, Peer::User);
    assert_eq!(process.run(), ExitStatus::Exited(0));
    assert_eq!(status(&process), 1, "STXR fails after a guest TID switch");
    assert!(process.proc.threads[&peer].mach.csw > 0);
}

#[test]
fn selecting_a_kernel_only_thread_clears_reservation_through_process_run() {
    let mut process = process();
    let peer = add_peer(&mut process, Peer::KernelOnly);
    assert_eq!(process.run(), ExitStatus::Exited(0));
    assert_eq!(status(&process), 1, "kernel-only TID selection is a switch");
    let selected = &process.proc.threads[&peer];
    assert_eq!(selected.cpu.pc(), OTHER, "peer never entered user mode");
    assert!(selected.wait.is_some(), "peer parked awaiting its reply");
}

#[test]
fn async_signal_handler_entry_clears_reservation_after_budget_yield() {
    let mut process = process();
    write_words(&process, CODE, &[LDXR_X8_X6]);
    write_words(&process, HANDLER, &[STXR_W9_X8_X6]);
    let tid = *process.proc.threads.keys().next().unwrap();
    let mut thread = process.proc.threads.remove(&tid).unwrap();
    let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
        unreachable!("arm64 image selected")
    };
    cpu.core_mut().set_x(6, DATA);
    assert_eq!(cpu.run(1), A64Exit::Yield);
    assert_eq!(cpu.pc(), CODE + 4);

    let sig = signal::SIGUSR1;
    process.proc.sigacts.set(
        sig,
        &signal::SigAction {
            handler: HANDLER,
            tramp: HANDLER,
            ..Default::default()
        },
    );
    thread.sig.pending |= signal::bit(sig);
    signal::ast(&mut process.proc, &mut thread);
    assert_eq!(thread.cpu.pc(), HANDLER);
    assert_eq!(thread.sig.pending_sigreturn, 1);
    let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
        unreachable!("arm64 image selected")
    };
    assert_eq!(cpu.run(1), A64Exit::Yield);
    assert_eq!(cpu.core().get_x(9), 1, "handler STXR must fail");
}

#[test]
fn bounded_calls_preserve_round_robin_and_exclusive_monitor_lifetime() {
    for peer in [None, Some(Peer::User), Some(Peer::KernelOnly)] {
        let mut process = process();
        let other = peer.map(|kind| add_peer(&mut process, kind));
        let cancelled = AtomicBool::new(false);
        let mut result = RunStatus::BudgetExhausted;
        for _ in 0..32 {
            result = process.run_slice(1, &cancelled);
            if matches!(result, RunStatus::Complete(_)) {
                break;
            }
            assert_eq!(result, RunStatus::BudgetExhausted);
        }
        assert_eq!(result, RunStatus::Complete(ExitStatus::Exited(0)));
        assert_eq!(status(&process), u32::from(other.is_some()));
        if let Some(tid) = other {
            assert!(process.proc.threads[&tid].mach.csw > 0);
        }
    }
}
