//! Real EPT exits and detached continuations for one-memory string operations.
use super::*;

pub(super) fn run(output: &Path) {
    const DIRECTION: u64 = 1 << 10;
    const RESUME: u64 = 1 << 16;
    const HIGH: u64 = 0x7654_3210_0000_0000;
    const REPLIES: [u64; 2] = [0x8877_6655_4433_2211, 0x1357_9bdf_0246_8ace];
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (code, size, read, repeat, address32, backwards) in [
        (&[0xac][..], 1, true, false, false, false),
        (&[0x48, 0xab][..], 8, false, false, false, true),
        (&[0xf3, 0x67, 0xad][..], 4, true, true, true, true),
        (&[0xf3, 0x66, 0xad][..], 2, true, true, false, false),
        (&[0xf3, 0x67, 0xaa][..], 1, false, true, true, false),
        (&[0xf3, 0x48, 0xab][..], 8, false, true, false, true),
    ] {
        let label = if read { "lods" } else { "stos" };
        let iterations = if repeat { 2 } else { 1 };
        let flags = 2 | if backwards { DIRECTION } else { 0 };
        let high = if address32 { HIGH } else { 0 };
        let mask = u64::MAX >> (64 - 8 * size);
        let increment = if backwards {
            -(size as i64)
        } else {
            size as i64
        };
        for restore in [false, true] {
            let memory = guest_memory(code);
            word(&memory, 0x4000, 0x4000_009b);
            let (mut vm, mut cpu) = machine(&memory);
            let mut initial = state(cpu.as_ref());
            initial.regs.rflags = flags;
            initial.regs.rcx = high | 2;
            if read {
                initial.regs.rsi = high | MMIO;
            } else {
                initial.regs.rdi = high | MMIO;
            }
            cpu.set_state(&CpuState::X86_64(initial)).unwrap();

            let mut rax = SEED;
            let mut address = MMIO;
            for (iteration, &reply) in REPLIES.iter().take(iterations).enumerate() {
                let pending = |cpu: &mut dyn VCpu| {
                    let exit = event(cpu);
                    match exit {
                        VcpuExit::MmioRead { addr, size: width }
                            if read && addr == address && usize::from(width) == size => {}
                        VcpuExit::MmioWrite { addr, ref data }
                            if !read && addr == address && data == &SEED.to_le_bytes()[..size] => {}
                        _ => panic!("unexpected {label} exit for {code:02x?}: {exit:?}"),
                    }
                    assert!(cpu.get_state().is_err());
                    assert!(cpu.io_completion_result().is_err());
                };
                pending(cpu.as_mut());
                if restore {
                    let boundary = vm.checkpoint_boundary().unwrap();
                    let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                    let context = context.unwrap();
                    let CpuState::X86_64(regs) = &saved.state else {
                        panic!("wrong saved CPU");
                    };
                    let high = if iteration == 0 { high } else { 0 };
                    assert_eq!(regs.regs.rip, CODE);
                    assert_eq!(regs.regs.rax, rax);
                    assert_eq!(regs.regs.rcx, high | (2 - iteration as u64));
                    assert_eq!(
                        if read { regs.regs.rsi } else { regs.regs.rdi },
                        high | address
                    );
                    drop(boundary);
                    drop(cpu);
                    drop(vm);
                    (vm, cpu) = machine(&memory);
                    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&context))
                        .unwrap();
                    pending(cpu.as_mut());
                }
                if read {
                    cpu.complete_io_in(&reply.to_le_bytes()[..size]);
                    rax = if size == 4 {
                        reply & mask
                    } else {
                        (rax & !mask) | (reply & mask)
                    };
                } else {
                    cpu.complete_io_out().unwrap();
                }
                cpu.io_completion_result().unwrap();
                address = address.wrapping_add_signed(increment);
                let regs = state(cpu.as_ref()).regs;
                let done = iteration + 1 == iterations;
                assert_eq!(regs.rip, CODE + if done { code.len() as u64 } else { 0 });
                assert_eq!(regs.rax, rax);
                assert_eq!(
                    regs.rcx,
                    if repeat {
                        (iterations - iteration - 1) as u64
                    } else {
                        2
                    }
                );
                assert_eq!(if read { regs.rsi } else { regs.rdi }, address);
                assert_eq!(regs.rflags, flags | if done { 0 } else { RESUME });
                assert_eq!(
                    regs.r10, 0,
                    "guest executed behind a pending string operation"
                );
            }
            assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
            let ended = state(cpu.as_ref()).regs;
            assert_eq!(ended.rip, CODE + code.len() as u64 + 11);
            assert_eq!(ended.r10, MARKER);
            assert_eq!(if read { ended.rsi } else { ended.rdi }, address);
            assert_eq!(ended.rax, rax);
            assert_eq!(ended.rflags, flags);
            let mode = if repeat { "rep" } else { "scalar" };
            let continuation = if restore { "restored" } else { "direct" };
            record(
                output,
                case,
                &format!("{label}-{mode}-{continuation}"),
                size,
                rax,
            );
            case += 1;
        }
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
