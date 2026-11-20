//! Real EPT exits and detached continuations for one-memory string operations.
use super::*;

fn string_registers(regs: &rax::vm::vcpu::Registers, load: bool) -> (u64, u64) {
    (regs.rcx, if load { regs.rsi } else { regs.rdi })
}

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
            assert_eq!(
                string_registers(&state(cpu.as_ref()).regs, read),
                (high | 2, high | MMIO)
            );

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
                    assert_eq!(regs.regs.rip, CODE);
                    assert_eq!(regs.regs.rax, rax);
                    let (count, index) = string_registers(&regs.regs, read);
                    let expected_count = 2 - iteration as u64;
                    if address32 && iteration == 0 {
                        // The native EPT exit may clear the upper halves
                        // before completing the first 32-bit REP iteration.
                        assert_eq!(count as u32, expected_count as u32);
                        assert_eq!(index as u32, address as u32);
                        assert!(matches!(count & !u64::from(u32::MAX), 0 | HIGH));
                        assert!(matches!(index & !u64::from(u32::MAX), 0 | HIGH));
                        println!("{label} native EPT frontier: count={count:#x}, index={index:#x}");
                    } else {
                        assert_eq!((count, index), (expected_count, address));
                    }
                    drop(boundary);
                    drop(cpu);
                    drop(vm);
                    (vm, cpu) = machine(&memory);
                    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&context))
                        .unwrap();
                    pending(cpu.as_mut());
                    let boundary = vm.checkpoint_boundary().unwrap();
                    let (restored, _) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                    let CpuState::X86_64(restored) = restored.state else {
                        panic!("wrong restored CPU");
                    };
                    assert_eq!(string_registers(&restored.regs, read), (count, index));
                    assert_eq!(restored.regs.rax, regs.regs.rax);
                    assert_eq!(restored.regs.rip, regs.regs.rip);
                    assert_eq!(restored.regs.rflags, regs.regs.rflags);
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
    let case = run_scalar_scan(output, case);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}

fn run_scalar_scan(output: &Path, mut case: usize) -> usize {
    const DF: u64 = 1 << 10;
    const RF: u64 = 1 << 16;
    const CF: u64 = 1;
    const PF: u64 = 1 << 2;
    const AF: u64 = 1 << 4;
    const ZF: u64 = 1 << 6;
    const SF: u64 = 1 << 7;
    const OF: u64 = 1 << 11;
    const STATUS: u64 = CF | PF | AF | ZF | SF | OF;
    const COUNT: u64 = 0x1234_4321_0000_0002;
    for (code, size, acc, rhs, backwards, expected) in [
        (
            &[0xae][..],
            1,
            0x1234_5678_9abc_007fu64,
            0x80u64,
            false,
            CF | PF | SF | OF,
        ),
        (
            &[0x66, 0xaf][..],
            2,
            0x1234_5678_9abc_0000,
            1,
            true,
            CF | PF | AF | SF,
        ),
        (
            &[0xaf][..],
            4,
            0x1234_5678_8000_0000,
            0x8000_0000,
            false,
            PF | ZF,
        ),
        (
            &[0x48, 0xaf][..],
            8,
            0,
            0x8000_0000_0000_0000,
            true,
            CF | PF | SF | OF,
        ),
        (
            &[0x67, 0xae][..],
            1,
            0x1234_5678_9abc_007f,
            0x80,
            true,
            CF | PF | SF | OF,
        ),
    ] {
        let direction = if backwards { DF } else { 0 };
        for restored in [false, true] {
            let memory = guest_memory(code);
            word(&memory, 0x4000, 0x4000_009b);
            let (mut vm, mut cpu) = machine(&memory);
            let mut initial = state(cpu.as_ref());
            initial.regs.rax = acc;
            initial.regs.rcx = COUNT;
            initial.regs.rdi = if code[0] == 0x67 {
                0x7654_3210_0000_0000 | MMIO
            } else {
                MMIO
            };
            initial.regs.rflags = 2 | direction | STATUS;
            cpu.set_state(&CpuState::X86_64(initial)).unwrap();
            let pending = |cpu: &mut dyn VCpu| {
                let exit = event(cpu);
                assert!(
                    matches!(exit, VcpuExit::MmioRead { addr: MMIO, size: actual } if usize::from(actual) == size),
                    "unexpected SCAS exit for {code:02x?}: {exit:?}"
                );
                assert!(cpu.io_completion_result().is_err());
            };
            pending(cpu.as_mut());
            if restored {
                let boundary = vm.checkpoint_boundary().unwrap();
                let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                let CpuState::X86_64(saved_cpu) = &saved.state else {
                    panic!("wrong saved CPU")
                };
                assert_eq!(saved_cpu.regs.rax, acc);
                assert_eq!(saved_cpu.regs.rcx, COUNT);
                assert_eq!(saved_cpu.regs.rdi as u32, MMIO as u32);
                assert_eq!(saved_cpu.regs.rip, CODE);
                assert_eq!(saved_cpu.regs.rflags & !RF, 2 | direction | STATUS);
                drop(boundary);
                drop(cpu);
                drop(vm);
                (vm, cpu) = machine(&memory);
                cpu.restore_checkpoint_context(
                    &saved.state,
                    &saved.emulator,
                    Some(&context.unwrap()),
                )
                .unwrap();
                pending(cpu.as_mut());
                let boundary = vm.checkpoint_boundary().unwrap();
                let (restored_cpu, _) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                let CpuState::X86_64(restored_cpu) = restored_cpu.state else {
                    panic!("wrong restored CPU")
                };
                assert_eq!(restored_cpu.regs.rdi, saved_cpu.regs.rdi);
                assert_eq!(restored_cpu.regs.rflags, saved_cpu.regs.rflags);
            }
            cpu.complete_io_in(&rhs.to_le_bytes()[..size]);
            cpu.io_completion_result().unwrap();
            let regs = state(cpu.as_ref()).regs;
            let next = MMIO.wrapping_add_signed(if backwards {
                -(size as i64)
            } else {
                size as i64
            });
            assert_eq!(regs.rax, acc);
            assert_eq!(regs.rcx, COUNT);
            assert_eq!(regs.rdi, next);
            assert_eq!(regs.rip, CODE + code.len() as u64);
            assert_eq!(regs.rflags, 2 | direction | expected);
            assert_eq!(regs.r10, 0);
            assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
            let ended = state(cpu.as_ref()).regs;
            assert_eq!(ended.r10, MARKER);
            assert_eq!(ended.rdi, next);
            assert_eq!(ended.rflags, regs.rflags);
            let label = if restored {
                "scas-scalar-restored"
            } else {
                "scas-scalar-direct"
            };
            record(output, case, label, size, ended.rflags);
            case += 1;
        }
    }
    case
}
