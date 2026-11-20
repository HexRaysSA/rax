//! Native SSE2 memory transfers and source-free CPU continuation through EPT.
use super::*;

pub(super) fn run(output: &Path) {
    const REPLY: u64 = 0x8877_6655_4433_2211;
    const FLAGS: u64 = 0x8d7;
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (code, size, index, read) in [
        (&[0x66, 0x0f, 0x6e, 0x07][..], 4, 0, true),
        (&[0x66, 0x44, 0x0f, 0x7e, 0x3f], 4, 15, false),
        (&[0x66, 0x4c, 0x0f, 0x6e, 0x3f], 8, 15, true),
        (&[0x66, 0x48, 0x0f, 0x7e, 0x07], 8, 0, false),
        (&[0xf3, 0x44, 0x0f, 0x7e, 0x3f], 8, 15, true),
        (&[0x66, 0x0f, 0xd6, 0x07], 8, 0, false),
    ] {
        for restore in [false, true] {
            let memory = guest_memory(code);
            word(&memory, 0x4000, 0x4000_009b);
            let (mut vm, mut cpu) = machine(&memory);
            let mut initial = state(cpu.as_ref());
            initial.regs.xmm = std::array::from_fn(|lane| {
                let low = SEED.wrapping_add(lane as u64);
                [low, !low]
            });
            initial.regs.rflags = FLAGS;
            let mut lanes = initial.regs.xmm;
            let store = lanes[index][0].to_le_bytes();
            cpu.set_state(&CpuState::X86_64(initial)).unwrap();

            let pending = |cpu: &mut dyn VCpu| {
                let exit = event(cpu);
                match exit {
                    VcpuExit::MmioRead {
                        addr: MMIO,
                        size: width,
                    } if read && usize::from(width) == size => {}
                    VcpuExit::MmioWrite {
                        addr: MMIO,
                        ref data,
                    } if !read && data == &store[..size] => {}
                    _ => panic!("unexpected XMM MMIO exit for {code:02x?}: {exit:?}"),
                }
                assert!(cpu.get_state().is_err());
                assert!(cpu.io_completion_result().is_err());
            };
            pending(cpu.as_mut());
            if restore {
                let boundary = vm.checkpoint_boundary().unwrap();
                let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                assert_eq!(saved.state.pc(), CODE);
                let context = context.unwrap();
                drop(boundary);
                drop(cpu);
                drop(vm);
                (vm, cpu) = machine(&memory);
                cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&context))
                    .unwrap();
                pending(cpu.as_mut());
            }
            let mask = u64::MAX >> (64 - 8 * size);
            let value = if read {
                cpu.complete_io_in(&REPLY.to_le_bytes()[..size]);
                lanes[index] = [REPLY & mask, 0];
                REPLY & mask
            } else {
                cpu.complete_io_out().unwrap();
                u64::from_le_bytes(store) & mask
            };
            cpu.io_completion_result().unwrap();
            let finished = state(cpu.as_ref());
            assert_eq!(finished.regs.rip, CODE + code.len() as u64);
            assert_eq!(finished.regs.xmm, lanes);
            halted_with_flags(cpu.as_mut(), code.len(), SEED, FLAGS);
            assert_eq!(state(cpu.as_ref()).regs.xmm, lanes);
            drop(cpu);
            drop(vm);
            let name = match (read, restore) {
                (true, false) => "legacy-xmm-read",
                (true, true) => "legacy-xmm-read-restored",
                (false, false) => "legacy-xmm-write",
                (false, true) => "legacy-xmm-write-restored",
            };
            record(output, case, name, size, value);
            case += 1;
        }
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
