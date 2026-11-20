//! Native SSE2 and AVX scalar memory transfers and source-free CPU continuation through EPT.
use super::*;

fn enable_guest_avx(memory: &GuestMemoryWrapper, cpu: &mut dyn VCpu) {
    const BOOTSTRAP: u64 = CODE + 0x1000;
    memory
        .memory()
        .write_slice(
            &[
                0x31, 0xc9, // XOR ECX, ECX: XCR0.
                0x31, 0xd2, // XOR EDX, EDX: high half of XCR0.
                0xb8, 7, 0, 0, 0, // MOV EAX, 7: x87, SSE and AVX.
                0x0f, 0x01, 0xd1, // XSETBV.
                0x0f, 0x01, 0xd0, // XGETBV.
                0xe7, 0xe9, // OUT 0xe9, EAX.
            ],
            GuestAddress(BOOTSTRAP),
        )
        .unwrap();
    let mut initial = state(cpu);
    initial.regs.rip = BOOTSTRAP;
    initial.sregs.cr4 |= 1 << 18; // OSXSAVE.
    cpu.set_state(&CpuState::X86_64(initial)).unwrap();
    let exit = event(cpu);
    assert!(
        matches!(exit, VcpuExit::IoOut { port: 0xe9, ref data } if data == &7u32.to_le_bytes()),
        "guest must read back XCR0=7 before AVX MMIO: {exit:?}",
    );
    cpu.complete_io_out().unwrap();
    cpu.io_completion_result().unwrap();
}

pub(super) fn run(output: &Path, vex: bool) {
    const REPLY: u64 = 0x8877_6655_4433_2211;
    const FLAGS: u64 = 0x8d7;
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    let cases: [(&[u8], usize, usize, bool); 6] = if vex {
        [
            (&[0xc5, 0xf9, 0x6e, 0x07], 4, 0, true),
            (&[0xc5, 0x79, 0x7e, 0x3f], 4, 15, false),
            (&[0xc4, 0x61, 0xf9, 0x6e, 0x3f], 8, 15, true),
            (&[0xc4, 0xe1, 0xf9, 0x7e, 0x07], 8, 0, false),
            (&[0xc5, 0x7a, 0x7e, 0x3f], 8, 15, true),
            (&[0xc5, 0xf9, 0xd6, 0x07], 8, 0, false),
        ]
    } else {
        [
            (&[0x66, 0x0f, 0x6e, 0x07], 4, 0, true),
            (&[0x66, 0x44, 0x0f, 0x7e, 0x3f], 4, 15, false),
            (&[0x66, 0x4c, 0x0f, 0x6e, 0x3f], 8, 15, true),
            (&[0x66, 0x48, 0x0f, 0x7e, 0x07], 8, 0, false),
            (&[0xf3, 0x44, 0x0f, 0x7e, 0x3f], 8, 15, true),
            (&[0x66, 0x0f, 0xd6, 0x07], 8, 0, false),
        ]
    };
    for (code, size, index, read) in cases {
        for restore in [false, true] {
            let memory = guest_memory(code);
            word(&memory, 0x4000, 0x4000_009b);
            let (mut vm, mut cpu) = machine(&memory);
            if vex {
                enable_guest_avx(&memory, cpu.as_mut());
            }
            let mut initial = state(cpu.as_ref());
            initial.regs.rip = CODE;
            initial.regs.rax = SEED;
            if vex {
                initial.regs.ymm_high = std::array::from_fn(|lane| {
                    let low = MARKER.wrapping_add(lane as u64);
                    [low, !low]
                });
            }
            initial.regs.xmm = std::array::from_fn(|lane| {
                let low = SEED.wrapping_add(lane as u64);
                [low, !low]
            });
            initial.regs.rflags = FLAGS;
            let mut lanes = initial.regs.xmm;
            let mut upper = initial.regs.ymm_high;
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
                if vex {
                    upper[index] = [0; 2];
                }
                REPLY & mask
            } else {
                cpu.complete_io_out().unwrap();
                u64::from_le_bytes(store) & mask
            };
            cpu.io_completion_result().unwrap();
            let finished = state(cpu.as_ref());
            assert_eq!(finished.regs.rip, CODE + code.len() as u64);
            assert_eq!(finished.regs.xmm, lanes);
            assert_eq!(finished.regs.ymm_high, upper);
            halted_with_flags(cpu.as_mut(), code.len(), SEED, FLAGS);
            let regs = state(cpu.as_ref()).regs;
            assert_eq!(regs.xmm, lanes);
            assert_eq!(regs.ymm_high, upper);
            drop(cpu);
            drop(vm);
            let profile = if vex { "vex-xmm" } else { "legacy-xmm" };
            let suffix = match (read, restore) {
                (true, false) => "read",
                (true, true) => "read-restored",
                (false, false) => "write",
                (false, true) => "write-restored",
            };
            record(output, case, &format!("{profile}-{suffix}"), size, value);
            case += 1;
        }
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
