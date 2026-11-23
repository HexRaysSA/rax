//! Native SSE, SSE2 and AVX XMM memory transfers, alignment faults and source-free continuation.
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
        "guest must read back XCR0=7 before testing the XMM and YMM lanes: {exit:?}",
    );
    cpu.complete_io_out().unwrap();
    cpu.io_completion_result().unwrap();
}

pub(super) fn run(output: &Path, vex: bool) {
    const REPLY: u128 = 0x1100_ffee_ddcc_bbaa_8877_6655_4433_2211;
    const FLAGS: u64 = 0x8d7;
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    let profile = if vex { "vex-xmm" } else { "legacy-xmm" };
    let existing_cases: [(&[u8], usize, usize, bool); 8] = if vex {
        [
            (&[0xc5, 0xf9, 0x6e, 0x07], 4, 0, true),
            (&[0xc5, 0x79, 0x7e, 0x3f], 4, 15, false),
            (&[0xc4, 0x61, 0xf9, 0x6e, 0x3f], 8, 15, true),
            (&[0xc4, 0xe1, 0xf9, 0x7e, 0x07], 8, 0, false),
            (&[0xc5, 0x7a, 0x7e, 0x3f], 8, 15, true),
            (&[0xc5, 0xf9, 0xd6, 0x07], 8, 0, false),
            (&[0xc5, 0x7a, 0x6f, 0x7f, 3], 16, 15, true),
            (&[0xc5, 0xfa, 0x7f, 0x47, 3], 16, 0, false),
        ]
    } else {
        [
            (&[0x66, 0x0f, 0x6e, 0x07], 4, 0, true),
            (&[0x66, 0x44, 0x0f, 0x7e, 0x3f], 4, 15, false),
            (&[0x66, 0x4c, 0x0f, 0x6e, 0x3f], 8, 15, true),
            (&[0x66, 0x48, 0x0f, 0x7e, 0x07], 8, 0, false),
            (&[0xf3, 0x44, 0x0f, 0x7e, 0x3f], 8, 15, true),
            (&[0x66, 0x0f, 0xd6, 0x07], 8, 0, false),
            (&[0xf3, 0x44, 0x0f, 0x6f, 0x7f, 3], 16, 15, true),
            (&[0xf3, 0x0f, 0x7f, 0x47, 3], 16, 0, false),
        ]
    };
    let aligned_cases: [(&[u8], usize, usize, bool); 2] = if vex {
        [
            (&[0xc5, 0x79, 0x6f, 0x3f], 16, 15, true),
            (&[0xc4, 0xe1, 0x79, 0x7f, 0x07], 16, 0, false),
        ]
    } else {
        [
            (&[0x66, 0x0f, 0x6f, 0x07], 16, 0, true),
            (&[0x66, 0x44, 0x0f, 0x7f, 0x3f], 16, 15, false),
        ]
    };
    // Unaligned memory forms encode [RDI+3]. Aligned forms use [RDI].
    let packed_cases: [((&[u8], usize, usize, bool), bool, &str); 8] = if vex {
        [
            (
                (&[0xc5, 0x78, 0x10, 0x7f, 0x03], 16, 15, true),
                false,
                "packed-ups-",
            ),
            (
                (&[0xc5, 0xf8, 0x11, 0x47, 0x03], 16, 0, false),
                false,
                "packed-ups-",
            ),
            (
                (&[0xc4, 0x61, 0xf9, 0x10, 0x7f, 0x03], 16, 15, true),
                false,
                "packed-upd-",
            ),
            (
                (&[0xc4, 0x61, 0xf9, 0x11, 0x7f, 0x03], 16, 15, false),
                false,
                "packed-upd-",
            ),
            (
                (&[0xc5, 0x78, 0x28, 0x3f], 16, 15, true),
                true,
                "packed-aps-",
            ),
            (
                (&[0xc5, 0xf8, 0x29, 0x07], 16, 0, false),
                true,
                "packed-aps-",
            ),
            (
                (&[0xc4, 0x61, 0xf9, 0x28, 0x3f], 16, 15, true),
                true,
                "packed-apd-",
            ),
            (
                (&[0xc4, 0x61, 0xf9, 0x29, 0x3f], 16, 15, false),
                true,
                "packed-apd-",
            ),
        ]
    } else {
        [
            (
                (&[0x0f, 0x10, 0x47, 0x03], 16, 0, true),
                false,
                "packed-ups-",
            ),
            (
                (&[0x44, 0x0f, 0x11, 0x7f, 0x03], 16, 15, false),
                false,
                "packed-ups-",
            ),
            (
                (&[0x66, 0x44, 0x0f, 0x10, 0x7f, 0x03], 16, 15, true),
                false,
                "packed-upd-",
            ),
            (
                (&[0x66, 0x44, 0x0f, 0x11, 0x7f, 0x03], 16, 15, false),
                false,
                "packed-upd-",
            ),
            ((&[0x0f, 0x28, 0x07], 16, 0, true), true, "packed-aps-"),
            (
                (&[0x44, 0x0f, 0x29, 0x3f], 16, 15, false),
                true,
                "packed-aps-",
            ),
            (
                (&[0x66, 0x44, 0x0f, 0x28, 0x3f], 16, 15, true),
                true,
                "packed-apd-",
            ),
            (
                (&[0x66, 0x44, 0x0f, 0x29, 0x3f], 16, 15, false),
                true,
                "packed-apd-",
            ),
        ]
    };
    let scalar_cases: [((&[u8], usize, usize, bool), bool, &str); 4] = if vex {
        [
            (
                (&[0xc5, 0x7a, 0x10, 0x3f], 4, 15, true),
                false,
                "scalar-ss-",
            ),
            (
                (&[0xc5, 0xfa, 0x11, 0x07], 4, 0, false),
                false,
                "scalar-ss-",
            ),
            (
                (&[0xc4, 0x61, 0xfb, 0x10, 0x3f], 8, 15, true),
                false,
                "scalar-sd-",
            ),
            (
                (&[0xc4, 0x61, 0xfb, 0x11, 0x3f], 8, 15, false),
                false,
                "scalar-sd-",
            ),
        ]
    } else {
        [
            ((&[0xf3, 0x0f, 0x10, 0x07], 4, 0, true), false, "scalar-ss-"),
            (
                (&[0xf3, 0x44, 0x0f, 0x11, 0x3f], 4, 15, false),
                false,
                "scalar-ss-",
            ),
            (
                (&[0xf2, 0x44, 0x0f, 0x10, 0x3f], 8, 15, true),
                false,
                "scalar-sd-",
            ),
            (
                (&[0xf2, 0x44, 0x0f, 0x11, 0x3f], 8, 15, false),
                false,
                "scalar-sd-",
            ),
        ]
    };
    let transfers = existing_cases
        .into_iter()
        .map(|entry| (entry, false, ""))
        .chain(
            aligned_cases
                .into_iter()
                .map(|entry| (entry, true, "aligned-")),
        )
        .chain(packed_cases)
        .chain(scalar_cases);
    for ((code, size, index, read), aligned, form) in transfers {
        for restore in [false, true] {
            let memory = guest_memory(code);
            word(&memory, 0x4000, 0x4000_009b);
            let (mut vm, mut cpu) = machine(&memory);
            enable_guest_avx(&memory, cpu.as_mut());
            let mut initial = state(cpu.as_ref());
            initial.regs.rip = CODE;
            initial.regs.rax = SEED;
            let address = if size == 16 && !aligned {
                MMIO + 3
            } else {
                MMIO
            };
            initial.regs.ymm_high = std::array::from_fn(|lane| {
                let low = MARKER.wrapping_add(lane as u64);
                [low, !low]
            });
            initial.regs.xmm = std::array::from_fn(|lane| {
                let low = SEED.wrapping_add(lane as u64);
                [low, !low]
            });
            initial.regs.rflags = FLAGS;
            let mut lanes = initial.regs.xmm;
            let mut upper = initial.regs.ymm_high;
            let mut store = [0; 16];
            store[..8].copy_from_slice(&lanes[index][0].to_le_bytes());
            store[8..].copy_from_slice(&lanes[index][1].to_le_bytes());
            cpu.set_state(&CpuState::X86_64(initial)).unwrap();

            let pending = |cpu: &mut dyn VCpu| {
                let exit = event(cpu);
                match exit {
                    VcpuExit::MmioRead { addr, size: width }
                        if read && addr == address && usize::from(width) == size => {}
                    VcpuExit::MmioWrite { addr, ref data }
                        if !read && addr == address && data == &store[..size] => {}
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
            let mask = u64::MAX >> (64 - 8 * size.min(8));
            let value = if read {
                cpu.complete_io_in(&REPLY.to_le_bytes()[..size]);
                let upper_reply = if size == 16 { (REPLY >> 64) as u64 } else { 0 };
                lanes[index] = [REPLY as u64 & mask, upper_reply];
                if vex {
                    upper[index] = [0; 2];
                }
                REPLY as u64 & mask
            } else {
                cpu.complete_io_out().unwrap();
                lanes[index][0] & mask
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
            let suffix = match (read, restore) {
                (true, false) => "read",
                (true, true) => "read-restored",
                (false, false) => "write",
                (false, true) => "write-restored",
            };
            record(
                output,
                case,
                &format!("{profile}-{form}{suffix}"),
                size,
                value,
            );
            case += 1;
        }
    }
    let faults = aligned_cases.into_iter().map(|entry| (entry, "")).chain(
        packed_cases
            .into_iter()
            .filter_map(|(entry, aligned, name)| aligned.then_some((entry, name))),
    );
    for ((code, size, _, read), form) in faults {
        let fault_pc = alignment_fault(code, vex);
        let direction = if read { "read" } else { "write" };
        record(
            output,
            case,
            &format!("{profile}-{form}misaligned-{direction}"),
            size,
            fault_pc,
        );
        case += 1;
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}

fn alignment_fault(code: &[u8], vex: bool) -> u64 {
    const OBSERVATIONS: u64 = 0xa000;
    const HANDLER: u64 = 0xb000;
    const IDT: u64 = 0xc000;
    let memory = guest_memory(code);
    word(&memory, 0x4000, 0x4000_009b);
    let gate = (HANDLER & 0xffff) | (8 << 16) | (0x8e << 40) | (((HANDLER >> 16) & 0xffff) << 48);
    word(&memory, IDT + 13 * 16, gate);
    word(&memory, IDT + 13 * 16 + 8, HANDLER >> 32);
    let handler = gp_fault_handler(OBSERVATIONS as u32, code.len() as u8);
    memory
        .memory()
        .write_slice(&handler, GuestAddress(HANDLER))
        .unwrap();
    let (_vm, mut cpu) = machine(&memory);
    if vex {
        enable_guest_avx(&memory, cpu.as_mut());
    }
    let mut input = state(cpu.as_ref());
    input.regs.rip = CODE;
    input.regs.rdi = MMIO + 3;
    input.regs.rflags = 0x8d7;
    input.regs.xmm = std::array::from_fn(|lane| [SEED + lane as u64, MARKER ^ lane as u64]);
    if vex {
        input.regs.ymm_high =
            std::array::from_fn(|lane| [!SEED - lane as u64, !MARKER ^ lane as u64]);
    }
    input.sregs.idt.base = IDT;
    input.sregs.idt.limit = 4095;
    cpu.set_state(&CpuState::X86_64(input.clone())).unwrap();
    let exit = event(cpu.as_mut());
    assert!(
        matches!(exit, VcpuExit::Hlt),
        "misaligned XMM must reach the guest #GP handler, got {exit:?}"
    );
    let after = state(cpu.as_ref());
    assert_eq!(after.regs.rip, CODE + code.len() as u64 + 11);
    assert_eq!(after.regs.r10, MARKER);
    assert_eq!(after.regs.rdi, MMIO + 3);
    assert_eq!(after.regs.rflags, input.regs.rflags);
    assert_eq!(after.regs.xmm, input.regs.xmm);
    assert_eq!(after.regs.ymm_high, input.regs.ymm_high);
    assert_eq!(read_word(&memory, OBSERVATIONS), 1);
    assert_eq!(read_word(&memory, OBSERVATIONS + 8), 0);
    let fault_pc = read_word(&memory, OBSERVATIONS + 16);
    assert_eq!(fault_pc, CODE);
    fault_pc
}
