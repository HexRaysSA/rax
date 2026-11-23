//! Native SSE, SSE2 and AVX vector memory transfers, alignment faults and source-free continuation.
use super::*;

type MoveCase<'a> = ((&'a [u8], usize, usize, bool), bool, &'a str);

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
    let packed_cases: [MoveCase<'_>; 8] = if vex {
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
    let scalar_cases: [MoveCase<'_>; 4] = if vex {
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
    // Each pair uses a VEX2 load into YMM15 and a VEX3 store from YMM0.
    // The 32-byte aligned forms address [RDI], while unaligned forms use [RDI+3].
    let ymm_cases = [
        (2, 0x6f, 0x7f, false, "ymm-dqu-"),
        (1, 0x6f, 0x7f, true, "ymm-dqa-"),
        (0, 0x10, 0x11, false, "ymm-ups-"),
        (1, 0x10, 0x11, false, "ymm-upd-"),
        (0, 0x28, 0x29, true, "ymm-aps-"),
        (1, 0x28, 0x29, true, "ymm-apd-"),
    ];
    let ymm_code = ymm_cases.map(|(prefix, read, write, aligned, _)| {
        let load_rm = if aligned { 0x3f } else { 0x7f };
        let store_rm = if aligned { 0x07 } else { 0x47 };
        let load = [0xc5, 0x7c | prefix, read, load_rm, 3];
        let store = [0xc4, 0xe1, 0xfc | prefix, write, store_rm, 3];
        (load, store)
    });
    let ymm_transfers = ymm_cases.iter().zip(&ymm_code).filter(|_| vex).flat_map(
        |((_, _, _, aligned, name), (load, store))| {
            let displacement = usize::from(!aligned);
            [
                ((&load[..4 + displacement], 32, 15, true), *aligned, *name),
                ((&store[..5 + displacement], 32, 0, false), *aligned, *name),
            ]
        },
    );
    let transfers = existing_cases
        .into_iter()
        .map(|entry| (entry, false, ""))
        .chain(
            aligned_cases
                .into_iter()
                .map(|entry| (entry, true, "aligned-")),
        )
        .chain(packed_cases)
        .chain(scalar_cases)
        .chain(ymm_transfers);
    run_cases(output, vex, profile, transfers.collect());
}

pub(super) fn run_streaming_stores(output: &Path, vex: bool) {
    let profile = if vex { "vex-ntstore" } else { "legacy-ntstore" };
    let forms = [
        (
            0,
            0x2b,
            [
                "ntps-",
                "vex2-xmm-ntps-",
                "vex3-xmm-ntps-",
                "vex2-ymm-ntps-",
                "vex3-ymm-ntps-",
            ],
        ),
        (
            1,
            0x2b,
            [
                "ntpd-",
                "vex2-xmm-ntpd-",
                "vex3-xmm-ntpd-",
                "vex2-ymm-ntpd-",
                "vex3-ymm-ntpd-",
            ],
        ),
        (
            1,
            0xe7,
            [
                "ntdq-",
                "vex2-xmm-ntdq-",
                "vex3-xmm-ntdq-",
                "vex2-ymm-ntdq-",
                "vex3-ymm-ntdq-",
            ],
        ),
    ];
    let encodings = forms.map(|(prefix, opcode, _)| {
        [
            [0x66, 0x44, 0x0f, opcode, 0x3f],
            [0xc5, 0x78 | prefix, opcode, 0x3f, 0],
            [0xc4, 0x61, 0xf8 | prefix, opcode, 0x3f],
            [0xc5, 0x7c | prefix, opcode, 0x3f, 0],
            [0xc4, 0x61, 0xfc | prefix, opcode, 0x3f],
        ]
    });
    let mut cases = Vec::new();
    for ((prefix, _, names), code) in forms.into_iter().zip(&encodings) {
        let legacy = &code[0][usize::from(prefix == 0)..];
        let vex_forms = [&code[1][..4], &code[2], &code[3][..4], &code[4]];
        if vex {
            for ((code, name), width) in
                vex_forms.into_iter().zip(&names[1..]).zip([16, 16, 32, 32])
            {
                cases.push(((code, width, 15, false), true, *name));
            }
        } else {
            cases.push(((legacy, 16, 15, false), true, names[0]));
        }
    }
    run_cases(output, vex, profile, cases);
}

pub(super) fn run_lanes(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (prefix, lane, name) in [(0, 0, "lps"), (0, 1, "hps"), (1, 0, "lpd"), (1, 1, "hpd")] {
        for read in [true, false] {
            let opcode = 0x12 + lane as u8 * 4 + u8::from(!read);
            let vex = if read { 0x38 } else { 0x78 } | prefix;
            let legacy = [0x66, 0x44, 0x0f, opcode, 0x7f, 3];
            for (code, encoding) in [
                (&legacy[usize::from(prefix == 0)..], "legacy"),
                (&[0xc5, vex, opcode, 0x7f, 3][..], "vex2"),
                (&[0xc4, 0x61, vex, opcode, 0x7f, 3], "vex3"),
            ] {
                for restore in [false, true] {
                    let value = lane_case(code, lane, encoding != "legacy", read, restore);
                    let direction = if read { "read" } else { "write" };
                    let phase = if restore { "restored" } else { "direct" };
                    record(
                        output,
                        case,
                        &format!("xmm-lanes-{encoding}-{name}-{direction}-{phase}"),
                        8,
                        value,
                    );
                    case += 1;
                }
            }
        }
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}

fn lane_case(code: &[u8], lane: usize, vex: bool, read: bool, restore: bool) -> u64 {
    const FLAGS: u64 = 0x8d7;
    const VALUE: u64 = 0x7e2d_b864_11db_feb0;
    let memory = guest_memory(code);
    word(&memory, 0x4000, 0x4000_009b);
    let (mut vm, mut cpu) = machine(&memory);
    enable_guest_avx(&memory, cpu.as_mut());
    let mut initial = state(cpu.as_ref());
    initial.regs.rip = CODE;
    initial.regs.rdi = MMIO;
    initial.regs.rax = SEED;
    initial.regs.rflags = FLAGS;
    initial.regs.xmm = std::array::from_fn(|index| [SEED + index as u64, MARKER - index as u64]);
    initial.regs.ymm_high =
        std::array::from_fn(|index| [!SEED - index as u64, !MARKER + index as u64]);
    let mut xmm = initial.regs.xmm;
    let mut upper = initial.regs.ymm_high;
    let output = xmm[15][lane].to_le_bytes();
    cpu.set_state(&CpuState::X86_64(initial)).unwrap();

    let pending = |cpu: &mut dyn VCpu| {
        let exit = event(cpu);
        match exit {
            VcpuExit::MmioRead { addr, size: 8 } if read && addr == MMIO + 3 => (),
            VcpuExit::MmioWrite { addr, ref data }
                if !read && addr == MMIO + 3 && data == &output =>
            {
                ()
            }
            _ => panic!("unexpected XMM lane exit for {code:02x?}: {exit:?}"),
        }
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
    if read {
        cpu.complete_io_in(&VALUE.to_le_bytes());
        if vex {
            xmm[15] = xmm[8];
            upper[15] = [0; 2];
        }
        xmm[15][lane] = VALUE;
    } else {
        cpu.complete_io_out().unwrap();
    }
    cpu.io_completion_result().unwrap();
    let retired = state(cpu.as_ref());
    assert_eq!(retired.regs.rip, CODE + code.len() as u64);
    assert_eq!(retired.regs.xmm, xmm);
    assert_eq!(retired.regs.ymm_high, upper);
    halted_with_flags(cpu.as_mut(), code.len(), SEED, FLAGS);
    let final_state = state(cpu.as_ref());
    assert_eq!(final_state.regs.xmm, xmm);
    assert_eq!(final_state.regs.ymm_high, upper);
    drop(cpu);
    drop(vm);
    if read {
        VALUE
    } else {
        u64::from_le_bytes(output)
    }
}

pub(super) fn run_logic(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (prefix, opcode, name) in [
        (0, 0x54, "andps"),
        (0, 0x55, "andnps"),
        (0, 0x56, "orps"),
        (0, 0x57, "xorps"),
        (1, 0x54, "andpd"),
        (1, 0x55, "andnpd"),
        (1, 0x56, "orpd"),
        (1, 0x57, "xorpd"),
        (1, 0xdb, "pand"),
        (1, 0xdf, "pandn"),
        (1, 0xeb, "por"),
        (1, 0xef, "pxor"),
    ] {
        let legacy = [0x66, 0x44, 0x0f, opcode, 0x3f];
        let legacy = &legacy[usize::from(prefix == 0)..];
        let vex = 0x38 | prefix;
        for (code, encoding, width, vex) in [
            (legacy, "legacy", 16, false),
            (&[0xc5, vex, opcode, 0x7f, 3], "vex2-128", 16, true),
            (&[0xc4, 0x61, vex, opcode, 0x7f, 3], "vex3-128", 16, true),
            (&[0xc5, vex | 4, opcode, 0x7f, 3], "vex2-256", 32, true),
            (
                &[0xc4, 0x61, vex | 4, opcode, 0x7f, 3],
                "vex3-256",
                32,
                true,
            ),
        ] {
            for restore in [false, true] {
                let value = logic_case(code, opcode, width, vex, restore);
                let phase = if restore { "restored" } else { "direct" };
                record(
                    output,
                    case,
                    &format!("vector-logic-{encoding}-{name}-{phase}"),
                    width,
                    value,
                );
                case += 1;
            }
        }
        let fault_pc = alignment_fault(legacy, false, 3);
        record(
            output,
            case,
            &format!("vector-logic-legacy-{name}-misaligned"),
            16,
            fault_pc,
        );
        case += 1;
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}

fn logic_case(code: &[u8], opcode: u8, width: usize, vex: bool, restore: bool) -> u64 {
    const FLAGS: u64 = 0x8d7;
    const REPLY: [u64; 4] = [
        0x1608_a460_3d32_5a17,
        0x0033_ee86_b407_a9de,
        0x7bcd_ff42_ea16_70af,
        0xec73_3584_8dc6_bf0a,
    ];
    let memory = guest_memory(code);
    word(&memory, 0x4000, 0x4000_009b);
    let (mut vm, mut cpu) = machine(&memory);
    enable_guest_avx(&memory, cpu.as_mut());
    let mut initial = state(cpu.as_ref());
    let device_address = MMIO + if vex { 3 } else { 0 };
    initial.regs.rip = CODE;
    initial.regs.rdi = MMIO;
    initial.regs.rax = SEED;
    initial.regs.rflags = FLAGS;
    initial.regs.xmm = std::array::from_fn(|index| [SEED + index as u64, MARKER - index as u64]);
    initial.regs.ymm_high =
        std::array::from_fn(|index| [!SEED - index as u64, !MARKER + index as u64]);
    let mut xmm = initial.regs.xmm;
    let mut upper = initial.regs.ymm_high;
    let source = if vex { 8 } else { 15 };
    cpu.set_state(&CpuState::X86_64(initial)).unwrap();

    let pending = |cpu: &mut dyn VCpu| {
        let exit = event(cpu);
        assert!(
            matches!(exit, VcpuExit::MmioRead { addr, size } if addr == device_address && usize::from(size) == width),
            "unexpected packed logic exit for {code:02x?}: {exit:?}",
        );
        assert!(cpu.io_completion_result().is_err());
    };
    pending(cpu.as_mut());
    if restore {
        (vm, cpu) = restore_vector_read(&memory, vm, cpu);
        pending(cpu.as_mut());
    }
    let result = |left: u64, right: u64| match opcode {
        0x54 | 0xdb => left & right,
        0x55 | 0xdf => !left & right,
        0x56 | 0xeb => left | right,
        0x57 | 0xef => left ^ right,
        _ => unreachable!(),
    };
    xmm[15] = [
        result(xmm[source][0], REPLY[0]),
        result(xmm[source][1], REPLY[1]),
    ];
    if width == 32 {
        upper[15] = [
            result(upper[source][0], REPLY[2]),
            result(upper[source][1], REPLY[3]),
        ];
    } else if vex {
        upper[15] = [0; 2];
    }
    let reply = REPLY.map(u64::to_le_bytes).concat();
    cpu.complete_io_in(&reply[..width]);
    cpu.io_completion_result().unwrap();
    let retired = state(cpu.as_ref());
    assert_eq!(retired.regs.rip, CODE + code.len() as u64);
    assert_eq!(retired.regs.rdi, MMIO);
    assert_eq!(retired.regs.rflags, FLAGS);
    assert_eq!(retired.regs.xmm, xmm);
    assert_eq!(retired.regs.ymm_high, upper);
    halted_with_flags(cpu.as_mut(), code.len(), SEED, FLAGS);
    let final_state = state(cpu.as_ref());
    assert_eq!(final_state.regs.xmm, xmm);
    assert_eq!(final_state.regs.ymm_high, upper);
    drop(cpu);
    drop(vm);
    let [low0, low1] = retired.regs.xmm[15];
    let [high0, high1] = retired.regs.ymm_high[15];
    low0 ^ low1.rotate_left(7) ^ high0.rotate_left(23) ^ high1.rotate_left(41)
}

fn restore_vector_read(
    memory: &GuestMemoryWrapper,
    vm: Box<dyn Vm>,
    cpu: Box<dyn VCpu>,
) -> (Box<dyn Vm>, Box<dyn VCpu>) {
    // Re-execution would fault on UD2. Only the recorded transaction can retire.
    memory
        .memory()
        .write_slice(&[0x0f, 0x0b], GuestAddress(CODE))
        .unwrap();
    let boundary = vm.checkpoint_boundary().unwrap();
    let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    assert_eq!(saved.state.pc(), CODE);
    drop(boundary);
    drop(cpu);
    drop(vm);
    let (vm, mut cpu) = machine(memory);
    cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&context.unwrap()))
        .unwrap();
    (vm, cpu)
}

pub(super) fn run_bit_tests(output: &Path) {
    const LEGACY: [u8; 6] = [0x66, 0x44, 0x0f, 0x38, 0x17, 0x3f];
    assert!(!output.exists(), "observations must be new");
    let mut cases = vec![("ptest", LEGACY, 16, 1, false)];
    for (opcode, name, stride) in [
        (0x17, "vptest", 1),
        (0x0e, "vtestps", 4),
        (0x0f, "vtestpd", 8),
    ] {
        let prefixes = if opcode == 0x17 {
            &[0x79, 0x7d, 0xf9, 0xfd][..]
        } else {
            &[0x79, 0x7d]
        };
        for &prefix in prefixes {
            let width = if prefix & 4 == 0 { 16 } else { 32 };
            let code = [0xc4, 0x62, prefix, opcode, 0x7f, 3];
            cases.push((name, code, width, stride, true));
        }
    }
    let mut case = 0;
    for (name, code, width, stride, vex) in cases {
        for flags in 0..4 {
            for restore in [false, true] {
                let value = bit_test_case(&code, width, stride, vex, flags, restore);
                let phase = if restore { "restored" } else { "direct" };
                let w = u8::from(vex && code[2] & 0x80 != 0);
                record(
                    output,
                    case,
                    &format!("vector-bit-test-{name}-{width}-w{w}-{flags}-{phase}"),
                    width,
                    value,
                );
                case += 1;
            }
        }
    }
    let fault_pc = alignment_fault(&LEGACY, false, 3);
    record(
        output,
        case,
        "vector-bit-test-ptest-misaligned",
        16,
        fault_pc,
    );
    case += 1;
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}

fn bit_test_case(
    code: &[u8],
    width: usize,
    stride: usize,
    vex: bool,
    flags: u8,
    restore: bool,
) -> u64 {
    const FLAGS: u64 = 0x8d7;
    let memory = guest_memory(code);
    word(&memory, 0x4000, 0x4000_009b);
    let (mut vm, mut cpu) = machine(&memory);
    enable_guest_avx(&memory, cpu.as_mut());

    let mut left = [0x4a; 32];
    let mut reply = [if stride == 1 { 0 } else { 0x37 }; 32];
    if flags & 1 != 0 {
        left[stride - 1] |= 0x80;
        reply[stride - 1] |= 0x80;
    }
    if flags & 2 != 0 {
        reply[width - 1] |= 0x80;
    }
    let words: [u64; 4] = std::array::from_fn(|index| {
        u64::from_le_bytes(left[index * 8..index * 8 + 8].try_into().unwrap())
    });
    let mut initial = state(cpu.as_ref());
    initial.regs.rip = CODE;
    initial.regs.rdi = MMIO;
    initial.regs.rax = SEED;
    initial.regs.rflags = FLAGS;
    initial.regs.xmm = std::array::from_fn(|index| [SEED + index as u64, MARKER - index as u64]);
    initial.regs.ymm_high =
        std::array::from_fn(|index| [!SEED - index as u64, !MARKER + index as u64]);
    initial.regs.xmm[15] = [words[0], words[1]];
    initial.regs.ymm_high[15] = [words[2], words[3]];
    let xmm = initial.regs.xmm;
    let upper = initial.regs.ymm_high;
    cpu.set_state(&CpuState::X86_64(initial)).unwrap();

    let device_address = MMIO + if vex { 3 } else { 0 };
    let pending = |cpu: &mut dyn VCpu| {
        let exit = event(cpu);
        assert!(
            matches!(exit, VcpuExit::MmioRead { addr, size } if addr == device_address && usize::from(size) == width),
            "unexpected packed bit-test exit for {code:02x?}: {exit:?}",
        );
        assert!(cpu.io_completion_result().is_err());
    };
    pending(cpu.as_mut());
    if restore {
        (vm, cpu) = restore_vector_read(&memory, vm, cpu);
        pending(cpu.as_mut());
    }
    cpu.complete_io_in(&reply[..width]);
    cpu.io_completion_result().unwrap();
    let expected = 2 | (u64::from(flags & 1 == 0) << 6) | u64::from(flags & 2 == 0);
    let retired = state(cpu.as_ref());
    assert_eq!(retired.regs.rip, CODE + code.len() as u64);
    assert_eq!(retired.regs.rdi, MMIO);
    assert_eq!(retired.regs.rflags, expected);
    assert_eq!(retired.regs.xmm, xmm);
    assert_eq!(retired.regs.ymm_high, upper);
    halted_with_flags(cpu.as_mut(), code.len(), SEED, expected);
    assert_eq!(state(cpu.as_ref()).regs.ymm_high, upper);
    drop(cpu);
    drop(vm);
    retired.regs.rflags & 0x8d5
}

fn run_cases(output: &Path, vex: bool, profile: &str, transfers: Vec<MoveCase<'_>>) {
    const REPLY: u128 = 0x1100_ffee_ddcc_bbaa_8877_6655_4433_2211;
    const HIGH_REPLY: u128 = 0x99aa_2233_4567_dead_babe_1111_7777_cafe;
    const FLAGS: u64 = 0x8d7;
    let mut reply = [0; 32];
    reply[..16].copy_from_slice(&REPLY.to_le_bytes());
    reply[16..].copy_from_slice(&HIGH_REPLY.to_le_bytes());
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for &((code, size, index, read), aligned, form) in &transfers {
        for restore in [false, true] {
            let memory = guest_memory(code);
            word(&memory, 0x4000, 0x4000_009b);
            let (mut vm, mut cpu) = machine(&memory);
            enable_guest_avx(&memory, cpu.as_mut());
            let mut initial = state(cpu.as_ref());
            initial.regs.rip = CODE;
            initial.regs.rax = SEED;
            let address = if size >= 16 && !aligned {
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
            let mut store = [0; 32];
            for (bytes, value) in store
                .chunks_exact_mut(8)
                .zip(lanes[index].into_iter().chain(upper[index]))
            {
                bytes.copy_from_slice(&value.to_le_bytes());
            }
            cpu.set_state(&CpuState::X86_64(initial)).unwrap();

            let pending = |cpu: &mut dyn VCpu| {
                let exit = event(cpu);
                match exit {
                    VcpuExit::MmioRead { addr, size: width }
                        if read && addr == address && usize::from(width) == size => {}
                    VcpuExit::MmioWrite { addr, ref data }
                        if !read && addr == address && data == &store[..size] => {}
                    _ => panic!("unexpected vector MMIO exit for {code:02x?}: {exit:?}"),
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
                cpu.complete_io_in(&reply[..size]);
                let high_xmm = if size >= 16 { (REPLY >> 64) as u64 } else { 0 };
                lanes[index] = [REPLY as u64 & mask, high_xmm];
                if size == 32 {
                    upper[index] = [HIGH_REPLY as u64, (HIGH_REPLY >> 64) as u64];
                } else if vex {
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
    let faults = transfers.into_iter().filter_map(|(entry, aligned, name)| {
        // Existing aligned cases use the profile name alone for fault rows.
        aligned.then_some((entry, if name == "aligned-" { "" } else { name }))
    });
    for ((code, size, _, read), form) in faults {
        // Offset 16 remains aligned for XMM moves but faults for aligned YMM moves.
        let offset = if size == 32 { 16 } else { 3 };
        let fault_pc = alignment_fault(code, vex, offset);
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

fn alignment_fault(code: &[u8], vex: bool, offset: u64) -> u64 {
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
    input.regs.rdi = MMIO + offset;
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
        "misaligned vector move must reach the guest #GP handler, got {exit:?}"
    );
    let after = state(cpu.as_ref());
    assert_eq!(after.regs.rip, CODE + code.len() as u64 + 11);
    assert_eq!(after.regs.r10, MARKER);
    assert_eq!(after.regs.rdi, input.regs.rdi);
    assert_eq!(after.regs.rflags, input.regs.rflags);
    assert_eq!(after.regs.xmm, input.regs.xmm);
    assert_eq!(after.regs.ymm_high, input.regs.ymm_high);
    assert_eq!(read_word(&memory, OBSERVATIONS), 1);
    assert_eq!(read_word(&memory, OBSERVATIONS + 8), 0);
    let fault_pc = read_word(&memory, OBSERVATIONS + 16);
    assert_eq!(fault_pc, CODE);
    fault_pc
}
