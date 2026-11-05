//! Native HVF controls selected from independent Linux KVM fixture records.
//! See docs/development/hvf-mmio-double-shifts for indices, provenance and limits.
use super::*;
use rax::devices::bus::MmioRmwOp;

// (reference index, encoding, bytes, source GPR, captured source, raw count,
//  observed memory word, observed flags, defined/unaffected flag mask).
type Reference = (u32, &'static [u8], u8, u8, u64, u8, u64, u64, u32);
const REFERENCES: &[Reference] = &[
    (
        29,
        &[0x66, 0x0f, 0xa4, 0x07, 0x00],
        2,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        209,
        &[0x66, 0x0f, 0xa4, 0x0f, 0x01],
        2,
        1,
        0x39c65aa5f00fc33c,
        1,
        0xa55aa55aa55a4ab5,
        0x803,
        0xffffffef,
    ),
    (
        677,
        &[0x66, 0x44, 0x0f, 0xa4, 0x07, 0x08],
        2,
        8,
        0x39c65aa5f00fc33c,
        8,
        0xa55aa55aa55a5ac3,
        0x807,
        0xfffff7ef,
    ),
    (
        1001,
        &[0x66, 0x44, 0x0f, 0xa4, 0x3f, 0x0f],
        2,
        15,
        0x39c65aa5f00fc33c,
        15,
        0xa55aa55aa55a619e,
        0x803,
        0xfffff7ef,
    ),
    (
        1757,
        &[0x66, 0x0f, 0xa5, 0x07],
        2,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        1937,
        &[0x66, 0x0f, 0xa5, 0x0f],
        2,
        1,
        0x39c65aa5f00fc301,
        1,
        0xa55aa55aa55a4ab5,
        0x803,
        0xffffffef,
    ),
    (
        2405,
        &[0x66, 0x44, 0x0f, 0xa5, 0x07],
        2,
        8,
        0x39c65aa5f00fc33c,
        8,
        0xa55aa55aa55a5ac3,
        0x807,
        0xfffff7ef,
    ),
    (
        2729,
        &[0x66, 0x44, 0x0f, 0xa5, 0x3f],
        2,
        15,
        0x39c65aa5f00fc33c,
        15,
        0xa55aa55aa55a619e,
        0x803,
        0xfffff7ef,
    ),
    (
        3485,
        &[0x0f, 0xa4, 0x07, 0x00],
        4,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        3665,
        &[0x0f, 0xa4, 0x0f, 0x01],
        4,
        1,
        0x39c65aa5f00fc33c,
        1,
        0xa55aa55a4ab54ab5,
        0x803,
        0xffffffef,
    ),
    (
        4565,
        &[0x44, 0x0f, 0xa4, 0x07, 0x10],
        4,
        8,
        0x39c65aa5f00fc33c,
        16,
        0xa55aa55aa55af00f,
        0x886,
        0xfffff7ef,
    ),
    (
        4889,
        &[0x44, 0x0f, 0xa4, 0x3f, 0x1f],
        4,
        15,
        0x39c65aa5f00fc33c,
        31,
        0xa55aa55a7807e19e,
        0x803,
        0xfffff7ef,
    ),
    (
        5789,
        &[0x0f, 0xa5, 0x07],
        4,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        5969,
        &[0x0f, 0xa5, 0x0f],
        4,
        1,
        0x39c65aa5f00fc301,
        1,
        0xa55aa55a4ab54ab5,
        0x803,
        0xffffffef,
    ),
    (
        6869,
        &[0x44, 0x0f, 0xa5, 0x07],
        4,
        8,
        0x39c65aa5f00fc33c,
        16,
        0xa55aa55aa55af00f,
        0x886,
        0xfffff7ef,
    ),
    (
        7193,
        &[0x44, 0x0f, 0xa5, 0x3f],
        4,
        15,
        0x39c65aa5f00fc33c,
        31,
        0xa55aa55a7807e19e,
        0x803,
        0xfffff7ef,
    ),
    (
        8093,
        &[0x48, 0x0f, 0xa4, 0x07, 0x00],
        8,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        8273,
        &[0x48, 0x0f, 0xa4, 0x0f, 0x01],
        8,
        1,
        0x39c65aa5f00fc33c,
        1,
        0x4ab54ab54ab54ab4,
        0x807,
        0xffffffef,
    ),
    (
        9605,
        &[0x4c, 0x0f, 0xa4, 0x07, 0x20],
        8,
        8,
        0x39c65aa5f00fc33c,
        32,
        0xa55aa55a39c65aa5,
        0x886,
        0xfffff7ef,
    ),
    (
        9929,
        &[0x4c, 0x0f, 0xa4, 0x3f, 0x3f],
        8,
        15,
        0x39c65aa5f00fc33c,
        63,
        0x1ce32d52f807e19e,
        0x803,
        0xfffff7ef,
    ),
    (
        10397,
        &[0x48, 0x0f, 0xa5, 0x07],
        8,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        10577,
        &[0x48, 0x0f, 0xa5, 0x0f],
        8,
        1,
        0x39c65aa5f00fc301,
        1,
        0x4ab54ab54ab54ab4,
        0x807,
        0xffffffef,
    ),
    (
        11909,
        &[0x4c, 0x0f, 0xa5, 0x07],
        8,
        8,
        0x39c65aa5f00fc33c,
        32,
        0xa55aa55a39c65aa5,
        0x886,
        0xfffff7ef,
    ),
    (
        12233,
        &[0x4c, 0x0f, 0xa5, 0x3f],
        8,
        15,
        0x39c65aa5f00fc33c,
        63,
        0x1ce32d52f807e19e,
        0x803,
        0xfffff7ef,
    ),
    (
        12701,
        &[0x66, 0x0f, 0xac, 0x07, 0x00],
        2,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        12881,
        &[0x66, 0x0f, 0xac, 0x0f, 0x01],
        2,
        1,
        0x39c65aa5f00fc33c,
        1,
        0xa55aa55aa55a52ad,
        0x802,
        0xffffffef,
    ),
    (
        13349,
        &[0x66, 0x44, 0x0f, 0xac, 0x07, 0x08],
        2,
        8,
        0x39c65aa5f00fc33c,
        8,
        0xa55aa55aa55a3ca5,
        0x806,
        0xfffff7ef,
    ),
    (
        13673,
        &[0x66, 0x44, 0x0f, 0xac, 0x3f, 0x0f],
        2,
        15,
        0x39c65aa5f00fc33c,
        15,
        0xa55aa55aa55a8679,
        0x882,
        0xfffff7ef,
    ),
    (
        14429,
        &[0x66, 0x0f, 0xad, 0x07],
        2,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        14609,
        &[0x66, 0x0f, 0xad, 0x0f],
        2,
        1,
        0x39c65aa5f00fc301,
        1,
        0xa55aa55aa55ad2ad,
        0x82,
        0xffffffef,
    ),
    (
        15077,
        &[0x66, 0x44, 0x0f, 0xad, 0x07],
        2,
        8,
        0x39c65aa5f00fc33c,
        8,
        0xa55aa55aa55a3ca5,
        0x806,
        0xfffff7ef,
    ),
    (
        15401,
        &[0x66, 0x44, 0x0f, 0xad, 0x3f],
        2,
        15,
        0x39c65aa5f00fc33c,
        15,
        0xa55aa55aa55a8679,
        0x882,
        0xfffff7ef,
    ),
    (
        16157,
        &[0x0f, 0xac, 0x07, 0x00],
        4,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        16337,
        &[0x0f, 0xac, 0x0f, 0x01],
        4,
        1,
        0x39c65aa5f00fc33c,
        1,
        0xa55aa55a52ad52ad,
        0x802,
        0xffffffef,
    ),
    (
        17237,
        &[0x44, 0x0f, 0xac, 0x07, 0x10],
        4,
        8,
        0x39c65aa5f00fc33c,
        16,
        0xa55aa55ac33ca55a,
        0x887,
        0xfffff7ef,
    ),
    (
        17561,
        &[0x44, 0x0f, 0xac, 0x3f, 0x1f],
        4,
        15,
        0x39c65aa5f00fc33c,
        31,
        0xa55aa55ae01f8679,
        0x882,
        0xfffff7ef,
    ),
    (
        18461,
        &[0x0f, 0xad, 0x07],
        4,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        18641,
        &[0x0f, 0xad, 0x0f],
        4,
        1,
        0x39c65aa5f00fc301,
        1,
        0xa55aa55ad2ad52ad,
        0x82,
        0xffffffef,
    ),
    (
        19541,
        &[0x44, 0x0f, 0xad, 0x07],
        4,
        8,
        0x39c65aa5f00fc33c,
        16,
        0xa55aa55ac33ca55a,
        0x887,
        0xfffff7ef,
    ),
    (
        19865,
        &[0x44, 0x0f, 0xad, 0x3f],
        4,
        15,
        0x39c65aa5f00fc33c,
        31,
        0xa55aa55ae01f8679,
        0x882,
        0xfffff7ef,
    ),
    (
        20765,
        &[0x48, 0x0f, 0xac, 0x07, 0x00],
        8,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        20945,
        &[0x48, 0x0f, 0xac, 0x0f, 0x01],
        8,
        1,
        0x39c65aa5f00fc33c,
        1,
        0x52ad52ad52ad52ad,
        0x802,
        0xffffffef,
    ),
    (
        22277,
        &[0x4c, 0x0f, 0xac, 0x07, 0x20],
        8,
        8,
        0x39c65aa5f00fc33c,
        32,
        0xf00fc33ca55aa55a,
        0x887,
        0xfffff7ef,
    ),
    (
        22601,
        &[0x4c, 0x0f, 0xac, 0x3f, 0x3f],
        8,
        15,
        0x39c65aa5f00fc33c,
        63,
        0x738cb54be01f8679,
        0x802,
        0xfffff7ef,
    ),
    (
        23069,
        &[0x48, 0x0f, 0xad, 0x07],
        8,
        0,
        0x39c65aa5f00fc33c,
        0,
        0xa55aa55aa55aa55a,
        0x8d7,
        0xffffffff,
    ),
    (
        23249,
        &[0x48, 0x0f, 0xad, 0x0f],
        8,
        1,
        0x39c65aa5f00fc301,
        1,
        0xd2ad52ad52ad52ad,
        0x82,
        0xffffffef,
    ),
    (
        24581,
        &[0x4c, 0x0f, 0xad, 0x07],
        8,
        8,
        0x39c65aa5f00fc33c,
        32,
        0xf00fc33ca55aa55a,
        0x887,
        0xfffff7ef,
    ),
    (
        24905,
        &[0x4c, 0x0f, 0xad, 0x3f],
        8,
        15,
        0x39c65aa5f00fc33c,
        63,
        0x738cb54be01f8679,
        0x802,
        0xfffff7ef,
    ),
];

fn gprs(state: &X86_64CpuState) -> [u64; 16] {
    let r = &state.regs;
    [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ]
}

pub(super) fn emit_references() {
    for &(reference, instruction, width, source, value, count, result, flags, mask) in REFERENCES {
        let code = instruction
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!(
            "{{\"reference\":{reference},\"instruction_hex\":\"{code}\",\"width\":{width},\"source\":{source},\"value\":{value},\"count\":{count},\"result\":{result},\"flags\":{flags},\"flag_mask\":{mask}}}"
        );
    }
}

pub(super) fn run(output: &Path, case: &mut usize) {
    for &(reference, instruction, width, source, value, count, result, flags, mask) in REFERENCES {
        let cl = instruction[instruction.len() - 2] == 0xa5
            || instruction[instruction.len() - 2] == 0xad;
        let right = instruction
            .iter()
            .rev()
            .nth(if cl { 1 } else { 2 })
            .unwrap()
            & 8
            != 0;
        let memory = guest_memory(instruction);
        let (mut vm, mut cpu) = machine(&memory);
        let mut input = initial();
        let CpuState::X86_64(ref mut before) = input else {
            unreachable!()
        };
        before.regs.rflags = 0x8d7;
        *match source {
            0 => &mut before.regs.rax,
            1 => &mut before.regs.rcx,
            8 => &mut before.regs.r8,
            15 => &mut before.regs.r15,
            _ => unreachable!(),
        } = value;
        if cl {
            before.regs.rcx = (before.regs.rcx & !255) | u64::from(count);
        }
        let expected_gprs = gprs(before);
        cpu.set_state(&input).unwrap();
        let pending = event(cpu.as_mut());
        let operation = match pending {
            VcpuExit::MmioRmw {
                addr: MMIO,
                size,
                operation,
            } if size == width => operation,
            exit => panic!("double-shift reference {reference}: {exit:?}"),
        };
        let operand = value & (u64::MAX >> (64 - u32::from(width) * 8));
        let expected_operation = if right {
            MmioRmwOp::DoubleShiftRight {
                source: operand,
                count,
            }
        } else {
            MmioRmwOp::DoubleShiftLeft {
                source: operand,
                count,
            }
        };
        assert_eq!(operation, expected_operation, "reference {reference}");
        assert!(cpu.get_state().is_err());
        assert!(cpu.io_completion_result().is_err());
        assert_eq!(format!("{:?}", event(cpu.as_mut())), format!("{pending:?}"));
        if cl {
            // Capture the encoded private payload while the instruction is
            // suspended, then restore into a fresh VM/SDK CPU on its owner.
            let boundary = vm.checkpoint_boundary().unwrap();
            let (saved, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
            let private = private.expect("native pending transaction payload");
            assert_eq!(private.kind, rax::vm::snapshot::HVF_INTEL_CONTEXT);
            assert!(!private.data.is_empty());
            drop(boundary);
            drop(cpu);
            drop(vm);
            (vm, cpu) = machine(&memory);
            cpu.restore_checkpoint_context(&saved.state, &saved.emulator, Some(&private))
                .unwrap();
            assert!(cpu.get_state().is_err());
            assert_eq!(format!("{:?}", event(cpu.as_mut())), format!("{pending:?}"));
        }
        let old = 0xa55a_a55a_a55a_a55au64;
        let mut device = [0u8; 24];
        for chunk in device.chunks_exact_mut(8) {
            chunk.copy_from_slice(&old.to_le_bytes());
        }
        operation
            .apply(&mut device[8..8 + usize::from(width)])
            .unwrap();
        assert_eq!(&device[..8], &old.to_le_bytes());
        assert_eq!(
            &device[8..16],
            &result.to_le_bytes(),
            "reference {reference}"
        );
        assert_eq!(&device[16..], &old.to_le_bytes());
        cpu.complete_io_in(&old.to_le_bytes()[..usize::from(width)]);
        cpu.io_completion_result().unwrap();
        let completed = state(cpu.as_ref());
        assert_eq!(gprs(&completed), expected_gprs);
        assert_eq!(completed.regs.rip, CODE + instruction.len() as u64);
        assert_eq!(
            (completed.regs.rflags ^ flags) & u64::from(mask),
            0,
            "reference {reference}: defined/unaffected flags"
        );
        assert!(matches!(event(cpu.as_mut()), VcpuExit::Hlt));
        let completed = state(cpu.as_ref());
        assert_eq!(completed.regs.rip, CODE + instruction.len() as u64 + 11);
        assert_eq!(completed.regs.r10, MARKER);
        let mut expected = expected_gprs;
        expected[10] = MARKER;
        assert_eq!(gprs(&completed), expected);
        assert_eq!((completed.regs.rflags ^ flags) & u64::from(mask), 0);
        println!("native_double_shift_reference={reference} restored={cl} result={result:#x}");
        drop(cpu);
        drop(vm);
        record(
            output,
            *case,
            "native-double-shift",
            usize::from(width),
            u64::from(reference),
        );
        *case += 1;
    }
}
