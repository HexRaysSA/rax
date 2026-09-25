//! Direct/native differentials for state-backed x87 environment operations.

use super::*;
use crate::vm::vcpu::VCpu;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const STACK: u64 = 0x8000;

/// The exact binary80 encoding of the binary64 value with `bits`.
fn raw(bits: u64) -> [u8; 10] {
    crate::smir::interpret::SmirInterpreter::x86_x87_from_f64(f64::from_bits(bits))
}

fn register_store_forms() -> impl Iterator<Item = (u8, u8, bool, u16)> {
    [
        (0xDD, 0xD0, false, 0x05D0),
        (0xDD, 0xD8, true, 0x05D8),
        (0xDF, 0xD0, true, 0x07D0),
    ]
    .into_iter()
    .flat_map(|(escape, base, pop, fop)| {
        (0..8u8).map(move |st| (escape, base + st, pop, fop + u16::from(st)))
    })
}

#[test]
fn x87_register_store_preserves_physical_tags_and_masked_unmasked_stack_responses() {
    for (escape, modrm, pop, fop) in register_store_forms() {
        for top in 0..8u8 {
            for tag in 0..4u16 {
                for masked in [false, true] {
                    let mut cpu = test_vcpu(memory_with_code(&[escape, modrm, 0xF4]));
                    cpu.fpu.top = top;
                    cpu.fpu.status_word = (u16::from(top) << 11) | 0x4700;
                    cpu.fpu.control_word = 0x037E | u16::from(masked);
                    cpu.fpu.tag_word = (0x6996 & !(3 << (top * 2))) | (tag << (top * 2));
                    cpu.fpu.st[usize::from(top)] = raw(0xFFF0_A5A5_5A5A_1234);
                    let mut expected = fpu_image(&cpu);
                    expected.instr_ptr = 0;
                    expected.last_opcode = fop;
                    expected.status_word &= !0x0200;
                    let empty = tag == 3;
                    if empty {
                        expected.status_word |= 0x0041;
                        if !masked {
                            expected.status_word |= 0x8080;
                        }
                    }
                    if !empty || masked {
                        let destination = (top + (modrm & 7)) & 7;
                        expected.st[usize::from(destination)] = if empty {
                            crate::smir::X86X87State::INDEFINITE
                        } else {
                            expected.st[usize::from(top)]
                        };
                        let result_tag = if empty { 2 } else { tag };
                        expected.tag_word = (expected.tag_word & !(3 << (destination * 2)))
                            | (result_tag << (destination * 2));
                        if pop {
                            expected.tag_word |= 3 << (top * 2);
                            expected.top = (top + 1) & 7;
                            expected.status_word =
                                (expected.status_word & !0x3800) | (u16::from(expected.top) << 11);
                        }
                    }
                    assert!(cpu.step().unwrap().is_none());
                    assert_eq!(cpu.regs.rip, 2);
                    assert_eq!(
                        fpu_image(&cpu),
                        expected,
                        "{escape:02X} {modrm:02X}, TOP={top}, tag={tag}, masked={masked}"
                    );
                }
            }
        }
    }
}

#[test]
fn x87_register_store_waiting_faults_are_precise_and_noncommitting() {
    for (escape, modrm, _, _) in register_store_forms() {
        for (cr0, pending, vector) in [
            (4, false, 7),
            (8, false, 7),
            (0x2C, true, 7),
            (0x20, true, 16),
        ] {
            let mut cpu = test_vcpu(memory_with_code(&[escape, modrm, 0xF4]));
            cpu.sregs.cr0 = cr0;
            cpu.fpu.status_word &= !0x8080;
            if pending {
                cpu.fpu.status_word |= 0x8080;
            }
            let before = fpu_image(&cpu);
            let mut native = test_vcpu(memory_with_code(&[escape, modrm, 0xEB, 0x00, 0xF4]));
            let region = native
                .jit_compile_region()
                .unwrap()
                .expect("guarded native store");
            native.sregs.cr0 = cr0;
            native.fpu = cpu.fpu.clone();
            let registers_before = register_image(&native);
            native.jit_run_region_native(&region);
            assert_eq!(register_image(&native), registers_before);
            assert_eq!(fpu_image(&native), before);
            let error = exception_without_idt(&mut cpu);
            assert!(
                error.contains(&format!("IDT entry {vector} not present")),
                "{error}"
            );
            assert_eq!(
                fpu_image(&cpu),
                before,
                "{escape:02X} {modrm:02X}, CR0={cr0:#x}"
            );
            assert_eq!(cpu.regs.rip, 0);
        }
    }
}

#[test]
fn jit_x87_register_store_matches_direct_and_deopts_empty_sources_without_commit() {
    for (escape, modrm, _, _) in register_store_forms() {
        for top in 0..8u8 {
            for (tag, masked) in
                (0..4u16).flat_map(|tag| [false, true].map(move |masked| (tag, masked)))
            {
                let code = [escape, modrm, 0xEB, 0x00, 0xF4];
                let mut direct = test_vcpu(memory_with_code(&code));
                let mut native = test_vcpu(memory_with_code(&code));
                for cpu in [&mut direct, &mut native] {
                    cpu.fpu.top = top;
                    cpu.fpu.status_word = (u16::from(top) << 11) | 0x4700;
                    cpu.fpu.control_word = 0x037E | u16::from(masked);
                    cpu.fpu.tag_word = (0x6996 & !(3 << (top * 2))) | (tag << (top * 2));
                    cpu.fpu.st[usize::from(top)] = raw(0xFFF0_A5A5_5A5A_1234);
                    cpu.regs.r8 = 0x8877_6655_4433_2211;
                }
                let before = fpu_image(&native);
                let before_registers = register_image(&native);
                let region = native
                    .jit_compile_region()
                    .unwrap()
                    .expect("native register store admission");
                assert!(region.uses_x87_environment_state);
                native.jit_run_region_native(&region);
                if tag == 3 {
                    assert_eq!(native.regs.rip, 0);
                    assert_eq!(fpu_image(&native), before);
                    assert_eq!(register_image(&native), before_registers);
                    run_direct_to(&mut native, 4);
                } else {
                    assert_eq!(native.regs.rip, 4);
                }
                run_direct_to(&mut direct, 4);
                assert_eq!(
                    fpu_image(&native),
                    fpu_image(&direct),
                    "{escape:02X} {modrm:02X}, TOP={top}, tag={tag}"
                );
                assert_eq!(register_image(&native), register_image(&direct));
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FpuImage {
    control_word: u16,
    status_word: u16,
    tag_word: u16,
    data_ptr: u64,
    instr_ptr: u64,
    last_opcode: u16,
    st: [[u8; 10]; 8],
    top: u8,
}

fn fpu_image(vcpu: &X86_64Vcpu) -> FpuImage {
    FpuImage {
        control_word: vcpu.fpu.control_word,
        status_word: vcpu.fpu.status_word,
        tag_word: vcpu.fpu.tag_word,
        data_ptr: vcpu.fpu.data_ptr,
        instr_ptr: vcpu.fpu.instr_ptr,
        last_opcode: vcpu.fpu.last_opcode,
        st: vcpu.fpu.st,
        top: vcpu.fpu.top,
    }
}

fn register_image(vcpu: &X86_64Vcpu) -> serde_json::Value {
    serde_json::to_value(vcpu.get_regs().expect("read materialized x86 registers"))
        .expect("serialize x86 register image")
}

fn memory_with_code(code: &[u8]) -> Arc<GuestMemoryMmap> {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    memory
}

fn test_vcpu(memory: Arc<GuestMemoryMmap>) -> X86_64Vcpu {
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.selector = 0;
    vcpu.sregs.cr0 = 0x21;
    vcpu.regs.rip = 0;
    vcpu.regs.rsp = STACK;
    vcpu.regs.rbp = 0x7000;
    vcpu.regs.rax = 0xA5A5_5A5A_DEAD_BEEF;
    vcpu.regs.rbx = 0x1122_3344_5566_7788;
    vcpu.regs.rcx = 0x8877_6655_4433_2211;
    vcpu.regs.rdx = 0x0123_4567_89AB_CDEF;
    vcpu.regs.r16 = 0x1616_1616_1616_1616;
    vcpu.regs.r31 = 0x3131_3131_3131_3131;
    vcpu.regs.rflags = 0x2 | 0x08D5 | flags::bits::DF;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);
    seed_fpu(&mut vcpu);
    vcpu
}

fn seed_fpu(vcpu: &mut X86_64Vcpu) {
    vcpu.fpu.control_word = 0x027F;
    vcpu.fpu.status_word = (5 << 11) | 0x87FF;
    vcpu.fpu.tag_word = 0x6996;
    vcpu.fpu.data_ptr = 0x1122_3344_5566_7788;
    vcpu.fpu.instr_ptr = 0x8877_6655_4433_2211;
    vcpu.fpu.last_opcode = 0x05A5;
    vcpu.fpu.st = std::array::from_fn(|index| {
        raw(0x3FF0_0000_0000_0000 | ((index as u64) << 40) | index as u64)
    });
    vcpu.fpu.top = 5;
}

fn seed_stack_metadata_fpu(vcpu: &mut X86_64Vcpu) {
    seed_fpu(vcpu);
    vcpu.fpu.control_word = 0x027F;
    vcpu.fpu.status_word = (5 << 11) | 0x4700 | 0x003F;
    vcpu.fpu.tag_word = 0;
    vcpu.fpu.top = 5;
}

#[derive(Clone, Copy, Debug)]
enum StackMetadata {
    DecrementTop,
    IncrementTop,
    Free(u8),
    FreePop(u8),
}

impl StackMetadata {
    fn encoding(self) -> [u8; 2] {
        match self {
            Self::DecrementTop => [0xD9, 0xF6],
            Self::IncrementTop => [0xD9, 0xF7],
            Self::Free(st) => [0xDD, 0xC0 + st],
            Self::FreePop(st) => [0xDF, 0xC0 + st],
        }
    }

    fn fop(self) -> u16 {
        match self {
            Self::DecrementTop => 0x01F6,
            Self::IncrementTop => 0x01F7,
            Self::Free(st) => 0x05C0 + u16::from(st),
            Self::FreePop(st) => 0x07C0 + u16::from(st),
        }
    }

    fn expected(self, mut before: FpuImage, guest_pc: u64) -> FpuImage {
        let old_top = before.top;
        match self {
            Self::DecrementTop => {
                before.top = old_top.wrapping_sub(1) & 7;
                before.status_word = (before.status_word & !0x3A00) | (u16::from(before.top) << 11);
            }
            Self::IncrementTop => {
                before.top = old_top.wrapping_add(1) & 7;
                before.status_word = (before.status_word & !0x3A00) | (u16::from(before.top) << 11);
            }
            Self::Free(st) => {
                let physical = old_top.wrapping_add(st) & 7;
                before.tag_word |= 3 << (u16::from(physical) * 2);
            }
            Self::FreePop(st) => {
                let physical = old_top.wrapping_add(st) & 7;
                before.tag_word |= 3 << (u16::from(physical) * 2);
                before.tag_word |= 3 << (u16::from(old_top) * 2);
                before.top = old_top.wrapping_add(1) & 7;
                before.status_word = (before.status_word & !0x3800) | (u16::from(before.top) << 11);
            }
        }
        before.instr_ptr = guest_pc;
        before.last_opcode = self.fop();
        before
    }
}

fn stack_metadata_forms() -> Vec<StackMetadata> {
    let mut forms = vec![StackMetadata::DecrementTop, StackMetadata::IncrementTop];
    for st in 0..8 {
        forms.push(StackMetadata::Free(st));
        forms.push(StackMetadata::FreePop(st));
    }
    forms
}

#[derive(Clone, Copy, Debug)]
enum SignOperation {
    ChangeSign,
    Absolute,
}

impl SignOperation {
    fn encoding(self) -> [u8; 2] {
        match self {
            Self::ChangeSign => [0xD9, 0xE0],
            Self::Absolute => [0xD9, 0xE1],
        }
    }

    fn fop(self) -> u16 {
        match self {
            Self::ChangeSign => 0x01E0,
            Self::Absolute => 0x01E1,
        }
    }

    fn expected_bits(self, bits: u64) -> u64 {
        match self {
            Self::ChangeSign => bits ^ (1 << 63),
            Self::Absolute => bits & !(1 << 63),
        }
    }
}

const SIGN_OPERATIONS: [SignOperation; 2] = [SignOperation::ChangeSign, SignOperation::Absolute];
const LEGACY_X87_PREFIXES: [&[u8]; 14] = [
    &[],
    &[0x66],
    &[0xF2],
    &[0xF3],
    &[0x67],
    &[0x64],
    &[0x65],
    &[0x48],
    &[0x44],
    &[0x41],
    &[0x4D],
    &[0x66, 0x48],
    &[0xF2, 0x48],
    &[0xF3, 0x48],
];

fn run_direct_to(vcpu: &mut X86_64Vcpu, target: u64) {
    for _ in 0..16 {
        if vcpu.regs.rip == target {
            return;
        }
        assert!(
            vcpu.step().expect("direct x87 control sequence").is_none(),
            "unexpected direct exit at {:#x}",
            vcpu.regs.rip
        );
    }
    panic!("direct x87 execution did not reach {target:#x}");
}

fn exception_without_idt(vcpu: &mut X86_64Vcpu) -> String {
    format!(
        "{:#}",
        vcpu.step()
            .expect_err("exception delivery must fail against the empty test IDT")
    )
}

#[test]
fn jit_x87_no_wait_controls_match_direct_for_every_ignored_prefix_class() {
    for (name, instruction) in [
        ("FNCLEX", &[0xDB, 0xE2][..]),
        ("FNINIT", &[0xDB, 0xE3][..]),
        ("FNSTSW AX", &[0xDF, 0xE0][..]),
    ] {
        for prefix in [None, Some(0x66), Some(0xF2), Some(0xF3)] {
            let encoded = prefix
                .into_iter()
                .chain(instruction.iter().copied())
                .collect::<Vec<_>>();
            let mut code = encoded.clone();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let hlt_pc = encoded.len() as u64 + 2;
            let mut direct = test_vcpu(memory_with_code(&code));
            let mut native = test_vcpu(memory_with_code(&code));

            run_direct_to(&mut direct, hlt_pc);
            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{name}, {prefix:?}: compile error: {error:?}"))
                .unwrap_or_else(|| panic!("{name}, {prefix:?}: must be native eligible"));
            assert!(region.uses_x87_environment_state, "{name}, {prefix:?}");
            assert!(!region.uses_mmx, "{name}, {prefix:?}");
            native.jit_run_region_native(&region);

            assert_eq!(
                register_image(&native),
                register_image(&direct),
                "{name}, {prefix:?}: register state"
            );
            assert_eq!(
                fpu_image(&native),
                fpu_image(&direct),
                "{name}, {prefix:?}: x87 state"
            );
            assert_eq!(native.regs.rip, hlt_pc, "{name}, {prefix:?}: frontier");
        }
    }
}

#[test]
fn jit_x87_cr0_em_ts_guard_is_dynamic_precise_and_noncommitting() {
    for fault_bits in [1 << 2, 1 << 3, (1 << 2) | (1 << 3)] {
        for (name, instruction) in [
            ("FNCLEX", &[0xDB, 0xE2][..]),
            ("FNINIT", &[0xDB, 0xE3][..]),
            ("FNSTSW AX", &[0xDF, 0xE0][..]),
        ] {
            let mut code = instruction.to_vec();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let mut native = test_vcpu(memory_with_code(&code));

            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{name}: compile error: {error:?}"))
                .unwrap_or_else(|| panic!("{name}: CR0 guard must remain native"));
            native.sregs.cr0 |= fault_bits;
            let registers_before = register_image(&native);
            let fpu_before = fpu_image(&native);
            native.jit_run_region_native(&region);

            assert_eq!(native.regs.rip, 0, "{name}, CR0={fault_bits:#x}");
            assert_eq!(
                register_image(&native),
                registers_before,
                "{name}, CR0={fault_bits:#x}: register commit"
            );
            assert_eq!(
                fpu_image(&native),
                fpu_before,
                "{name}, CR0={fault_bits:#x}: x87 commit"
            );
            let error = exception_without_idt(&mut native);
            assert!(
                error.contains("IDT entry 7 not present"),
                "{name}, CR0={fault_bits:#x}: expected #NM, got {error}"
            );
        }
    }
}

#[test]
fn x87_encoding_faults_precede_cr0_device_not_available() {
    for (name, instruction) in [
        ("FNCLEX", &[0xDB, 0xE2][..]),
        ("FNINIT", &[0xDB, 0xE3][..]),
        ("FNSTSW AX", &[0xDF, 0xE0][..]),
        ("FDECSTP", &[0xD9, 0xF6][..]),
        ("FINCSTP", &[0xD9, 0xF7][..]),
        ("FFREE ST(3)", &[0xDD, 0xC3][..]),
        ("FFREEP ST(3)", &[0xDF, 0xC3][..]),
        ("FCHS", &[0xD9, 0xE0][..]),
        ("FABS", &[0xD9, 0xE1][..]),
        ("FST ST(3)", &[0xDD, 0xD3][..]),
        ("FSTP ST(3)", &[0xDD, 0xDB][..]),
        ("FSTP ST(3) alias", &[0xDF, 0xD3][..]),
    ] {
        let mut locked = vec![0xF0];
        locked.extend_from_slice(instruction);
        let mut direct = test_vcpu(memory_with_code(&locked));
        direct.sregs.cr0 |= 1 << 3;
        let registers_before = register_image(&direct);
        let fpu_before = fpu_image(&direct);
        let error = exception_without_idt(&mut direct);
        assert!(
            error.contains("IDT entry 6 not present"),
            "LOCK {name}: expected #UD before #NM, got {error}"
        );
        assert_eq!(register_image(&direct), registers_before, "LOCK {name}");
        assert_eq!(fpu_image(&direct), fpu_before, "LOCK {name}");

        let mut rex2 = vec![0xD5, 0x00];
        rex2.extend_from_slice(instruction);
        rex2.extend_from_slice(&[0xEB, 0x00, 0xF4]);

        let mut apx_disabled = test_vcpu(memory_with_code(&rex2));
        apx_disabled.sregs.cr0 |= 1 << 3;
        apx_disabled.set_apx_enabled(true);
        let region = apx_disabled
            .jit_compile_region()
            .unwrap_or_else(|compile| panic!("REX2 {name}: {compile:?}"))
            .unwrap_or_else(|| panic!("REX2 {name}: guarded form must be native"));
        apx_disabled.set_apx_enabled(false);
        let registers_before = register_image(&apx_disabled);
        let fpu_before = fpu_image(&apx_disabled);
        apx_disabled.jit_run_region_native(&region);
        assert_eq!(apx_disabled.regs.rip, 0, "REX2 {name}: APX frontier");
        assert_eq!(
            register_image(&apx_disabled),
            registers_before,
            "REX2 {name}"
        );
        assert_eq!(fpu_image(&apx_disabled), fpu_before, "REX2 {name}");
        let error = exception_without_idt(&mut apx_disabled);
        assert!(
            error.contains("IDT entry 6 not present"),
            "REX2 {name}: expected #UD before #NM, got {error}"
        );

        let mut apx_enabled = test_vcpu(memory_with_code(&rex2));
        apx_enabled.sregs.cr0 |= 1 << 3;
        apx_enabled.set_apx_enabled(true);
        let region = apx_enabled
            .jit_compile_region()
            .unwrap_or_else(|compile| panic!("REX2 {name}: {compile:?}"))
            .unwrap_or_else(|| panic!("REX2 {name}: guarded form must be native"));
        apx_enabled.jit_run_region_native(&region);
        assert_eq!(apx_enabled.regs.rip, 0, "REX2 {name}: x87 frontier");
        let error = exception_without_idt(&mut apx_enabled);
        assert!(
            error.contains("IDT entry 7 not present"),
            "REX2 {name}: expected #NM with APX enabled, got {error}"
        );
    }
}

#[test]
fn jit_x87_stack_metadata_matches_direct_for_all_scanned_register_encodings() {
    for form in stack_metadata_forms() {
        for prefix in LEGACY_X87_PREFIXES {
            let encoded = prefix
                .iter()
                .copied()
                .chain(form.encoding())
                .collect::<Vec<_>>();
            let mut code = encoded.clone();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let hlt_pc = encoded.len() as u64 + 2;
            let mut direct = test_vcpu(memory_with_code(&code));
            let mut native = test_vcpu(memory_with_code(&code));
            seed_stack_metadata_fpu(&mut direct);
            seed_stack_metadata_fpu(&mut native);
            let expected = form.expected(fpu_image(&direct), 0);

            run_direct_to(&mut direct, hlt_pc);
            assert_eq!(fpu_image(&direct), expected, "{form:?}, {prefix:02X?}");

            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{form:?}, {prefix:02X?}: {error:?}"))
                .unwrap_or_else(|| panic!("{form:?}, {prefix:02X?}: native gate"));
            assert!(region.uses_x87_environment_state, "{form:?}, {prefix:02X?}");
            assert!(!region.uses_mmx, "{form:?}, {prefix:02X?}");
            native.jit_run_region_native(&region);

            assert_eq!(
                register_image(&native),
                register_image(&direct),
                "{form:?}, {prefix:02X?}: register state"
            );
            assert_eq!(
                fpu_image(&native),
                fpu_image(&direct),
                "{form:?}, {prefix:02X?}: x87 state"
            );
            assert_eq!(native.regs.rip, hlt_pc, "{form:?}, {prefix:02X?}");
        }
    }
}

#[test]
fn jit_x87_stack_metadata_waiting_guard_is_dynamic_precise_and_noncommitting() {
    for form in [
        StackMetadata::DecrementTop,
        StackMetadata::IncrementTop,
        StackMetadata::Free(3),
        StackMetadata::FreePop(3),
    ] {
        for (fault_bits, expected_vector) in
            [(0, 16), (1 << 2, 7), (1 << 3, 7), ((1 << 2) | (1 << 3), 7)]
        {
            let mut code = form.encoding().to_vec();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let mut native = test_vcpu(memory_with_code(&code));
            seed_stack_metadata_fpu(&mut native);
            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{form:?}: {error:?}"))
                .unwrap_or_else(|| panic!("{form:?}: guarded form must remain native"));

            native.sregs.cr0 |= (1 << 5) | fault_bits;
            native.fpu.status_word |= 0x8080;
            let registers_before = register_image(&native);
            let fpu_before = fpu_image(&native);
            native.jit_run_region_native(&region);

            assert_eq!(native.regs.rip, 0, "{form:?}, CR0={fault_bits:#x}");
            assert_eq!(register_image(&native), registers_before, "{form:?}");
            assert_eq!(fpu_image(&native), fpu_before, "{form:?}");
            let error = exception_without_idt(&mut native);
            assert!(
                error.contains(&format!("IDT entry {expected_vector} not present")),
                "{form:?}, CR0={fault_bits:#x}: {error}"
            );
            assert_eq!(register_image(&native), registers_before, "{form:?}");
            assert_eq!(fpu_image(&native), fpu_before, "{form:?}");
        }
    }
}

#[test]
fn jit_x87_stack_metadata_executes_when_no_native_error_is_pending() {
    for form in [
        StackMetadata::DecrementTop,
        StackMetadata::IncrementTop,
        StackMetadata::Free(3),
        StackMetadata::FreePop(3),
    ] {
        for (profile, native_errors, status_bits) in [
            ("legacy-error-mode", false, 0x8080),
            ("summary-status-clear", true, 0x0001),
        ] {
            let mut code = form.encoding().to_vec();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let hlt_pc = 4;
            let mut direct = test_vcpu(memory_with_code(&code));
            let mut native = test_vcpu(memory_with_code(&code));
            for vcpu in [&mut direct, &mut native] {
                seed_stack_metadata_fpu(vcpu);
                if native_errors {
                    vcpu.sregs.cr0 |= 1 << 5;
                } else {
                    vcpu.sregs.cr0 &= !(1 << 5);
                }
                vcpu.fpu.status_word |= status_bits;
            }

            run_direct_to(&mut direct, hlt_pc);
            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{profile}: compile x87 metadata: {error:?}"))
                .unwrap_or_else(|| panic!("{profile}: x87 metadata remains native"));
            native.jit_run_region_native(&region);
            assert_eq!(
                register_image(&native),
                register_image(&direct),
                "{form:?}, {profile}"
            );
            assert_eq!(
                fpu_image(&native),
                fpu_image(&direct),
                "{form:?}, {profile}"
            );
            assert_eq!(native.regs.rip, hlt_pc, "{form:?}, {profile}");
        }
    }
}

#[test]
fn jit_x87_sign_payload_matches_direct_for_all_scanned_prefixes_and_value_classes() {
    const INPUTS: [u64; 16] = [
        0,
        1 << 63,
        0x0000_0000_0000_0001,
        0x8000_0000_0000_0001,
        f64::INFINITY.to_bits(),
        f64::NEG_INFINITY.to_bits(),
        0x7FF8_A5A5_5A5A_1234,
        0xFFF8_A5A5_5A5A_1234,
        0x7FF0_A5A5_5A5A_1234,
        0xFFF0_A5A5_5A5A_1234,
        0x000F_FFFF_FFFF_FFFF,
        0x800F_FFFF_FFFF_FFFF,
        0x0010_0000_0000_0000,
        0x8010_0000_0000_0000,
        0x7FEF_FFFF_FFFF_FFFF,
        0xFFEF_FFFF_FFFF_FFFF,
    ];

    for form in SIGN_OPERATIONS {
        for prefix in LEGACY_X87_PREFIXES {
            for input in INPUTS {
                let encoded = prefix
                    .iter()
                    .copied()
                    .chain(form.encoding())
                    .collect::<Vec<_>>();
                let mut code = encoded.clone();
                code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
                let hlt_pc = encoded.len() as u64 + 2;
                let mut direct = test_vcpu(memory_with_code(&code));
                let mut native = test_vcpu(memory_with_code(&code));
                for vcpu in [&mut direct, &mut native] {
                    seed_stack_metadata_fpu(vcpu);
                    vcpu.fpu.st[5] = raw(input);
                }

                run_direct_to(&mut direct, hlt_pc);
                assert_eq!(
                    direct.fpu.st[5],
                    raw(form.expected_bits(input)),
                    "{form:?}, {prefix:02X?}, {input:#018x}"
                );
                assert_eq!(direct.fpu.status_word & 0x0200, 0);
                assert_eq!(direct.fpu.status_word & 0x4500, 0x4500);
                assert_eq!(direct.fpu.instr_ptr, 0);
                assert_eq!(direct.fpu.last_opcode, form.fop());

                let region = native
                    .jit_compile_region()
                    .unwrap_or_else(|error| panic!("{form:?}, {prefix:02X?}: {error:?}"))
                    .unwrap_or_else(|| panic!("{form:?}, {prefix:02X?}: native gate"));
                assert!(region.uses_x87_environment_state);
                assert!(!region.uses_mmx);
                native.jit_run_region_native(&region);

                assert_eq!(
                    register_image(&native),
                    register_image(&direct),
                    "{form:?}, {prefix:02X?}, {input:#018x}: register state"
                );
                assert_eq!(
                    fpu_image(&native),
                    fpu_image(&direct),
                    "{form:?}, {prefix:02X?}, {input:#018x}: x87 state"
                );
                assert_eq!(native.regs.rip, hlt_pc);
            }
        }
    }
}

#[test]
fn jit_verifier_accepts_multi_operation_x87_sign_payload_region() {
    const CODE: &[u8] = &[
        0xD9, 0xE0, // fchs
        0xD9, 0xE1, // fabs
        0xD9, 0xE0, // fchs
        0xEB, 0x00, // jmp hlt
        0xF4, // hlt
    ];
    let mut vcpu = test_vcpu(memory_with_code(CODE));
    seed_stack_metadata_fpu(&mut vcpu);
    vcpu.fpu.st[5] = raw(0x7FF8_A5A5_5A5A_1234);

    let region = vcpu
        .jit_compile_region()
        .expect("compile x87 verifier region")
        .expect("x87 sign payload region must be native eligible");
    vcpu.jit_run_region_verified(&region);

    assert_eq!(vcpu.regs.rip, 8);
    assert_eq!(vcpu.fpu.st[5], raw(0xFFF8_A5A5_5A5A_1234));
    assert_eq!(vcpu.fpu.instr_ptr, 4);
    assert_eq!(vcpu.fpu.last_opcode, 0x01E0);
}

#[test]
fn jit_x87_sign_payload_empty_stack_deopts_for_exact_direct_underflow_response() {
    for form in SIGN_OPERATIONS {
        for masked in [true, false] {
            let mut code = form.encoding().to_vec();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let mut native = test_vcpu(memory_with_code(&code));
            seed_stack_metadata_fpu(&mut native);
            native.fpu.control_word = if masked { 0x037F } else { 0x037E };
            native.fpu.status_word = (5 << 11) | 0x4700;
            native.fpu.tag_word = 3 << (5 * 2);
            native.fpu.st[5] = raw(0x7FF8_A5A5_5A5A_1234);

            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{form:?}: {error:?}"))
                .unwrap_or_else(|| panic!("{form:?}: guarded form must remain native"));
            let registers_before = register_image(&native);
            let fpu_before = fpu_image(&native);
            native.jit_run_region_native(&region);

            assert_eq!(native.regs.rip, 0, "{form:?}, masked={masked}");
            assert_eq!(register_image(&native), registers_before);
            assert_eq!(fpu_image(&native), fpu_before);

            assert!(
                native
                    .step()
                    .expect("direct stack-underflow replay")
                    .is_none()
            );
            assert_eq!(native.regs.rip, 2);
            assert_eq!(native.fpu.status_word & 0x0241, 0x0041);
            assert_eq!(native.fpu.status_word & 0x4500, 0x4500);
            assert_eq!(native.fpu.instr_ptr, 0);
            assert_eq!(native.fpu.last_opcode, form.fop());
            if masked {
                assert_eq!(native.fpu.status_word & 0x8080, 0);
                assert_eq!((native.fpu.tag_word >> (5 * 2)) & 3, 2);
                assert_eq!(native.fpu.st[5], raw(0xFFF8_0000_0000_0000));
            } else {
                assert_eq!(native.fpu.status_word & 0x8080, 0x8080);
                assert_eq!((native.fpu.tag_word >> (5 * 2)) & 3, 3);
                assert_eq!(native.fpu.st[5], raw(0x7FF8_A5A5_5A5A_1234));
            }
        }
    }
}

#[test]
fn jit_x87_sign_payload_waiting_guard_is_dynamic_precise_and_noncommitting() {
    for form in SIGN_OPERATIONS {
        for (fault_bits, pending, expected_vector) in [
            (0, true, 16),
            (1 << 2, true, 7),
            (1 << 3, false, 7),
            ((1 << 2) | (1 << 3), true, 7),
        ] {
            let mut code = form.encoding().to_vec();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let mut native = test_vcpu(memory_with_code(&code));
            seed_stack_metadata_fpu(&mut native);
            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{form:?}: {error:?}"))
                .unwrap_or_else(|| panic!("{form:?}: waiting guard must remain native"));
            native.sregs.cr0 |= (1 << 5) | fault_bits;
            if pending {
                native.fpu.status_word |= 0x8080;
            }
            let registers_before = register_image(&native);
            let fpu_before = fpu_image(&native);
            native.jit_run_region_native(&region);

            assert_eq!(native.regs.rip, 0, "{form:?}, CR0={fault_bits:#x}");
            assert_eq!(register_image(&native), registers_before);
            assert_eq!(fpu_image(&native), fpu_before);
            let error = exception_without_idt(&mut native);
            assert!(
                error.contains(&format!("IDT entry {expected_vector} not present")),
                "{form:?}, CR0={fault_bits:#x}: {error}"
            );
            assert_eq!(register_image(&native), registers_before);
            assert_eq!(fpu_image(&native), fpu_before);
        }
    }
}

#[test]
fn jit_x87_sign_payload_executes_in_legacy_error_mode_and_with_clear_summary_status() {
    for form in SIGN_OPERATIONS {
        for (native_errors, status_bits) in [(false, 0x8080), (true, 0x0001)] {
            let mut code = form.encoding().to_vec();
            code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
            let mut direct = test_vcpu(memory_with_code(&code));
            let mut native = test_vcpu(memory_with_code(&code));
            for vcpu in [&mut direct, &mut native] {
                seed_stack_metadata_fpu(vcpu);
                if native_errors {
                    vcpu.sregs.cr0 |= 1 << 5;
                } else {
                    vcpu.sregs.cr0 &= !(1 << 5);
                }
                vcpu.fpu.status_word |= status_bits;
                vcpu.fpu.st[5] = raw(0xFFF8_A5A5_5A5A_1234);
            }

            run_direct_to(&mut direct, 4);
            let region = native
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{form:?}: {error:?}"))
                .unwrap_or_else(|| panic!("{form:?}: sign operation remains native"));
            native.jit_run_region_native(&region);
            assert_eq!(register_image(&native), register_image(&direct));
            assert_eq!(fpu_image(&native), fpu_image(&direct));
            assert_eq!(native.regs.rip, 4);
        }
    }
}

#[test]
fn jit_callout_round_trips_x87_payload_changes_in_both_directions() {
    const CODE: &[u8] = &[
        0xD9, 0xE0, // fchs: native pre-call payload change
        0xE8, 0x05, 0x00, 0x00, 0x00, // call callee at 0x0c
        0xD9, 0xE0, // fchs: native post-call payload change
        0xEB, 0x00, // jmp hlt
        0xF4, // hlt
        0xD9, 0xE1, // callee: fabs through the direct interpreter
        0xC3, // ret
    ];
    let mut direct = test_vcpu(memory_with_code(CODE));
    let mut native = test_vcpu(memory_with_code(CODE));
    for vcpu in [&mut direct, &mut native] {
        vcpu.set_jit_call(true);
        seed_stack_metadata_fpu(vcpu);
        vcpu.fpu.st[5] = raw(0x7FF8_A5A5_5A5A_1234);
    }

    run_direct_to(&mut direct, 0x0B);
    let region = native
        .jit_compile_region()
        .expect("compile x87 payload call-through region")
        .expect("x87 sign operations around CALL must be native eligible");
    assert!(region.uses_x87_environment_state);
    assert_eq!(region.callout_boundaries, vec![(2, 7)]);
    native.jit_run_region_native(&region);

    assert_eq!(register_image(&native), register_image(&direct));
    assert_eq!(fpu_image(&native), fpu_image(&direct));
    assert_eq!(native.regs.rip, 0x0B);
    assert_eq!(native.fpu.st[5], raw(0xFFF8_A5A5_5A5A_1234));
    assert_eq!(native.fpu.instr_ptr, 7);
    assert_eq!(native.fpu.last_opcode, 0x01E0);
}

#[test]
fn jit_callout_round_trips_complete_x87_environment_and_payload_ownership() {
    const CODE: &[u8] = &[
        0xDB, 0xE2, // fnclex
        0xE8, 0x05, 0x00, 0x00, 0x00, // call callee at 0x0c
        0xDF, 0xE0, // fnstsw ax
        0xEB, 0x00, // jmp hlt
        0xF4, // hlt
        0xD9, 0xE8, // callee: fld1
        0xC3, // ret
    ];
    let mut direct = test_vcpu(memory_with_code(CODE));
    let mut native = test_vcpu(memory_with_code(CODE));
    for vcpu in [&mut direct, &mut native] {
        vcpu.set_jit_call(true);
        vcpu.fpu.init();
        vcpu.fpu.status_word = 0x80FF;
        vcpu.fpu.st =
            std::array::from_fn(|index| raw(0x4000_0000_0000_0000 | ((index as u64) << 40)));
    }

    run_direct_to(&mut direct, 0x0B);
    let region = native
        .jit_compile_region()
        .expect("compile x87 call-through region")
        .expect("state-backed x87 controls around CALL must be native eligible");
    assert!(region.uses_x87_environment_state);
    assert_eq!(region.callout_boundaries, vec![(2, 7)]);
    native.jit_run_region_native(&region);

    assert_eq!(register_image(&native), register_image(&direct));
    assert_eq!(fpu_image(&native), fpu_image(&direct));
    assert_eq!(native.regs.rip, 0x0B);
    assert_eq!(native.fpu.top, 7);
    assert_eq!(native.fpu.status_word, 7 << 11);
    assert_eq!(native.fpu.tag_word, 0x3FFF);
    assert_eq!(native.fpu.st[7], raw(1.0f64.to_bits()));
    assert_eq!(native.regs.rax & 0xFFFF, 7 << 11);
}

#[test]
fn jit_x87_callout_payload_marker_preserves_legacy_frames() {
    use crate::smir::lower::runtime::GuestRegs;

    for active in [false, true] {
        let mut vcpu = test_vcpu(memory_with_code(&[0xD9, 0xE0, 0xC3]));
        seed_stack_metadata_fpu(&mut vcpu);
        let cpu_bits = 0x7FF8_A5A5_5A5A_1234u64;
        // The frame's registers hold +1.0: significand 8000...0, exponent
        // 3FFFh.
        let (frame_significand, frame_high) = (0x8000_0000_0000_0000u64, 0x3FFFu64);
        vcpu.fpu.st[5] = raw(cpu_bits);
        let mut gr = GuestRegs::default();
        vcpu.marshal_x87_environment_to_guest_regs(&mut gr);
        gr.x87_state_active = 1;
        gr.x87_payload_active = u64::from(active);
        gr.x87_payload = [frame_significand; 8];
        gr.x87_payload_high = [frame_high; 8];
        gr.ctx = (&mut vcpu as *mut X86_64Vcpu) as u64;
        gr.cr0 = vcpu.sregs.cr0;
        gr.efer = vcpu.sregs.efer;
        gr.gpr[4] = STACK;
        gr.rflags = 2;

        // SAFETY: the frame and owning vCPU remain live throughout the call.
        let ok = unsafe { rax_jit_call(&mut gr, 0, 0x100, 0x80) };
        assert_eq!(ok, 1, "payload marker={active}");
        // FCHS runs on the frame's payload only when the marker says so.
        let expected = if active {
            raw((-1.0f64).to_bits())
        } else {
            raw(cpu_bits ^ (1 << 63))
        };
        assert_eq!(vcpu.fpu.st[5], expected);
        assert_eq!(gr.x87_payload[5], frame_significand);
        let expected_high = if active {
            frame_high ^ 0x8000
        } else {
            frame_high
        };
        assert_eq!(gr.x87_payload_high[5], expected_high);
        assert_eq!(gr.x87_instr_ptr, 0);
        assert_eq!(gr.x87_last_opcode, 0x01E0);
    }
}
