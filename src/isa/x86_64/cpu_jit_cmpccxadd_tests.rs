//! Direct and helper-backed native-JIT differentials for original VEX CMPccXADD.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const DATA: u64 = 0x3000;
const CR0_PE: u64 = 1;
const CR0_AM: u64 = 1 << 18;

fn instruction(cmp: u8, add: u8, base: u8, width: u8, cc: u8, register: bool) -> Vec<u8> {
    assert!(cmp < 16 && add < 16 && base < 16 && matches!(width, 4 | 8) && cc < 16);
    let mode = if register { 0xC0 } else { 0x40 };
    let mut bytes = vec![
        0xC4,
        (if cmp < 8 { 0x80 } else { 0 }) | 0x40 | (if base < 8 { 0x20 } else { 0 }) | 2,
        (u8::from(width == 8) << 7) | ((!add & 0x0F) << 3) | 1,
        0xE0 | cc,
        mode | ((cmp & 7) << 3) | (base & 7),
    ];
    if !register {
        if base & 7 == 4 {
            bytes.push(0x24);
        }
        bytes.push(0);
    }
    bytes
}

fn sib_instruction(cmp: u8, add: u8, base: u8, index: u8, scale: u8, width: u8, cc: u8) -> Vec<u8> {
    assert!(
        cmp < 16
            && add < 16
            && base < 16
            && index < 16
            && matches!(scale, 1 | 2 | 4 | 8)
            && matches!(width, 4 | 8)
            && cc < 16
    );
    vec![
        0xC4,
        (if cmp < 8 { 0x80 } else { 0 })
            | (if index < 8 { 0x40 } else { 0 })
            | (if base < 8 { 0x20 } else { 0 })
            | 2,
        (u8::from(width == 8) << 7) | ((!add & 0x0F) << 3) | 1,
        0xE0 | cc,
        0x40 | ((cmp & 7) << 3) | 4,
        ((scale.trailing_zeros() as u8) << 6) | ((index & 7) << 3) | (base & 7),
        0,
    ]
}

fn memory(code: &[u8], address: u64, old: u64, width: u8) -> Arc<GuestMemoryMmap> {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    memory
        .write_slice(
            &old.to_le_bytes()[..usize::from(width)],
            GuestAddress(address),
        )
        .unwrap();
    memory
}

fn vcpu(memory: Arc<GuestMemoryMmap>) -> X86_64Vcpu {
    let mut vcpu = X86_64Vcpu::new(0, memory);
    vcpu.sregs.cr0 = CR0_PE;
    vcpu.sregs.efer = 1 << 10;
    vcpu.sregs.cs.l = true;
    vcpu.sregs.cs.selector = 0;
    vcpu.regs.rip = 0;
    vcpu.regs.rflags = 0x2 | 0x08D5 | flags::bits::DF;
    vcpu.regs.rax = 0x0123_4567_89AB_CDEF;
    vcpu.regs.rcx = 0x1111_2222_3333_4444;
    vcpu.regs.rdx = 0x5555_6666_7777_8888;
    vcpu.regs.rbx = DATA;
    vcpu.regs.rsp = 0x8000;
    vcpu.regs.rbp = 0x7000;
    vcpu.regs.rsi = 0x9999_AAAA_BBBB_CCCC;
    vcpu.regs.rdi = 0xDDDD_EEEE_FFFF_0000;
    vcpu.regs.r8 = 0x0808_0808_0808_0808;
    vcpu.regs.r9 = 0x0909_0909_0909_0909;
    vcpu.regs.r10 = 0x1010_1010_1010_1010;
    vcpu.regs.r11 = 0x1111_1111_1111_1111;
    vcpu.regs.r12 = 0x1212_1212_1212_1212;
    vcpu.regs.r13 = 0x1313_1313_1313_1313;
    vcpu.regs.r14 = 0x1414_1414_1414_1414;
    vcpu.regs.r15 = 0x1515_1515_1515_1515;
    vcpu.set_jit_mem(true);
    vcpu.set_jit_call(false);
    vcpu
}

fn gprs(regs: &Registers) -> [u64; 32] {
    [
        regs.rax, regs.rcx, regs.rdx, regs.rbx, regs.rsp, regs.rbp, regs.rsi, regs.rdi, regs.r8,
        regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.r16, regs.r17,
        regs.r18, regs.r19, regs.r20, regs.r21, regs.r22, regs.r23, regs.r24, regs.r25, regs.r26,
        regs.r27, regs.r28, regs.r29, regs.r30, regs.r31,
    ]
}

fn run_direct_to(vcpu: &mut X86_64Vcpu, target: u64) {
    for _ in 0..8 {
        if vcpu.regs.rip == target {
            return;
        }
        assert!(vcpu.step().expect("direct CMPccXADD").is_none());
    }
    panic!("direct CMPccXADD did not reach {target:#x}");
}

fn assert_native_matches_direct(
    direct: &X86_64Vcpu,
    native: &X86_64Vcpu,
    direct_memory: &GuestMemoryMmap,
    native_memory: &GuestMemoryMmap,
    address: u64,
    width: u8,
    context: &str,
) {
    assert_eq!(gprs(&native.regs), gprs(&direct.regs), "{context}: GPRs");
    assert_eq!(native.regs.rflags, direct.regs.rflags, "{context}: RFLAGS");
    assert_eq!(native.regs.rip, direct.regs.rip, "{context}: RIP");
    let mut direct_value = [0u8; 8];
    let mut native_value = [0u8; 8];
    direct_memory
        .read_slice(
            &mut direct_value[..usize::from(width)],
            GuestAddress(address),
        )
        .unwrap();
    native_memory
        .read_slice(
            &mut native_value[..usize::from(width)],
            GuestAddress(address),
        )
        .unwrap();
    assert_eq!(native_value, direct_value, "{context}: memory");
}

fn condition_operands(condition_code: u8, truth: bool, width: u8) -> (u64, u64) {
    let minimum = if width == 4 {
        u64::from(1_u32 << 31)
    } else {
        1_u64 << 63
    };
    let (true_pair, false_pair) = match condition_code {
        0x0 => ((minimum, 1), (0, 0)),
        0x1 => ((0, 0), (minimum, 1)),
        0x2 => ((0, 1), (1, 0)),
        0x3 => ((1, 0), (0, 1)),
        0x4 => ((1, 1), (1, 0)),
        0x5 => ((1, 0), (1, 1)),
        0x6 => ((0, 1), (2, 1)),
        0x7 => ((2, 1), (1, 1)),
        0x8 => ((0, 1), (1, 0)),
        0x9 => ((1, 0), (0, 1)),
        0xA => ((1, 1), (2, 1)),
        0xB => ((2, 1), (1, 1)),
        0xC => ((minimum, 1), (0, 0)),
        0xD => ((0, 0), (minimum, 1)),
        0xE => ((0, 0), (2, 1)),
        0xF => ((2, 1), (0, 0)),
        _ => unreachable!("four-bit condition code"),
    };
    if truth { true_pair } else { false_pair }
}

#[test]
fn native_matches_direct_for_all_conditions_widths_and_writeback_outcomes() {
    let mut cases = 0usize;
    for cc in 0..16 {
        for width in [4, 8] {
            for truth in [false, true] {
                let (old, cmp) = condition_operands(cc, truth, width);
                let add = 7_u64;
                let mut code = instruction(9, 10, 3, width, cc, false);
                code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
                let frontier = code.len() as u64 - 1;
                let direct_memory = memory(&code, DATA, old, width);
                let native_memory = memory(&code, DATA, old, width);
                let mut direct = vcpu(direct_memory.clone());
                let mut native = vcpu(native_memory.clone());
                for candidate in [&mut direct, &mut native] {
                    candidate.regs.r9 = cmp;
                    candidate.regs.r10 = add;
                }

                run_direct_to(&mut direct, frontier);
                let region = native
                    .jit_compile_region()
                    .unwrap_or_else(|error| panic!("cc={cc:#x} W{width}: {error}"))
                    .unwrap_or_else(|| panic!("cc={cc:#x} W{width}: not native eligible"));
                native.jit_run_region_native(&region);
                assert_native_matches_direct(
                    &direct,
                    &native,
                    &direct_memory,
                    &native_memory,
                    DATA,
                    width,
                    &format!("cc={cc:#x} W{width} truth={truth}"),
                );
                let mask = if width == 4 {
                    u64::from(u32::MAX)
                } else {
                    u64::MAX
                };
                assert_eq!(native.regs.r9, old & mask);
                assert_eq!(
                    native_memory.read_obj::<u64>(GuestAddress(DATA)).unwrap() & mask,
                    if truth {
                        old.wrapping_add(add) & mask
                    } else {
                        old & mask
                    }
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 16 * 2 * 2);
}

#[test]
fn aliases_stack_registers_high_registers_and_addr32_state_match_direct() {
    for (name, cmp, add, base, width, configure) in [
        ("comparison/addend alias", 9, 9, 3, 8, 0),
        ("comparison/base alias", 5, 10, 5, 8, 1),
        ("addend/base alias", 9, 4, 4, 8, 2),
        ("RSP comparison destination", 4, 10, 3, 8, 3),
        ("RBP comparison destination", 5, 10, 3, 8, 4),
        ("RSP addend", 9, 4, 3, 8, 5),
        ("RBP addend", 9, 5, 3, 8, 6),
        ("high base and W32 zero extension", 9, 10, 12, 4, 7),
    ] {
        let old = 0x0000_0000_0000_5000;
        let mut code = instruction(cmp, add, base, width, 5, false);
        if configure == 7 {
            code.insert(0, 0x67);
        }
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let frontier = code.len() as u64 - 1;
        let direct_memory = memory(&code, DATA, old, width);
        let native_memory = memory(&code, DATA, old, width);
        let mut direct = vcpu(direct_memory.clone());
        let mut native = vcpu(native_memory.clone());
        for candidate in [&mut direct, &mut native] {
            candidate.set_reg(cmp, 0x1000, width);
            candidate.set_reg(add, 3, width);
            candidate.set_reg(base, DATA, 8);
            match configure {
                0 => candidate.set_reg(9, 1, 8),
                1 => candidate.regs.rbp = DATA,
                2 => candidate.regs.rsp = DATA,
                3 => candidate.regs.rsp = 0x1000,
                4 => candidate.regs.rbp = 0x1000,
                5 => candidate.regs.rsp = 3,
                6 => candidate.regs.rbp = 3,
                7 => {
                    candidate.regs.r12 = 0xFFFF_FFFF_0000_0000 | DATA;
                    candidate.regs.r9 = 0xFFFF_FFFF_0000_1000;
                }
                _ => unreachable!(),
            }
        }

        run_direct_to(&mut direct, frontier);
        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .unwrap_or_else(|| panic!("{name}: not native eligible"));
        native.jit_run_region_native(&region);
        assert_native_matches_direct(
            &direct,
            &native,
            &direct_memory,
            &native_memory,
            DATA,
            width,
            name,
        );
        if width == 4 {
            assert_eq!(
                native.regs.r9 >> 32,
                0,
                "{name}: W32 destination zero extension"
            );
        }
    }
}

#[test]
fn sib_base_and_index_aliases_are_snapshotted_before_destination_commit() {
    for (name, cmp, add, base, index, scale, base_value, cmp_value, add_value) in [
        ("comparison/index alias", 9, 10, 3, 9, 2, DATA - 2, 1, 7),
        ("addend/index alias", 9, 10, 3, 10, 1, DATA - 7, 1, 7),
        ("base/index alias", 9, 10, 3, 3, 1, DATA / 2, 1, 7),
    ] {
        let mut code = sib_instruction(cmp, add, base, index, scale, 8, 5);
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let frontier = code.len() as u64 - 1;
        let direct_memory = memory(&code, DATA, 5, 8);
        let native_memory = memory(&code, DATA, 5, 8);
        let mut direct = vcpu(direct_memory.clone());
        let mut native = vcpu(native_memory.clone());
        for candidate in [&mut direct, &mut native] {
            candidate.set_reg(base, base_value, 8);
            candidate.set_reg(cmp, cmp_value, 8);
            candidate.set_reg(add, add_value, 8);
            if base == index {
                candidate.set_reg(base, base_value, 8);
            }
        }

        run_direct_to(&mut direct, frontier);
        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .unwrap_or_else(|| panic!("{name}: not native eligible"));
        native.jit_run_region_native(&region);
        assert_native_matches_direct(
            &direct,
            &native,
            &direct_memory,
            &native_memory,
            DATA,
            8,
            name,
        );
    }
}

#[test]
fn verified_execution_undoes_and_replays_the_complete_transaction() {
    let mut code = instruction(9, 10, 3, 8, 5, false);
    code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
    let memory = memory(&code, DATA, 5, 8);
    let mut vcpu = vcpu(memory.clone());
    vcpu.regs.r9 = 1;
    vcpu.regs.r10 = 7;
    let region = vcpu
        .jit_compile_region()
        .expect("compile verified CMPccXADD")
        .expect("CMPccXADD must be native eligible");

    vcpu.jit_run_region_verified(&region);

    assert_eq!(vcpu.regs.r9, 5);
    assert_eq!(memory.read_obj::<u64>(GuestAddress(DATA)).unwrap(), 12);
    assert_eq!(vcpu.regs.rip, code.len() as u64 - 1);
}

fn exception_without_idt(vcpu: &mut X86_64Vcpu) -> String {
    format!(
        "{:#}",
        vcpu.step()
            .expect_err("exception delivery must fail against the empty test IDT")
    )
}

#[test]
fn dynamic_alignment_and_noncanonical_faults_deopt_without_commit_and_keep_priority() {
    for (name, base, address, expected_vector) in [
        ("unaligned #AC", 3, DATA + 1, Some(17)),
        (
            "noncanonical #GP precedes #AC",
            3,
            0x0000_8000_0000_0001,
            Some(13),
        ),
        (
            "noncanonical #SS precedes #AC",
            5,
            0x0000_8000_0000_0001,
            Some(12),
        ),
        (
            "range crossing into noncanonical space is #GP",
            3,
            0x0000_7FFF_FFFF_FFFE,
            Some(13),
        ),
        ("range crossing unmapped backing memory", 3, 0xFFFF, None),
    ] {
        let mut code = instruction(9, 10, base, 4, 5, false);
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let memory_address = if expected_vector == Some(17) {
            address
        } else {
            DATA
        };
        let memory = memory(&code, memory_address, 5, 4);
        let mut native = vcpu(memory.clone());
        if expected_vector.is_some() {
            native.sregs.cr0 |= CR0_AM;
            native.sregs.cs.selector = 3;
            native.regs.rflags |= flags::bits::AC;
        }
        native.set_reg(base, address, 8);
        native.regs.r9 = 1;
        native.regs.r10 = 7;
        let before_gprs = gprs(&native.regs);
        let before_rflags = native.regs.rflags;
        let before_rip = native.regs.rip;
        let memory_before = memory
            .read_obj::<u32>(GuestAddress(memory_address))
            .unwrap();

        let region = native
            .jit_compile_region()
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .unwrap_or_else(|| panic!("{name}: dynamic fault must remain native eligible"));
        native.jit_run_region_native(&region);

        assert_eq!(gprs(&native.regs), before_gprs, "{name}: native guard GPRs");
        assert_eq!(
            native.regs.rflags, before_rflags,
            "{name}: native guard RFLAGS"
        );
        assert_eq!(native.regs.rip, before_rip, "{name}: native guard RIP");
        assert_eq!(
            memory
                .read_obj::<u32>(GuestAddress(memory_address))
                .unwrap(),
            memory_before,
            "{name}: native guard memory"
        );
        let error = native.step().expect_err("fault must remain noncommitting");
        if let Some(expected_vector) = expected_vector {
            assert!(
                error
                    .to_string()
                    .contains(&format!("IDT entry {expected_vector} not present")),
                "{name}: {error}"
            );
        } else {
            assert!(
                matches!(error, crate::error::Error::GuestAccess(fault)
                    if fault.address == 0x10000
                        && fault.access == crate::error::MemoryAccessKind::Read
                        && fault.kind == crate::error::MemoryFaultKind::Unmapped),
                "{name}: {error}"
            );
        }
    }
}

#[test]
fn code_page_guard_and_reserved_forms_retain_the_exact_direct_frontier() {
    let mut code = instruction(9, 10, 3, 4, 5, false);
    code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
    let code_memory = memory(&code, 0x800, 5, 4);
    let mut native = vcpu(code_memory.clone());
    native.regs.rbx = 0x800;
    native.regs.r9 = 1;
    native.regs.r10 = 7;
    let before_gprs = gprs(&native.regs);
    let before_rflags = native.regs.rflags;
    let before_rip = native.regs.rip;
    let memory_before = code_memory.read_obj::<u32>(GuestAddress(0x800)).unwrap();
    let region = native
        .jit_compile_region()
        .expect("compile code-page guarded CMPccXADD")
        .expect("code-page guard remains dynamically eligible");
    native.jit_run_region_native(&region);
    assert_eq!(gprs(&native.regs), before_gprs);
    assert_eq!(native.regs.rflags, before_rflags);
    assert_eq!(native.regs.rip, before_rip);
    assert_eq!(
        code_memory.read_obj::<u32>(GuestAddress(0x800)).unwrap(),
        memory_before
    );
    assert!(native.step().expect("direct code-page replay").is_none());
    assert_eq!(native.regs.r9, 5);
    assert_eq!(
        code_memory.read_obj::<u32>(GuestAddress(0x800)).unwrap(),
        12
    );

    for (name, code, compatibility) in [
        ("register ModR/M", instruction(1, 2, 3, 4, 5, true), false),
        (
            "compatibility mode",
            instruction(1, 2, 3, 4, 5, false),
            true,
        ),
    ] {
        let memory = memory(&code, DATA, 5, 4);
        let mut vcpu = vcpu(memory);
        if compatibility {
            vcpu.sregs.cs.l = false;
            vcpu.sregs.cs.db = true;
            assert!(
                vcpu.jit_compile_region()
                    .expect("compile compatibility-mode frontier")
                    .is_none(),
                "compatibility-mode CMPccXADD must not enter the native tier"
            );
        }
        assert!(
            exception_without_idt(&mut vcpu).contains("IDT entry 6 not present"),
            "{name}"
        );
        assert_eq!(vcpu.regs.rip, 0, "{name}: faulting RIP");
    }
}

#[test]
fn apx_promoted_evex_executes_egpr_and_legacy_addend_forms_but_is_not_native_admitted() {
    for (name, instruction, address, configure, expected_destination) in [
        (
            "EGPR comparison addend base and index",
            &[0x62, 0xEA, 0x61, 0x00, 0xE2, 0x44, 0x91, 0x20][..],
            DATA,
            0_u8,
            16_u8,
        ),
        (
            "legacy addend with EGPR comparison and base",
            &[0x62, 0xEA, 0x65, 0x08, 0xE2, 0x08][..],
            DATA,
            1,
            17,
        ),
    ] {
        let mut code = instruction.to_vec();
        code.extend_from_slice(&[0xEB, 0x00, 0xF4]);
        let memory = memory(&code, address, 5, 4);
        let mut direct = vcpu(memory.clone());
        direct.set_apx_enabled(true);
        match configure {
            0 => {
                direct.regs.r16 = 0xFFFF_FFFF_0000_000A;
                direct.regs.r17 = DATA - 0x20;
                direct.regs.r18 = 0;
                direct.regs.r19 = 7;
            }
            1 => {
                direct.regs.r16 = DATA;
                direct.regs.r17 = 0xFFFF_FFFF_0000_000A;
                direct.regs.rbx = 7;
            }
            _ => unreachable!(),
        }

        assert!(
            direct
                .jit_compile_region()
                .unwrap_or_else(|error| panic!("{name}: {error}"))
                .is_none(),
            "{name}: APX-promoted EVEX must not enter the original-VEX native replay"
        );
        assert!(direct.step().expect(name).is_none(), "{name}");
        assert_eq!(direct.regs.rip, instruction.len() as u64, "{name}: RIP");
        assert_eq!(
            direct.get_reg(expected_destination, 8),
            5,
            "{name}: comparison destination"
        );
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(address)).unwrap(),
            12,
            "{name}: conditional locked add"
        );
        assert_ne!(direct.regs.rflags & flags::bits::CF, 0, "{name}: 5 < 10");
        assert_ne!(
            direct.regs.rflags & flags::bits::DF,
            0,
            "{name}: non-status flags"
        );
    }
}

#[test]
fn apx_guard_precedes_natural_alignment_and_both_are_noncommitting() {
    const INSTRUCTION: &[u8] = &[0x62, 0xEA, 0x65, 0x08, 0xE2, 0x08];
    for (name, apx_enabled, expected_vector) in [
        ("APX disabled", false, 6),
        ("APX natural alignment", true, 13),
    ] {
        let memory = memory(INSTRUCTION, DATA + 1, 5, 4);
        let mut direct = vcpu(memory.clone());
        direct.set_apx_enabled(apx_enabled);
        direct.regs.r16 = DATA + 1;
        direct.regs.r17 = 10;
        direct.regs.rbx = 7;
        let before_gprs = gprs(&direct.regs);
        let before_rflags = direct.regs.rflags;
        let before_memory = memory.read_obj::<u32>(GuestAddress(DATA + 1)).unwrap();

        let error = exception_without_idt(&mut direct);
        assert!(
            error.contains(&format!("IDT entry {expected_vector} not present")),
            "{name}: {error}"
        );
        assert_eq!(gprs(&direct.regs), before_gprs, "{name}: GPRs");
        assert_eq!(direct.regs.rflags, before_rflags, "{name}: RFLAGS");
        assert_eq!(direct.regs.rip, 0, "{name}: faulting RIP");
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(DATA + 1)).unwrap(),
            before_memory,
            "{name}: memory"
        );
    }
}

#[test]
fn apx_noncanonical_ss_range_precedes_natural_alignment_without_commit() {
    const INSTRUCTION: &[u8] = &[0x36, 0x62, 0xEA, 0x65, 0x08, 0xE2, 0x08];
    let memory = memory(INSTRUCTION, DATA, 5, 4);
    let mut direct = vcpu(memory.clone());
    direct.set_apx_enabled(true);
    direct.regs.r16 = 0x0000_8000_0000_0001;
    direct.regs.r17 = 10;
    direct.regs.rbx = 7;
    let before_gprs = gprs(&direct.regs);
    let before_rflags = direct.regs.rflags;
    let before_memory = memory.read_obj::<u32>(GuestAddress(DATA)).unwrap();

    let error = exception_without_idt(&mut direct);
    assert!(
        error.contains("IDT entry 12 not present"),
        "noncanonical SS range must raise #SS before natural-alignment #GP: {error}"
    );
    assert_eq!(gprs(&direct.regs), before_gprs);
    assert_eq!(direct.regs.rflags, before_rflags);
    assert_eq!(direct.regs.rip, 0);
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(DATA)).unwrap(),
        before_memory
    );
}

#[test]
fn crossing_backing_fault_has_typed_identity_without_jit_execution() {
    let code = instruction(9, 10, 3, 4, 5, false);
    let memory = memory(&code, DATA, 5, 4);
    let mut cpu = vcpu(memory.clone());
    cpu.regs.rbx = 0xffff;
    let before_gprs = gprs(&cpu.regs);
    let before_flags = cpu.regs.rflags;
    let error = cpu.step().expect_err("crossing read must fault");
    assert!(
        matches!(error, crate::error::Error::GuestAccess(fault)
        if fault.address == 0x10000
            && fault.access == crate::error::MemoryAccessKind::Read
            && fault.kind == crate::error::MemoryFaultKind::Unmapped),
        "{error}"
    );
    assert_eq!(gprs(&cpu.regs), before_gprs);
    assert_eq!(cpu.regs.rflags, before_flags);
    assert_eq!(cpu.regs.rip, 0);
    assert_eq!(memory.read_obj::<u32>(GuestAddress(DATA)).unwrap(), 5);
}
