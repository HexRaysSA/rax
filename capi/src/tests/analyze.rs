//! rax_analyze — versioned stateless SMIR effect ABI (since API 1.3)

use std::mem::{offset_of, size_of};
use std::os::raw::c_void;
use std::ptr;

use crate::analyze::*;
use crate::arch::{RAX_MODE_16, RAX_MODE_64, RAX_MODE_ARM, RaxArch};
use crate::decode::{RAX_FLOW_COND_BRANCH, RAX_FLOW_FALLTHROUGH};
use crate::status::RaxStatus;

fn query(arch: RaxArch, mode: u32, bytes: &[u8]) -> (RaxAnalysis, usize) {
    let mut out = RaxAnalysis::zeroed();
    let mut required = usize::MAX;
    let status = rax_analyze(
        arch as i32,
        mode,
        0x1000,
        bytes.as_ptr().cast::<c_void>(),
        bytes.len(),
        &mut out,
        ptr::null_mut(),
        0,
        &mut required,
    );
    assert_eq!(status, RaxStatus::Ok);
    assert_eq!(out.effect_count, 0);
    assert_eq!(out.required_effect_count as usize, required);
    assert_eq!(out.flags & RAX_ANALYSIS_TRUNCATED, 0);
    (out, required)
}

fn analyze(arch: RaxArch, mode: u32, bytes: &[u8]) -> (RaxAnalysis, Vec<RaxAnalysisEffect>) {
    let (_, required) = query(arch, mode, bytes);
    let mut effects = vec![RaxAnalysisEffect::empty(0, 0); required];
    let mut out = RaxAnalysis::zeroed();
    let mut reported = 0;
    let status = rax_analyze(
        arch as i32,
        mode,
        0x1000,
        bytes.as_ptr().cast::<c_void>(),
        bytes.len(),
        &mut out,
        effects.as_mut_ptr(),
        effects.len(),
        &mut reported,
    );
    assert_eq!(status, RaxStatus::Ok);
    assert_eq!(reported, required);
    assert_eq!(out.effect_count as usize, required);
    (out, effects)
}

fn effect<'a>(
    effects: &'a [RaxAnalysisEffect],
    kind: u16,
    access: u32,
    reg: i32,
) -> &'a RaxAnalysisEffect {
    effects
        .iter()
        .find(|effect| {
            effect.kind == kind
                && effect.access & access == access
                && (reg == -1 || effect.reg == reg)
        })
        .unwrap_or_else(|| panic!("missing effect kind={kind} access={access:#x} reg={reg}"))
}

#[test]
fn abi_layout_is_frozen_and_self_describing() {
    assert_eq!(size_of::<RaxAnalysis>(), 112);
    assert_eq!(offset_of!(RaxAnalysis, decoded), 8);
    assert_eq!(offset_of!(RaxAnalysis, flags), 48);
    assert_eq!(offset_of!(RaxAnalysis, _reserved), 80);
    assert_eq!(size_of::<RaxAnalysisEffect>(), 88);
    assert_eq!(offset_of!(RaxAnalysisEffect, access), 8);
    assert_eq!(offset_of!(RaxAnalysisEffect, value), 48);
    assert_eq!(offset_of!(RaxAnalysisEffect, _reserved), 72);

    let (summary, effects) = analyze(
        RaxArch::X86,
        RAX_MODE_64,
        &[0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00],
    );
    assert_eq!(summary.struct_size as usize, size_of::<RaxAnalysis>());
    assert_eq!(summary.abi_version, RAX_ANALYSIS_ABI_VERSION);
    assert!(effects.iter().all(|effect| {
        effect.struct_size as usize == size_of::<RaxAnalysisEffect>()
            && effect.abi_version as u32 == RAX_ANALYSIS_ABI_VERSION
            && effect._reserved == [0; 2]
    }));
    assert_eq!(summary._reserved, [0; 4]);
}

#[test]
fn x86_constant_and_register_results_are_proved() {
    let (summary, effects) = analyze(
        RaxArch::X86,
        RAX_MODE_64,
        &[0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00],
    );
    assert_eq!(summary.decoded.flow, RAX_FLOW_FALLTHROUGH);
    assert_eq!(summary.flags & RAX_ANALYSIS_COMPLETE, RAX_ANALYSIS_COMPLETE);
    let write = effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, 0x0100);
    assert_eq!(write.width_bits, 64);
    assert_eq!(write.value_kind, RAX_VALUE_CONSTANT);
    assert_eq!(write.value, 0x1234);
    assert_ne!(write.access & RAX_EFFECT_VALUE_COMPLETE, 0);

    // Like engine_open, an omitted x86 bitness normalizes to 64-bit.
    let (default_mode, _) = analyze(RaxArch::X86, 0, &[0x90]);
    assert_eq!(
        default_mode.flags & RAX_ANALYSIS_COMPLETE,
        RAX_ANALYSIS_COMPLETE
    );

    // mov rax, rbx
    let (_, effects) = analyze(RaxArch::X86, RAX_MODE_64, &[0x48, 0x89, 0xD8]);
    effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_READ, 0x0103);
    let write = effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, 0x0100);
    assert_eq!(write.value_kind, RAX_VALUE_REGISTER);
    assert_eq!(write.source_reg, 0x0103);

    // movzx rax, bl reads RBX but is a transformation, not a direct copy.
    let (_, effects) = analyze(RaxArch::X86, RAX_MODE_64, &[0x48, 0x0F, 0xB6, 0xC3]);
    effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_READ, 0x0103);
    let write = effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, 0x0100);
    assert_eq!(write.value_kind, RAX_VALUE_UNKNOWN);
    assert_eq!(write.access & RAX_EFFECT_VALUE_COMPLETE, 0);
}

#[test]
fn x86_memory_address_and_value_characteristics() {
    // mov rax, [rbx+8]
    let (_, effects) = analyze(RaxArch::X86, RAX_MODE_64, &[0x48, 0x8B, 0x43, 0x08]);
    effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_READ, 0x0103);
    effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, 0x0100);
    let memory = effect(&effects, RAX_EFFECT_MEMORY, RAX_EFFECT_READ, -1);
    assert_eq!(memory.width_bits, 64);
    assert_eq!(memory.address_kind, RAX_ADDRESS_BASE_DISP);
    assert_eq!(memory.base_reg, 0x0103);
    assert_eq!(memory.displacement, 8);
    assert_ne!(memory.access & RAX_EFFECT_ADDRESS_COMPLETE, 0);

    // mov qword ptr [rbx+8], rax
    let (_, effects) = analyze(RaxArch::X86, RAX_MODE_64, &[0x48, 0x89, 0x43, 0x08]);
    let memory = effect(&effects, RAX_EFFECT_MEMORY, RAX_EFFECT_WRITE, -1);
    assert_eq!(memory.value_kind, RAX_VALUE_REGISTER);
    assert_eq!(memory.source_reg, 0x0100);
    assert_ne!(memory.access & RAX_EFFECT_VALUE_COMPLETE, 0);

    // mov rax, [rip+0x10] resolves against next RIP (0x1007).
    let (_, effects) = analyze(
        RaxArch::X86,
        RAX_MODE_64,
        &[0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00],
    );
    let memory = effect(&effects, RAX_EFFECT_MEMORY, RAX_EFFECT_READ, -1);
    assert_eq!(memory.address_kind, RAX_ADDRESS_PC_RELATIVE);
    assert_eq!(memory.displacement, 0x10);
    assert_eq!(memory.address, 0x1017);
    assert_ne!(memory.access & RAX_EFFECT_ADDRESS_COMPLETE, 0);

    // mov rax, [rax*4+0x2000] has an absent (JSON null) SIB base.
    let (summary, effects) = analyze(
        RaxArch::X86,
        RAX_MODE_64,
        &[0x48, 0x8B, 0x04, 0x85, 0x00, 0x20, 0x00, 0x00],
    );
    assert_eq!(summary.flags & RAX_ANALYSIS_COMPLETE, RAX_ANALYSIS_COMPLETE);
    effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_READ, 0x0100);
    let memory = effect(&effects, RAX_EFFECT_MEMORY, RAX_EFFECT_READ, -1);
    assert_eq!(memory.address_kind, RAX_ADDRESS_BASE_INDEX_DISP);
    assert_eq!(memory.base_reg, -1);
    assert_eq!(memory.index_reg, 0x0100);
    assert_eq!(memory.scale, 4);
    assert_eq!(memory.displacement, 0x2000);
}

#[test]
fn x86_condition_flags_are_reported() {
    let (summary, _) = analyze(RaxArch::X86, RAX_MODE_64, &[0x74, 0x05]);
    assert_eq!(summary.decoded.flow, RAX_FLOW_COND_BRANCH);
    assert_eq!(summary.decoded.target, 0x1007);
    assert_ne!(summary.flags_read & RAX_FLAG_Z, 0);

    // add rax, rbx writes the x86 arithmetic flag set.
    let (summary, _) = analyze(RaxArch::X86, RAX_MODE_64, &[0x48, 0x01, 0xD8]);
    assert_ne!(summary.flags_written & RAX_FLAG_NZCV, 0);

    // cmp rax, rbx has an implicit all-arithmetic FlagUpdate in SMIR.
    let (summary, _) = analyze(RaxArch::X86, RAX_MODE_64, &[0x48, 0x39, 0xD8]);
    assert_eq!(summary.flags_written, RAX_FLAG_ARITHMETIC);
}

#[test]
fn x86_call_includes_implicit_stack_push() {
    let (summary, effects) = analyze(RaxArch::X86, RAX_MODE_64, &[0xE8, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(summary.flags & RAX_ANALYSIS_COMPLETE, RAX_ANALYSIS_COMPLETE);
    effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_READ, 0x0104);
    effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, 0x0104);
    let stack = effect(&effects, RAX_EFFECT_MEMORY, RAX_EFFECT_WRITE, -1);
    assert_ne!(stack.access & RAX_EFFECT_IMPLICIT, 0);
    assert_eq!(stack.address_kind, RAX_ADDRESS_BASE_DISP);
    assert_eq!(stack.base_reg, 0x0104);
    assert_eq!(stack.displacement, -8);
    assert_eq!(stack.width_bits, 64);
    assert_eq!(stack.value_kind, RAX_VALUE_CONSTANT);
    assert_eq!(stack.value, 0x1005);

    // call qword ptr [rax] also reads the address carrier and target memory.
    let (_, indirect) = analyze(RaxArch::X86, RAX_MODE_64, &[0xFF, 0x10]);
    effect(&indirect, RAX_EFFECT_REGISTER, RAX_EFFECT_READ, 0x0100);
    let target = effect(&indirect, RAX_EFFECT_MEMORY, RAX_EFFECT_READ, -1);
    assert_eq!(target.address_kind, RAX_ADDRESS_REGISTER);
    assert_eq!(target.base_reg, 0x0100);
    assert_ne!(target.access & RAX_EFFECT_IMPLICIT, 0);

    let (syscall, _) = analyze(RaxArch::X86, RAX_MODE_64, &[0x0F, 0x05]);
    assert_eq!(syscall.flags & RAX_ANALYSIS_COMPLETE, 0);
    assert_eq!(syscall.flags & RAX_ANALYSIS_PARTIAL, RAX_ANALYSIS_PARTIAL);
}

#[test]
fn aarch64_constant_write_is_reported() {
    // movz x0, #1
    let (summary, effects) = analyze(RaxArch::Arm64, 0, &[0x20, 0x00, 0x80, 0xD2]);
    assert_eq!(summary.flags & RAX_ANALYSIS_COMPLETE, RAX_ANALYSIS_COMPLETE);
    let write = effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, 0x0100);
    assert_eq!(write.value_kind, RAX_VALUE_CONSTANT);
    assert_eq!(write.value, 1);
    assert_eq!(write.width_bits, 64);

    // b.eq reads Z from NZCV.
    let (branch, _) = analyze(RaxArch::Arm64, 0, &[0x00, 0x00, 0x00, 0x54]);
    assert_eq!(branch.decoded.flow, RAX_FLOW_COND_BRANCH);
    assert_eq!(branch.flags_read, RAX_FLAG_Z);
}

#[test]
fn rv64_ssa_output_is_mapped_back_to_arch_register() {
    // addi x1, x0, 5. The RISC-V lifter defines an SSA VReg and records the
    // architectural x1 binding separately; the C ABI must hide that detail.
    let (summary, effects) = analyze(RaxArch::Riscv64, 0, &[0x93, 0x00, 0x50, 0x00]);
    assert_eq!(summary.flags & RAX_ANALYSIS_COMPLETE, RAX_ANALYSIS_COMPLETE);
    let write = effect(&effects, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, 0x0101);
    assert_eq!(write.value_kind, RAX_VALUE_CONSTANT);
    assert_eq!(write.value, 5);
    assert_eq!(write.width_bits, 64);
}

#[test]
fn hexagon_lifter_is_available_and_deterministic() {
    // Debug builds of the comprehensive Hexagon lifter use more than the
    // Rust test harness's deliberately small default worker stack. This is
    // the same large-stack convention used by the engine's Hexagon lift
    // suite; normal host application threads and release builds are much
    // less constrained.
    std::thread::Builder::new()
        .name("capi-hexagon-analysis".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            // `{ r0 = #5 }`, assembled for Hexagon v69.
            let bytes = [0xA0, 0xC0, 0x00, 0x78];
            let (first, first_effects) = analyze(RaxArch::Hexagon, 0, &bytes);
            let (second, second_effects) = analyze(RaxArch::Hexagon, 0, &bytes);
            assert_eq!(first.flags & RAX_ANALYSIS_HAS_SMIR, RAX_ANALYSIS_HAS_SMIR);
            assert_eq!(first.flags & RAX_ANALYSIS_COMPLETE, RAX_ANALYSIS_COMPLETE);
            assert_eq!(first.decoded.size, 4);
            assert_eq!(first.required_effect_count, second.required_effect_count);
            assert_eq!(first.flags_read, second.flags_read);
            assert_eq!(first.flags_written, second.flags_written);
            assert_eq!(first_effects, second_effects);
            let write = effect(
                &first_effects,
                RAX_EFFECT_REGISTER,
                RAX_EFFECT_WRITE,
                0x0100,
            );
            assert_eq!(write.width_bits, 32);
            assert_eq!(write.value_kind, RAX_VALUE_CONSTANT);
            assert_eq!(write.value, 5);
        })
        .expect("spawn Hexagon analysis test")
        .join()
        .expect("Hexagon analysis test panicked");
}

#[test]
fn unsupported_mode_keeps_decode_and_marks_partial() {
    // AArch32 decode is supported, but the rich API deliberately promises
    // SMIR effects only for the four documented architectures/modes.
    let (summary, effects) = analyze(
        RaxArch::Arm,
        RAX_MODE_ARM,
        &[0x00, 0x00, 0xA0, 0xE1], // mov r0, r0
    );
    assert_eq!(summary.flags & RAX_ANALYSIS_VALID, RAX_ANALYSIS_VALID);
    assert_eq!(
        summary.flags & RAX_ANALYSIS_UNSUPPORTED,
        RAX_ANALYSIS_UNSUPPORTED
    );
    assert_eq!(summary.flags & RAX_ANALYSIS_PARTIAL, RAX_ANALYSIS_PARTIAL);
    assert!(effects.is_empty());
}

#[test]
fn effect_buffer_negotiation_returns_deterministic_prefix() {
    let bytes = [0x48, 0x8B, 0x43, 0x08]; // at least read-reg, write-reg, load
    let (_, all) = analyze(RaxArch::X86, RAX_MODE_64, &bytes);
    assert!(all.len() >= 3);

    let mut summary = RaxAnalysis::zeroed();
    let mut one = [RaxAnalysisEffect::empty(0, 0); 1];
    let mut required = 0;
    let status = rax_analyze(
        RaxArch::X86 as i32,
        RAX_MODE_64,
        0x1000,
        bytes.as_ptr().cast::<c_void>(),
        bytes.len(),
        &mut summary,
        one.as_mut_ptr(),
        one.len(),
        &mut required,
    );
    assert_eq!(status, RaxStatus::Bounds);
    assert_eq!(required, all.len());
    assert_eq!(summary.effect_count, 1);
    assert_eq!(summary.required_effect_count as usize, all.len());
    assert_ne!(summary.flags & RAX_ANALYSIS_TRUNCATED, 0);
    assert_eq!(one[0], all[0]);
}

#[test]
fn stateless_analysis_is_concurrent_and_deterministic() {
    let bytes = [0x48, 0x8B, 0x43, 0x08];
    let (baseline_summary, baseline_effects) = analyze(RaxArch::X86, RAX_MODE_64, &bytes);
    let mut threads = Vec::new();
    for _ in 0..8 {
        let expected = baseline_effects.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..32 {
                let (summary, effects) = analyze(RaxArch::X86, RAX_MODE_64, &bytes);
                assert_eq!(summary.flags, baseline_summary.flags);
                assert_eq!(summary.decoded.size, baseline_summary.decoded.size);
                assert_eq!(
                    summary.required_effect_count,
                    baseline_summary.required_effect_count
                );
                assert_eq!(summary.flags_read, baseline_summary.flags_read);
                assert_eq!(summary.flags_written, baseline_summary.flags_written);
                assert_eq!(effects, expected);
            }
        }));
    }
    for thread in threads {
        thread.join().expect("analysis worker panicked");
    }
}

#[test]
fn malformed_arguments_are_rejected_and_outputs_initialized() {
    let bytes = [0x90u8];
    let mut out = RaxAnalysis::zeroed();
    let mut count = 77usize;
    assert_eq!(
        rax_analyze(
            RaxArch::X86 as i32,
            RAX_MODE_64,
            0x1000,
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut count,
        ),
        RaxStatus::Arg
    );
    assert_eq!(
        rax_analyze(
            RaxArch::X86 as i32,
            RAX_MODE_64,
            0x1000,
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
            &mut out,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        ),
        RaxStatus::Arg
    );
    assert_eq!(
        rax_analyze(
            RaxArch::X86 as i32,
            RAX_MODE_64,
            0x1000,
            ptr::null(),
            1,
            &mut out,
            ptr::null_mut(),
            0,
            &mut count,
        ),
        RaxStatus::Arg
    );
    assert_eq!(out.decoded.valid, 0);
    assert_eq!(count, 0);
    assert_eq!(
        rax_analyze(
            RaxArch::X86 as i32,
            RAX_MODE_64,
            0x1000,
            bytes.as_ptr().cast::<c_void>(),
            usize::MAX,
            &mut out,
            ptr::null_mut(),
            0,
            &mut count,
        ),
        RaxStatus::Arg
    );
    assert_eq!(
        rax_analyze(
            RaxArch::X86 as i32,
            RAX_MODE_64,
            0x1000,
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
            &mut out,
            ptr::null_mut(),
            1,
            &mut count,
        ),
        RaxStatus::Arg
    );
    assert_eq!(
        rax_analyze(
            999,
            RAX_MODE_64,
            0x1000,
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
            &mut out,
            ptr::null_mut(),
            0,
            &mut count,
        ),
        RaxStatus::Arch
    );
    assert_eq!(
        rax_analyze(
            RaxArch::X86 as i32,
            RAX_MODE_16 | RAX_MODE_64,
            0x1000,
            bytes.as_ptr().cast::<c_void>(),
            bytes.len(),
            &mut out,
            ptr::null_mut(),
            0,
            &mut count,
        ),
        RaxStatus::Mode
    );
}

#[test]
fn x86_legacy_code_decodes_without_effects() {
    use crate::arch::RAX_MODE_32;
    // inc eax (40) in 32-bit code: the decode is exact, the effects are
    // not modeled (the SMIR lifter covers 64-bit code only).
    let (out, effects) = analyze(RaxArch::X86, RAX_MODE_32, &[0x40, 0x90]);
    assert_eq!((out.decoded.valid, out.decoded.size), (1, 1));
    assert_eq!(
        out.flags,
        RAX_ANALYSIS_VALID | RAX_ANALYSIS_UNSUPPORTED | RAX_ANALYSIS_PARTIAL
    );
    assert!(effects.is_empty());
}
