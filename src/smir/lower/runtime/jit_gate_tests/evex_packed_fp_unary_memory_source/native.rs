//! Native x86-64 differential, helper-call, and precise-fault coverage.

use super::semantics::{SemanticState, initial_state, interpret_mapped, source_bytes};
use super::*;
use crate::smir::lower::runtime::{ExecMem, GuestRegs};

#[repr(C)]
struct LoadResult {
    value: u64,
    ok: u64,
}

struct LaneMemoryContext {
    base: u64,
    value: [u8; 64],
    lane_bytes: usize,
    fail_address: Option<u64>,
    calls: usize,
    addresses: [u64; 64],
}

extern "C" fn lane_load_helper(
    context: *mut LaneMemoryContext,
    address: u64,
    size: u64,
    signed: u64,
) -> LoadResult {
    let context = unsafe { &mut *context };
    assert_eq!(size as usize, context.lane_bytes);
    assert_eq!(signed, 0);
    context.addresses[context.calls] = address;
    context.calls += 1;
    if context.fail_address == Some(address) {
        return LoadResult { value: 0, ok: 0 };
    }
    let offset = usize::try_from(address - context.base).unwrap();
    assert!(offset + context.lane_bytes <= context.value.len());
    let mut value = [0u8; 8];
    value[..context.lane_bytes]
        .copy_from_slice(&context.value[offset..offset + context.lane_bytes]);
    LoadResult {
        value: u64::from_le_bytes(value),
        ok: 1,
    }
}

fn memory_words(bytes: &[u8; 64]) -> [u64; 8] {
    std::array::from_fn(|word| {
        u64::from_le_bytes(bytes[word * 8..word * 8 + 8].try_into().unwrap())
    })
}

fn guest_regs(initial: &SemanticState) -> GuestRegs {
    let mut registers = GuestRegs {
        gpr: initial.gpr,
        rflags: initial.rflags,
        vector_active: 1,
        k: initial.masks,
        mxcsr: initial.mxcsr,
        ..GuestRegs::default()
    };
    for (index, value) in initial.vectors.iter().enumerate() {
        registers.set_zmm(index, value[..8].try_into().unwrap());
    }
    registers
}

fn assert_architectural_state(
    actual: &GuestRegs,
    expected: &SemanticState,
    level: OptLevel,
    case: PackedUnaryMemoryCase,
) {
    assert_eq!(actual.gpr, expected.gpr, "{level:?} {case:?}: GPRs");
    for (index, vector) in expected.vectors.iter().enumerate() {
        assert_eq!(
            actual.get_zmm(index),
            <[u64; 8]>::try_from(&vector[..8]).unwrap(),
            "{level:?} {case:?}: ZMM{index}"
        );
    }
    assert_eq!(actual.k, expected.masks, "{level:?} {case:?}: opmasks");
    assert_eq!(actual.rflags, expected.rflags, "{level:?} {case:?}: RFLAGS");
    assert_eq!(actual.mxcsr, expected.mxcsr, "{level:?} {case:?}: MXCSR");
}

/// VRCPPH/VRSQRTPH results are implementation-specific approximations with
/// relative error below 2^-11 + 2^-14 (SDM Vol. 2C Tables 5-28 and 5-38).
const FP16_ESTIMATE_RELATIVE_ERROR_BOUND: f64 = 1.0 / 2048.0 + 1.0 / 16384.0;

fn fp16_estimate_is_rsqrt(operation: PackedUnaryOperation) -> Option<bool> {
    match operation {
        PackedUnaryOperation::RecipFp16 => Some(false),
        PackedUnaryOperation::RsqrtFp16 => Some(true),
        _ => None,
    }
}

fn fp16_value(bits: u16) -> f64 {
    let magnitude = match (bits >> 10) & 0x1F {
        0 => f64::from(bits & 0x03FF) * 2.0f64.powi(-24),
        0x1F if bits & 0x03FF == 0 => f64::INFINITY,
        0x1F => f64::NAN,
        exponent => f64::from(0x0400 | (bits & 0x03FF)) * 2.0f64.powi(i32::from(exponent) - 25),
    };
    if bits & 0x8000 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

fn fp16_lane(words: &[u64], lane: usize) -> u16 {
    (words[lane / 4] >> ((lane % 4) * 16)) as u16
}

fn clear_fp16_lane(words: &mut [u64], lane: usize) {
    words[lane / 4] &= !(0xFFFFu64 << ((lane % 4) * 16));
}

/// Checks one active lane against the SDM contract, independently of the
/// interpreter: exact special cases and powers of two, otherwise the bound.
fn fp16_estimate_violation(rsqrt: bool, input: u16, output: u16) -> Option<&'static str> {
    let sign = input & 0x8000;
    let magnitude = input & 0x7FFF;
    let exact_bits = if magnitude > 0x7C00 {
        Some(input | 0x0200)
    } else if rsqrt && sign != 0 && magnitude != 0 {
        Some(0xFE00)
    } else if magnitude == 0 {
        Some(sign | 0x7C00)
    } else if magnitude == 0x7C00 {
        Some(if rsqrt { 0 } else { sign })
    } else if !rsqrt && fp16_value(input).abs() <= 2.0f64.powi(-16) {
        Some(sign | 0x7C00)
    } else {
        None
    };
    if let Some(expected) = exact_bits {
        return (output != expected).then_some("special case");
    }
    let value = fp16_value(input);
    let exact = if rsqrt {
        value.sqrt().recip()
    } else {
        value.recip()
    };
    let actual = fp16_value(output);
    if exact.to_bits() & ((1u64 << 52) - 1) == 0 {
        return (actual != exact).then_some("power of two");
    }
    if rsqrt && magnitude < 0x0400 && output & 0x7C00 == 0 {
        return Some("denormal input must return a normal result");
    }
    let error = (actual - exact).abs();
    // The relative bound is unrepresentable for some subnormal reciprocals;
    // there, the result must be the nearest binary16 value.
    let subnormal_nearest = output & 0x7C00 == 0 && error <= 2.0f64.powi(-25);
    (error / exact.abs() >= FP16_ESTIMATE_RELATIVE_ERROR_BOUND && !subnormal_nearest)
        .then_some("relative error bound")
}

fn assert_fp16_estimate(rsqrt: bool, input: u16, output: u16, label: &str) {
    if let Some(violation) = fp16_estimate_violation(rsqrt, input, output) {
        panic!("{label}: {violation}: input={input:04X} output={output:04X}");
    }
}

/// Compares successful execution. Active VRCPPH/VRSQRTPH lanes are checked
/// independently against the SDM bound on both sides, then excluded from the
/// otherwise bit-exact comparison.
fn assert_success_state(
    actual: &GuestRegs,
    expected: &SemanticState,
    level: OptLevel,
    case: PackedUnaryMemoryCase,
    bytes: &[u8; 64],
    active_mask: u64,
) {
    let Some(rsqrt) = fp16_estimate_is_rsqrt(case.operation) else {
        assert_architectural_state(actual, expected, level, case);
        return;
    };
    let destination = usize::from(case.destination);
    let mut actual = *actual;
    let mut expected = expected.clone();
    let mut actual_zmm = actual.get_zmm(destination);
    for lane in
        (0..case.width.lanes(case.elem()) as usize).filter(|lane| active_mask & (1u64 << lane) != 0)
    {
        let memory_lane = if case.broadcast() { 0 } else { lane };
        let input = u16::from_le_bytes([bytes[memory_lane * 2], bytes[memory_lane * 2 + 1]]);
        for (side, words) in [
            ("native", &actual_zmm[..]),
            ("interpreter", &expected.vectors[destination][..8]),
        ] {
            let label = format!("{level:?} {case:?} {side} lane {lane}");
            assert_fp16_estimate(rsqrt, input, fp16_lane(words, lane), &label);
        }
        clear_fp16_lane(&mut actual_zmm, lane);
        clear_fp16_lane(&mut expected.vectors[destination], lane);
    }
    actual.set_zmm(destination, actual_zmm);
    assert_architectural_state(&actual, &expected, level, case);
}

fn selected_cases() -> Vec<PackedUnaryMemoryCase> {
    let mut cases = Vec::new();
    for operation in PackedUnaryOperation::ALL {
        cases.push(PackedUnaryMemoryCase {
            operation,
            width: VecWidth::V512,
            destination: 17,
            form: SourceForm::Vector,
            control: MaskControl::None,
        });
        cases.push(PackedUnaryMemoryCase {
            operation,
            width: VecWidth::V512,
            destination: 17,
            form: SourceForm::Vector,
            control: MaskControl::Merge,
        });
        cases.push(PackedUnaryMemoryCase {
            operation,
            width: if operation.needs_er() {
                VecWidth::V512
            } else {
                VecWidth::V256
            },
            destination: if operation.needs_er() { 17 } else { 9 },
            form: SourceForm::Broadcast,
            control: MaskControl::Zero,
        });
    }
    cases
}

fn host_supports(case: PackedUnaryMemoryCase) -> bool {
    (!case.operation.needs_fp16() || std::is_x86_feature_detected!("avx512fp16"))
        && (case.operation.uses_k16_opmasks() || std::is_x86_feature_detected!("avx512bw"))
        && (!case.operation.needs_dq() || std::is_x86_feature_detected!("avx512dq"))
        && (!case.operation.needs_er() || crate::smir::lower::runtime::x86_host_has_avx512er())
        && (case.width == VecWidth::V512 || std::is_x86_feature_detected!("avx512vl"))
}

#[test]
fn native_packed_unary_matches_interpreter_helpers_faults_and_mask_suppression() {
    use super::super::vex_fma3_memory_source::{VectorMemoryContext, vector_load_helper};

    if !std::is_x86_feature_detected!("avx") || !std::is_x86_feature_detected!("avx512f") {
        eprintln!("skipping native packed unary differential: host lacks AVX/AVX-512F");
        return;
    }
    let cases: Vec<_> = selected_cases()
        .into_iter()
        .filter(|case| host_supports(*case))
        .collect();
    assert!(!cases.is_empty());

    let mut successes = 0usize;
    let mut faults = 0usize;
    let mut suppressions = 0usize;
    for (ordinal, case) in cases.iter().copied().enumerate() {
        for level in [OptLevel::O0, OptLevel::O2] {
            let function = optimize(lift_case(case), level);
            let (code, entry) = lower(&function, case);
            let exec =
                ExecMem::new(&code).unwrap_or_else(|error| panic!("{level:?} {case:?}: {error:?}"));
            let bytes = source_bytes(case, ordinal + 3);
            let initial = initial_state(case, ordinal + 3, &bytes);
            let expected = interpret_mapped(&function, &initial, &bytes, case);

            if case.form == SourceForm::Vector && case.control == MaskControl::None {
                let value = memory_words(&bytes);
                let mut context = VectorMemoryContext {
                    value,
                    ok: 1,
                    calls: 0,
                    last_addr: 0,
                    last_index: 0,
                    last_size: 0,
                    last_zero_upper: 0,
                };
                let mut registers = guest_regs(&initial);
                registers.ctx = (&mut context as *mut VectorMemoryContext) as u64;
                registers.vec_load_fn = vector_load_helper as *const () as usize as u64;
                exec.run(entry, &mut registers);
                assert_success_state(&registers, &expected, level, case, &bytes, u64::MAX);
                assert_eq!(context.calls, 1, "{level:?} {case:?}");
                assert_eq!(context.last_addr, MEMORY_ADDRESS, "{level:?} {case:?}");
                assert_eq!(
                    context.last_index,
                    crate::smir::lower::X86_JIT_VECTOR_SCRATCH_INDEX,
                    "{level:?} {case:?}"
                );
                assert_eq!(context.last_size, case.width.bytes(), "{level:?} {case:?}");
                assert_eq!(context.last_zero_upper, 1, "{level:?} {case:?}");
                successes += 1;

                let mut context = VectorMemoryContext {
                    value,
                    ok: 0,
                    calls: 0,
                    last_addr: 0,
                    last_index: 0,
                    last_size: 0,
                    last_zero_upper: 0,
                };
                let mut registers = guest_regs(&initial);
                registers.ctx = (&mut context as *mut VectorMemoryContext) as u64;
                registers.vec_load_fn = vector_load_helper as *const () as usize as u64;
                let mut expected_fault = registers;
                expected_fault.exit_pc = PC;
                exec.run(entry, &mut registers);
                expected_fault.host_mxcsr = registers.host_mxcsr;
                assert_eq!(registers, expected_fault, "{level:?} {case:?}: fault");
                assert_eq!(context.calls, 1, "{level:?} {case:?}: fault calls");
                faults += 1;
                continue;
            }

            let active_mask = if case.mask() == 0 {
                u64::MAX
            } else {
                initial.masks[usize::from(case.mask())]
            };
            let mut context = LaneMemoryContext {
                base: MEMORY_ADDRESS,
                value: bytes,
                lane_bytes: case.elem().bytes() as usize,
                fail_address: None,
                calls: 0,
                addresses: [0; 64],
            };
            let mut registers = guest_regs(&initial);
            registers.ctx = (&mut context as *mut LaneMemoryContext) as u64;
            registers.load_fn = lane_load_helper as *const () as usize as u64;
            exec.run(entry, &mut registers);
            assert_success_state(&registers, &expected, level, case, &bytes, active_mask);
            let expected_addresses: Vec<u64> = if case.broadcast() {
                vec![MEMORY_ADDRESS]
            } else {
                (0..case.width.lanes(case.elem()))
                    .filter(|lane| active_mask & (1u64 << lane) != 0)
                    .map(|lane| MEMORY_ADDRESS + u64::from(lane) * u64::from(case.elem().bytes()))
                    .collect()
            };
            assert_eq!(
                &context.addresses[..context.calls],
                expected_addresses,
                "{level:?} {case:?}: active source addresses"
            );
            successes += 1;

            let first_active = (0..case.width.lanes(case.elem()))
                .find(|lane| active_mask & (1u64 << lane) != 0)
                .expect("selected mask has an active lane");
            let fail_address = if case.broadcast() {
                MEMORY_ADDRESS
            } else {
                MEMORY_ADDRESS + u64::from(first_active) * u64::from(case.elem().bytes())
            };
            let mut context = LaneMemoryContext {
                base: MEMORY_ADDRESS,
                value: bytes,
                lane_bytes: case.elem().bytes() as usize,
                fail_address: Some(fail_address),
                calls: 0,
                addresses: [0; 64],
            };
            let mut registers = guest_regs(&initial);
            registers.ctx = (&mut context as *mut LaneMemoryContext) as u64;
            registers.load_fn = lane_load_helper as *const () as usize as u64;
            let mut expected_fault = registers;
            expected_fault.exit_pc = PC;
            exec.run(entry, &mut registers);
            expected_fault.host_mxcsr = registers.host_mxcsr;
            assert_eq!(registers, expected_fault, "{level:?} {case:?}: fault");
            assert_eq!(
                context.addresses[context.calls - 1],
                fail_address,
                "{level:?} {case:?}: fault address"
            );
            faults += 1;

            if case.mask() != 0 {
                let mut suppressed_initial = initial.clone();
                // Every packed form observes at most K[31:0]. This also
                // catches an incorrect sign-extended TEST imm32 broadcast
                // guard: high K bits are set while every architectural bit is
                // clear.
                suppressed_initial.masks[usize::from(case.mask())] = 0xFFFF_FFFF_0000_0000;
                let expected = interpret_mapped(&function, &suppressed_initial, &bytes, case);
                let mut context = LaneMemoryContext {
                    base: MEMORY_ADDRESS,
                    value: bytes,
                    lane_bytes: case.elem().bytes() as usize,
                    fail_address: Some(MEMORY_ADDRESS),
                    calls: 0,
                    addresses: [0; 64],
                };
                let mut registers = guest_regs(&suppressed_initial);
                registers.ctx = (&mut context as *mut LaneMemoryContext) as u64;
                registers.load_fn = lane_load_helper as *const () as usize as u64;
                exec.run(entry, &mut registers);
                assert_architectural_state(&registers, &expected, level, case);
                assert_eq!(context.calls, 0, "{level:?} {case:?}");
                suppressions += 1;
            }
        }
    }
    assert_eq!(successes, cases.len() * 2);
    assert_eq!(faults, successes);
    assert!(suppressions >= cases.len());
}

#[test]
fn fp16_estimate_checker_accepts_sdm_approximations_and_rejects_violations() {
    use crate::smir::interpret::SmirInterpreter;

    // An AVX512-FP16 CI host returned VRSQRTPH(0x03FF) = 0x5800 (128.0);
    // rounding 4096/sqrt(1023) ~= 128.06255 to nearest gives 0x5801. Both
    // are within the bound, while results two ULPs away are not.
    assert_eq!(fp16_estimate_violation(true, 0x03FF, 0x5800), None);
    assert_eq!(fp16_estimate_violation(true, 0x03FF, 0x5801), None);
    for output in [0x57FF, 0x5802] {
        assert_eq!(
            fp16_estimate_violation(true, 0x03FF, output),
            Some("relative error bound")
        );
    }
    assert_eq!(
        fp16_estimate_violation(true, 0x0003, 0x0001),
        Some("denormal input must return a normal result")
    );

    // Exact rows of SDM Vol. 2C Tables 5-28 and 5-38.
    for (rsqrt, input, output) in [
        (true, 0x0400, 0x5800),
        (true, 0x4400, 0x3800),
        (true, 0xBC00, 0xFE00),
        (true, 0x8000, 0xFC00),
        (true, 0x7C00, 0x0000),
        (true, 0x7D01, 0x7F01),
        (false, 0x0100, 0x7C00),
        (false, 0x8001, 0xFC00),
        (false, 0xFC00, 0x8000),
        (false, 0x0400, 0x7400),
        (false, 0xB800, 0xC000),
    ] {
        assert_eq!(fp16_estimate_violation(rsqrt, input, output), None);
        let adjacent = output ^ 1;
        assert!(
            fp16_estimate_violation(rsqrt, input, adjacent).is_some(),
            "rsqrt={rsqrt} input={input:04X} output={adjacent:04X}"
        );
    }

    // The interpreter model satisfies the same independent contract.
    for input in 0..=u16::MAX {
        for rsqrt in [false, true] {
            let output = SmirInterpreter::x86_fp16_approx(input, rsqrt);
            assert_eq!(
                fp16_estimate_violation(rsqrt, input, output),
                None,
                "rsqrt={rsqrt} input={input:04X} output={output:04X}"
            );
        }
    }
}

#[test]
fn fp16_estimate_success_comparison_excludes_only_active_estimate_lanes() {
    fn set_fp16_lane(words: &mut [u64], lane: usize, value: u16) {
        clear_fp16_lane(words, lane);
        words[lane / 4] |= u64::from(value) << ((lane % 4) * 16);
    }

    let case = PackedUnaryMemoryCase {
        operation: PackedUnaryOperation::RsqrtFp16,
        width: VecWidth::V512,
        destination: 17,
        form: SourceForm::Vector,
        control: MaskControl::Merge,
    };
    let destination = usize::from(case.destination);
    let bytes: [u8; 64] = std::array::from_fn(|index| 0x03FFu16.to_le_bytes()[index % 2]);
    let mut expected = initial_state(case, 0, &bytes);
    let active_mask = expected.masks[usize::from(case.mask())];
    let active = |lane: &usize| active_mask & (1u64 << lane) != 0;
    for lane in (0..32).filter(active) {
        set_fp16_lane(&mut expected.vectors[destination], lane, 0x5801);
    }
    let mut actual = guest_regs(&expected);
    let mut zmm = actual.get_zmm(destination);
    for lane in (0..32).filter(active) {
        set_fp16_lane(&mut zmm, lane, 0x5800);
    }
    actual.set_zmm(destination, zmm);
    let compare = |actual: &GuestRegs| {
        std::panic::catch_unwind(|| {
            assert_success_state(actual, &expected, OptLevel::O0, case, &bytes, active_mask)
        })
        .is_ok()
    };
    assert!(compare(&actual), "bounded active-lane difference");

    let inactive = (0..32).find(|lane| !active(lane)).unwrap();
    let mut changed = actual;
    let mut changed_zmm = zmm;
    changed_zmm[inactive / 4] ^= 1 << ((inactive % 4) * 16);
    changed.set_zmm(destination, changed_zmm);
    assert!(
        !compare(&changed),
        "inactive merge lane must stay bit-exact"
    );

    let first_active = (0..32).find(active).unwrap();
    let mut changed = actual;
    let mut changed_zmm = zmm;
    set_fp16_lane(&mut changed_zmm, first_active, 0x5802);
    changed.set_zmm(destination, changed_zmm);
    assert!(!compare(&changed), "active lane outside the bound");

    let mut changed = actual;
    changed.mxcsr ^= 1 << 5;
    assert!(!compare(&changed), "state outside the estimate lanes");
}
