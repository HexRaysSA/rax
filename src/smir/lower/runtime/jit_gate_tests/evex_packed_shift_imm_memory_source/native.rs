//! Native differential execution, helper access policy, and fault frontier.

use super::super::vex_fma3_memory_source::{VectorMemoryContext, vector_load_helper};
use super::semantics::{expected, initial, source};
use super::*;
use crate::smir::ir::context::ArchRegState;
use crate::smir::lower::runtime::{ExecMem, GuestRegs, X86_VECTOR_STATE_K64};

#[repr(C)]
struct LoadResult {
    value: u64,
    ok: u64,
}
struct ScalarMemory {
    calls: Vec<u64>,
    failure: Option<u64>,
    size: u64,
}

extern "C" fn scalar_load(
    context: *mut ScalarMemory,
    address: u64,
    size: u64,
    signed: u64,
) -> LoadResult {
    // SAFETY: Each synchronous ExecMem::run below installs the unique address
    // of a live ScalarMemory in GuestRegs.ctx. No callback escapes that run,
    // and the caller does not access the context until native execution ends.
    let context = unsafe { &mut *context };
    context.calls.push(address);
    if size != context.size || signed != 0 || context.failure == Some(address) {
        return LoadResult { value: 0, ok: 0 };
    }
    let Some(offset) = address
        .checked_sub(0x2000)
        .and_then(|n| usize::try_from(n).ok())
    else {
        return LoadResult { value: 0, ok: 0 };
    };
    let input = source();
    let Some(bytes) = input.get(offset..offset.saturating_add(size as usize)) else {
        return LoadResult { value: 0, ok: 0 };
    };
    let mut value = [0u8; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    LoadResult {
        value: u64::from_le_bytes(value),
        ok: 1,
    }
}

fn registers(mask: u64) -> GuestRegs {
    let ArchRegState::X86_64(state) = initial(mask).arch_regs else {
        unreachable!()
    };
    let mut regs = GuestRegs {
        gpr: state.gpr,
        rflags: state.rflags,
        k: state.k,
        mxcsr: state.mxcsr,
        vector_active: X86_VECTOR_STATE_K64,
        exit_pc: 0xCAFE,
        ..GuestRegs::default()
    };
    for (index, vector) in state.xmm.iter().enumerate() {
        regs.set_zmm(index, vector[..8].try_into().unwrap());
    }
    regs
}

fn compare(regs: &GuestRegs, case: Case, mask: u64) {
    let initial = registers(mask);
    for (index, vector) in expected(case, mask).iter().enumerate() {
        assert_eq!(
            regs.get_zmm(index),
            <[u64; 8]>::try_from(&vector[..8]).unwrap(),
            "{case:?}: ZMM{index}"
        );
    }
    assert_eq!(regs.gpr, initial.gpr, "{case:?}: GPR");
    assert_eq!(regs.k, initial.k, "{case:?}: opmask");
    assert_eq!(regs.rflags, initial.rflags, "{case:?}: flags");
    assert_eq!(regs.mxcsr, initial.mxcsr, "{case:?}: MXCSR");
    assert_eq!(
        regs.exit_pc, initial.exit_pc,
        "{case:?}: unexpected fallback"
    );
}

#[test]
fn native_immediate_shift_memory_all_kinds_match_model_and_exact_access_policies() {
    if !std::is_x86_feature_detected!("avx512f") || !std::is_x86_feature_detected!("avx512bw") {
        eprintln!("skipping native immediate-shift memory execution: host lacks AVX-512F/BW");
        return;
    }
    let has_vl = std::is_x86_feature_detected!("avx512vl");
    let mut executions = 0;
    for case in cases()
        .into_iter()
        .step_by(4)
        .filter(|case| case.width == VecWidth::V512 || has_vl)
        .flat_map(|case| {
            // Word and byte-lane forms ignore W. Exercise the alternate
            // encoding on hardware as well as in the portable classifier.
            let wig = case.kind.e4nf().then_some(Case {
                kind: Kind {
                    w: true,
                    ..case.kind
                },
                ..case
            });
            std::iter::once(case).chain(wig)
        })
    {
        let case = Case {
            amount: if case.kind.byte_lane {
                7
            } else {
                case.kind.elem.bytes() as u8 * 8 - 1
            },
            ..case
        };
        for level in [OptLevel::O0, OptLevel::O2] {
            let function = optimized(lift(&case.bytes()), level);
            let (code, entry) = lower(&function);
            let exec = ExecMem::new(&code).expect("native immediate-shift replay");
            for mask in [0, 1, u64::MAX, 0x8000_0000_0000_0000, 0xA55A] {
                let mut regs = registers(mask);
                if !case.scalar() {
                    let bytes = source();
                    let mut context = VectorMemoryContext {
                        value: std::array::from_fn(|i| {
                            u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())
                        }),
                        ok: 1,
                        calls: 0,
                        last_addr: 0,
                        last_index: 0,
                        last_size: 0,
                        last_zero_upper: 0,
                    };
                    regs.ctx = (&mut context as *mut VectorMemoryContext) as u64;
                    regs.vec_load_fn = vector_load_helper as *const () as usize as u64;
                    exec.run(entry, &mut regs);
                    compare(&regs, case, mask);
                    assert_eq!(
                        (context.calls, context.last_addr, context.last_size),
                        (1, 0x2000, case.width.bytes()),
                        "{case:?}: unconditional E4NF/vector load"
                    );
                    assert_eq!(
                        context.last_index,
                        crate::smir::lower::X86_JIT_VECTOR_SCRATCH_INDEX
                    );
                } else {
                    let mut context = ScalarMemory {
                        calls: Vec::new(),
                        failure: None,
                        size: case.kind.elem.bytes() as u64,
                    };
                    regs.ctx = (&mut context as *mut ScalarMemory) as u64;
                    regs.load_fn = scalar_load as *const () as usize as u64;
                    exec.run(entry, &mut regs);
                    compare(&regs, case, mask);
                    let live = if case.mask == 0 { u64::MAX } else { mask };
                    let addresses: Vec<u64> = if case.broadcast {
                        if live & ((1u64 << case.lanes()) - 1) != 0 {
                            vec![0x2000]
                        } else {
                            vec![]
                        }
                    } else {
                        (0..case.lanes())
                            .filter(|lane| live & (1u64 << lane) != 0)
                            .map(|lane| 0x2000 + lane as u64 * context.size)
                            .collect()
                    };
                    assert_eq!(context.calls, addresses, "{case:?}: scalar access policy");
                }
                executions += 1;
            }
        }
    }
    assert!(executions >= 2320, "{executions} native cases");
    eprintln!("immediate-shift native executions: {executions}; no fallback");
}

#[test]
fn native_immediate_shift_memory_first_late_and_mask_zero_faults_preserve_all_state() {
    if !std::is_x86_feature_detected!("avx512f") || !std::is_x86_feature_detected!("avx512bw") {
        eprintln!("skipping native immediate-shift precise faults: host lacks AVX-512F/BW");
        return;
    }
    for kind in Kind::all() {
        for broadcast in [false, true] {
            if kind.e4nf() && broadcast {
                continue;
            }
            let case = Case {
                kind,
                width: VecWidth::V512,
                destination: 17,
                mask: if kind.byte_lane { 0 } else { 3 },
                zeroing: !kind.byte_lane,
                broadcast,
                amount: 255,
            };
            for level in [OptLevel::O0, OptLevel::O2] {
                let (code, entry) = lower(&optimized(lift(&case.bytes()), level));
                let exec = ExecMem::new(&code).unwrap();
                if !case.scalar() {
                    for mask in [0, u64::MAX] {
                        let mut context = VectorMemoryContext {
                            value: [0; 8],
                            ok: 0,
                            calls: 0,
                            last_addr: 0,
                            last_index: 0,
                            last_size: 0,
                            last_zero_upper: 0,
                        };
                        let mut regs = registers(mask);
                        regs.ctx = (&mut context as *mut VectorMemoryContext) as u64;
                        regs.vec_load_fn = vector_load_helper as *const () as usize as u64;
                        let mut fault = regs;
                        fault.exit_pc = PC;
                        exec.run(entry, &mut regs);
                        fault.host_mxcsr = regs.host_mxcsr;
                        assert_eq!(regs, fault, "{case:?}: E4NF fault with mask {mask:#x}");
                        assert_eq!(context.calls, 1);
                    }
                } else {
                    for lane in [0, if broadcast { 0 } else { case.lanes() - 1 }] {
                        let address = 0x2000 + lane as u64 * kind.elem.bytes() as u64;
                        let mut context = ScalarMemory {
                            calls: Vec::new(),
                            failure: Some(address),
                            size: kind.elem.bytes() as u64,
                        };
                        let mut regs = registers(u64::MAX);
                        regs.ctx = (&mut context as *mut ScalarMemory) as u64;
                        regs.load_fn = scalar_load as *const () as usize as u64;
                        let mut fault = regs;
                        fault.exit_pc = PC;
                        exec.run(entry, &mut regs);
                        fault.host_mxcsr = regs.host_mxcsr;
                        assert_eq!(regs, fault, "{case:?}: late fault lane {lane}");
                        assert_eq!(context.calls.last(), Some(&address));
                        assert_eq!(context.calls.len(), if broadcast { 1 } else { lane + 1 });
                    }
                }
            }
        }
    }
}
