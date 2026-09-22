//! Atomic callback ABI, fixed-width semantics, and concurrent transaction tests.

use super::*;

#[test]
fn atomic_callback_abi_is_append_only_and_rejects_unknown_tags_and_sizes() {
    assert_eq!(
        std::mem::offset_of!(GuestRegs, atomic_rmw_fn),
        std::mem::offset_of!(GuestRegs, x86_vsib_instruction_ordinal) + 8
    );
    assert_eq!(
        std::mem::offset_of!(GuestRegs, atomic_rmw_fn),
        crate::smir::lower::X86_GUEST_ATOMIC_RMW_FN_OFFSET as usize
    );
    assert_eq!(GuestRegs::default().atomic_rmw_fn, 0);
    assert_eq!(std::mem::size_of::<X86AtomicRmwRet>(), 16);
    assert_eq!(std::mem::offset_of!(X86AtomicRmwRet, ok), 8);
    for raw in [6, 7, 0x8000_0000, u32::MAX] {
        assert_eq!(X86AtomicRmwOp::from_raw(raw), None);
    }
    for raw in 0..6 {
        let op = X86AtomicRmwOp::from_raw(raw).unwrap();
        assert_eq!(op as u32, raw);
        for size in [0, 3, 5, 7, 9, 16, u32::MAX] {
            assert_eq!(op.apply(u64::MAX, 1, size), None);
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod native {
    use super::*;
    use crate::smir::ir::SmirFunction;
    use crate::smir::ir::types::{AtomicOp, MemWidth, MemoryOrder};
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::x86_64::X86_64Lowerer;
    use crate::smir::optimize::{OptLevel, optimize_function};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    const PC: u64 = 0x1234_5678_9000;
    const ADDRESS: u64 = 0x2000;
    const ARITH: u64 = 0x8D5;
    const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

    #[derive(Clone, Copy, Debug)]
    enum Source {
        Register(u8),
        Immediate(u64, bool),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Replay {
        None,
        Binary,
        Inc,
        Dec,
    }

    fn reg(index: u8) -> VReg {
        VReg::Arch(ArchReg::X86(X86Reg::gpr(index)))
    }

    fn widths(size: u32) -> (MemWidth, OpWidth) {
        match size {
            1 => (MemWidth::B1, OpWidth::W8),
            2 => (MemWidth::B2, OpWidth::W16),
            4 => (MemWidth::B4, OpWidth::W32),
            8 => (MemWidth::B8, OpWidth::W64),
            _ => unreachable!(),
        }
    }

    fn function(
        op: u32,
        source: Source,
        base: u8,
        size: u32,
        replay: Replay,
        writeback: Option<u8>,
        level: OptLevel,
    ) -> SmirFunction {
        let (mem_width, width) = widths(size);
        let mut builder = FunctionBuilder::new(FunctionId(0), PC);
        let src = match source {
            Source::Register(index) => reg(index),
            Source::Immediate(value, imm64) => {
                let src = VReg::virt(200);
                builder.push_op(
                    PC,
                    OpKind::Mov {
                        dst: src,
                        src: if imm64 {
                            SrcOperand::Imm64(value as i64)
                        } else {
                            SrcOperand::Imm(value as i64)
                        },
                        width,
                    },
                );
                src
            }
        };
        let old = VReg::virt(201);
        let dst = VReg::virt(202);
        let op_kind = match op {
            0 => AtomicOp::Add,
            1 => AtomicOp::Or,
            2 => AtomicOp::And,
            3 => AtomicOp::Sub,
            4 => AtomicOp::Xor,
            5 => AtomicOp::Swap,
            _ => unreachable!(),
        };
        builder.push_op(
            PC,
            OpKind::AtomicRmw {
                dst: old,
                addr: Address::Direct(reg(base)),
                src,
                op: op_kind,
                width: mem_width,
                order: MemoryOrder::SeqCst,
            },
        );
        if replay != Replay::None {
            let src2 = SrcOperand::Reg(src);
            let flags = FlagUpdate::All;
            let kind = match replay {
                Replay::Inc => OpKind::Inc {
                    dst,
                    src: old,
                    width,
                    flags,
                },
                Replay::Dec => OpKind::Dec {
                    dst,
                    src: old,
                    width,
                    flags,
                },
                Replay::Binary => match op {
                    0 => OpKind::Add {
                        dst,
                        src1: old,
                        src2,
                        width,
                        flags,
                    },
                    1 => OpKind::Or {
                        dst,
                        src1: old,
                        src2,
                        width,
                        flags,
                    },
                    2 => OpKind::And {
                        dst,
                        src1: old,
                        src2,
                        width,
                        flags,
                    },
                    3 => OpKind::Sub {
                        dst,
                        src1: old,
                        src2,
                        width,
                        flags,
                    },
                    4 => OpKind::Xor {
                        dst,
                        src1: old,
                        src2,
                        width,
                        flags,
                    },
                    _ => unreachable!(),
                },
                Replay::None => unreachable!(),
            };
            builder.push_op(PC, kind);
        }
        if let Some(index) = writeback {
            builder.push_op(
                PC,
                OpKind::Mov {
                    dst: reg(index),
                    src: SrcOperand::Reg(old),
                    width,
                },
            );
        }
        builder.set_terminator(Terminator::Return { values: vec![] });
        let mut function = builder.finish();
        optimize_function(&mut function, level);
        function
    }

    fn lower(function: &SmirFunction, mmx: bool) -> (Arc<ExecMem>, usize) {
        assert!(
            is_native_clobber_safe_excluding(function, &std::collections::HashMap::new(), true),
            "{function:#?}"
        );
        let mut lowerer = X86_64Lowerer::new();
        lowerer.set_mem_helpers(true);
        lowerer.set_jit_fault_deopt_guards(true);
        lowerer.set_preserve_mmx_helpers(mmx);
        let result = lowerer.lower_function(function).unwrap();
        let bytes = lowerer.finalize().unwrap();
        (Arc::new(ExecMem::new(&bytes).unwrap()), result.entry_offset)
    }

    /// Independent reference, evaluated in 128 bits then reduced modulo 2^N.
    /// AF from logical operations is undefined and excluded from comparisons.
    fn reference(
        op: u32,
        old: u64,
        source: u64,
        size: u32,
        flags: u64,
        replay: Replay,
    ) -> (u64, u64, u64) {
        let bits = size * 8;
        let modulus = 1u128 << bits;
        let mask = (modulus - 1) as u64;
        let a = old & mask;
        let b = source & mask;
        let value = match op {
            0 => ((u128::from(a) + u128::from(b)) % modulus) as u64,
            1 => a | b,
            2 => a & b,
            3 => ((u128::from(a) + modulus - u128::from(b)) % modulus) as u64,
            4 => a ^ b,
            5 => b,
            _ => unreachable!(),
        };
        if replay == Replay::None {
            return (value, flags, u64::MAX);
        }
        let sign = 1u64 << (bits - 1);
        let signed = |v: u64| {
            if v & sign == 0 {
                i128::from(v)
            } else {
                i128::from(v) - modulus as i128
            }
        };
        let signed_result = if op == 3 {
            signed(a) - signed(b)
        } else {
            signed(a) + signed(b)
        };
        let logical = matches!(op, 1 | 2 | 4);
        let cf = if replay == Replay::Inc || replay == Replay::Dec {
            flags & 1 != 0
        } else if op == 0 {
            u128::from(a) + u128::from(b) >= modulus
        } else {
            op == 3 && a < b
        };
        let of =
            !logical && (signed_result < -(i128::from(sign)) || signed_result >= i128::from(sign));
        let generated = u64::from(cf)
            | (u64::from((value as u8).count_ones() % 2 == 0) << 2)
            | (u64::from((a ^ b ^ value) & 0x10 != 0) << 4)
            | (u64::from(value == 0) << 6)
            | (u64::from(value & sign != 0) << 7)
            | (u64::from(of) << 11);
        let defined = if logical { ARITH & !0x10 } else { ARITH };
        (
            value,
            (flags & !defined) | (generated & defined),
            if logical { !0x10 } else { u64::MAX },
        )
    }

    struct Shared {
        value: AtomicU64,
        barrier: Option<Barrier>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Call {
        address: u64,
        operand: u64,
        size: u32,
        operation: u32,
        old: u64,
    }

    struct Context {
        shared: Arc<Shared>,
        calls: Mutex<Vec<Call>>,
        loads: AtomicUsize,
        stores: AtomicUsize,
        callback_mxcsr: AtomicUsize,
        fail: bool,
        clobber_mmx: bool,
    }

    impl Context {
        fn new(shared: Arc<Shared>, fail: bool, clobber_mmx: bool) -> Self {
            Self {
                shared,
                calls: Mutex::new(Vec::new()),
                loads: AtomicUsize::new(0),
                stores: AtomicUsize::new(0),
                callback_mxcsr: AtomicUsize::new(usize::MAX),
                fail,
                clobber_mmx,
            }
        }
    }

    unsafe extern "C" fn transaction(
        ctx: *mut core::ffi::c_void,
        address: u64,
        operand: u64,
        size: u32,
        operation: u32,
    ) -> X86AtomicRmwRet {
        // SAFETY: the execution owns an Arc<Context> throughout this call.
        // Only shared references are constructed; all mutations use atomics or
        // a mutex. No canonical CPU/MMU or ordinary RAM is shared by threads.
        let context = unsafe { &*ctx.cast::<Context>() };
        let valid = address == ADDRESS && matches!(size, 1 | 2 | 4 | 8) && operation < 6;
        if context.fail || !valid {
            context.calls.lock().unwrap().push(Call {
                address,
                operand,
                size,
                operation,
                old: 0,
            });
            return X86AtomicRmwRet::default();
        }
        if let Some(barrier) = &context.shared.barrier {
            barrier.wait();
        }
        let mask = ((1u128 << (size * 8)) - 1) as u64;
        let old = context
            .shared
            .value
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |word| {
                let result = reference(operation, word, operand, size, 0, Replay::None).0;
                Some((word & !mask) | result)
            })
            .unwrap()
            & mask;
        context.calls.lock().unwrap().push(Call {
            address,
            operand,
            size,
            operation,
            old,
        });
        if context.clobber_mmx {
            // SAFETY: MMX is caller-clobbered. EMMS restores the host ABI's
            // empty x87 tag state before returning to generated code.
            unsafe {
                core::arch::asm!(
                    "pxor mm0, mm0",
                    "pxor mm1, mm1",
                    "pxor mm2, mm2",
                    "pxor mm3, mm3",
                    "pxor mm4, mm4",
                    "pxor mm5, mm5",
                    "pxor mm6, mm6",
                    "pxor mm7, mm7",
                    "emms",
                    options(nostack)
                );
            }
        }
        X86AtomicRmwRet {
            old_value: old,
            ok: 1,
        }
    }

    unsafe extern "C" fn ordinary_load(
        ctx: *mut core::ffi::c_void,
        _: u64,
        _: u32,
        _: u32,
    ) -> X86AtomicRmwRet {
        // SAFETY: same Arc lifetime and synchronized interior state as transaction.
        let context = unsafe { &*ctx.cast::<Context>() };
        context.loads.fetch_add(1, Ordering::SeqCst);
        let old_value = context.shared.value.load(Ordering::SeqCst);
        if let Some(barrier) = &context.shared.barrier {
            barrier.wait();
        }
        X86AtomicRmwRet { old_value, ok: 1 }
    }

    #[target_feature(enable = "avx")]
    unsafe extern "C" fn transaction_with_vector_clobber(
        ctx: *mut core::ffi::c_void,
        address: u64,
        operand: u64,
        size: u32,
        operation: u32,
    ) -> X86AtomicRmwRet {
        // SAFETY: the same live Arc<Context> contract as transaction. The test
        // invokes this callback only after detecting host AVX support.
        let context = unsafe { &*ctx.cast::<Context>() };
        let mut mxcsr = 0u32;
        // SAFETY: STMXCSR writes this initialized, aligned four-byte slot.
        unsafe {
            core::arch::asm!("stmxcsr [{slot}]", slot = in(reg) &mut mxcsr, options(nostack, preserves_flags));
        }
        context
            .callback_mxcsr
            .store(mxcsr as usize, Ordering::SeqCst);
        // SAFETY: forwarding the unchanged valid callback arguments.
        let result = unsafe { transaction(ctx, address, operand, size, operation) };
        // SAFETY: AVX was checked. Every affected SIMD register is declared
        // caller-clobbered; this changes no MXCSR control or status bit.
        unsafe {
            core::arch::asm!("vzeroall",
                out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
                out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
                out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
                out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
                options(nostack, preserves_flags)
            );
        }
        result
    }

    unsafe extern "C" fn ordinary_store(
        ctx: *mut core::ffi::c_void,
        _: u64,
        value: u64,
        _: u32,
    ) -> u64 {
        // SAFETY: same Arc lifetime and synchronized interior state as transaction.
        let context = unsafe { &*ctx.cast::<Context>() };
        context.stores.fetch_add(1, Ordering::SeqCst);
        context.shared.value.store(value, Ordering::SeqCst);
        1
    }

    fn initial(
        context: &Arc<Context>,
        source: Source,
        base: u8,
        flags: u64,
        callback: bool,
    ) -> GuestRegs {
        let mut regs = GuestRegs {
            gpr: core::array::from_fn(|index| {
                0x8765_4321_FEDC_BA90u64.wrapping_add(index as u64 * 0x101_0101)
            }),
            rflags: flags,
            exit_pc: 0xABCD_EF01_1234_5678,
            ctx: Arc::as_ptr(context) as u64,
            load_fn: ordinary_load as *const () as u64,
            store_fn: ordinary_store as *const () as u64,
            atomic_rmw_fn: if callback {
                transaction as *const () as u64
            } else {
                0
            },
            mm: core::array::from_fn(|index| 0x1234_5678_9ABC_DEF0 + index as u64),
            zmm: core::array::from_fn(|index| {
                core::array::from_fn(|lane| 0x1234_5678_90AB_CDEF + (index * 8 + lane) as u64)
            }),
            k: [0x0102_0304_0506_0708; 8],
            mxcsr: 0x3FA1,
            mmx_active: u64::from(context.clobber_mmx),
            x87_tag_word: 0xA5A5,
            ..GuestRegs::default()
        };
        if let Source::Register(index) = source {
            regs.gpr[index as usize] ^= u64::MAX;
        }
        regs.gpr[base as usize] = ADDRESS;
        regs
    }

    fn check_state(actual: GuestRegs, mut expected: GuestRegs, mask: u64, label: &str) {
        expected.host_mxcsr = actual.host_mxcsr;
        expected.rflags = (expected.rflags & mask) | (actual.rflags & !mask);
        assert_eq!(actual, expected, "{label}");
    }

    fn check_one(
        exec: &ExecMem,
        entry: usize,
        op: u32,
        source: Source,
        base: u8,
        size: u32,
        replay: Replay,
        writeback: Option<u8>,
        flags: u64,
        mode: u8,
        clobber_mmx: bool,
    ) {
        let before = 0xA5B6_C7D8_7F80_FF00;
        let shared = Arc::new(Shared {
            value: AtomicU64::new(before),
            barrier: None,
        });
        let context = Arc::new(Context::new(shared.clone(), mode == 1, clobber_mmx));
        let mut regs = initial(&context, source, base, flags, mode != 2);
        let mut expected = regs;
        let operand = match source {
            Source::Register(index) => regs.gpr[index as usize],
            Source::Immediate(value, _) => value,
        };
        let (result, out_flags, mask) = reference(op, before, operand, size, flags, replay);
        let width_mask = ((1u128 << (size * 8)) - 1) as u64;
        let callback_operand = if matches!(source, Source::Immediate(_, _)) {
            // The source virtual is defined by a width-truncating SMIR MOV.
            operand & width_mask
        } else {
            operand
        };
        if mode == 0 {
            expected.rflags = out_flags;
            if let Some(index) = writeback {
                let old = before & width_mask;
                expected.gpr[index as usize] = if size == 2 {
                    (expected.gpr[index as usize] & !width_mask) | old
                } else {
                    old
                };
            }
        } else {
            expected.exit_pc = PC;
        }
        exec.run(entry, &mut regs);
        let label = format!(
            "op={op} {source:?} base={base} size={size} {replay:?} wb={writeback:?} flags={flags:#x} mode={mode}"
        );
        check_state(
            regs,
            expected,
            if mode == 0 { mask } else { u64::MAX },
            &label,
        );
        assert_eq!(context.loads.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(context.stores.load(Ordering::SeqCst), 0, "{label}");
        let calls = context.calls.lock().unwrap();
        assert_eq!(calls.len(), usize::from(mode != 2), "{label}");
        if let Some(call) = calls.first() {
            assert_eq!(
                *call,
                Call {
                    address: ADDRESS,
                    operand: callback_operand,
                    size,
                    operation: op,
                    old: if mode == 0 { before & width_mask } else { 0 }
                },
                "{label}"
            );
        }
        assert_eq!(
            shared.value.load(Ordering::SeqCst),
            if mode == 0 {
                (before & !width_mask) | result
            } else {
                before
            },
            "{label}"
        );
    }

    #[test]
    fn every_atomic_width_and_gpr_alias_uses_one_callback_or_precise_deopt() {
        let mut executions = 0;
        for level in LEVELS {
            for op in 0..6 {
                for size in [1, 2, 4, 8] {
                    for index in 0..32 {
                        for base in [index, (index + 17) & 31] {
                            for replay in [Replay::None, Replay::Binary] {
                                if op == 5 && replay == Replay::Binary {
                                    continue;
                                }
                                let source = Source::Register(index);
                                let function =
                                    function(op, source, base, size, replay, None, level);
                                let (exec, entry) = lower(&function, false);
                                for mode in 0..3 {
                                    check_one(
                                        &exec,
                                        entry,
                                        op,
                                        source,
                                        base,
                                        size,
                                        replay,
                                        None,
                                        0xED6 | u64::from(index & 1),
                                        mode,
                                        false,
                                    );
                                    executions += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(executions, 3 * 11 * 4 * 32 * 2 * 3);
        eprintln!(
            "executed {executions} atomic width/GPR/alias/success/failure/null-callback cases"
        );
    }

    #[test]
    fn narrow_materialized_immediates_deliver_the_exact_smir_callback_operand() {
        let mut executions = 0;
        for level in LEVELS {
            for op in 0..6 {
                for size in [1, 2, 4] {
                    for value in [u64::MAX, 0x1_0000_0000, 0x1234_5678_9ABC_DEF0] {
                        for imm64 in [false, true] {
                            let source = Source::Immediate(value, imm64);
                            for replay in [Replay::None, Replay::Binary] {
                                // O1/O2 can normalize a narrow replay literal
                                // while retaining the original materializer.
                                // That pre-existing live-replay shape remains
                                // outside admission; do not expand its grammar
                                // to test the callback's source-value boundary.
                                if replay == Replay::Binary && (op == 5 || level != OptLevel::O0) {
                                    continue;
                                }
                                let (exec, entry) = lower(
                                    &function(op, source, 5, size, replay, None, level),
                                    false,
                                );
                                for mode in 0..3 {
                                    check_one(
                                        &exec, entry, op, source, 5, size, replay, None, 0xED7,
                                        mode, false,
                                    );
                                    executions += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(executions, (3 * 6 + 5) * 3 * 3 * 2 * 3);
        eprintln!(
            "executed {executions} narrow-immediate callback operand/success/failure/null cases"
        );
    }

    #[test]
    fn optimized_narrow_live_replay_keeps_its_existing_fail_closed_boundary() {
        let function = function(
            0,
            Source::Immediate(u64::MAX, false),
            5,
            4,
            Replay::Binary,
            None,
            OptLevel::O2,
        );
        // The optimizer has normalized only the flag replay's immediate.
        // Width-aware replay equivalence is separate from the callback ABI.
        assert!(matches!(
            function.blocks[0].ops[2].kind,
            OpKind::Add {
                src2: SrcOperand::Imm(0xFFFF_FFFF),
                ..
            }
        ));
        assert!(!is_native_clobber_safe_excluding(
            &function,
            &std::collections::HashMap::new(),
            true,
        ));
        let mut lowerer = X86_64Lowerer::new();
        lowerer.set_mem_helpers(true);
        assert!(lowerer.lower_function(&function).is_err());
    }

    #[test]
    fn two_native_threads_share_one_seqcst_transaction_per_instruction() {
        let mut executions = 0;
        for level in LEVELS {
            for operation in 0..6 {
                for size in [1, 2, 4, 8] {
                    for operand in [
                        1,
                        if size == 8 {
                            0x1_0000_0001
                        } else {
                            (1 << (size * 8 - 1)) | 3
                        },
                    ] {
                        for imm64 in [false, true] {
                            let source = Source::Immediate(operand, imm64);
                            let replay = if operation == 5 {
                                Replay::None
                            } else {
                                Replay::Binary
                            };
                            let (exec, entry) = lower(
                                &function(operation, source, 7, size, replay, None, level),
                                false,
                            );
                            let before = 0x1234_5678_7FFF_FFFE;
                            let shared = Arc::new(Shared {
                                value: AtomicU64::new(before),
                                barrier: Some(Barrier::new(2)),
                            });
                            let handles: Vec<_> = (0..2)
                                .map(|thread| {
                                    let exec = exec.clone();
                                    let context =
                                        Arc::new(Context::new(shared.clone(), false, false));
                                    std::thread::spawn(move || {
                                        let mut regs =
                                            initial(&context, source, 7, 0xED6 | thread, true);
                                        let mut expected = regs;
                                        exec.run(entry, &mut regs);
                                        let calls = context.calls.lock().unwrap();
                                        assert_eq!(
                                            calls.len(),
                                            1,
                                            "one atomic transaction per instruction"
                                        );
                                        let call = calls[0];
                                        let (_, flags, mask) = reference(
                                            operation,
                                            call.old,
                                            operand,
                                            size,
                                            expected.rflags,
                                            replay,
                                        );
                                        expected.rflags = flags;
                                        check_state(
                                            regs,
                                            expected,
                                            mask,
                                            "concurrent native state",
                                        );
                                        assert_eq!(context.loads.load(Ordering::SeqCst), 0);
                                        assert_eq!(context.stores.load(Ordering::SeqCst), 0);
                                        assert_eq!(
                                            (call.address, call.operand, call.size, call.operation),
                                            (ADDRESS, operand, size, operation)
                                        );
                                        call.old
                                    })
                                })
                                .collect();
                            let mut observed: Vec<_> = handles
                                .into_iter()
                                .map(|handle| handle.join().unwrap())
                                .collect();
                            let mask = ((1u128 << (size * 8)) - 1) as u64;
                            let first =
                                reference(operation, before, operand, size, 0, Replay::None).0;
                            let second =
                                reference(operation, first, operand, size, 0, Replay::None).0;
                            let mut expected = [before & mask, first];
                            observed.sort_unstable();
                            expected.sort_unstable();
                            assert_eq!(
                                observed, expected,
                                "both old values must form one serial history"
                            );
                            assert_eq!(
                                shared.value.load(Ordering::SeqCst),
                                (before & !mask) | second
                            );
                            executions += 2;
                        }
                    }
                }
            }
        }
        assert_eq!(executions, 3 * 6 * 4 * 2 * 2 * 2);
        eprintln!("executed {executions} deterministic two-thread native atomic transactions");
    }

    #[test]
    fn atomic_unary_flags_and_xadd_xchg_writeback_survive_callback_boundaries() {
        let mut executions = 0;
        for level in LEVELS {
            for (op, replay) in [(0, Replay::Inc), (3, Replay::Dec)] {
                for size in [1, 2, 4, 8] {
                    let source = Source::Immediate(1, false);
                    let (exec, entry) =
                        lower(&function(op, source, 5, size, replay, None, level), false);
                    for image in 0..64 {
                        let flags = [0, 2, 4, 6, 7, 11]
                            .into_iter()
                            .enumerate()
                            .fold(0x602, |flags, (bit, shift)| {
                                flags | (((image >> bit) & 1) << shift)
                            });
                        for mode in 0..3 {
                            check_one(
                                &exec, entry, op, source, 5, size, replay, None, flags, mode, false,
                            );
                            executions += 1;
                        }
                    }
                }
            }
            for op in [0, 5] {
                for size in [2, 4, 8] {
                    for index in [0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
                        for base in [index, (index + 7) & 15] {
                            let source = Source::Register(index);
                            let replay = if op == 0 {
                                Replay::Binary
                            } else {
                                Replay::None
                            };
                            let (exec, entry) = lower(
                                &function(op, source, base, size, replay, Some(index), level),
                                false,
                            );
                            for mode in 0..3 {
                                check_one(
                                    &exec,
                                    entry,
                                    op,
                                    source,
                                    base,
                                    size,
                                    replay,
                                    Some(index),
                                    0xED7,
                                    mode,
                                    false,
                                );
                                executions += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(executions, 3 * (2 * 4 * 64 * 3 + 2 * 3 * 14 * 2 * 3));
        eprintln!("executed {executions} atomic INC/DEC flag and XADD/XCHG writeback cases");
    }

    #[test]
    fn atomic_callback_preserves_live_mmx_and_guest_tags() {
        let source = Source::Immediate(0x1_0000_0001, true);
        for mode in 0..3 {
            let (exec, entry) = lower(
                &function(0, source, 4, 8, Replay::Binary, None, OptLevel::O2),
                true,
            );
            check_one(
                &exec,
                entry,
                0,
                source,
                4,
                8,
                Replay::Binary,
                None,
                0xED7,
                mode,
                true,
            );
        }
    }

    #[test]
    fn atomic_callback_preserves_live_ymm_mmx_mxcsr_and_dormant_opmask_zmm_state() {
        if !std::is_x86_feature_detected!("avx") {
            eprintln!("SKIP atomic live-YMM callback boundary: host AVX unavailable");
            return;
        }
        let source = Source::Immediate(0x1_0000_0001, true);
        let function = function(0, source, 4, 8, Replay::Binary, None, OptLevel::O2);
        for mmx in [false, true] {
            let mut lowerer = X86_64Lowerer::new();
            lowerer.set_mem_helpers(true);
            lowerer.set_jit_fault_deopt_guards(true);
            lowerer.set_preserve_mmx_helpers(mmx);
            lowerer.set_preserve_vector_mem_helpers(true);
            lowerer.set_avx_ymm16_vector_state(true);
            let entry = lowerer.lower_function(&function).unwrap().entry_offset;
            let exec = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
            for mode in 0..3 {
                let shared = Arc::new(Shared {
                    value: AtomicU64::new(7),
                    barrier: None,
                });
                let context = Arc::new(Context::new(shared.clone(), mode == 1, mmx));
                let mut regs = initial(&context, source, 4, 0xED7, mode != 2);
                // YMM0-15 are live; opmasks and upper ZMM bytes remain dormant
                // GuestRegs fields and must not change during this boundary.
                regs.vector_active = X86_VECTOR_STATE_YMM16;
                if mode != 2 {
                    regs.atomic_rmw_fn = transaction_with_vector_clobber as *const () as u64;
                }
                let mut expected = regs;
                if mode == 0 {
                    expected.rflags =
                        reference(0, 7, 0x1_0000_0001, 8, regs.rflags, Replay::Binary).1;
                } else {
                    expected.exit_pc = PC;
                }
                exec.run(entry, &mut regs);
                check_state(
                    regs,
                    expected,
                    u64::MAX,
                    "live YMM/MMX/MXCSR atomic callback",
                );
                assert_eq!(context.loads.load(Ordering::SeqCst), 0);
                assert_eq!(context.stores.load(Ordering::SeqCst), 0);
                assert_eq!(context.calls.lock().unwrap().len(), usize::from(mode != 2));
                assert_eq!(
                    context.callback_mxcsr.load(Ordering::SeqCst),
                    if mode != 2 {
                        regs.host_mxcsr as usize
                    } else {
                        usize::MAX
                    },
                    "Rust callback must observe host MXCSR, not guest MXCSR"
                );
                assert_eq!(
                    shared.value.load(Ordering::SeqCst),
                    if mode == 0 { 0x1_0000_0008 } else { 7 }
                );
            }
        }
        eprintln!("executed 6 live-YMM/MMX/MXCSR plus dormant-opmask/ZMM atomic callback cases");
    }
}
