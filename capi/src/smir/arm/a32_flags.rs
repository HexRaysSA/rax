//! Additional strict A32 logical flag bodies, expressed in shared SMIR.
//! Unshifted registers preserve C/V. Expanded immediates preserve C when their
//! encoding has rotation zero, otherwise C receives expanded immediate bit 31.
//! V is always preserved. Register shifters remain rejected.
use super::*;
use rax_engine::isa::arm::decoder::Operand;
use rax_engine::smir::{ir::flags::FlagSet, lift::LiftResult};

pub(super) fn lift(pc: u64, bytes: &[u8], context: &mut LiftContext) -> Checked<LiftResult> {
    let raw = u32::from_le_bytes(bytes.try_into().map_err(|_| ())?);
    let insn = Aarch32Decoder::decode(raw).map_err(|_| ())?;
    if insn.cond.is_some() {
        return Err(());
    }
    let test = matches!(insn.mnemonic, Mnemonic::TST | Mnemonic::TEQ);
    if !test
        && !matches!(
            insn.mnemonic,
            Mnemonic::ANDS | Mnemonic::ORRS | Mnemonic::EORS | Mnemonic::BICS
        )
    {
        return Err(());
    }
    let (destination, left, right) = match insn.operands.as_slice() {
        [Operand::Reg(left), right] if test => (None, left, right),
        [Operand::Reg(dst), Operand::Reg(left), right] if !test && dst.num < 15 => {
            (Some(dst.num), left, right)
        }
        _ => return Err(()),
    };
    if left.num >= 15 {
        return Err(());
    }
    let src2 = match right {
        Operand::Reg(reg) if reg.num < 15 => {
            SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg.num))))
        }
        Operand::Imm(imm) => SrcOperand::Imm(imm.effective_value()),
        _ => return Err(()),
    };
    let dst = destination.map_or_else(
        || context.alloc_vreg(),
        |reg| VReg::Arch(ArchReg::Arm(ArmReg::X(reg))),
    );
    let src1 = VReg::Arch(ArchReg::Arm(ArmReg::X(left.num)));
    let width = OpWidth::W32;
    let flags = FlagUpdate::Specific(FlagSet::SF.union(FlagSet::ZF));
    let kind = match insn.mnemonic {
        Mnemonic::TST | Mnemonic::ANDS => OpKind::And {
            dst,
            src1,
            src2,
            width,
            flags,
        },
        Mnemonic::TEQ | Mnemonic::EORS => OpKind::Xor {
            dst,
            src1,
            src2,
            width,
            flags,
        },
        Mnemonic::ORRS => OpKind::Or {
            dst,
            src1,
            src2,
            width,
            flags,
        },
        Mnemonic::BICS => OpKind::AndNot {
            dst,
            src1,
            src2,
            width,
            flags,
        },
        _ => return Err(()),
    };
    let mut ops = vec![SmirOp::new(OpId(0), pc, kind)];
    if let Operand::Imm(imm) = right {
        if (raw >> 8) & 15 != 0 {
            // SMIR CF is the inverse of ARM C (its no-borrow convention).
            ops.push(SmirOp::new(
                OpId(1),
                pc,
                OpKind::SetCF {
                    value: (imm.effective_value() as u32) & 0x80000000 == 0,
                },
            ));
        }
    }
    Ok(LiftResult {
        ops,
        bytes_consumed: 4,
        control_flow: ControlFlow::Fallthrough,
        branch_targets: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::{rax_engine_close, rax_engine_open},
        mem::rax_mem_write,
        reg::{rax_reg_read_u64, rax_reg_write_u64},
        run::rax_emu_step,
    };
    use rax_engine::smir::{
        interpret::{BlockResult, SmirInterpreter},
        ir::{
            FunctionBuilder, Terminator, TrapKind,
            context::{ExitReason, SmirContext},
            flags::MaterializedFlags,
            memory::FlatMemory,
        },
    };

    #[test]
    fn logical_bodies_match_native_gpr_and_all_nzcv_bits() {
        // TST, TEQ, ANDS, ORRS, EORS, BICS; rotated and non-rotated immediates.
        for word in [
            0xe1100001u32,
            0xe1300001,
            0xe0102001,
            0xe1902001,
            0xe0302001,
            0xe1d02001,
            0xe3100102,
            0xe3100202,
            0xe31000ff,
        ] {
            let mut lctx = LiftContext::new(SourceArch::Aarch32);
            let body = lift(0, &word.to_le_bytes(), &mut lctx).unwrap();
            let mut builder = FunctionBuilder::new(FunctionId(0), 0);
            builder.set_terminator(Terminator::Trap {
                kind: TrapKind::Halt,
            });
            let mut function = builder.finish();
            function.blocks[0].ops = body.ops;
            for (left, right) in [
                (0u32, 0u32),
                (u32::MAX, 0),
                (0x80000000, 1),
                (0xaaaaaaaa, 0x55555555),
            ] {
                for flags in 0u32..16 {
                    let mut ctx = SmirContext::new_aarch64();
                    ctx.source_arch = SourceArch::Aarch32;
                    ctx.flags.materialized = MaterializedFlags::from_nzcv(flags << 28);
                    for (reg, value) in [(0, left), (1, right), (2, 0x77777777)] {
                        ctx.write_vreg(VReg::Arch(ArchReg::Arm(ArmReg::X(reg))), u64::from(value));
                    }
                    let result = SmirInterpreter::new().execute_block(
                        &mut ctx,
                        &mut FlatMemory::new(16),
                        &function.blocks[0],
                    );
                    assert!(matches!(result, BlockResult::Exit(ExitReason::Halt)));
                    ctx.flags.materialize_all();
                    let expected_flags = ctx.flags.materialized.to_nzcv();
                    let mut engine = std::ptr::null_mut();
                    assert_eq!(rax_engine_open(3, RAX_MODE_ARM, &mut engine), RaxStatus::Ok);
                    assert_eq!(
                        rax_mem_write(engine, 0, word.to_le_bytes().as_ptr().cast(), 4),
                        RaxStatus::Ok
                    );
                    for (reg, value) in [
                        (0x100, u64::from(left)),
                        (0x101, u64::from(right)),
                        (0x102, 0x77777777),
                        (0x12, u64::from(flags << 28) | 0x13),
                    ] {
                        assert_eq!(rax_reg_write_u64(engine, reg, value), RaxStatus::Ok);
                    }
                    let mut done = 0;
                    assert_eq!(rax_emu_step(engine, 1, &mut done), RaxStatus::Ok);
                    assert_eq!(done, 1);
                    let mut actual = 0;
                    assert_eq!(rax_reg_read_u64(engine, 0x12, &mut actual), RaxStatus::Ok);
                    assert_eq!(
                        actual as u32 & 0xf0000000,
                        expected_flags,
                        "word={word:#x}, flags={flags:#x}"
                    );
                    assert_eq!(rax_reg_read_u64(engine, 0x102, &mut actual), RaxStatus::Ok);
                    assert_eq!(
                        actual,
                        ctx.read_vreg(VReg::Arch(ArchReg::Arm(ArmReg::X(2))))
                    );
                    rax_engine_close(engine);
                }
            }
        }
    }
}
