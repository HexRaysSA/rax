//! tests.rs

use super::*;

// ---- split test submodules ----
#[cfg(test)]
mod apx;
#[cfg(test)]
mod arm;
#[cfg(test)]
mod evex;
#[cfg(test)]
mod leave;
#[cfg(test)]
mod opmask;
mod pauth;
#[cfg(test)]
mod riscv;
#[cfg(test)]
mod scalar;
#[cfg(test)]
mod simd;
#[cfg(test)]
mod sse4a;
#[cfg(test)]
mod stack_flags;
#[cfg(test)]
mod string;
#[cfg(test)]
mod tbm;
#[cfg(test)]
mod three_dnow;
#[cfg(test)]
mod x86_fma;
#[cfg(test)]
mod x87;
#[cfg(test)]
mod xop;
#[cfg(test)]
mod xop_vpcmov;
#[cfg(test)]
mod xop_vpcom;
use crate::smir::ir::FunctionBuilder;
use crate::smir::ir::flags::{FlagSet, FlagUpdate, MaterializedFlags};
use crate::smir::ir::memory::{FlatMemory, SmirMemory};
use crate::smir::ir::types::ShiftOp;

fn exec_x86_rax_op(op: OpKind, rax_value: u64, rcx_value: u64, rflags: u64) -> (u64, u64) {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let mut ctx = SmirContext::new_x86_64();
    ctx.write_vreg(rax, rax_value);
    ctx.write_vreg(rcx, rcx_value);
    ctx.flags.materialized = MaterializedFlags::from_rflags(rflags);
    ctx.flags.lazy = None;

    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, op);
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let func = builder.finish();
    let block = &func.blocks[0];

    let exit = interp.execute_block(&mut ctx, &mut memory, block);
    assert!(matches!(exit, BlockResult::Exit(ExitReason::Halt)));
    ctx.flags.materialize_all();
    (ctx.read_vreg(rax), ctx.flags.materialized.to_rflags())
}

fn execute_lifted_x86(
    bytes: &[u8],
    ctx: &mut SmirContext,
    memory: &mut dyn SmirMemory,
) -> BlockResult {
    use crate::smir::ir::types::SourceArch;
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    let mut lifter = X86_64Lifter::strict();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    let result = lifter.lift_insn(0x1000, bytes, &mut lctx).unwrap();
    assert_eq!(result.bytes_consumed, bytes.len());

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let mut func = builder.finish();
    func.blocks[0].ops = result.ops;
    SmirInterpreter::new().execute_block(ctx, memory, &func.blocks[0])
}

fn execute_lifted_thumb(bytes: &[u8], ctx: &mut SmirContext) -> BlockResult {
    use crate::smir::ir::types::SourceArch;
    use crate::smir::lift::thumb::ThumbLifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    let mut lifter = ThumbLifter::new();
    let mut lctx = LiftContext::new(SourceArch::Thumb);
    let result = lifter.lift_insn(0x1000, bytes, &mut lctx).unwrap();
    assert_eq!(result.bytes_consumed, bytes.len());

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let mut func = builder.finish();
    func.blocks[0].ops = result.ops;
    SmirInterpreter::new().execute_block(ctx, &mut FlatMemory::new(0x1000), &func.blocks[0])
}

fn lifted_a32_block(raw: u32) -> SmirBlock {
    use crate::smir::ir::types::SourceArch;
    use crate::smir::lift::aarch32::Aarch32Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    let mut lifter = Aarch32Lifter::new();
    let mut lctx = LiftContext::new(SourceArch::Aarch32);
    let result = lifter
        .lift_insn(0x1000, &raw.to_le_bytes(), &mut lctx)
        .unwrap();
    assert_eq!(result.bytes_consumed, 4);

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let mut func = builder.finish();
    func.blocks[0].ops = result.ops;
    func.blocks.remove(0)
}

fn execute_lifted_x86_condition(
    bytes: &[u8],
    ctx: &mut SmirContext,
    memory: &mut dyn SmirMemory,
) -> bool {
    use crate::smir::ir::types::SourceArch;
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};

    let mut lifter = X86_64Lifter::strict();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    let result = lifter.lift_insn(0x1000, bytes, &mut lctx).unwrap();
    let condition = match result.control_flow {
        ControlFlow::CondBranchReg { cond, .. } => cond,
        other => panic!("expected register conditional branch, got {other:?}"),
    };
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let mut func = builder.finish();
    func.blocks[0].ops = result.ops;
    SmirInterpreter::new().execute_block(ctx, memory, &func.blocks[0]);
    ctx.read_vreg(condition) != 0
}

fn vec_from_bytes(bytes: &[u8]) -> VecValue {
    let mut value = [0u64; 16];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let mut lane = [0u8; 8];
        lane[..chunk.len()].copy_from_slice(chunk);
        value[idx] = u64::from_le_bytes(lane);
    }
    value
}

fn run_widenmul(
    v0: [u64; 16],
    v1: [u64; 16],
    src_elem: VecElementType,
    signed1: bool,
    signed2: bool,
) -> ([u64; 16], [u64; 16]) {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
        hex.set_v(0, v0);
        hex.set_v(1, v1);
    }
    let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::VWidenMul {
                dst_lo: mkv(2),
                dst_hi: mkv(3),
                src1: mkv(0),
                src2: mkv(1),
                src_elem,
                signed1,
                signed2,
                acc: false,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    match &ctx.arch_regs {
        ArchRegState::Hexagon(hex) => (hex.get_v(2), hex.get_v(3)),
        _ => panic!("not hexagon"),
    }
}

// Run a single VNarrowShiftSat (src_lo=V0, src_hi=V1, amount=R0) and return V2.
fn run_narrow_shift_sat(
    v0: [u64; 16],
    v1: [u64; 16],
    rt: u32,
    src_elem: VecElementType,
    arith: bool,
    round: bool,
    sat: u8,
) -> [u64; 16] {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
        hex.set_v(0, v0);
        hex.set_v(1, v1);
    }
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::R(0)), rt as u64);
    let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::VNarrowShiftSat {
                dst: mkv(2),
                src_lo: mkv(0),
                src_hi: mkv(1),
                src_elem,
                amount: SrcOperand::Reg(VReg::Arch(ArchReg::Hexagon(HexagonReg::R(0)))),
                arith,
                round,
                sat,
                set_ovf: false,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    match &ctx.arch_regs {
        ArchRegState::Hexagon(hex) => hex.get_v(2),
        _ => panic!("not hexagon"),
    }
}

fn run_widenext(
    v0: [u64; 16],
    src_elem: VecElementType,
    signed: bool,
    interleave: bool,
) -> ([u64; 16], [u64; 16]) {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
        hex.set_v(0, v0);
    }
    let mkv = |n| VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n)));
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::VWidenExt {
                dst_lo: mkv(2),
                dst_hi: mkv(3),
                src: mkv(0),
                src_elem,
                signed,
                interleave,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    match &ctx.arch_regs {
        ArchRegState::Hexagon(hex) => (hex.get_v(2), hex.get_v(3)),
        _ => panic!("not hexagon"),
    }
}

fn run_vec2(v0: [u64; 16], v1: [u64; 16], op: OpKind) -> [u64; 16] {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
        hex.set_v(0, v0);
        hex.set_v(1, v1);
    }
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: op,
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    match &ctx.arch_regs {
        ArchRegState::Hexagon(hex) => hex.get_v(2),
        _ => panic!("not hexagon"),
    }
}

// Run an op with V0=Vx(dst), V1=Vu, Q0 seeded; return V0 after.
fn run_lanecond(vx: [u64; 16], vu: [u64; 16], q: [u64; 16], op: OpKind) -> [u64; 16] {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
        hex.set_v(0, vx);
        hex.set_v(1, vu);
        hex.set_q(0, q);
    }
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: op,
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    match &ctx.arch_regs {
        ArchRegState::Hexagon(hex) => hex.get_v(0),
        _ => panic!("not hexagon"),
    }
}

// ---- BidirShift (Hexagon register-amount bidirectional shift) ----------

/// Reference (verbatim from `sem/shift.rs` `fBIDIR_*` for the 32-bit `4_8`
/// forms): widen the 32-bit source then shift in 64-bit, truncate to u32.
fn ref_bidir32(src: u32, shamt: i32, kind: u8) -> u32 {
    let r: u64 = match kind {
        0 => {
            // arithmetic left
            let s = src as i32 as i64;
            (if shamt < 0 {
                (s >> ((-shamt) - 1)) >> 1
            } else {
                s << shamt
            }) as u64
        }
        1 => {
            // arithmetic right
            let s = src as i32 as i64;
            (if shamt < 0 {
                (s << ((-shamt) - 1)) << 1
            } else {
                s >> shamt
            }) as u64
        }
        2 => {
            // logical left
            let u = src as u64;
            if shamt < 0 {
                (u >> ((-shamt) - 1)) >> 1
            } else {
                u << shamt
            }
        }
        _ => {
            // logical right
            let u = src as u64;
            if shamt < 0 {
                (u << ((-shamt) - 1)) << 1
            } else {
                u >> shamt
            }
        }
    };
    r as u32
}

/// Reference for the 64-bit `8_8` forms (no truncation).
fn ref_bidir64(src: u64, shamt: i32, kind: u8) -> u64 {
    match kind {
        0 => {
            let s = src as i64;
            (if shamt < 0 {
                (s >> ((-shamt) - 1)) >> 1
            } else {
                s << shamt
            }) as u64
        }
        1 => {
            let s = src as i64;
            (if shamt < 0 {
                (s << ((-shamt) - 1)) << 1
            } else {
                s >> shamt
            }) as u64
        }
        2 => {
            if shamt < 0 {
                (src >> ((-shamt) - 1)) >> 1
            } else {
                src << shamt
            }
        }
        _ => {
            if shamt < 0 {
                (src << ((-shamt) - 1)) << 1
            } else {
                src >> shamt
            }
        }
    }
}

fn run_bidir(src: u64, amount_rt: u32, kind: u8, width: OpWidth) -> u64 {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    // Hexagon R registers are 32-bit; for the W64 pair forms the lifter uses
    // a 64-bit Virtual temp, so mirror that here to round-trip the full value.
    let (rsrc, rdst) = match width {
        OpWidth::W64 => (VReg::virt(101), VReg::virt(100)),
        _ => (
            VReg::Arch(ArchReg::Hexagon(HexagonReg::R(1))),
            VReg::Arch(ArchReg::Hexagon(HexagonReg::R(0))),
        ),
    };
    let ramt = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(2)));
    ctx.write_vreg(rsrc, src);
    ctx.write_vreg(ramt, amount_rt as u64);
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::BidirShift {
                dst: rdst,
                src: SrcOperand::Reg(rsrc),
                amount: SrcOperand::Reg(ramt),
                kind,
                width,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    ctx.read_vreg(rdst)
}

/// Execute one `OpKind::SatN` over a W64-wide source value, returning the
/// 32-bit destination register and whether USR:OVF (bit 0) ended up set.
/// The source is fed via a W64 virtual temp (mirrors the lifter, which
/// composes an already-sign-extended value before SatN).
fn run_sat_n(src: i64, sat_bits: u8, signed: bool, set_ovf: bool) -> (u32, bool) {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::Usr), 0);
    let tmp = VReg::virt(0);
    let rd = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(0)));
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![
            SmirOp {
                id: OpId(0),
                guest_pc: 0x1000,
                kind: OpKind::Mov {
                    dst: tmp,
                    src: SrcOperand::Imm(src),
                    width: OpWidth::W64,
                },
                x86_hint: None,
            },
            SmirOp {
                id: OpId(1),
                guest_pc: 0x1004,
                kind: OpKind::SatN {
                    dst: rd,
                    src: SrcOperand::Reg(tmp),
                    sat_bits,
                    signed,
                    set_ovf,
                    width: OpWidth::W64,
                },
                x86_hint: None,
            },
        ],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    let rd_val = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::R(0))) as u32;
    let ovf = (ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::Usr)) & 1) != 0;
    (rd_val, ovf)
}

/// Execute one `OpKind::ClMul` and return (dst_lo, dst_hi). The `acc`
/// forms read the existing dst pair, so seed it via `init`.
fn run_clmul(a: u32, b: u32, elem_bits: u8, lanes: u8, acc: bool, init: (u32, u32)) -> (u32, u32) {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    let r0 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(0)));
    let r1 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(1)));
    let r2 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(2)));
    let r3 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(3)));
    ctx.write_vreg(r2, a as u64);
    ctx.write_vreg(r3, b as u64);
    ctx.write_vreg(r0, init.0 as u64);
    ctx.write_vreg(r1, init.1 as u64);
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::ClMul {
                dst: r0,
                dst_hi: Some(r1),
                src1: SrcOperand::Reg(r2),
                src2: SrcOperand::Reg(r3),
                elem_bits,
                lanes,
                acc,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    (
        ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::R(0))) as u32,
        ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::R(1))) as u32,
    )
}

fn run_clmul64(a: u64, b: u64, acc: bool, init: (u64, u64)) -> (u64, u64) {
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    let lo = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let hi = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
    let lhs = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let rhs = VReg::Arch(ArchReg::X86(X86Reg::R9));
    ctx.write_vreg(lhs, a);
    ctx.write_vreg(rhs, b);
    ctx.write_vreg(lo, init.0);
    ctx.write_vreg(hi, init.1);
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::ClMul {
                dst: lo,
                dst_hi: Some(hi),
                src1: SrcOperand::Reg(lhs),
                src2: SrcOperand::Reg(rhs),
                elem_bits: 64,
                lanes: 1,
                acc,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    (ctx.read_vreg(lo), ctx.read_vreg(hi))
}

fn run_crc32c(crc: u64, data: u64, data_width: OpWidth) -> u64 {
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    let dst = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let crc_reg = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let data_reg = VReg::Arch(ArchReg::X86(X86Reg::R9));
    ctx.write_vreg(crc_reg, crc);
    ctx.write_vreg(data_reg, data);
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::Crc32C {
                dst,
                crc: crc_reg,
                data: data_reg,
                data_width,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    ctx.read_vreg(dst)
}

/// Execute one `OpKind::CmpyW128Sat`, returning (dst, usr_ovf_set).
#[allow(clippy::too_many_arguments)]
fn run_wcmpy(rss: u64, rtt: u64, w: (u8, u8, u8, u8), add: bool, rnd: bool) -> (u32, bool) {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::Usr), 0);
    // Rss = r3:2, Rtt = r5:4, Rd = r0.
    let r2 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(2)));
    let r3 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(3)));
    let r4 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(4)));
    let r5 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(5)));
    ctx.write_vreg(r2, rss & 0xffff_ffff);
    ctx.write_vreg(r3, (rss >> 32) & 0xffff_ffff);
    ctx.write_vreg(r4, rtt & 0xffff_ffff);
    ctx.write_vreg(r5, (rtt >> 32) & 0xffff_ffff);
    let rd = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(0)));
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::CmpyW128Sat {
                dst: rd,
                rss_lo: r2,
                rss_hi: r3,
                rtt_lo: r4,
                rtt_hi: r5,
                w0: w.0,
                w1: w.1,
                w2: w.2,
                w3: w.3,
                add,
                rnd,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    (
        ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::R(0))) as u32,
        (ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::Usr)) & 1) != 0,
    )
}

/// Execute one `OpKind::SatOrigShl`, returning (dst, usr_ovf_set).
fn run_sat_orig_shl(src: u32, amount: i32, right: bool) -> (u32, bool) {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x1000);
    let interp = SmirInterpreter::new();
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::Usr), 0);
    let rd = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(0)));
    let rsrc = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(1)));
    let ramt = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(2)));
    ctx.write_vreg(rsrc, src as u64);
    // Encode the shift into the low 7 bits; upper bits must be ignored.
    ctx.write_vreg(ramt, ((amount as u32) & 0x7f) as u64 | 0x1234_5600);
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::SatOrigShl {
                dst: rd,
                src: SrcOperand::Reg(rsrc),
                amount: SrcOperand::Reg(ramt),
                right,
                width: OpWidth::W32,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    (
        ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::R(0))) as u32,
        (ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::Usr)) & 1) != 0,
    )
}

/// Verbatim reference port of sem/shift.rs sat_orig_shl + the asl/asr_r_r_sat
/// dispatch, used as the oracle for the SatOrigShl sweep.
fn ref_sat_orig_shl(src: u32, sh: i32, right: bool) -> (u32, bool) {
    fn sat(a: i64, orig: u32) -> (u32, bool) {
        let orig_s = orig as i32;
        // sat_n(a, 32) sets OVF on clamp.
        let (s, mut ovf) = if a < i32::MIN as i64 {
            (i32::MIN, true)
        } else if a > i32::MAX as i64 {
            (i32::MAX, true)
        } else {
            (a as i32, false)
        };
        if (s ^ orig_s) < 0 {
            ovf = true;
            ((if orig_s < 0 { i32::MIN } else { i32::MAX }) as u32, ovf)
        } else if orig_s > 0 && a == 0 {
            (i32::MAX as u32, true)
        } else {
            (s as u32, ovf)
        }
    }
    let orig = src as i32 as i64;
    if !right {
        if sh < 0 {
            ((((orig >> ((-sh) - 1)) >> 1) as i64) as u32, false)
        } else {
            sat(orig << sh, src)
        }
    } else if sh < 0 {
        sat((orig << ((-sh) - 1)) << 1, src)
    } else {
        ((orig >> sh) as u32, false)
    }
}

// ------------------------------------------------------------------------
// PredLoad / PredStore: conditional-commit memory ops (Hexagon predicated
// loads/stores). BOTH branches are exercised: cond bit0 set -> commit;
// cond bit0 clear -> dst / memory UNCHANGED (and no fault).
// ------------------------------------------------------------------------

/// Run a single PredLoad reading word at addr `ea` into R1, with P0 = `p0`.
/// R1 is pre-seeded with `seed`; returns the resulting R1.
fn run_pred_load(ea: u64, mem_word: u32, p0: u8, seed: u32) -> u32 {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x10000);
    let interp = SmirInterpreter::new();
    memory.write(ea, &mem_word.to_le_bytes()).unwrap();
    let r2 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(2)));
    let r1 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(1)));
    let p0v = VReg::Arch(ArchReg::Hexagon(HexagonReg::P(0)));
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::R(2)), ea);
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::R(1)), seed as u64);
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::P(0)), p0 as u64);
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::PredLoad {
                dst: r1,
                cond: p0v,
                addr: Address::Direct(r2),
                width: MemWidth::B4,
                signed: SignExtend::Zero,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    ctx.read_vreg(r1) as u32
}

/// Run a single PredStore writing R1=`val` to word at addr `ea`, with
/// P0 = `p0`. Memory at `ea` is pre-seeded with `seed`; returns the word
/// in memory afterwards.
fn run_pred_store(ea: u64, val: u32, p0: u8, seed: u32) -> u32 {
    let mut ctx = SmirContext::new_hexagon();
    let mut memory = FlatMemory::new(0x10000);
    let interp = SmirInterpreter::new();
    memory.write(ea, &seed.to_le_bytes()).unwrap();
    let r2 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(2)));
    let r1 = VReg::Arch(ArchReg::Hexagon(HexagonReg::R(1)));
    let p0v = VReg::Arch(ArchReg::Hexagon(HexagonReg::P(0)));
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::R(2)), ea);
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::R(1)), val as u64);
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::P(0)), p0 as u64);
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: 0x1000,
        phis: vec![],
        ops: vec![SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::PredStore {
                src: SrcOperand::Reg(r1),
                cond: p0v,
                addr: Address::Direct(r2),
                width: MemWidth::B4,
            },
            x86_hint: None,
        }],
        terminator: Terminator::Trap {
            kind: TrapKind::Halt,
        },
        exec_count: 0,
    };
    interp.execute_block(&mut ctx, &mut memory, &block);
    let mut buf = [0u8; 4];
    memory.read(ea, &mut buf).unwrap();
    u32::from_le_bytes(buf)
}

// Regression for issue #21: a 32-bit CMPXCHG must not clear the upper 32 bits
// of a register on its no-op path (a successful compare leaves RAX unchanged;
// a failed compare leaves the destination unchanged). Lifts a real CMPXCHG and
// runs the emitted ops through the interpreter.
fn run_cmpxchg32(rax: u64, rcx: u64, rdx: u64) -> (u64, u64) {
    use crate::smir::ir::types::SourceArch;
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    // CMPXCHG ECX, EDX (0F B1 D1): compare EAX with r/m=ECX; source = EDX.
    let bytes = [0x0F, 0xB1, 0xD1];
    let mut lifter = X86_64Lifter::new();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    let result = lifter.lift_insn(0x1000, &bytes, &mut lctx).unwrap();

    let rax_r = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx_r = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rdx_r = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
    let mut ctx = SmirContext::new_x86_64();
    ctx.write_vreg(rax_r, rax);
    ctx.write_vreg(rcx_r, rcx);
    ctx.write_vreg(rdx_r, rdx);

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    for op in result.ops {
        builder.push_op(op.guest_pc, op.kind);
    }
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let func = builder.finish();

    let interp = SmirInterpreter::new();
    let mut memory = FlatMemory::new(0x1000);
    interp.execute_block(&mut ctx, &mut memory, &func.blocks[0]);

    (ctx.read_vreg(rax_r), ctx.read_vreg(rcx_r))
}

fn rv_vector_test_state(x10_src: VReg) -> RvVectorState {
    RvVectorState {
        x_srcs: std::array::from_fn(|i| {
            if i == 0 {
                VReg::Imm(0)
            } else if i == 10 {
                x10_src
            } else {
                VReg::Arch(ArchReg::RiscV(RiscVReg::X(i as u8)))
            }
        }),
        x_dsts: std::array::from_fn(|i| {
            if i == 0 {
                VReg::Imm(0)
            } else {
                VReg::Arch(ArchReg::RiscV(RiscVReg::X(i as u8)))
            }
        }),
        f_srcs: std::array::from_fn(|i| VReg::Arch(ArchReg::RiscV(RiscVReg::F(i as u8)))),
        f_dsts: std::array::from_fn(|i| VReg::Arch(ArchReg::RiscV(RiscVReg::F(i as u8)))),
        fcsr_src: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x003))),
        fcsr_dst: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x003))),
        vl_src: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0xc20))),
        vl_dst: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0xc20))),
        vtype_src: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0xc21))),
        vtype_dst: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0xc21))),
        vstart_src: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x008))),
        vstart_dst: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x008))),
        vcsr_src: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x00f))),
        vcsr_dst: VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x00f))),
    }
}

// Regression for issue #23: a non-LOCK memory XADD must be fault-precise. The
// lift emits Load → (flag-free) Add → Store → source writeback → flag-only Add,
// so a store that faults (e.g. a read-only page) leaves BOTH the arithmetic
// flags and the source register architecturally unchanged. Before the fix the
// flag-producing Add ran before the Store, committing flags that a faulting
// XADD must never produce.

/// Test memory that serves reads from an inner `FlatMemory` and faults a
/// configured store with a write page fault. A value of zero models a
/// read-only page; positive values permit that many stores to retire first.
struct StoreFaultMemory {
    inner: FlatMemory,
    stores_before_fault: usize,
}

impl SmirMemory for StoreFaultMemory {
    fn read(&mut self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        self.inner.read(addr, buf)
    }
    fn write(&mut self, addr: GuestAddr, data: &[u8]) -> Result<(), MemoryError> {
        if self.stores_before_fault != 0 {
            self.stores_before_fault -= 1;
            return self.inner.write(addr, data);
        }
        Err(MemoryError::PageFault {
            addr,
            write: true,
            user: true,
        })
    }
    fn atomic_load(
        &mut self,
        addr: GuestAddr,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        self.inner.atomic_load(addr, size, order)
    }
    fn atomic_store(
        &mut self,
        addr: GuestAddr,
        value: u64,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<(), MemoryError> {
        self.inner.atomic_store(addr, value, size, order)
    }
    fn compare_and_swap(
        &mut self,
        addr: GuestAddr,
        expected: u64,
        new: u64,
        size: MemWidth,
        success_order: MemoryOrder,
        failure_order: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError> {
        self.inner
            .compare_and_swap(addr, expected, new, size, success_order, failure_order)
    }
    fn compare_and_swap_writeback(
        &mut self,
        addr: GuestAddr,
        expected: u64,
        new: u64,
        size: MemWidth,
        _success_order: MemoryOrder,
        failure_order: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError> {
        let old = self.inner.atomic_load(addr, size, failure_order)?;
        let mask = match size {
            MemWidth::B1 => 0xFF,
            MemWidth::B2 => 0xFFFF,
            MemWidth::B4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        };
        let success = old & mask == expected & mask;
        self.write(
            addr,
            &(if success { new } else { old }).to_le_bytes()[..size.bytes() as usize],
        )?;
        Ok((old, success))
    }
    fn atomic_rmw(
        &mut self,
        addr: GuestAddr,
        op: AtomicOp,
        operand: u64,
        size: MemWidth,
        order: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        if self.stores_before_fault == 0 {
            return Err(MemoryError::PageFault {
                addr,
                write: true,
                user: true,
            });
        }
        self.stores_before_fault -= 1;
        self.inner.atomic_rmw(addr, op, operand, size, order)
    }
    fn load_exclusive(&mut self, addr: GuestAddr, size: MemWidth) -> Result<u64, MemoryError> {
        self.inner.load_exclusive(addr, size)
    }
    fn store_exclusive(
        &mut self,
        addr: GuestAddr,
        value: u64,
        size: MemWidth,
    ) -> Result<bool, MemoryError> {
        self.inner.store_exclusive(addr, value, size)
    }
    fn clear_exclusive(&mut self) {
        self.inner.clear_exclusive()
    }
    fn fence(&mut self, kind: FenceKind) {
        self.inner.fence(kind)
    }
    fn probe(&self, addr: GuestAddr, size: usize, write: bool) -> Result<(), MemoryError> {
        self.inner.probe(addr, size, write)
    }
}

/// Lift `xadd dword ptr [rax], ecx` (0F C1 08) and run it through the
/// interpreter over `memory`, with `rax` pointing at `addr`, `ecx = src`, and
/// the flags pre-seeded from `init_rflags`. Returns the resulting RCX, the
/// block exit, and the materialized RFLAGS.
fn run_xadd_mem32(
    addr: u64,
    src: u32,
    init_rflags: u64,
    memory: &mut dyn SmirMemory,
) -> (u64, BlockResult, u64) {
    use crate::smir::ir::types::SourceArch;
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    // xadd dword ptr [rax], ecx: DEST = [rax] (memory), SRC = ecx.
    let bytes = [0x0F, 0xC1, 0x08];
    let mut lifter = X86_64Lifter::new();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    let result = lifter.lift_insn(0x1000, &bytes, &mut lctx).unwrap();

    let rax_r = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx_r = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let mut ctx = SmirContext::new_x86_64();
    ctx.write_vreg(rax_r, addr);
    ctx.write_vreg(rcx_r, src as u64);
    ctx.flags.materialized = MaterializedFlags::from_rflags(init_rflags);
    ctx.flags.lazy = None;

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    for op in result.ops {
        builder.push_op(op.guest_pc, op.kind);
    }
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let func = builder.finish();

    let interp = SmirInterpreter::new();
    let exit = interp.execute_block(&mut ctx, memory, &func.blocks[0]);
    ctx.flags.materialize_all();
    (
        ctx.read_vreg(rcx_r),
        exit,
        ctx.flags.materialized.to_rflags(),
    )
}
