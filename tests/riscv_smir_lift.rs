//! RISC-V -> SMIR lift verification harness.
//!
//! For each instruction we lift the RISC-V machine word to SMIR ops, execute
//! them on the `SmirInterpreter` from a seeded register state, and compare the
//! resulting x/f/fcsr state against rax's RISC-V interpreter (`RiscVCpu`, itself
//! differentially verified against `qemu-riscv64` at 0 divergence). A match
//! proves the lift is semantically correct for that op; an instruction whose
//! lift returns `Unsupported`/`InvalidEncoding` is reported as an (unimplemented)
//! lift gap, not a divergence.
//!
//! Needs no external toolchain — `RiscVCpu` is the golden oracle and encodings
//! are generated directly. The test FAILS on any divergence and prints a
//! per-`Op` breakdown of remaining lift gaps.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use rax::riscv::{decode, FlatMemory as RvMem, Isa, Op, RiscVConfig, RiscVCpu, RiscVExit, Xlen};
use rax::smir::types::{ArchReg, BlockId, OpId, RiscVReg, SourceArch};
use rax::smir::{
    ArchRegState, FlatMemory as SmirMem, LiftContext, LiftError, RiscVLifter, SmirBlock,
    SmirContext, SmirInterpreter, SmirLifter, Terminator, TrapKind,
};

const CODE_ADDR: u64 = 0x1000;
const SCRATCH: u64 = 0x4000; // base for memory operands
const MEM_SIZE: u64 = 0x10000;

#[derive(Clone, Copy)]
struct State {
    x: [u64; 32],
    f: [u64; 32],
    fcsr: u32,
    scratch: [u64; 64], // 512-byte shared data window at SCRATCH
}

impl State {
    fn eq_regs(&self, o: &State) -> Option<String> {
        for i in 1..32 {
            if self.x[i] != o.x[i] {
                return Some(format!("x{i}: ref={:#x} smir={:#x}", self.x[i], o.x[i]));
            }
        }
        for i in 0..32 {
            if self.f[i] != o.f[i] {
                return Some(format!("f{i}: ref={:#x} smir={:#x}", self.f[i], o.f[i]));
            }
        }
        if self.fcsr != o.fcsr {
            return Some(format!("fcsr: ref={:#x} smir={:#x}", self.fcsr, o.fcsr));
        }
        for i in 0..64 {
            if self.scratch[i] != o.scratch[i] {
                return Some(format!(
                    "scratch[{i}]: ref={:#x} smir={:#x}",
                    self.scratch[i], o.scratch[i]
                ));
            }
        }
        None
    }
}

struct Rng(u64);
impl Rng {
    fn new(s: u64) -> Self {
        Rng(s)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn rand_state(rng: &mut Rng) -> State {
    let mut s = State {
        x: [0; 32],
        f: [0; 32],
        fcsr: 0,
        scratch: [0; 64],
    };
    for i in 1..32 {
        s.x[i] = rng.next();
    }
    for i in 0..32 {
        // NaN-box low values sometimes; raw otherwise.
        s.f[i] = rng.next();
    }
    s.fcsr = (rng.next() & 0xff) as u32; // frm[7:5] + fflags[4:0]
    for i in 0..64 {
        s.scratch[i] = rng.next();
    }
    s
}

/// Run one instruction on the golden `RiscVCpu`; `None` if it traps.
fn run_ref(insn: &[u8], init: &State) -> Option<State> {
    let mem = RvMem::new(0, MEM_SIZE as usize);
    let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(mem));
    for i in 1..32u8 {
        cpu.set_x(i, init.x[i as usize]);
    }
    for i in 0..32u8 {
        cpu.set_f(i, init.f[i as usize]);
    }
    cpu.set_fcsr(init.fcsr);
    // scratch
    let mut sb = Vec::with_capacity(512);
    for w in init.scratch.iter() {
        sb.extend_from_slice(&w.to_le_bytes());
    }
    cpu.write_memory(SCRATCH, &sb).ok()?;
    cpu.write_memory(CODE_ADDR, insn).ok()?;
    cpu.set_pc(CODE_ADDR);
    match cpu.step() {
        RiscVExit::Continue => {}
        _ => return None,
    }
    let mut out = State {
        x: [0; 32],
        f: [0; 32],
        fcsr: 0,
        scratch: [0; 64],
    };
    for i in 1..32u8 {
        out.x[i as usize] = cpu.x(i);
    }
    for i in 0..32u8 {
        out.f[i as usize] = cpu.f(i);
    }
    out.fcsr = cpu.fcsr();
    for (i, w) in out.scratch.iter_mut().enumerate() {
        *w = cpu.mem_read_u64(SCRATCH + (i as u64) * 8).ok()?;
    }
    Some(out)
}

/// Lift the instruction to SMIR and run it. `Ok(None)` => lift gap.
fn run_smir(insn: &[u8], init: &State) -> Result<Option<State>, String> {
    let mut lifter = RiscVLifter::rv64gc();
    let mut lctx = LiftContext::new(SourceArch::RiscV64);
    let res = match lifter.lift_insn(CODE_ADDR, insn, &mut lctx) {
        Ok(r) => r,
        Err(LiftError::Unsupported { .. }) | Err(LiftError::InvalidEncoding { .. }) => {
            return Ok(None)
        }
        Err(e) => return Err(format!("lift error: {e:?}")),
    };
    let mut ops = res.ops;
    for (i, op) in ops.iter_mut().enumerate() {
        op.id = OpId(i as u16);
    }
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: CODE_ADDR,
        phis: vec![],
        ops,
        terminator: Terminator::Trap {
            kind: TrapKind::Breakpoint,
        },
        exec_count: 0,
    };
    let mut ctx = SmirContext::new_riscv();
    if let ArchRegState::RiscV(rv) = &mut ctx.arch_regs {
        rv.x[1..32].copy_from_slice(&init.x[1..32]);
        rv.f.copy_from_slice(&init.f);
        rv.fcsr = init.fcsr;
        rv.pc = CODE_ADDR;
    }
    let _ = ArchReg::RiscV(RiscVReg::X(0)); // keep import used
    ctx.pc = CODE_ADDR;

    let mut mem = SmirMem::with_base(0, MEM_SIZE as usize);
    let mut sb = Vec::with_capacity(512);
    for w in init.scratch.iter() {
        sb.extend_from_slice(&w.to_le_bytes());
    }
    use rax::smir::SmirMemory;
    mem.write(SCRATCH, &sb).map_err(|e| format!("mem seed: {e:?}"))?;

    let interp = SmirInterpreter::new();
    interp.execute_block(&mut ctx, &mut mem, &block);

    let mut out = State {
        x: [0; 32],
        f: [0; 32],
        fcsr: 0,
        scratch: [0; 64],
    };
    // The lifter writes results to SSA virtual regs; resolve each arch reg's
    // final value through the lifter's arch->vreg mapping (an undefined reg maps
    // back to VReg::Arch, which reads the seeded arch_regs unchanged).
    for n in 0..32u8 {
        out.x[n as usize] =
            ctx.read_vreg(lctx.get_arch_reg(ArchReg::RiscV(RiscVReg::X(n))));
        out.f[n as usize] =
            ctx.read_vreg(lctx.get_arch_reg(ArchReg::RiscV(RiscVReg::F(n))));
    }
    out.x[0] = 0;
    // fcsr: resolve via the CSR mapping if the lift wrote it, else seeded value.
    let fcsr_vreg = lctx.get_arch_reg(ArchReg::RiscV(RiscVReg::Csr(0x003)));
    out.fcsr = match fcsr_vreg {
        rax::smir::types::VReg::Arch(_) => {
            if let ArchRegState::RiscV(rv) = &ctx.arch_regs {
                rv.fcsr
            } else {
                0
            }
        }
        _ => ctx.read_vreg(fcsr_vreg) as u32,
    };
    for i in 0..64u64 {
        let mut b = [0u8; 8];
        mem.read(SCRATCH + i * 8, &mut b)
            .map_err(|e| format!("mem read: {e:?}"))?;
        out.scratch[i as usize] = u64::from_le_bytes(b);
    }
    Ok(Some(out))
}

/// Tally outcomes over a stream of random words for the given opcodes.
fn sweep(seed: u64, opcodes: &[u32], count: usize) {
    let mut rng = Rng::new(seed);
    let isa = Isa::rv64gc();
    let mut matched = 0usize;
    let mut gaps: BTreeMap<String, usize> = BTreeMap::new();
    let mut diverged: Vec<(u32, String)> = Vec::new();
    let mut tried = 0usize;
    while tried < count {
        let opc = opcodes[(rng.next() as usize) % opcodes.len()];
        let w = (rng.next() as u32 & !0x7f) | opc;
        let insn = decode(w, Xlen::Rv64, &isa);
        if insn.is_illegal() {
            continue;
        }
        // Skip control-flow / system / fence — not single-step register compares.
        if matches!(
            insn.op,
            Op::Jal | Op::Jalr | Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu
                | Op::Ecall | Op::Ebreak | Op::Fence | Op::FenceI | Op::Mret | Op::Sret | Op::Wfi
        ) {
            continue;
        }
        tried += 1;
        // For memory ops, force the base register to point into scratch.
        let (w, base_reg) = retarget_mem(w, &insn.op);
        let mut st = rand_state(&mut rng);
        if let Some(rs1) = base_reg {
            st.x[rs1 as usize] = SCRATCH + 0x40; // mid-window, room either side
        }
        let bytes = w.to_le_bytes();
        let r = match run_ref(&bytes, &st) {
            Some(r) => r,
            None => continue, // ref trapped (e.g. unaligned/odd encoding); skip
        };
        match run_smir(&bytes, &st) {
            Ok(Some(s)) => {
                if let Some(d) = r.eq_regs(&s) {
                    if diverged.len() < 40 {
                        diverged.push((w, format!("{:?}: {d}", insn.op)));
                    }
                } else {
                    matched += 1;
                }
            }
            Ok(None) => *gaps.entry(format!("{:?}", insn.op)).or_default() += 1,
            Err(e) => diverged.push((w, format!("{:?}: {e}", insn.op))),
        }
    }
    eprintln!(
        "sweep(seed={seed:#x}): matched={matched}, gap-ops={}, diverged={}",
        gaps.len(),
        diverged.len()
    );
    let mut gv: Vec<_> = gaps.iter().collect();
    gv.sort_by(|a, b| b.1.cmp(a.1));
    for (op, n) in gv.iter().take(60) {
        eprintln!("  GAP {op}: {n}");
    }
    if !diverged.is_empty() {
        let mut msg = format!("\n{} lift divergence(s) from RiscVCpu:\n", diverged.len());
        for (w, d) in diverged.iter().take(40) {
            msg += &format!("  insn={w:#010x}: {d}\n");
        }
        panic!("{msg}");
    }
}

/// If the instruction reads memory, rewrite rs1 to a fixed base register and
/// report it so the harness can point it into the scratch window. Also clamp
/// the immediate offset small so the access stays in-window.
fn retarget_mem(w: u32, insn: &Op) -> (u32, Option<u32>) {
    let _ = insn;
    let opc = w & 0x7f;
    match opc {
        0x03 | 0x07 => {
            // I-type load: rs1 = bits[19:15]; clamp imm[31:20] to a small value.
            let w = (w & !(0xfff << 20)) | (8u32 << 20);
            let w = (w & !(0x1f << 15)) | (10 << 15);
            (w, Some(10))
        }
        0x23 | 0x27 => {
            // S-type store: imm split; set both halves small, rs1 = x10.
            let mut w = w & !((0x7f << 25) | (0x1f << 7));
            w |= 8 << 7; // imm[4:0] = 8
            let w = (w & !(0x1f << 15)) | (10 << 15);
            (w, Some(10))
        }
        0x2f => {
            // AMO: address = x[rs1]; set rs1 = x10 (aligned base).
            let w = (w & !(0x1f << 15)) | (10 << 15);
            (w, Some(10))
        }
        _ => (w, None),
    }
}

#[test]
fn lift_op_imm() {
    // OP-IMM (0x13), OP-IMM-32 (0x1b), LUI (0x37), AUIPC (0x17)
    sweep(0x5117_0001, &[0x13, 0x1b, 0x37, 0x17], 40_000);
}

#[test]
fn lift_op() {
    // OP (0x33), OP-32 (0x3b)
    sweep(0x5117_0002, &[0x33, 0x3b], 40_000);
}

#[test]
fn lift_mem() {
    // loads (0x03), stores (0x23), AMO (0x2f)
    sweep(0x5117_0003, &[0x03, 0x23, 0x2f], 40_000);
}

#[test]
fn lift_fp() {
    // FP load/store/op/fma (0x07, 0x27, 0x53, 0x43, 0x47, 0x4b, 0x4f)
    sweep(0x5117_0004, &[0x07, 0x27, 0x53, 0x43, 0x47, 0x4b, 0x4f], 60_000);
}
