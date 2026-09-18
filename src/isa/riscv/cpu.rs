//! RISC-V hart state and the decode/execute interpreter loop.
//!
//! [`RiscVCpu`] owns the architectural register files, CSRs and PC, and a
//! [`Memory`] backing store. [`step`](RiscVCpu::step) fetches, decodes and
//! executes exactly one instruction, returning a [`RiscVExit`] describing how
//! control left the instruction (normal retire, environment call, breakpoint,
//! wait-for-interrupt, or a synchronous trap).

use std::collections::HashMap;

use super::crypto;
use super::csr::Csr;
use super::decode::{DecodeError, Insn, Op, decode_at};
use super::float::RoundingMode;
use super::memory::{MemError, Memory};
use super::{Isa, Xlen};

mod csr_ops;
mod execution;
mod fp_moves;
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod jit;
mod vector_config;
mod vector_conversion;
mod vector_mask;
mod vector_memory;
mod vector_permute;
mod vector_validation;

/// Privilege level of the hart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priv {
    /// User mode.
    User = 0,
    /// Supervisor mode.
    Supervisor = 1,
    /// Machine mode.
    Machine = 3,
}

/// Application vector length source for `vsetvl*`.
enum Avl {
    /// `rs1 == x0 && rd == x0`: keep the current `vl`.
    Keep,
    /// `rs1 == x0 && rd != x0`: set `vl` to `VLMAX`.
    Max,
    /// AVL from a register or immediate.
    Reg(u64),
}

/// Standard RISC-V trap cause codes.
pub mod cause {
    /// Instruction address misaligned.
    pub const INSTR_MISALIGNED: u64 = 0;
    /// Instruction access fault.
    pub const INSTR_ACCESS_FAULT: u64 = 1;
    /// Illegal instruction.
    pub const ILLEGAL_INSTR: u64 = 2;
    /// Breakpoint.
    pub const BREAKPOINT: u64 = 3;
    /// Load address misaligned.
    pub const LOAD_MISALIGNED: u64 = 4;
    /// Load access fault.
    pub const LOAD_ACCESS_FAULT: u64 = 5;
    /// Store/AMO address misaligned.
    pub const STORE_MISALIGNED: u64 = 6;
    /// Store/AMO access fault.
    pub const STORE_ACCESS_FAULT: u64 = 7;
    /// Environment call from U-mode.
    pub const ECALL_U: u64 = 8;
    /// Environment call from S-mode.
    pub const ECALL_S: u64 = 9;
    /// Environment call from M-mode.
    pub const ECALL_M: u64 = 11;
    /// Machine software interrupt.
    pub const INT_M_SOFTWARE: u64 = 3;
    /// Machine timer interrupt.
    pub const INT_M_TIMER: u64 = 7;
    /// Machine external interrupt.
    pub const INT_M_EXTERNAL: u64 = 11;
    /// Supervisor software interrupt.
    pub const INT_S_SOFTWARE: u64 = 1;
    /// Supervisor timer interrupt.
    pub const INT_S_TIMER: u64 = 5;
    /// Supervisor external interrupt.
    pub const INT_S_EXTERNAL: u64 = 9;
}

/// A trap raised while executing an instruction or accepting an interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trap {
    /// Cause code (see [`cause`]).
    pub cause: u64,
    /// Trap value (`mtval`): faulting address or instruction bits.
    pub tval: u64,
}

impl Trap {
    /// Illegal instruction carrying the offending encoding in `tval`.
    pub fn illegal(raw: u32) -> Self {
        Trap {
            cause: cause::ILLEGAL_INSTR,
            tval: raw as u64,
        }
    }
}

/// How control left an executed instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiscVExit {
    /// Instruction retired normally; continue execution.
    Continue,
    /// `ECALL` executed; the embedder services the environment call.
    Ecall,
    /// `EBREAK` executed.
    Ebreak,
    /// `WFI` executed (treated as a hint).
    Wfi,
    /// A trap was raised and delivered to the trap vector.
    Trap(Trap),
}

/// Configuration of a [`RiscVCpu`].
#[derive(Clone, Copy, Debug)]
pub struct RiscVConfig {
    /// Register width.
    pub xlen: Xlen,
    /// Enabled extensions.
    pub isa: Isa,
}

impl Default for RiscVConfig {
    fn default() -> Self {
        RiscVConfig {
            xlen: Xlen::Rv64,
            isa: Isa::rv64gc(),
        }
    }
}

impl RiscVConfig {
    /// Standard RV64GC configuration.
    pub fn rv64gc() -> Self {
        RiscVConfig::default()
    }

    /// RV32 with the given ISA.
    pub fn rv32(isa: Isa) -> Self {
        RiscVConfig {
            xlen: Xlen::Rv32,
            isa,
        }
    }
}

/// Observable counters for the opt-in host-native RISC-V SMIR execution path.
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiscVJitStats {
    /// Compiled and interpreter-only entries currently retained in the cache.
    pub cache_entries: usize,
    /// Cache lookups that reused an existing decision or native block.
    pub cache_hits: u64,
    /// Cache lookups that required a new native-admission decision.
    pub cache_misses: u64,
    /// Successfully entered native blocks, including blocks that faulted.
    pub native_executions: u64,
    /// Instructions executed by the interpreter because the JIT boundary did
    /// not admit them or because native execution requested a safe replay.
    pub interpreter_fallbacks: u64,
}

/// A single RISC-V hart.
pub struct RiscVCpu {
    cfg: RiscVConfig,
    /// Integer registers `x0..x31` (`x0` is hardwired zero).
    x: [u64; 32],
    /// Floating-point registers `f0..f31` (raw bits, NaN-boxed for single).
    f: [u64; 32],
    /// Program counter.
    pc: u64,
    /// Floating-point control/status (`frm` in [7:5], `fflags` in [4:0]).
    fcsr: u32,
    /// Current privilege level.
    priv_: Priv,
    /// LR/SC reservation address (single-hart model).
    reservation: Option<u64>,

    // ---- machine-mode trap CSRs (subset) ----
    mstatus: u64,
    mtvec: u64,
    mepc: u64,
    sepc: u64,
    mcause: u64,
    mtval: u64,
    mscratch: u64,
    mie: u64,
    mip: u64,
    medeleg: u64,
    mideleg: u64,
    mcounteren: u64,
    scounteren: u64,
    mhartid: u64,
    jvt: u64,

    // ---- counters ----
    cycle: u64,
    time: u64,
    instret: u64,

    // ---- vector state (V extension) ----
    vl: u64,
    vtype: u64,
    vstart: u64,
    vxrm: u64,
    vxsat: u64,
    /// Vector register file: 32 registers of VLEN bits, stored as a flat byte
    /// array (register `r` element-byte `b` at `v[r*VLENB + b]`), so LMUL groups
    /// and element strides index naturally.
    v: [u8; 32 * VLENB as usize],

    /// Permissive store-only scratch for vendor / not-yet-modeled CSRs
    /// (Xsoteria `mgpscratch0..15`/`mnmivec`, PMP `pmpcfg`/`pmpaddr`,
    /// `mcountinhibit`, …). Only consulted when `isa.xsoteria` is set, so the
    /// strict RV64GC differential-oracle path is unaffected.
    ext_csr: HashMap<u16, u64>,

    /// Guest memory.
    mem: Box<dyn Memory>,

    /// Opt-in SMIR JIT cache for single-step blocks and bounded run regions. The
    /// ordinary [`step`](Self::step) and [`run`](Self::run) paths never consult it.
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    jit: jit::RiscVJitCache,
}

/// Vector register length in bits (matches the qemu-riscv64 default).
const VLEN: u64 = 128;
/// Vector register length in bytes.
const VLENB: u64 = VLEN / 8;
const SSTATUS_BASE_MASK: u64 = (1 << 1) // SIE
    | (1 << 5) // SPIE
    | (1 << 6) // UBE
    | (1 << 8) // SPP
    | (0b11 << 9) // VS
    | (0b11 << 13) // FS
    | (0b11 << 15) // XS
    | (1 << 18) // SUM
    | (1 << 19); // MXR
const S_INTERRUPT_MASK: u64 =
    (1 << cause::INT_S_SOFTWARE) | (1 << cause::INT_S_TIMER) | (1 << cause::INT_S_EXTERNAL);
const MSTATUS_MIE: u64 = 1 << 3;
const MIP_MSIP: u64 = 1 << cause::INT_M_SOFTWARE;
const MIP_MTIP: u64 = 1 << cause::INT_M_TIMER;
const MIP_MEIP: u64 = 1 << cause::INT_M_EXTERNAL;
const M_INTERRUPT_MASK: u64 = MIP_MSIP | MIP_MTIP | MIP_MEIP;
const IMPLEMENTED_INTERRUPT_MASK: u64 = M_INTERRUPT_MASK | S_INTERRUPT_MASK;
const DELEGATABLE_EXCEPTION_MASK: u64 = (1 << cause::INSTR_MISALIGNED)
    | (1 << cause::INSTR_ACCESS_FAULT)
    | (1 << cause::ILLEGAL_INSTR)
    | (1 << cause::BREAKPOINT)
    | (1 << cause::LOAD_MISALIGNED)
    | (1 << cause::LOAD_ACCESS_FAULT)
    | (1 << cause::STORE_MISALIGNED)
    | (1 << cause::STORE_ACCESS_FAULT)
    | (1 << cause::ECALL_U)
    | (1 << cause::ECALL_S)
    | (1 << 12) // instruction page fault
    | (1 << 13) // load page fault
    | (1 << 15); // store/AMO page fault

impl RiscVCpu {
    /// Create a hart with the given configuration and memory.
    pub fn new(cfg: RiscVConfig, mem: Box<dyn Memory>) -> Self {
        RiscVCpu {
            cfg,
            x: [0; 32],
            f: [0; 32],
            pc: 0,
            fcsr: 0,
            priv_: Priv::Machine,
            reservation: None,
            mstatus: 0,
            mtvec: 0,
            mepc: 0,
            sepc: 0,
            mcause: 0,
            mtval: 0,
            mscratch: 0,
            mie: 0,
            mip: 0,
            medeleg: 0,
            mideleg: 0,
            mcounteren: 0,
            scounteren: 0,
            mhartid: 0,
            jvt: 0,
            cycle: 0,
            time: 0,
            instret: 0,
            vl: 0,
            vtype: 0,
            vstart: 0,
            vxrm: 0,
            vxsat: 0,
            v: [0; 32 * VLENB as usize],
            ext_csr: HashMap::new(),
            mem,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit: jit::RiscVJitCache::default(),
        }
    }

    /// Warm-reset architectural state to power-on values and jump to `entry`,
    /// keeping the configuration and guest memory (and thus MMIO-backed device
    /// state) intact. Models a self-triggered SoC reset for embedded firmware
    /// that reboots itself as part of its boot sequence. Counters are preserved
    /// for diagnostics.
    pub fn reset(&mut self, entry: u64) {
        self.x = [0; 32];
        self.f = [0; 32];
        self.pc = entry;
        self.fcsr = 0;
        self.priv_ = Priv::Machine;
        self.reservation = None;
        self.mstatus = 0;
        self.mtvec = 0;
        self.mepc = 0;
        self.sepc = 0;
        self.mcause = 0;
        self.mtval = 0;
        self.mscratch = 0;
        self.mie = 0;
        self.mip = 0;
        self.medeleg = 0;
        self.mideleg = 0;
        self.mcounteren = 0;
        self.scounteren = 0;
        self.jvt = 0;
        self.vl = 0;
        self.vtype = 0;
        self.vstart = 0;
        self.vxrm = 0;
        self.vxsat = 0;
        self.v = [0; 32 * VLENB as usize];
        self.ext_csr.clear();
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        self.jit.clear();
    }

    /// Read the raw 16-byte contents of vector register `i`.
    pub fn vreg(&self, i: u8) -> [u8; VLENB as usize] {
        let base = (i as usize & 31) * VLENB as usize;
        let mut out = [0u8; VLENB as usize];
        out.copy_from_slice(&self.v[base..base + VLENB as usize]);
        out
    }

    /// Write the raw 16-byte contents of vector register `i`.
    pub fn set_vreg(&mut self, i: u8, val: &[u8; VLENB as usize]) {
        let base = (i as usize & 31) * VLENB as usize;
        self.v[base..base + VLENB as usize].copy_from_slice(val);
    }

    /// Current `vl` / `vtype` (for the vector execution path and tests).
    pub fn vl(&self) -> u64 {
        self.vl
    }
    pub fn vtype(&self) -> u64 {
        self.vtype
    }
    pub fn set_vl_vtype(&mut self, vl: u64, vtype: u64) {
        self.vl = vl;
        self.vtype = vtype;
    }

    /// Read `vcsr` = {vxrm[2:1], vxsat[0]}.
    #[inline]
    pub fn vcsr(&self) -> u64 {
        (self.vxrm << 1) | self.vxsat
    }
    /// Write `vcsr`, splitting it into the `vxrm`/`vxsat` CSRs.
    #[inline]
    pub fn set_vcsr(&mut self, v: u64) {
        self.vxsat = v & 1;
        self.vxrm = (v >> 1) & 3;
    }

    // ---------------------------------------------------------------
    // Public accessors (used by tests, the diff oracle, and embedders).
    // ---------------------------------------------------------------

    /// Read integer register `i` (raw XLEN value, zero-extended on RV32).
    #[inline]
    pub fn x(&self, i: u8) -> u64 {
        self.x[(i & 31) as usize]
    }

    /// Write integer register `i` (writes to `x0` are ignored).
    #[inline]
    pub fn set_x(&mut self, i: u8, v: u64) {
        let i = (i & 31) as usize;
        if i != 0 {
            self.x[i] = v & self.cfg.xlen.mask();
        }
    }

    /// Read floating-point register `i` (raw 64-bit storage).
    #[inline]
    pub fn f(&self, i: u8) -> u64 {
        self.f[(i & 31) as usize]
    }

    /// Write floating-point register `i` (raw 64-bit storage).
    #[inline]
    pub fn set_f(&mut self, i: u8, bits: u64) {
        self.f[(i & 31) as usize] = bits;
    }

    /// Current program counter.
    #[inline]
    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Set the program counter.
    #[inline]
    pub fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }

    /// Render the instruction at the current PC as assembly, for tracing.
    /// Returns a marker string if the fetch faults.
    pub fn disasm_pc(&self) -> String {
        match decode_at(self.mem.as_ref(), self.pc, self.cfg.xlen, &self.cfg.isa) {
            Ok(insn) => format!("{insn}"),
            Err(_) => "<fetch fault>".to_string(),
        }
    }

    /// Read the `fcsr` register.
    #[inline]
    pub fn fcsr(&self) -> u32 {
        self.fcsr & 0xff
    }

    /// Write the `fcsr` register.
    #[inline]
    pub fn set_fcsr(&mut self, v: u32) {
        self.fcsr = v & 0xff;
    }

    /// Read the `vstart` CSR.
    #[inline]
    pub fn vstart(&self) -> u64 {
        self.vstart
    }

    /// Write the `vstart` CSR.
    #[inline]
    pub fn set_vstart(&mut self, v: u64) {
        self.vstart = v;
    }

    /// Execute a single already-decoded instruction at `pc` (no fetch). Used by
    /// the SMIR `RvVector` op to drive the verified vector engine over a
    /// transient CPU loaded with the SMIR machine state. Returns the trap on an
    /// illegal/faulting instruction (caller leaves state unchanged).
    pub fn execute_insn(&mut self, insn: &Insn, pc: u64) -> Result<RiscVExit, Trap> {
        self.execute(insn, pc)
    }

    /// Current privilege level.
    pub fn privilege(&self) -> Priv {
        self.priv_
    }

    /// Set the current privilege level.
    pub fn set_privilege(&mut self, p: Priv) {
        self.priv_ = p;
    }

    /// Assert or deassert one or more pending interrupt bits in `mip`.
    pub fn set_interrupt_pending(&mut self, mask: u64, pending: bool) {
        let mask = mask & IMPLEMENTED_INTERRUPT_MASK & self.xmask();
        if pending {
            self.mip |= mask;
        } else {
            self.mip &= !mask;
        }
    }

    /// Deliver the `ECALL` left pending by [`RiscVExit::Ecall`].
    pub fn deliver_ecall_trap(&mut self) {
        let trap = Trap {
            cause: match self.priv_ {
                Priv::User => cause::ECALL_U,
                Priv::Supervisor => cause::ECALL_S,
                Priv::Machine => cause::ECALL_M,
            },
            tval: 0,
        };
        self.deliver_trap(trap, self.pc);
    }

    /// Retired instruction count.
    pub fn instret(&self) -> u64 {
        self.instret
    }

    /// Configuration.
    pub fn config(&self) -> &RiscVConfig {
        &self.cfg
    }

    /// Borrow guest memory.
    pub fn memory(&self) -> &dyn Memory {
        self.mem.as_ref()
    }

    /// Mutably borrow guest memory.
    pub fn memory_mut(&mut self) -> &mut dyn Memory {
        self.mem.as_mut()
    }

    /// Write bytes to guest memory.
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), MemError> {
        self.mem.write(addr, data)
    }

    /// Read bytes from guest memory.
    pub fn read_memory(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemError> {
        self.mem.read(addr, buf)
    }

    /// Read a little-endian doubleword from guest memory.
    pub fn mem_read_u64(&self, addr: u64) -> Result<u64, MemError> {
        self.mem.read_u64(addr)
    }

    /// Decode and disassemble the instruction at `addr` (for tracing /
    /// diagnostics). Returns `<unreadable>` if the fetch faults.
    pub fn disassemble_at(&self, addr: u64) -> String {
        match decode_at(self.mem.as_ref(), addr, self.cfg.xlen, &self.cfg.isa) {
            Ok(insn) => insn.to_string(),
            Err(_) => "<unreadable>".to_string(),
        }
    }

    // ---------------------------------------------------------------
    // XLEN helpers.
    // ---------------------------------------------------------------

    #[inline]
    fn rv32(&self) -> bool {
        self.cfg.xlen == Xlen::Rv32
    }
    #[inline]
    fn xbits(&self) -> u32 {
        self.cfg.xlen.bits()
    }
    #[inline]
    fn xmask(&self) -> u64 {
        self.cfg.xlen.mask()
    }
    /// Sign-extend a stored register value from the XLEN MSB.
    #[inline]
    fn sx(&self, v: u64) -> i64 {
        if self.rv32() {
            v as u32 as i32 as i64
        } else {
            v as i64
        }
    }

    /// Deliver a trap to M-mode.
    fn deliver_trap(&mut self, trap: Trap, epc: u64) {
        self.mepc = epc;
        self.mcause = trap.cause;
        self.mtval = trap.tval;
        // mstatus: MPIE <- MIE, MIE <- 0, MPP <- current priv.
        let mie = (self.mstatus >> 3) & 1;
        self.mstatus &= !(1 << 7); // clear MPIE
        self.mstatus |= mie << 7; // MPIE = MIE
        self.mstatus &= !(1 << 3); // MIE = 0
        self.mstatus &= !(0b11 << 11); // clear MPP
        self.mstatus |= (self.priv_ as u64 & 0b11) << 11;
        self.priv_ = Priv::Machine;
        let base = self.mtvec & !0b11;
        let interrupt_bit = self.interrupt_cause_bit();
        let is_interrupt = trap.cause & interrupt_bit != 0;
        self.pc = if is_interrupt && self.mtvec & 0b11 == 1 {
            base.wrapping_add(4 * (trap.cause & !interrupt_bit)) & self.xmask()
        } else {
            base & self.xmask()
        };
    }

    fn pending_machine_interrupt(&self) -> Option<Trap> {
        let machine_interrupts_enabled =
            self.priv_ < Priv::Machine || self.mstatus & MSTATUS_MIE != 0;
        if !machine_interrupts_enabled {
            return None;
        }

        let pending = self.mip & self.mie & !self.mideleg & M_INTERRUPT_MASK & self.xmask();
        let cause = if pending & MIP_MEIP != 0 {
            cause::INT_M_EXTERNAL
        } else if pending & MIP_MSIP != 0 {
            cause::INT_M_SOFTWARE
        } else if pending & MIP_MTIP != 0 {
            cause::INT_M_TIMER
        } else {
            return None;
        };

        Some(Trap {
            cause: self.interrupt_cause_bit() | cause,
            tval: 0,
        })
    }

    fn interrupt_cause_bit(&self) -> u64 {
        1u64 << (self.xbits() - 1)
    }

    // ---------------------------------------------------------------
    // Instruction execution.
    // ---------------------------------------------------------------

    fn execute(&mut self, insn: &Insn, pc: u64) -> Result<RiscVExit, Trap> {
        // Default fall-through PC; control-flow ops override.
        self.pc = pc.wrapping_add(insn.len as u64) & self.xmask();

        if insn.op.is_fp() {
            return self.exec_fp(insn, pc);
        }

        let rd = insn.rd;
        let rs1 = insn.rs1;
        let rs2 = insn.rs2;
        let a = self.x(rs1);
        let b = self.x(rs2);
        let imm = insn.imm as u64;

        match insn.op {
            // ---- LUI / AUIPC ----
            Op::Lui => self.set_x(rd, imm),
            Op::Auipc => self.set_x(rd, pc.wrapping_add(imm)),

            // ---- jumps ----
            Op::Jal => {
                let target = pc.wrapping_add(imm);
                if self.cfg.isa.c == false && target & 0b11 != 0 {
                    return Err(Trap {
                        cause: cause::INSTR_MISALIGNED,
                        tval: target,
                    });
                }
                self.set_x(rd, pc.wrapping_add(insn.len as u64));
                self.pc = target & self.xmask();
            }
            Op::Jalr => {
                let target = a.wrapping_add(imm) & !1;
                if self.cfg.isa.c == false && target & 0b11 != 0 {
                    return Err(Trap {
                        cause: cause::INSTR_MISALIGNED,
                        tval: target,
                    });
                }
                self.set_x(rd, pc.wrapping_add(insn.len as u64));
                self.pc = target & self.xmask();
            }

            // ---- branches ----
            Op::Beq => self.branch(self.sx(a) == self.sx(b), pc, imm)?,
            Op::Bne => self.branch(self.sx(a) != self.sx(b), pc, imm)?,
            Op::Blt => self.branch(self.sx(a) < self.sx(b), pc, imm)?,
            Op::Bge => self.branch(self.sx(a) >= self.sx(b), pc, imm)?,
            Op::Bltu => self.branch(a < b, pc, imm)?,
            Op::Bgeu => self.branch(a >= b, pc, imm)?,

            // ---- loads ----
            Op::Lb => self.load(rd, a, imm, 1, true)?,
            Op::Lh => self.load(rd, a, imm, 2, true)?,
            Op::Lw => self.load(rd, a, imm, 4, true)?,
            Op::Ld => self.load(rd, a, imm, 8, true)?,
            Op::LdPair => self.load_pair(rd, a, imm)?,
            Op::Lbu => self.load(rd, a, imm, 1, false)?,
            Op::Lhu => self.load(rd, a, imm, 2, false)?,
            Op::Lwu => self.load(rd, a, imm, 4, false)?,

            // ---- stores ----
            Op::Sb => self.store(a, imm, b, 1)?,
            Op::Sh => self.store(a, imm, b, 2)?,
            Op::Sw => self.store(a, imm, b, 4)?,
            Op::Sd => self.store(a, imm, b, 8)?,
            Op::SdPair => self.store_pair(a, imm, rs2)?,

            // ---- OP-IMM ----
            Op::Addi => self.set_x(rd, a.wrapping_add(imm)),
            Op::Slti => self.set_x(rd, (self.sx(a) < imm as i64) as u64),
            Op::Sltiu => self.set_x(rd, ((a & self.xmask()) < (imm & self.xmask())) as u64),
            Op::Xori => self.set_x(rd, a ^ imm),
            Op::Ori => self.set_x(rd, a | imm),
            Op::Andi => self.set_x(rd, a & imm),
            Op::Slli => self.set_x(rd, self.sll(a, imm)),
            Op::Srli => self.set_x(rd, self.srl(a, imm)),
            Op::Srai => self.set_x(rd, self.sra(a, imm)),

            // ---- OP ----
            Op::Add => self.set_x(rd, a.wrapping_add(b)),
            Op::Sub => self.set_x(rd, a.wrapping_sub(b)),
            Op::Sll => self.set_x(rd, self.sll(a, b)),
            Op::Slt => self.set_x(rd, (self.sx(a) < self.sx(b)) as u64),
            Op::Sltu => self.set_x(rd, (a < b) as u64),
            Op::Xor => self.set_x(rd, a ^ b),
            Op::Srl => self.set_x(rd, self.srl(a, b)),
            Op::Sra => self.set_x(rd, self.sra(a, b)),
            Op::Or => self.set_x(rd, a | b),
            Op::And => self.set_x(rd, a & b),

            // ---- OP-IMM-32 (RV64) ----
            Op::Addiw => self.set_x(rd, word((a as u32).wrapping_add(imm as u32))),
            Op::Slliw => self.set_x(rd, word((a as u32) << (imm & 0x1f))),
            Op::Srliw => self.set_x(rd, word((a as u32) >> (imm & 0x1f))),
            Op::Sraiw => self.set_x(rd, word(((a as u32 as i32) >> (imm & 0x1f)) as u32)),

            // ---- OP-32 (RV64) ----
            Op::Addw => self.set_x(rd, word((a as u32).wrapping_add(b as u32))),
            Op::Subw => self.set_x(rd, word((a as u32).wrapping_sub(b as u32))),
            Op::Sllw => self.set_x(rd, word((a as u32) << (b & 0x1f))),
            Op::Sltw => self.set_x(rd, ((a as u32 as i32) < (b as u32 as i32)) as u64),
            Op::Srlw => self.set_x(rd, word((a as u32) >> (b & 0x1f))),
            Op::Sraw => self.set_x(rd, word(((a as u32 as i32) >> (b & 0x1f)) as u32)),

            // ---- FENCE / system ----
            Op::Fence
            | Op::FenceI
            | Op::Pause
            | Op::NtlP1
            | Op::NtlPall
            | Op::NtlS1
            | Op::NtlAll
            | Op::CboInval
            | Op::CboClean
            | Op::CboFlush
            | Op::PrefetchI
            | Op::PrefetchR
            | Op::PrefetchW
            | Op::SfenceVma
            | Op::SinvalVma
            | Op::SfenceWInval
            | Op::SfenceInvalIr
            | Op::HfenceVvma
            | Op::HfenceGvma
            | Op::HinvalVvma
            | Op::HinvalGvma => {}
            Op::CboZero => {
                let base = a & !0x3f;
                self.mem.write(base, &[0; 64]).map_err(|_| Trap {
                    cause: cause::STORE_ACCESS_FAULT,
                    tval: base,
                })?;
            }
            Op::Ecall => {
                self.pc = pc; // leave PC at the ECALL for the handler/embedder
                let trap = Trap {
                    cause: match self.priv_ {
                        Priv::User => cause::ECALL_U,
                        Priv::Supervisor => cause::ECALL_S,
                        Priv::Machine => cause::ECALL_M,
                    },
                    tval: 0,
                };
                let _ = trap;
                return Ok(RiscVExit::Ecall);
            }
            Op::Ebreak => {
                self.pc = pc;
                return Ok(RiscVExit::Ebreak);
            }
            Op::CmPush | Op::CmPop | Op::CmPopRetz | Op::CmPopRet => {
                self.exec_zcmp_stack(insn, pc)?
            }
            Op::CmMvsa01 => {
                self.set_x(rd, self.x(10));
                self.set_x(rs1, self.x(11));
            }
            Op::CmMva01s => {
                self.set_x(10, self.x(rd));
                self.set_x(11, self.x(rs1));
            }
            Op::CmJt | Op::CmJalt => self.exec_zcmt(insn, pc)?,
            Op::HlvB => self.load(rd, a, 0, 1, true)?,
            Op::HlvBu => self.load(rd, a, 0, 1, false)?,
            Op::HlvH => self.load(rd, a, 0, 2, true)?,
            Op::HlvHu | Op::HlvxHu => self.load(rd, a, 0, 2, false)?,
            Op::HlvW => self.load(rd, a, 0, 4, true)?,
            Op::HlvWu | Op::HlvxWu => self.load(rd, a, 0, 4, false)?,
            Op::HlvD => self.load(rd, a, 0, 8, true)?,
            Op::HsvB => self.store(a, 0, b, 1)?,
            Op::HsvH => self.store(a, 0, b, 2)?,
            Op::HsvW => self.store(a, 0, b, 4)?,
            Op::HsvD => self.store(a, 0, b, 8)?,
            Op::NdsLbgp => self.load(rd, a, imm, 1, true)?,
            Op::NdsLbugp => self.load(rd, a, imm, 1, false)?,
            Op::NdsLhgp => self.load(rd, a, imm, 2, true)?,
            Op::NdsLhugp => self.load(rd, a, imm, 2, false)?,
            Op::NdsLwgp => self.load(rd, a, imm, 4, true)?,
            Op::NdsLwugp => self.load(rd, a, imm, 4, false)?,
            Op::NdsLdgp => self.load(rd, a, imm, 8, true)?,
            Op::NdsSbgp => self.store(a, imm, b, 1)?,
            Op::NdsShgp => self.store(a, imm, b, 2)?,
            Op::NdsSwgp => self.store(a, imm, b, 4)?,
            Op::NdsSdgp => self.store(a, imm, b, 8)?,
            Op::NdsAddigp => self.set_x(rd, a.wrapping_add(imm)),
            Op::NdsBfoz | Op::NdsBfos => {
                self.set_x(
                    rd,
                    andes_bitfield(a, rs2, imm as u8, matches!(insn.op, Op::NdsBfos)),
                );
            }
            Op::NdsBbc => self.branch(((a >> rs2) & 1) == 0, pc, imm)?,
            Op::NdsBbs => self.branch(((a >> rs2) & 1) != 0, pc, imm)?,
            Op::NdsBeqc => self.branch((a & self.xmask()) == rs2 as u64, pc, imm)?,
            Op::NdsBnec => self.branch((a & self.xmask()) != rs2 as u64, pc, imm)?,
            Op::NdsLeaH => self.set_x(rd, a.wrapping_add(b << 1)),
            Op::NdsLeaW => self.set_x(rd, a.wrapping_add(b << 2)),
            Op::NdsLeaD => self.set_x(rd, a.wrapping_add(b << 3)),
            Op::NdsLeaBZe => self.set_x(rd, a.wrapping_add(b as u32 as u64)),
            Op::NdsLeaHZe => self.set_x(rd, a.wrapping_add((b as u32 as u64) << 1)),
            Op::NdsLeaWZe => self.set_x(rd, a.wrapping_add((b as u32 as u64) << 2)),
            Op::NdsLeaDZe => self.set_x(rd, a.wrapping_add((b as u32 as u64) << 3)),
            Op::NdsFfb | Op::NdsFfmism | Op::NdsFfzmism | Op::NdsFlmism => {
                self.set_x(rd, andes_byte_scan(insn.op, a, b, self.rv32()))
            }
            Op::ThDcacheCall
            | Op::ThDcacheCiall
            | Op::ThDcacheIall
            | Op::ThDcacheCpa
            | Op::ThDcacheCipa
            | Op::ThDcacheIpa
            | Op::ThDcacheCva
            | Op::ThDcacheCiva
            | Op::ThDcacheIva
            | Op::ThDcacheCsw
            | Op::ThDcacheCisw
            | Op::ThDcacheIsw
            | Op::ThDcacheCpal1
            | Op::ThDcacheCval1
            | Op::ThIcacheIall
            | Op::ThIcacheIalls
            | Op::ThIcacheIpa
            | Op::ThIcacheIva
            | Op::ThL2cacheCall
            | Op::ThL2cacheCiall
            | Op::ThL2cacheIall
            | Op::ThSfenceVmas
            | Op::ThSync
            | Op::ThSyncS
            | Op::ThSyncI
            | Op::ThSyncIS
            | Op::ThIpush
            | Op::ThIpop => {}
            Op::ThAddsl => self.set_x(rd, a.wrapping_add(b.wrapping_shl(insn.imm as u32))),
            Op::ThSrri => self.set_x(rd, self.ror(a, imm)),
            Op::ThSrriw => self.set_x(rd, word((a as u32).rotate_right((imm & 0x1f) as u32))),
            Op::ThExt | Op::ThExtu => {
                self.set_x(
                    rd,
                    thead_extract(
                        a,
                        rs2,
                        insn.imm as u8,
                        self.xbits(),
                        matches!(insn.op, Op::ThExt),
                    ),
                );
            }
            Op::ThFf0 => self.set_x(rd, thead_ff(a, self.xbits(), false)),
            Op::ThFf1 => self.set_x(rd, thead_ff(a, self.xbits(), true)),
            Op::ThRev => self.set_x(rd, rev8(a, self.rv32())),
            Op::ThRevw => self.set_x(rd, (a as u32).swap_bytes() as u64),
            Op::ThTstNbz => self.set_x(rd, thead_tstnbz(a, self.rv32())),
            Op::ThTst => {
                let bit = if imm < self.xbits() as u64 {
                    (a >> imm) & 1
                } else {
                    0
                };
                self.set_x(rd, bit);
            }
            Op::ThMveqz => self.set_x(rd, if b == 0 { a } else { self.x(rd) }),
            Op::ThMvnez => self.set_x(rd, if b != 0 { a } else { self.x(rd) }),
            Op::ThMula | Op::ThMuls | Op::ThMulah | Op::ThMulsh | Op::ThMulaw | Op::ThMulsw => {
                self.set_x(rd, thead_mac(insn.op, self.x(rd), a, b));
            }
            Op::ThFmvHwX => {
                let old = self.f(rd) & 0x0000_0000_ffff_ffff;
                self.set_f(rd, old | ((a & 0xffff_ffff) << 32));
            }
            Op::ThFmvXHw => self.set_x(rd, (self.f(rs1) >> 32) & 0xffff_ffff),
            Op::ThAndn => self.set_x(rd, a & !b),
            Op::ThOrn => self.set_x(rd, a | !b),
            Op::ThXorn => self.set_x(rd, !(a ^ b)),
            Op::ThPackl => self.set_x(rd, thead_packl(a, b, self.xbits())),
            Op::ThPackh => self.set_x(rd, ((b & 0xff) << 8) | (a & 0xff)),
            Op::ThPackhl => self.set_x(rd, thead_packhl(a, b, self.xbits())),
            op if thead_auto_mem(op).is_some() => self.exec_thead_auto_mem(insn)?,
            op if thead_reg_mem(op).is_some() => self.exec_thead_reg_mem(insn)?,
            op if thead_pair_mem(op).is_some() => self.exec_thead_pair_mem(insn)?,
            op if thead_fmem(op).is_some() => self.exec_thead_fmem(insn)?,
            Op::H3Block => return Ok(RiscVExit::Wfi),
            Op::H3Unblock => {}
            Op::H3Bextm => {
                let nbits = imm & 0xf;
                let mask = (1u64 << nbits) - 1;
                self.set_x(rd, (a >> (b & 0x1f)) & mask);
            }
            Op::H3Bextmi => {
                let nbits = imm & 0xf;
                let mask = (1u64 << nbits) - 1;
                self.set_x(rd, (a >> (rs2 as u64)) & mask);
            }
            Op::Wfi => {
                return Ok(if self.locally_enabled_interrupt_pending() {
                    RiscVExit::Continue
                } else {
                    RiscVExit::Wfi
                });
            }
            Op::WrsNto | Op::WrsSto => {}
            Op::Uret | Op::SfenceVm => return Err(Trap::illegal(insn.raw)),
            Op::Mret => self.mret(),
            Op::Sret => self.sret(insn)?,

            // ---- Zicsr ----
            Op::Csrrw | Op::Csrrs | Op::Csrrc | Op::Csrrwi | Op::Csrrsi | Op::Csrrci => {
                self.exec_csr(insn)?
            }

            // ---- M ----
            Op::Mul => self.set_x(rd, a.wrapping_mul(b)),
            Op::Mulh => self.set_x(rd, self.mulh(a, b)),
            Op::Mulhsu => self.set_x(rd, self.mulhsu(a, b)),
            Op::Mulhu => self.set_x(rd, self.mulhu(a, b)),
            Op::Div => self.set_x(rd, self.div(a, b)),
            Op::Divu => self.set_x(rd, self.divu(a, b)),
            Op::Rem => self.set_x(rd, self.rem(a, b)),
            Op::Remu => self.set_x(rd, self.remu(a, b)),
            Op::Mulw => self.set_x(rd, word((a as u32).wrapping_mul(b as u32))),
            Op::Divw => self.set_x(rd, divw(a as u32, b as u32, true, false)),
            Op::Divuw => self.set_x(rd, divw(a as u32, b as u32, false, false)),
            Op::Remw => self.set_x(rd, divw(a as u32, b as u32, true, true)),
            Op::Remuw => self.set_x(rd, divw(a as u32, b as u32, false, true)),

            // ---- A ----
            Op::LrW | Op::LrD | Op::ScW | Op::ScD => self.exec_lrsc(insn)?,
            Op::AmoswapW
            | Op::AmoaddW
            | Op::AmoxorW
            | Op::AmoandW
            | Op::AmoorW
            | Op::AmominW
            | Op::AmomaxW
            | Op::AmominuW
            | Op::AmomaxuW
            | Op::AmoswapD
            | Op::AmoaddD
            | Op::AmoxorD
            | Op::AmoandD
            | Op::AmoorD
            | Op::AmominD
            | Op::AmomaxD
            | Op::AmominuD
            | Op::AmomaxuD => self.exec_amo(insn)?,
            Op::AmocasW | Op::AmocasD | Op::AmocasQ => self.exec_amocas(insn)?,

            // ---- Zba ----
            Op::Sh1add => self.set_x(rd, (a << 1).wrapping_add(b)),
            Op::Sh2add => self.set_x(rd, (a << 2).wrapping_add(b)),
            Op::Sh3add => self.set_x(rd, (a << 3).wrapping_add(b)),
            Op::AddUw => self.set_x(rd, (a & 0xffff_ffff).wrapping_add(b)),
            Op::Sh1addUw => self.set_x(rd, ((a & 0xffff_ffff) << 1).wrapping_add(b)),
            Op::Sh2addUw => self.set_x(rd, ((a & 0xffff_ffff) << 2).wrapping_add(b)),
            Op::Sh3addUw => self.set_x(rd, ((a & 0xffff_ffff) << 3).wrapping_add(b)),
            Op::SlliUw => self.set_x(rd, (a & 0xffff_ffff) << (imm & 0x3f)),

            // ---- Zbb ----
            Op::Andn => self.set_x(rd, a & !b),
            Op::Orn => self.set_x(rd, a | !b),
            Op::Xnor => self.set_x(rd, !(a ^ b)),
            Op::Clz => self.set_x(rd, self.clz(a)),
            Op::Ctz => self.set_x(rd, self.ctz(a)),
            Op::Cpop => self.set_x(rd, (a & self.xmask()).count_ones() as u64),
            Op::Max => self.set_x(rd, if self.sx(a) >= self.sx(b) { a } else { b }),
            Op::Maxu => self.set_x(rd, if a >= b { a } else { b }),
            Op::Min => self.set_x(rd, if self.sx(a) <= self.sx(b) { a } else { b }),
            Op::Minu => self.set_x(rd, if a <= b { a } else { b }),
            Op::SextB => self.set_x(rd, a as u8 as i8 as i64 as u64),
            Op::SextH => self.set_x(rd, a as u16 as i16 as i64 as u64),
            Op::ZextH => self.set_x(rd, a & 0xffff),
            Op::Rol => self.set_x(rd, self.rol(a, b)),
            Op::Ror => self.set_x(rd, self.ror(a, b)),
            Op::Rori => self.set_x(rd, self.ror(a, imm)),
            Op::Orcb => self.set_x(rd, orc_b(a, self.xmask())),
            Op::Rev8 => self.set_x(rd, rev8(a, self.rv32())),
            Op::Clzw => self.set_x(rd, ((a as u32).leading_zeros()) as u64),
            Op::Ctzw => self.set_x(rd, clz_ctz_w(a as u32, true)),
            Op::Cpopw => self.set_x(rd, (a as u32).count_ones() as u64),
            Op::Rolw => self.set_x(rd, word((a as u32).rotate_left((b & 0x1f) as u32))),
            Op::Rorw => self.set_x(rd, word((a as u32).rotate_right((b & 0x1f) as u32))),
            Op::Roriw => self.set_x(rd, word((a as u32).rotate_right((imm & 0x1f) as u32))),

            // ---- Zbc ----
            Op::Clmul => self.set_x(rd, clmul(a, b, self.xbits())),
            Op::Clmulh => self.set_x(rd, clmulh(a, b, self.xbits())),
            Op::Clmulr => self.set_x(rd, clmulr(a, b, self.xbits())),

            // ---- Zbs ----
            Op::Bclr => self.set_x(rd, a & !(1u64 << (b & (self.xbits() as u64 - 1)))),
            Op::Bclri => self.set_x(rd, a & !(1u64 << (imm & (self.xbits() as u64 - 1)))),
            Op::Bext => self.set_x(rd, (a >> (b & (self.xbits() as u64 - 1))) & 1),
            Op::Bexti => self.set_x(rd, (a >> (imm & (self.xbits() as u64 - 1))) & 1),
            Op::Binv => self.set_x(rd, a ^ (1u64 << (b & (self.xbits() as u64 - 1)))),
            Op::Binvi => self.set_x(rd, a ^ (1u64 << (imm & (self.xbits() as u64 - 1)))),
            Op::Bset => self.set_x(rd, a | (1u64 << (b & (self.xbits() as u64 - 1)))),
            Op::Bseti => self.set_x(rd, a | (1u64 << (imm & (self.xbits() as u64 - 1)))),

            // ---- Xsoteria (Google Soteria/GSC vendor extension, RV32) ----
            // `a` is held zero-extended to 32 bits on RV32; results are masked
            // back to XLEN by `set_x`. Shift amounts and grev control take the
            // low 5 bits (XLEN=32 => log2(32)=5), matching the bitmanip GREV.
            Op::Grev => self.set_x(rd, grev32(a as u32, (b & 31) as u32) as u64),
            Op::Grevi => self.set_x(rd, grev32(a as u32, (imm & 31) as u32) as u64),
            Op::Bitc => self.set_x(rd, a & !(1u64 << (b & 31))),
            Op::Bitci => self.set_x(rd, a & !(1u64 << (imm & 31))),
            Op::Bits => self.set_x(rd, a | (1u64 << (b & 31))),
            Op::Bitsi => self.set_x(rd, a | (1u64 << (imm & 31))),
            Op::Pcnt => self.set_x(rd, (a as u32).count_ones() as u64),
            Op::Fls => self.set_x(rd, fls32(a as u32)),

            // ---- Zicond ----
            Op::CzeroEqz => self.set_x(rd, if b == 0 { 0 } else { a }),
            Op::CzeroNez => self.set_x(rd, if b != 0 { 0 } else { a }),

            // ---- Zbkb ----
            Op::Pack => {
                let half = self.xbits() / 2;
                let mask = (1u64 << half) - 1;
                self.set_x(rd, ((b & mask) << half) | (a & mask));
            }
            Op::Packh => self.set_x(rd, ((b & 0xff) << 8) | (a & 0xff)),
            Op::Packw => self.set_x(rd, word((((b & 0xffff) << 16) | (a & 0xffff)) as u32)),
            Op::Brev8 => self.set_x(rd, brev8(a) & self.xmask()),
            Op::Zip => self.set_x(rd, zip32(a as u32) as u64),
            Op::Unzip => self.set_x(rd, unzip32(a as u32) as u64),

            // ---- Zbkx ----
            Op::Xperm4 => self.set_x(rd, crypto::xperm4(a, b, self.xbits())),
            Op::Xperm8 => self.set_x(rd, crypto::xperm8(a, b, self.xbits())),

            // ---- Zknh (SHA) ----
            Op::Sha256Sig0 => self.set_x(rd, crypto::sha256sig0(a)),
            Op::Sha256Sig1 => self.set_x(rd, crypto::sha256sig1(a)),
            Op::Sha256Sum0 => self.set_x(rd, crypto::sha256sum0(a)),
            Op::Sha256Sum1 => self.set_x(rd, crypto::sha256sum1(a)),
            Op::Sha512Sig0 => self.set_x(rd, crypto::sha512sig0(a)),
            Op::Sha512Sig1 => self.set_x(rd, crypto::sha512sig1(a)),
            Op::Sha512Sum0 => self.set_x(rd, crypto::sha512sum0(a)),
            Op::Sha512Sum1 => self.set_x(rd, crypto::sha512sum1(a)),
            Op::Sha512Sig0l => self.set_x(rd, crypto::sha512sig0l(a, b)),
            Op::Sha512Sig0h => self.set_x(rd, crypto::sha512sig0h(a, b)),
            Op::Sha512Sig1l => self.set_x(rd, crypto::sha512sig1l(a, b)),
            Op::Sha512Sig1h => self.set_x(rd, crypto::sha512sig1h(a, b)),
            Op::Sha512Sum0r => self.set_x(rd, crypto::sha512sum0r(a, b)),
            Op::Sha512Sum1r => self.set_x(rd, crypto::sha512sum1r(a, b)),

            // ---- Zksh (SM3) ----
            Op::Sm3p0 => self.set_x(rd, crypto::sm3p0(a)),
            Op::Sm3p1 => self.set_x(rd, crypto::sm3p1(a)),

            // ---- Zksed (SM4) ----
            Op::Sm4ed => self.set_x(rd, crypto::sm4ed(a, b, (insn.raw >> 30) & 3)),
            Op::Sm4ks => self.set_x(rd, crypto::sm4ks(a, b, (insn.raw >> 30) & 3)),

            // ---- Zkne / Zknd (AES) ----
            Op::Aes32esi => self.set_x(rd, crypto::aes32esi(a, b, (insn.raw >> 30) & 3)),
            Op::Aes32esmi => self.set_x(rd, crypto::aes32esmi(a, b, (insn.raw >> 30) & 3)),
            Op::Aes32dsi => self.set_x(rd, crypto::aes32dsi(a, b, (insn.raw >> 30) & 3)),
            Op::Aes32dsmi => self.set_x(rd, crypto::aes32dsmi(a, b, (insn.raw >> 30) & 3)),
            Op::Aes64es => self.set_x(rd, crypto::aes64es(a, b)),
            Op::Aes64esm => self.set_x(rd, crypto::aes64esm(a, b)),
            Op::Aes64ds => self.set_x(rd, crypto::aes64ds(a, b)),
            Op::Aes64dsm => self.set_x(rd, crypto::aes64dsm(a, b)),
            Op::Aes64im => self.set_x(rd, crypto::aes64im(a)),
            Op::Aes64ks1i => self.set_x(rd, crypto::aes64ks1i(a, (insn.raw >> 20) & 0xf)),
            Op::Aes64ks2 => self.set_x(rd, crypto::aes64ks2(a, b)),

            // ---- V: vector configuration ----
            Op::Vsetvli => {
                let avl = if rs1 == 0 {
                    if rd == 0 { Avl::Keep } else { Avl::Max }
                } else {
                    Avl::Reg(a)
                };
                let vl = self.set_vtype(imm, avl);
                self.set_x(rd, vl);
            }
            Op::Vsetivli => {
                let vl = self.set_vtype(imm, Avl::Reg(rs1 as u64));
                self.set_x(rd, vl);
            }
            Op::Vsetvl => {
                let avl = if rs1 == 0 {
                    if rd == 0 { Avl::Keep } else { Avl::Max }
                } else {
                    Avl::Reg(a)
                };
                let vl = self.set_vtype(b, avl);
                self.set_x(rd, vl);
            }

            // ---- V: vector data path ----
            Op::Vle
            | Op::Vse
            | Op::Vlse
            | Op::Vsse
            | Op::Vlxei
            | Op::Vsxei
            | Op::Vlm
            | Op::Vsm
            | Op::Vlre
            | Op::Vsre
            | Op::Vlseg
            | Op::Vsseg
            | Op::Vleff
            | Op::Vadd
            | Op::Vsub
            | Op::Vrsub
            | Op::Vand
            | Op::Vor
            | Op::Vxor
            | Op::Vminu
            | Op::Vmin
            | Op::Vmaxu
            | Op::Vmax
            | Op::Vsll
            | Op::Vsrl
            | Op::Vsra
            | Op::Vmerge
            | Op::Vmseq
            | Op::Vmsne
            | Op::Vmsltu
            | Op::Vmslt
            | Op::Vmsleu
            | Op::Vmsle
            | Op::Vmsgtu
            | Op::Vmsgt
            | Op::Vmul
            | Op::Vmulh
            | Op::Vmulhu
            | Op::Vmulhsu
            | Op::Vdivu
            | Op::Vdiv
            | Op::Vremu
            | Op::Vrem
            | Op::Vfadd
            | Op::Vfsub
            | Op::Vfrsub
            | Op::Vfmul
            | Op::Vfdiv
            | Op::Vfrdiv
            | Op::Vfsqrt
            | Op::Vfmin
            | Op::Vfmax
            | Op::Vfsgnj
            | Op::Vfsgnjn
            | Op::Vfsgnjx
            | Op::Vmfeq
            | Op::Vmfne
            | Op::Vmflt
            | Op::Vmfle
            | Op::Vmfgt
            | Op::Vmfge
            | Op::Vfmacc
            | Op::Vfnmacc
            | Op::Vfmsac
            | Op::Vfnmsac
            | Op::Vfmadd
            | Op::Vfnmadd
            | Op::Vfmsub
            | Op::Vfnmsub
            | Op::Vredsum
            | Op::Vredand
            | Op::Vredor
            | Op::Vredxor
            | Op::Vredminu
            | Op::Vredmin
            | Op::Vredmaxu
            | Op::Vredmax
            | Op::Vfredusum
            | Op::Vfredosum
            | Op::Vfredmin
            | Op::Vfredmax
            | Op::VmvXS
            | Op::VmvSX
            | Op::VfmvFS
            | Op::VfmvSF
            | Op::Vmand
            | Op::Vmnand
            | Op::Vmandn
            | Op::Vmxor
            | Op::Vmor
            | Op::Vmnor
            | Op::Vmorn
            | Op::Vmxnor
            | Op::VzextVf2
            | Op::VsextVf2
            | Op::VzextVf4
            | Op::VsextVf4
            | Op::VzextVf8
            | Op::VsextVf8
            | Op::Vcpop
            | Op::Vfirst
            | Op::Vmsbf
            | Op::Vmsof
            | Op::Vmsif
            | Op::Viota
            | Op::Vid
            | Op::Vslideup
            | Op::Vslidedown
            | Op::Vslide1up
            | Op::Vslide1down
            | Op::Vfslide1up
            | Op::Vfslide1down
            | Op::Vrgather
            | Op::Vrgatherei16
            | Op::Vcompress
            | Op::Vadc
            | Op::Vmadc
            | Op::Vsbc
            | Op::Vmsbc
            | Op::Vsaddu
            | Op::Vsadd
            | Op::Vssubu
            | Op::Vssub
            | Op::Vaaddu
            | Op::Vaadd
            | Op::Vasubu
            | Op::Vasub
            | Op::Vssrl
            | Op::Vssra
            | Op::Vsmul
            | Op::Vwaddu
            | Op::Vwadd
            | Op::Vwsubu
            | Op::Vwsub
            | Op::VwadduW
            | Op::VwaddW
            | Op::VwsubuW
            | Op::VwsubW
            | Op::Vwmulu
            | Op::Vwmulsu
            | Op::Vwmul
            | Op::Vwmaccu
            | Op::Vwmacc
            | Op::Vwmaccsu
            | Op::Vwmaccus
            | Op::Vnsrl
            | Op::Vnsra
            | Op::Vnclipu
            | Op::Vnclip
            | Op::VfcvtXuF
            | Op::VfcvtXF
            | Op::VfcvtFXu
            | Op::VfcvtFX
            | Op::VfcvtRtzXuF
            | Op::VfcvtRtzXF
            | Op::VfwcvtXuF
            | Op::VfwcvtXF
            | Op::VfwcvtFXu
            | Op::VfwcvtFX
            | Op::VfwcvtFF
            | Op::VfwcvtRtzXuF
            | Op::VfwcvtRtzXF
            | Op::VfncvtXuF
            | Op::VfncvtXF
            | Op::VfncvtFXu
            | Op::VfncvtFX
            | Op::VfncvtFF
            | Op::VfncvtRodFF
            | Op::VfncvtRtzXuF
            | Op::VfncvtRtzXF
            | Op::Vfwadd
            | Op::Vfwsub
            | Op::Vfwmul
            | Op::VfwaddW
            | Op::VfwsubW
            | Op::Vfwmacc
            | Op::Vfwnmacc
            | Op::Vfwmsac
            | Op::Vfwnmsac
            | Op::Vwredsumu
            | Op::Vwredsum
            | Op::Vfwredusum
            | Op::Vfwredosum
            | Op::Vfclass
            | Op::Vmvr
            | Op::Vfrsqrt7
            | Op::Vfrec7
            | Op::ThVmaqa
            | Op::ThVmaqau
            | Op::ThVmaqasu
            | Op::ThVmaqaus => self.exec_vector(insn)?,

            Op::Illegal => return Err(Trap::illegal(insn.raw)),

            // FP handled above via exec_fp.
            _ => return Err(Trap::illegal(insn.raw)),
        }
        Ok(RiscVExit::Continue)
    }

    // ---------------------------------------------------------------
    // Control-flow / memory helpers.
    // ---------------------------------------------------------------

    #[inline]
    fn branch(&mut self, taken: bool, pc: u64, imm: u64) -> Result<(), Trap> {
        if taken {
            let target = pc.wrapping_add(imm);
            if !self.cfg.isa.c && target & 0b11 != 0 {
                return Err(Trap {
                    cause: cause::INSTR_MISALIGNED,
                    tval: target,
                });
            }
            self.pc = target & self.xmask();
        }
        Ok(())
    }

    fn load(&mut self, rd: u8, base: u64, imm: u64, size: usize, signed: bool) -> Result<(), Trap> {
        let addr = base.wrapping_add(imm) & self.xmask();
        let mut buf = [0u8; 8];
        self.mem.read(addr, &mut buf[..size]).map_err(|_| Trap {
            cause: cause::LOAD_ACCESS_FAULT,
            tval: addr,
        })?;
        let raw = u64::from_le_bytes(buf);
        let val = if signed {
            sign_extend(raw, size)
        } else {
            raw & mask_bytes(size)
        };
        self.set_x(rd, val);
        Ok(())
    }

    fn store(&mut self, base: u64, imm: u64, val: u64, size: usize) -> Result<(), Trap> {
        let addr = base.wrapping_add(imm) & self.xmask();
        self.mem
            .write(addr, &val.to_le_bytes()[..size])
            .map_err(|_| Trap {
                cause: cause::STORE_ACCESS_FAULT,
                tval: addr,
            })
    }

    fn load_pair(&mut self, rd: u8, base: u64, imm: u64) -> Result<(), Trap> {
        let addr = base.wrapping_add(imm) & self.xmask();
        let val = self.mem.read_u64(addr).map_err(|_| Trap {
            cause: cause::LOAD_ACCESS_FAULT,
            tval: addr,
        })?;
        // Zilsd defines rd=x0 as discarding the complete 64-bit result; x1 is
        // not the high destination in this special case.
        if rd != 0 {
            self.set_x(rd, val as u32 as u64);
            self.set_x(rd.wrapping_add(1), (val >> 32) as u32 as u64);
        }
        Ok(())
    }

    fn store_pair(&mut self, base: u64, imm: u64, rs2: u8) -> Result<(), Trap> {
        let addr = base.wrapping_add(imm) & self.xmask();
        // Zilsd/Zclsd define an x0 source pair as 64 zero bits; x1 is not read.
        let val = if rs2 == 0 {
            0
        } else {
            (self.x(rs2) as u32 as u64) | ((self.x(rs2.wrapping_add(1)) as u32 as u64) << 32)
        };
        self.mem.write_u64(addr, val).map_err(|_| Trap {
            cause: cause::STORE_ACCESS_FAULT,
            tval: addr,
        })
    }

    fn exec_thead_auto_mem(&mut self, insn: &Insn) -> Result<(), Trap> {
        let kind = thead_auto_mem(insn.op).expect("T-Head auto memory op");
        let inc = (sext5(insn.rs2) as i64).wrapping_shl(insn.imm as u32) as u64;
        let old_base = self.x(insn.rs1);
        let new_base = old_base.wrapping_add(inc) & self.xmask();
        let addr = if kind.pre { new_base } else { old_base };

        if kind.pre {
            self.set_x(insn.rs1, new_base);
        }
        if kind.load {
            self.load(insn.rd, addr, 0, kind.size, kind.signed)?;
        } else {
            self.store(addr, 0, self.x(insn.rd), kind.size)?;
        }
        if !kind.pre {
            self.set_x(insn.rs1, new_base);
        }
        Ok(())
    }

    fn exec_thead_reg_mem(&mut self, insn: &Insn) -> Result<(), Trap> {
        let kind = thead_reg_mem(insn.op).expect("T-Head indexed memory op");
        let offset = self.x(insn.rs2).wrapping_shl(insn.imm as u32);
        let addr = self.x(insn.rs1).wrapping_add(offset) & self.xmask();
        if kind.load {
            self.load(insn.rd, addr, 0, kind.size, kind.signed)
        } else {
            self.store(addr, 0, self.x(insn.rd), kind.size)
        }
    }

    fn exec_thead_pair_mem(&mut self, insn: &Insn) -> Result<(), Trap> {
        let kind = thead_pair_mem(insn.op).expect("T-Head pair memory op");
        let addr = self.x(insn.rs1).wrapping_add(insn.imm as u64) & self.xmask();
        if kind.load {
            self.load(insn.rd, addr, 0, kind.size, kind.signed)?;
            self.load(
                insn.rs2,
                addr.wrapping_add(kind.size as u64),
                0,
                kind.size,
                kind.signed,
            )
        } else {
            self.store(addr, 0, self.x(insn.rd), kind.size)?;
            self.store(
                addr.wrapping_add(kind.size as u64),
                0,
                self.x(insn.rs2),
                kind.size,
            )
        }
    }

    fn exec_thead_fmem(&mut self, insn: &Insn) -> Result<(), Trap> {
        let kind = thead_fmem(insn.op).expect("T-Head FP indexed memory op");
        let offset = self.x(insn.rs2).wrapping_shl(insn.imm as u32);
        let addr = self.x(insn.rs1).wrapping_add(offset) & self.xmask();
        match (kind.load, kind.size) {
            (true, 4) => {
                let bits = self
                    .mem
                    .read_u32(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                self.set_f(insn.rd, 0xffff_ffff_0000_0000 | bits as u64);
                Ok(())
            }
            (true, 8) => {
                let bits = self
                    .mem
                    .read_u64(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                self.set_f(insn.rd, bits);
                Ok(())
            }
            (false, 4) => self
                .mem
                .write_u32(addr, self.f(insn.rd) as u32)
                .map_err(|_| acc_fault(true, addr)),
            (false, 8) => self
                .mem
                .write_u64(addr, self.f(insn.rd))
                .map_err(|_| acc_fault(true, addr)),
            _ => unreachable!(),
        }
    }

    // ---------------------------------------------------------------
    // Shift / arithmetic helpers (XLEN-aware).
    // ---------------------------------------------------------------

    #[inline]
    fn shamt(&self, v: u64) -> u32 {
        (v & (self.xbits() as u64 - 1)) as u32
    }
    #[inline]
    fn sll(&self, a: u64, sh: u64) -> u64 {
        let s = self.shamt(sh);
        if self.rv32() {
            ((a as u32) << s) as u64
        } else {
            a << s
        }
    }
    #[inline]
    fn srl(&self, a: u64, sh: u64) -> u64 {
        let s = self.shamt(sh);
        if self.rv32() {
            ((a as u32) >> s) as u64
        } else {
            a >> s
        }
    }
    #[inline]
    fn sra(&self, a: u64, sh: u64) -> u64 {
        let s = self.shamt(sh);
        if self.rv32() {
            (((a as u32 as i32) >> s) as u32) as u64
        } else {
            ((a as i64) >> s) as u64
        }
    }
    #[inline]
    fn rol(&self, a: u64, sh: u64) -> u64 {
        let s = self.shamt(sh);
        if self.rv32() {
            (a as u32).rotate_left(s) as u64
        } else {
            a.rotate_left(s)
        }
    }
    #[inline]
    fn ror(&self, a: u64, sh: u64) -> u64 {
        let s = self.shamt(sh);
        if self.rv32() {
            (a as u32).rotate_right(s) as u64
        } else {
            a.rotate_right(s)
        }
    }
    #[inline]
    fn clz(&self, a: u64) -> u64 {
        if self.rv32() {
            (a as u32).leading_zeros() as u64
        } else {
            a.leading_zeros() as u64
        }
    }
    #[inline]
    fn ctz(&self, a: u64) -> u64 {
        if self.rv32() {
            (a as u32).trailing_zeros() as u64
        } else {
            a.trailing_zeros() as u64
        }
    }

    // ---------------------------------------------------------------
    // M-extension helpers (XLEN-aware high-multiply and divide).
    // ---------------------------------------------------------------

    fn mulh(&self, a: u64, b: u64) -> u64 {
        if self.rv32() {
            (((a as i32 as i64) * (b as i32 as i64)) >> 32) as u32 as u64
        } else {
            (((a as i64 as i128) * (b as i64 as i128)) >> 64) as u64
        }
    }
    fn mulhsu(&self, a: u64, b: u64) -> u64 {
        if self.rv32() {
            (((a as i32 as i64) * (b as u32 as i64)) >> 32) as u32 as u64
        } else {
            (((a as i64 as i128) * (b as u128 as i128)) >> 64) as u64
        }
    }
    fn mulhu(&self, a: u64, b: u64) -> u64 {
        if self.rv32() {
            (((a as u32 as u64) * (b as u32 as u64)) >> 32) as u32 as u64
        } else {
            (((a as u128) * (b as u128)) >> 64) as u64
        }
    }
    fn div(&self, a: u64, b: u64) -> u64 {
        if self.rv32() {
            let (x, y) = (a as i32, b as i32);
            let r = if y == 0 {
                -1
            } else if x == i32::MIN && y == -1 {
                i32::MIN
            } else {
                x / y
            };
            r as u32 as u64
        } else {
            let (x, y) = (a as i64, b as i64);
            let r = if y == 0 {
                -1
            } else if x == i64::MIN && y == -1 {
                i64::MIN
            } else {
                x / y
            };
            r as u64
        }
    }
    fn divu(&self, a: u64, b: u64) -> u64 {
        if self.rv32() {
            let (x, y) = (a as u32, b as u32);
            (if y == 0 { u32::MAX } else { x / y }) as u64
        } else {
            if b == 0 { u64::MAX } else { a / b }
        }
    }
    fn rem(&self, a: u64, b: u64) -> u64 {
        if self.rv32() {
            let (x, y) = (a as i32, b as i32);
            let r = if y == 0 {
                x
            } else if x == i32::MIN && y == -1 {
                0
            } else {
                x % y
            };
            r as u32 as u64
        } else {
            let (x, y) = (a as i64, b as i64);
            let r = if y == 0 {
                x
            } else if x == i64::MIN && y == -1 {
                0
            } else {
                x % y
            };
            r as u64
        }
    }
    fn remu(&self, a: u64, b: u64) -> u64 {
        if self.rv32() {
            let (x, y) = (a as u32, b as u32);
            (if y == 0 { x } else { x % y }) as u64
        } else {
            if b == 0 { a } else { a % b }
        }
    }

    // ---------------------------------------------------------------
    // A-extension.
    // ---------------------------------------------------------------

    fn exec_lrsc(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = self.x(insn.rs1) & self.xmask();
        let is_d = matches!(insn.op, Op::LrD | Op::ScD);
        let size = if is_d { 8 } else { 4 };
        if addr % size as u64 != 0 {
            let c = if matches!(insn.op, Op::ScW | Op::ScD) {
                cause::STORE_MISALIGNED
            } else {
                cause::LOAD_MISALIGNED
            };
            return Err(Trap {
                cause: c,
                tval: addr,
            });
        }
        match insn.op {
            Op::LrW => {
                let v = self
                    .mem
                    .read_u32(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                self.reservation = Some(addr);
                self.set_x(insn.rd, v as i32 as i64 as u64);
            }
            Op::LrD => {
                let v = self
                    .mem
                    .read_u64(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                self.reservation = Some(addr);
                self.set_x(insn.rd, v);
            }
            Op::ScW | Op::ScD => {
                let ok = self.reservation == Some(addr);
                self.reservation = None;
                if ok {
                    if is_d {
                        self.mem
                            .write_u64(addr, self.x(insn.rs2))
                            .map_err(|_| acc_fault(true, addr))?;
                    } else {
                        self.mem
                            .write_u32(addr, self.x(insn.rs2) as u32)
                            .map_err(|_| acc_fault(true, addr))?;
                    }
                } else {
                    // A failed SC generates no store operation, but it still
                    // must pass the addressed range's memory-permission check.
                    self.mem
                        .probe(addr, size, true)
                        .map_err(|_| acc_fault(true, addr))?;
                }
                self.set_x(insn.rd, if ok { 0 } else { 1 });
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn exec_amo(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = self.x(insn.rs1) & self.xmask();
        let src = self.x(insn.rs2);
        let is_d = matches!(
            insn.op,
            Op::AmoswapD
                | Op::AmoaddD
                | Op::AmoxorD
                | Op::AmoandD
                | Op::AmoorD
                | Op::AmominD
                | Op::AmomaxD
                | Op::AmominuD
                | Op::AmomaxuD
        );
        let size: u64 = if is_d { 8 } else { 4 };
        if addr % size != 0 {
            return Err(Trap {
                cause: cause::STORE_MISALIGNED,
                tval: addr,
            });
        }
        if is_d {
            let old = self
                .mem
                .read_u64(addr)
                .map_err(|_| acc_fault(false, addr))?;
            let new = amo_compute64(insn.op, old, src);
            self.mem
                .write_u64(addr, new)
                .map_err(|_| acc_fault(true, addr))?;
            self.set_x(insn.rd, old);
        } else {
            let old = self
                .mem
                .read_u32(addr)
                .map_err(|_| acc_fault(false, addr))?;
            let new = amo_compute32(insn.op, old, src as u32);
            self.mem
                .write_u32(addr, new)
                .map_err(|_| acc_fault(true, addr))?;
            self.set_x(insn.rd, old as i32 as i64 as u64);
        }
        Ok(())
    }

    fn exec_amocas(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = self.x(insn.rs1) & self.xmask();
        match insn.op {
            Op::AmocasW => {
                if addr % 4 != 0 {
                    return Err(Trap {
                        cause: cause::STORE_MISALIGNED,
                        tval: addr,
                    });
                }
                let old = self
                    .mem
                    .read_u32(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                if old == self.x(insn.rd) as u32 {
                    self.mem
                        .write_u32(addr, self.x(insn.rs2) as u32)
                        .map_err(|_| acc_fault(true, addr))?;
                }
                self.set_x(insn.rd, old as i32 as i64 as u64);
            }
            Op::AmocasD => {
                if addr % 8 != 0 {
                    return Err(Trap {
                        cause: cause::STORE_MISALIGNED,
                        tval: addr,
                    });
                }
                let old = self
                    .mem
                    .read_u64(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                if old == self.x(insn.rd) {
                    self.mem
                        .write_u64(addr, self.x(insn.rs2))
                        .map_err(|_| acc_fault(true, addr))?;
                }
                self.set_x(insn.rd, old);
            }
            Op::AmocasQ => {
                if addr % 16 != 0 {
                    return Err(Trap {
                        cause: cause::STORE_MISALIGNED,
                        tval: addr,
                    });
                }
                let cmp = if insn.rd == 0 {
                    0
                } else {
                    (self.x(insn.rd) as u128) | ((self.x(insn.rd.wrapping_add(1)) as u128) << 64)
                };
                let new = if insn.rs2 == 0 {
                    0
                } else {
                    (self.x(insn.rs2) as u128) | ((self.x(insn.rs2.wrapping_add(1)) as u128) << 64)
                };
                let mut old_bytes = [0u8; 16];
                self.mem
                    .read(addr, &mut old_bytes)
                    .map_err(|_| acc_fault(false, addr))?;
                let old = u128::from_le_bytes(old_bytes);
                if old == cmp {
                    self.mem
                        .write(addr, &new.to_le_bytes())
                        .map_err(|_| acc_fault(true, addr))?;
                }
                if insn.rd != 0 {
                    self.set_x(insn.rd, old as u64);
                    self.set_x(insn.rd.wrapping_add(1), (old >> 64) as u64);
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn exec_zcmp_stack(&mut self, insn: &Insn, _pc: u64) -> Result<(), Trap> {
        let Some(count) = zcmp_reg_count(insn.rd) else {
            return Err(Trap::illegal(insn.raw));
        };
        let slotsize = if self.rv32() { 4 } else { 8 };
        let stack_adj = insn.imm as u64;
        match insn.op {
            Op::CmPush => {
                let old_sp = self.x(2);
                let new_sp = old_sp.wrapping_sub(stack_adj) & self.xmask();
                for slot in 0..count {
                    let reg =
                        zcmp_reg_at(count - 1 - slot).expect("slot checked by zcmp_reg_count");
                    let off = stack_adj.wrapping_sub(((slot + 1) * slotsize) as u64);
                    self.store(new_sp, off, self.x(reg), slotsize)?;
                }
                self.set_x(2, new_sp);
            }
            Op::CmPop | Op::CmPopRetz | Op::CmPopRet => {
                let sp = self.x(2);
                let mut restored_ra = self.x(1);
                for slot in 0..count {
                    let reg =
                        zcmp_reg_at(count - 1 - slot).expect("slot checked by zcmp_reg_count");
                    let off = stack_adj.wrapping_sub(((slot + 1) * slotsize) as u64);
                    let addr = sp.wrapping_add(off) & self.xmask();
                    let val = if slotsize == 8 {
                        self.mem.read_u64(addr).map_err(|_| Trap {
                            cause: cause::LOAD_ACCESS_FAULT,
                            tval: addr,
                        })?
                    } else {
                        self.mem.read_u32(addr).map_err(|_| Trap {
                            cause: cause::LOAD_ACCESS_FAULT,
                            tval: addr,
                        })? as u64
                    };
                    if reg == 1 {
                        restored_ra = val;
                    }
                    self.set_x(reg, val);
                }
                self.set_x(2, sp.wrapping_add(stack_adj));
                if matches!(insn.op, Op::CmPopRetz) {
                    self.set_x(10, 0);
                }
                if matches!(insn.op, Op::CmPopRet | Op::CmPopRetz) {
                    self.pc = restored_ra & !1 & self.xmask();
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn exec_zcmt(&mut self, insn: &Insn, pc: u64) -> Result<(), Trap> {
        if self.jvt & 0x3f != 0 {
            return Err(Trap::illegal(insn.raw));
        }
        let entry_size = if self.rv32() { 4 } else { 8 };
        let addr = (self.jvt & !0x3f)
            .wrapping_add((insn.imm as u64).wrapping_mul(entry_size as u64))
            & self.xmask();
        let target = if entry_size == 8 {
            self.mem.read_u64(addr).map_err(|_| Trap {
                cause: cause::INSTR_ACCESS_FAULT,
                tval: addr,
            })?
        } else {
            self.mem.read_u32(addr).map_err(|_| Trap {
                cause: cause::INSTR_ACCESS_FAULT,
                tval: addr,
            })? as u64
        };
        if matches!(insn.op, Op::CmJalt) {
            self.set_x(1, pc.wrapping_add(insn.len as u64));
        }
        self.pc = target & !1 & self.xmask();
        Ok(())
    }

    // ---------------------------------------------------------------
    // V: vector element access and the data-path execution.
    // ---------------------------------------------------------------

    /// SEW (element width) in bytes from the current `vtype`.
    #[inline]
    fn sew_bytes(&self) -> usize {
        1usize << ((self.vtype >> 3) & 0x7)
    }
    /// VLMAX (maximum element count) for the current `vtype`.
    #[inline]
    fn vlmax_elems(&self) -> usize {
        let sew = 8u64 << ((self.vtype >> 3) & 0x7);
        (match self.vtype & 0x7 {
            0 => VLEN / sew,
            1 => VLEN * 2 / sew,
            2 => VLEN * 4 / sew,
            3 => VLEN * 8 / sew,
            5 => VLEN / 8 / sew,
            6 => VLEN / 4 / sew,
            7 => VLEN / 2 / sew,
            _ => 0,
        }) as usize
    }
    /// Read element `e` (of `eb` bytes) from vector register group `vreg`.
    #[inline]
    fn velem(&self, vreg: u8, e: usize, eb: usize) -> u64 {
        let off = vreg as usize * VLENB as usize + e * eb;
        let mut buf = [0u8; 8];
        if off + eb <= self.v.len() {
            buf[..eb].copy_from_slice(&self.v[off..off + eb]);
        }
        u64::from_le_bytes(buf)
    }
    #[inline]
    fn set_velem(&mut self, vreg: u8, e: usize, eb: usize, val: u64) {
        let off = vreg as usize * VLENB as usize + e * eb;
        if off + eb <= self.v.len() {
            self.v[off..off + eb].copy_from_slice(&val.to_le_bytes()[..eb]);
        }
    }
    /// Mask bit `e` of `v0`.
    #[inline]
    fn vmask_bit(&self, e: usize) -> bool {
        (self.v[e / 8] >> (e % 8)) & 1 != 0
    }
    /// Mask bit `e` of an arbitrary vector register `vreg`.
    #[inline]
    fn vbit(&self, vreg: u8, e: usize) -> bool {
        let byte = vreg as usize * VLENB as usize + e / 8;
        byte < self.v.len() && (self.v[byte] >> (e % 8)) & 1 != 0
    }
    /// Set/clear mask bit `e` of vector register `vreg`.
    #[inline]
    fn set_vmask_bit(&mut self, vreg: u8, e: usize, val: bool) {
        let byte = vreg as usize * VLENB as usize + e / 8;
        if byte < self.v.len() {
            if val {
                self.v[byte] |= 1 << (e % 8);
            } else {
                self.v[byte] &= !(1 << (e % 8));
            }
        }
    }
    #[inline]
    fn sew_mask(eb: usize) -> u64 {
        if eb >= 8 {
            u64::MAX
        } else {
            (1u64 << (eb * 8)) - 1
        }
    }

    /// Execute a vector data-path instruction. The tail/mask policy is
    /// undisturbed (only active body elements are written).
    fn exec_vector(&mut self, insn: &Insn) -> Result<(), Trap> {
        // Whole-register loads/stores do not depend on vtype and remain legal
        // while vill is set. Every other vector data operation does depend on
        // vtype and must trap without changing vstart.
        if self.vtype >> (self.xbits() - 1) & 1 != 0 && !matches!(insn.op, Op::Vlre | Op::Vsre) {
            return Err(Trap::illegal(insn.raw));
        }
        let vm = (insn.raw >> 25) & 1 != 0; // 1 = unmasked
        vector_validation::validate(self, insn, vm)?;
        let vd = insn.rd;
        let vs2 = insn.rs2;
        let vstart = self.vstart as usize;
        let vl = self.vl as usize;

        match insn.op {
            Op::Vle
            | Op::Vse
            | Op::Vlse
            | Op::Vsse
            | Op::Vlxei
            | Op::Vsxei
            | Op::Vleff
            | Op::Vlseg
            | Op::Vsseg
            | Op::Vlm
            | Op::Vsm
            | Op::Vlre
            | Op::Vsre => self.exec_vector_memory(insn, vm, vd, vstart, vl)?,
            Op::Vmerge => {
                // vmerge.v*m (vm=0): per-element select via v0; vmv.v.* (vm=1):
                // splat the second operand. Both write every body element.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1) & mask,
                    0b011 => sext5(insn.rs1) & mask,
                    _ => 0,
                };
                for e in vstart..vl {
                    let b = if insn.funct3 == 0b000 {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let r = if vm || self.vmask_bit(e) {
                        b
                    } else {
                        self.velem(vs2, e, eb)
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
            }
            Op::Vadd
            | Op::Vsub
            | Op::Vrsub
            | Op::Vand
            | Op::Vor
            | Op::Vxor
            | Op::Vminu
            | Op::Vmin
            | Op::Vmaxu
            | Op::Vmax
            | Op::Vsll
            | Op::Vsrl
            | Op::Vsra => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let bits = (eb * 8) as u32;
                // Operand form: OPIVV(0) uses vs1, OPIVX(4) a scalar, OPIVI(3) imm.
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1) & mask,
                    0b011 => sext5(insn.rs1) & mask,
                    _ => 0,
                };
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let b = if insn.funct3 == 0b000 {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let sa = sext_sew(a, eb);
                    let sb = sext_sew(b, eb);
                    // Shift amount: OPIVI uses the unsigned 5-bit field, else the
                    // low bits of the operand.
                    let sh = if insn.funct3 == 0b011 {
                        insn.rs1 as u32 & (bits - 1)
                    } else {
                        (b as u32) & (bits - 1)
                    };
                    let r = match insn.op {
                        Op::Vadd => a.wrapping_add(b),
                        Op::Vsub => a.wrapping_sub(b),
                        Op::Vrsub => b.wrapping_sub(a),
                        Op::Vand => a & b,
                        Op::Vor => a | b,
                        Op::Vxor => a ^ b,
                        Op::Vminu => a.min(b),
                        Op::Vmaxu => a.max(b),
                        Op::Vmin => {
                            if sa <= sb {
                                a
                            } else {
                                b
                            }
                        }
                        Op::Vmax => {
                            if sa >= sb {
                                a
                            } else {
                                b
                            }
                        }
                        Op::Vsll => a << sh,
                        Op::Vsrl => (a & mask) >> sh,
                        Op::Vsra => (sa >> sh) as u64,
                        _ => unreachable!(),
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
            }
            Op::Vmul
            | Op::Vmulh
            | Op::Vmulhu
            | Op::Vmulhsu
            | Op::Vdivu
            | Op::Vdiv
            | Op::Vremu
            | Op::Vrem => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let bits = (eb * 8) as u32;
                let is_vv = insn.funct3 == 0b010; // OPMVV vs OPMVX
                let scalar = self.x(insn.rs1) & mask;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let b = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let r = match insn.op {
                        Op::Vmul => a.wrapping_mul(b),
                        Op::Vmulhu => vmulh_u(a, b, bits),
                        Op::Vmulh => vmulh_s(a, b, eb, bits),
                        Op::Vmulhsu => vmulh_su(a, b, eb, bits),
                        Op::Vdivu => {
                            if b == 0 {
                                mask
                            } else {
                                a / b
                            }
                        }
                        Op::Vremu => {
                            if b == 0 {
                                a
                            } else {
                                a % b
                            }
                        }
                        Op::Vdiv => vdiv_sew(a, b, eb, bits, false),
                        Op::Vrem => vdiv_sew(a, b, eb, bits, true),
                        _ => unreachable!(),
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
            }
            Op::Vredsum
            | Op::Vredand
            | Op::Vredor
            | Op::Vredxor
            | Op::Vredminu
            | Op::Vredmin
            | Op::Vredmaxu
            | Op::Vredmax => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                // Accumulator seeds from vs1[0]; fold in active vs2 elements.
                let mut acc = self.velem(insn.rs1, 0, eb);
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let x = self.velem(vs2, e, eb);
                    acc = match insn.op {
                        Op::Vredsum => acc.wrapping_add(x),
                        Op::Vredand => acc & x,
                        Op::Vredor => acc | x,
                        Op::Vredxor => acc ^ x,
                        Op::Vredminu => acc.min(x),
                        Op::Vredmaxu => acc.max(x),
                        Op::Vredmin => {
                            if sext_sew(x, eb) < sext_sew(acc, eb) {
                                x
                            } else {
                                acc
                            }
                        }
                        Op::Vredmax => {
                            if sext_sew(x, eb) > sext_sew(acc, eb) {
                                x
                            } else {
                                acc
                            }
                        }
                        _ => unreachable!(),
                    } & mask;
                }
                // vl == 0 leaves vd[0] undisturbed; otherwise write the scalar result.
                if vl > vstart {
                    self.set_velem(vd, 0, eb, acc & mask);
                }
            }
            Op::Vmseq
            | Op::Vmsne
            | Op::Vmsltu
            | Op::Vmslt
            | Op::Vmsleu
            | Op::Vmsle
            | Op::Vmsgtu
            | Op::Vmsgt => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let source = self.vector_snapshot();
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1) & mask,
                    0b011 => sext5(insn.rs1) & mask,
                    _ => 0,
                };
                for e in vstart..vl {
                    if !vm && !Self::snapshot_mask_bit(&source, e) {
                        continue; // masked-off: undisturbed
                    }
                    let a = Self::snapshot_velem(&source, vs2, e, eb);
                    let b = if insn.funct3 == 0b000 {
                        Self::snapshot_velem(&source, insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let (sa, sb) = (sext_sew(a, eb), sext_sew(b, eb));
                    let r = match insn.op {
                        Op::Vmseq => a == b,
                        Op::Vmsne => a != b,
                        Op::Vmsltu => a < b,
                        Op::Vmslt => sa < sb,
                        Op::Vmsleu => a <= b,
                        Op::Vmsle => sa <= sb,
                        Op::Vmsgtu => a > b,
                        Op::Vmsgt => sa > sb,
                        _ => unreachable!(),
                    };
                    self.set_vmask_bit(vd, e, r);
                }
            }
            Op::Vfadd
            | Op::Vfsub
            | Op::Vfrsub
            | Op::Vfmul
            | Op::Vfdiv
            | Op::Vfrdiv
            | Op::Vfmin
            | Op::Vfmax
            | Op::Vfsgnj
            | Op::Vfsgnjn
            | Op::Vfsgnjx
            | Op::Vfsqrt => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let rm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let is_vv = insn.funct3 == 0b001; // OPFVV vs OPFVF
                let scalar = match eb {
                    2 => self.h(insn.rs1),
                    4 => self.s32(insn.rs1),
                    _ => self.f(insn.rs1),
                };
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let r = if insn.op == Op::Vfsqrt {
                        super::float::sf_sqrt(fmt_eb(eb), a, rm, &mut flags)
                    } else {
                        let b = if is_vv {
                            self.velem(insn.rs1, e, eb)
                        } else {
                            scalar
                        };
                        vfp_bin(insn.op, eb, a, b, rm, &mut flags)
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
                self.accrue(flags);
            }
            Op::Vfmacc
            | Op::Vfnmacc
            | Op::Vfmsac
            | Op::Vfnmsac
            | Op::Vfmadd
            | Op::Vfnmadd
            | Op::Vfmsub
            | Op::Vfnmsub => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let rm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let is_vv = insn.funct3 == 0b001;
                let scalar = match eb {
                    2 => self.h(insn.rs1),
                    4 => self.s32(insn.rs1),
                    _ => self.f(insn.rs1),
                };
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let src = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let vs2e = self.velem(vs2, e, eb);
                    let vde = self.velem(vd, e, eb);
                    let r = vfp_fma(insn.op, eb, src, vs2e, vde, rm, &mut flags);
                    self.set_velem(vd, e, eb, r & mask);
                }
                self.accrue(flags);
            }
            Op::Vfredusum | Op::Vfredosum | Op::Vfredmin | Op::Vfredmax => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let rm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let mut flags = 0u32;
                let mut acc = self.velem(insn.rs1, 0, eb); // vs1[0] seed
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let x = self.velem(vs2, e, eb);
                    let sub = match insn.op {
                        Op::Vfredusum | Op::Vfredosum => Op::Vfadd,
                        Op::Vfredmin => Op::Vfmin,
                        _ => Op::Vfmax,
                    };
                    acc = vfp_bin(sub, eb, acc, x, rm, &mut flags) & mask;
                }
                if vl > vstart {
                    self.set_velem(vd, 0, eb, acc & mask);
                }
                self.accrue(flags);
            }
            Op::VfcvtXuF
            | Op::VfcvtXF
            | Op::VfcvtFXu
            | Op::VfcvtFX
            | Op::VfcvtRtzXuF
            | Op::VfcvtRtzXF => {
                // Single-width FP <-> integer conversions at SEW.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let frm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let to_int = matches!(
                    insn.op,
                    Op::VfcvtXuF | Op::VfcvtXF | Op::VfcvtRtzXuF | Op::VfcvtRtzXF
                );
                let signed = matches!(insn.op, Op::VfcvtXF | Op::VfcvtRtzXF | Op::VfcvtFX);
                let rm = if matches!(insn.op, Op::VfcvtRtzXuF | Op::VfcvtRtzXF) {
                    RoundingMode::Rtz
                } else {
                    frm
                };
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let r = if to_int {
                        match eb {
                            2 => super::float::ftoi(
                                super::float::h_widen(a as u16),
                                signed,
                                16,
                                rm,
                                &mut flags,
                            ),
                            4 => super::float::ftoi(
                                f32::from_bits(a as u32),
                                signed,
                                32,
                                rm,
                                &mut flags,
                            ),
                            _ => super::float::ftoi(f64::from_bits(a), signed, 64, rm, &mut flags),
                        }
                    } else {
                        let v: i128 = if signed {
                            sext_sew(a, eb) as i128
                        } else {
                            a as i128
                        };
                        super::float::itof_fmt(fmt_eb(eb), v, frm, &mut flags)
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
                self.accrue(flags);
            }
            Op::Vwredsumu | Op::Vwredsum => {
                // Widening integer sum reduction: 2*SEW accumulator seeded by vs1[0].
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let web = eb * 2;
                let wmask = Self::sew_mask(web);
                let signed = insn.op == Op::Vwredsum;
                let mut acc = self.velem(insn.rs1, 0, web);
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let x = self.velem(vs2, e, eb);
                    let xe = if signed { sext_sew(x, eb) as u64 } else { x };
                    acc = acc.wrapping_add(xe) & wmask;
                }
                if vl > vstart {
                    self.set_velem(vd, 0, web, acc & wmask);
                }
            }
            Op::Vfwredusum | Op::Vfwredosum => {
                // Widening FP sum reduction: 2*SEW accumulator seeded by vs1[0].
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let web = eb * 2;
                let wmask = Self::sew_mask(web);
                let frm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let mut flags = 0u32;
                let mut acc = self.velem(insn.rs1, 0, web);
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let x = super::float::fcvt_round(
                        fmt_eb(eb),
                        fmt_eb(web),
                        self.velem(vs2, e, eb),
                        frm,
                        &mut flags,
                    );
                    acc = vfp_bin(Op::Vfadd, web, acc, x, frm, &mut flags) & wmask;
                }
                if vl > vstart {
                    self.set_velem(vd, 0, web, acc & wmask);
                }
                self.accrue(flags);
            }
            Op::Vfwmacc | Op::Vfwnmacc | Op::Vfwmsac | Op::Vfwnmsac => {
                // Widening FP FMA: vs1/vs2 widened to 2*SEW, fused into 2*SEW vd.
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let web = eb * 2;
                let wmask = Self::sew_mask(web);
                let frm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let is_vv = insn.funct3 == 0b001;
                let base = match insn.op {
                    Op::Vfwmacc => Op::Vfmacc,
                    Op::Vfwnmacc => Op::Vfnmacc,
                    Op::Vfwmsac => Op::Vfmsac,
                    _ => Op::Vfnmsac,
                };
                let scalar = match eb {
                    2 => self.h(insn.rs1),
                    _ => self.s32(insn.rs1),
                };
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let s_narrow = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let src = super::float::fcvt_round(
                        fmt_eb(eb),
                        fmt_eb(web),
                        s_narrow,
                        frm,
                        &mut flags,
                    );
                    let v2 = super::float::fcvt_round(
                        fmt_eb(eb),
                        fmt_eb(web),
                        self.velem(vs2, e, eb),
                        frm,
                        &mut flags,
                    );
                    let vde = self.velem(vd, e, web);
                    let r = vfp_fma(base, web, src, v2, vde, frm, &mut flags);
                    self.set_velem(vd, e, web, r & wmask);
                }
                self.accrue(flags);
            }
            Op::Vfwadd | Op::Vfwsub | Op::Vfwmul | Op::VfwaddW | Op::VfwsubW => {
                // Widening FP arithmetic: operands widened to 2*SEW, op at 2*SEW.
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let web = eb * 2;
                let wmask = Self::sew_mask(web);
                let frm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let is_vv = insn.funct3 == 0b001;
                let wide_vs2 = matches!(insn.op, Op::VfwaddW | Op::VfwsubW);
                let scalar = match eb {
                    2 => self.h(insn.rs1),
                    _ => self.s32(insn.rs1),
                };
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let aw = if wide_vs2 {
                        self.velem(vs2, e, web)
                    } else {
                        super::float::fcvt_round(
                            fmt_eb(eb),
                            fmt_eb(web),
                            self.velem(vs2, e, eb),
                            frm,
                            &mut flags,
                        )
                    };
                    let braw = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let bw =
                        super::float::fcvt_round(fmt_eb(eb), fmt_eb(web), braw, frm, &mut flags);
                    let r = match insn.op {
                        Op::Vfwadd | Op::VfwaddW => {
                            vfp_bin(Op::Vfadd, web, aw, bw, frm, &mut flags)
                        }
                        Op::Vfwsub | Op::VfwsubW => {
                            vfp_bin(Op::Vfsub, web, aw, bw, frm, &mut flags)
                        }
                        _ => vfp_bin(Op::Vfmul, web, aw, bw, frm, &mut flags),
                    };
                    self.set_velem(vd, e, web, r & wmask);
                }
                self.accrue(flags);
            }
            Op::VfwcvtXuF
            | Op::VfwcvtXF
            | Op::VfwcvtFXu
            | Op::VfwcvtFX
            | Op::VfwcvtFF
            | Op::VfwcvtRtzXuF
            | Op::VfwcvtRtzXF => {
                // Widening conversions: SEW source -> 2*SEW result.
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let web = eb * 2;
                let wmask = Self::sew_mask(web);
                let frm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let r = match insn.op {
                        Op::VfwcvtXuF | Op::VfwcvtXF | Op::VfwcvtRtzXuF | Op::VfwcvtRtzXF => {
                            let signed = matches!(insn.op, Op::VfwcvtXF | Op::VfwcvtRtzXF);
                            let rm = if matches!(insn.op, Op::VfwcvtRtzXuF | Op::VfwcvtRtzXF) {
                                RoundingMode::Rtz
                            } else {
                                frm
                            };
                            match eb {
                                2 => super::float::ftoi(
                                    super::float::h_widen(a as u16),
                                    signed,
                                    32,
                                    rm,
                                    &mut flags,
                                ),
                                _ => super::float::ftoi(
                                    f32::from_bits(a as u32),
                                    signed,
                                    64,
                                    rm,
                                    &mut flags,
                                ),
                            }
                        }
                        Op::VfwcvtFXu | Op::VfwcvtFX => {
                            let v: i128 = if insn.op == Op::VfwcvtFX {
                                sext_sew(a, eb) as i128
                            } else {
                                a as i128
                            };
                            super::float::itof_fmt(fmt_eb(web), v, frm, &mut flags)
                        }
                        _ => super::float::fcvt_round(fmt_eb(eb), fmt_eb(web), a, frm, &mut flags),
                    };
                    self.set_velem(vd, e, web, r & wmask);
                }
                self.accrue(flags);
            }
            Op::VfncvtXuF
            | Op::VfncvtXF
            | Op::VfncvtFXu
            | Op::VfncvtFX
            | Op::VfncvtFF
            | Op::VfncvtRodFF
            | Op::VfncvtRtzXuF
            | Op::VfncvtRtzXF => self.exec_vector_narrow_conversion(insn, vm)?,
            Op::Vmfeq | Op::Vmfne | Op::Vmflt | Op::Vmfle | Op::Vmfgt | Op::Vmfge => {
                let eb = self.sew_bytes();
                let is_vv = insn.funct3 == 0b001;
                let source = self.vector_snapshot();
                let scalar = match eb {
                    2 => self.h(insn.rs1),
                    4 => self.s32(insn.rs1),
                    _ => self.f(insn.rs1),
                };
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !Self::snapshot_mask_bit(&source, e) {
                        continue;
                    }
                    let a = Self::snapshot_velem(&source, vs2, e, eb);
                    let b = if is_vv {
                        Self::snapshot_velem(&source, insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let r = vfp_cmp(insn.op, eb, a, b, &mut flags);
                    self.set_vmask_bit(vd, e, r);
                }
                self.accrue(flags);
            }
            Op::VzextVf2
            | Op::VsextVf2
            | Op::VzextVf4
            | Op::VsextVf4
            | Op::VzextVf8
            | Op::VsextVf8 => {
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let (factor, signed) = match insn.op {
                    Op::VzextVf2 => (2usize, false),
                    Op::VsextVf2 => (2, true),
                    Op::VzextVf4 => (4, false),
                    Op::VsextVf4 => (4, true),
                    Op::VzextVf8 => (8, false),
                    _ => (8, true),
                };
                if eb < factor {
                    return Err(Trap::illegal(insn.raw)); // SEW too narrow for the source
                }
                let neb = eb / factor; // narrow source element width
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let src = self.velem(vs2, e, neb);
                    let v = if signed {
                        sext_sew(src, neb) as u64
                    } else {
                        src
                    };
                    self.set_velem(vd, e, eb, v & mask);
                }
            }
            Op::Vmand
            | Op::Vmnand
            | Op::Vmandn
            | Op::Vmxor
            | Op::Vmor
            | Op::Vmnor
            | Op::Vmorn
            | Op::Vmxnor => {
                // Mask-register logicals: vd.bit[i] = vs2.bit[i] OP vs1.bit[i],
                // always unmasked, over the body [vstart, vl). The vm=0 form is
                // reserved and must raise an illegal-instruction trap.
                if !vm {
                    return Err(Trap::illegal(insn.raw));
                }
                for e in vstart..vl {
                    let a = self.vbit(vs2, e);
                    let b = self.vbit(insn.rs1, e);
                    let r = match insn.op {
                        Op::Vmand => a & b,
                        Op::Vmnand => !(a & b),
                        Op::Vmandn => a & !b,
                        Op::Vmxor => a ^ b,
                        Op::Vmor => a | b,
                        Op::Vmnor => !(a | b),
                        Op::Vmorn => a | !b,
                        Op::Vmxnor => !(a ^ b),
                        _ => unreachable!(),
                    };
                    self.set_vmask_bit(vd, e, r);
                }
            }
            Op::Vslideup => {
                // vd[i] = vs2[i - offset] for i >= offset; lower elements untouched.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let offset = if insn.funct3 == 0b011 {
                    insn.rs1 as u64
                } else {
                    self.x(insn.rs1)
                };
                let start = vstart.max(offset as usize);
                for e in start..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let v = self.velem(vs2, e - offset as usize, eb);
                    self.set_velem(vd, e, eb, v & mask);
                }
            }
            Op::Vslidedown => {
                // vd[i] = vs2[i + offset], or 0 when i + offset >= VLMAX.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let vlmax = self.vlmax_elems() as u64;
                let offset = if insn.funct3 == 0b011 {
                    insn.rs1 as u64
                } else {
                    self.x(insn.rs1)
                };
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    // A guest-controlled scalar offset can be huge; saturate so
                    // an overflowing i+offset stays >= VLMAX and zeroes the lane
                    // rather than wrapping back into an in-range source index.
                    let src = (e as u64).saturating_add(offset);
                    let v = if src < vlmax {
                        self.velem(vs2, src as usize, eb)
                    } else {
                        0
                    };
                    self.set_velem(vd, e, eb, v & mask);
                }
            }
            Op::Vslide1up | Op::Vfslide1up => {
                // vd[0] = scalar; vd[i] = vs2[i-1] for i >= 1.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let scalar = if insn.op == Op::Vfslide1up {
                    match eb {
                        2 => self.h(insn.rs1),
                        4 => self.s32(insn.rs1),
                        _ => self.f(insn.rs1),
                    }
                } else {
                    self.x(insn.rs1)
                } & mask;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let v = if e == 0 {
                        scalar
                    } else {
                        self.velem(vs2, e - 1, eb)
                    };
                    self.set_velem(vd, e, eb, v & mask);
                }
            }
            Op::Vslide1down | Op::Vfslide1down => {
                // vd[i] = vs2[i+1] for i < vl-1; vd[vl-1] = scalar.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let scalar = if insn.op == Op::Vfslide1down {
                    match eb {
                        2 => self.h(insn.rs1),
                        4 => self.s32(insn.rs1),
                        _ => self.f(insn.rs1),
                    }
                } else {
                    self.x(insn.rs1)
                } & mask;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let v = if e + 1 < vl {
                        self.velem(vs2, e + 1, eb)
                    } else {
                        scalar
                    };
                    self.set_velem(vd, e, eb, v & mask);
                }
            }
            Op::Vwaddu
            | Op::Vwadd
            | Op::Vwsubu
            | Op::Vwsub
            | Op::VwadduW
            | Op::VwaddW
            | Op::VwsubuW
            | Op::VwsubW => {
                // Widening add/subtract: 2*SEW result. `.w` forms read a wide vs2.
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw)); // 2*SEW must fit ELEN=64
                }
                let web = eb * 2;
                let wmask = Self::sew_mask(web);
                let signed = matches!(insn.op, Op::Vwadd | Op::Vwsub | Op::VwaddW | Op::VwsubW);
                let sub = matches!(insn.op, Op::Vwsubu | Op::Vwsub | Op::VwsubuW | Op::VwsubW);
                let wide_vs2 =
                    matches!(insn.op, Op::VwadduW | Op::VwaddW | Op::VwsubuW | Op::VwsubW);
                let is_vv = insn.funct3 == 0b010;
                let scalar = self.x(insn.rs1) & Self::sew_mask(eb);
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a: i128 = if wide_vs2 {
                        let raw = self.velem(vs2, e, web);
                        if signed {
                            sext_sew(raw, web) as i128
                        } else {
                            raw as i128
                        }
                    } else {
                        let raw = self.velem(vs2, e, eb);
                        if signed {
                            sext_sew(raw, eb) as i128
                        } else {
                            raw as i128
                        }
                    };
                    let braw = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let b: i128 = if signed {
                        sext_sew(braw, eb) as i128
                    } else {
                        braw as i128
                    };
                    let r = if sub { a - b } else { a + b };
                    self.set_velem(vd, e, web, (r as u64) & wmask);
                }
            }
            Op::Vwmulu
            | Op::Vwmulsu
            | Op::Vwmul
            | Op::Vwmaccu
            | Op::Vwmacc
            | Op::Vwmaccsu
            | Op::Vwmaccus => {
                // Widening multiply / multiply-accumulate: 2*SEW product into vd group.
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let web = eb * 2;
                let wmask = Self::sew_mask(web);
                // Signedness of (a = vs2, b = vs1/rs1 multiplier).
                let (a_signed, b_signed) = match insn.op {
                    Op::Vwmulu | Op::Vwmaccu => (false, false),
                    Op::Vwmul | Op::Vwmacc => (true, true),
                    Op::Vwmulsu | Op::Vwmaccus => (true, false),
                    _ => (false, true), // Vwmaccsu
                };
                let is_vv = insn.funct3 == 0b010;
                let is_mac = matches!(
                    insn.op,
                    Op::Vwmaccu | Op::Vwmacc | Op::Vwmaccsu | Op::Vwmaccus
                );
                let scalar = self.x(insn.rs1) & Self::sew_mask(eb);
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let araw = self.velem(vs2, e, eb);
                    let braw = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let av: i128 = if a_signed {
                        sext_sew(araw, eb) as i128
                    } else {
                        araw as i128
                    };
                    let bv: i128 = if b_signed {
                        sext_sew(braw, eb) as i128
                    } else {
                        braw as i128
                    };
                    let mut prod = av * bv;
                    if is_mac {
                        prod = prod.wrapping_add(self.velem(vd, e, web) as i128);
                    }
                    self.set_velem(vd, e, web, (prod as u64) & wmask);
                }
            }
            Op::ThVmaqa | Op::ThVmaqau | Op::ThVmaqasu | Op::ThVmaqaus => {
                // XTheadVdot accumulates four 8-bit products into each 32-bit
                // destination lane. `vl` counts destination lanes, while v0 mask
                // bits gate the individual 8-bit source products.
                let eb = self.sew_bytes();
                if eb != 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let scalar = ((insn.raw >> 26) & 1) != 0;
                let (src1_signed, src2_signed) = match insn.op {
                    Op::ThVmaqa => (true, true),
                    Op::ThVmaqau => (false, false),
                    Op::ThVmaqasu => (true, false),
                    Op::ThVmaqaus => (false, true),
                    _ => unreachable!(),
                };
                for e in vstart..vl {
                    let a = if scalar {
                        self.x(insn.rs1) as u32
                    } else {
                        self.velem(insn.rs1, e, eb) as u32
                    };
                    let b = self.velem(vs2, e, eb) as u32;
                    let mut sum = 0i64;
                    for byte in 0..4 {
                        if vm || self.vmask_bit(e * 4 + byte) {
                            let av = th_vdot_byte((a >> (byte * 8)) as u8, src1_signed);
                            let bv = th_vdot_byte((b >> (byte * 8)) as u8, src2_signed);
                            sum += av * bv;
                        }
                    }
                    let acc = self.velem(vd, e, eb) as u32;
                    self.set_velem(vd, e, eb, acc.wrapping_add(sum as u32) as u64);
                }
            }
            Op::Vnsrl | Op::Vnsra | Op::Vnclipu | Op::Vnclip => {
                // Narrowing shift/clip: 2*SEW source vs2 -> SEW result.
                let eb = self.sew_bytes();
                if eb > 4 {
                    return Err(Trap::illegal(insn.raw));
                }
                let web = eb * 2;
                let mask = Self::sew_mask(eb);
                let bits = (eb * 8) as u32;
                let sh_mask = (web * 8 - 1) as u32;
                let vxrm = self.vxrm;
                let smax = (1i128 << (bits - 1)) - 1;
                let smin = -(1i128 << (bits - 1));
                let is_clip = matches!(insn.op, Op::Vnclipu | Op::Vnclip);
                let signed = matches!(insn.op, Op::Vnsra | Op::Vnclip);
                let is_vv = insn.funct3 == 0b000;
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1),
                    0b011 => insn.rs1 as u64,
                    _ => 0,
                };
                let mut sat = false;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let aw = self.velem(vs2, e, web);
                    let sh = (if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    }) as u32
                        & sh_mask;
                    let r = if !is_clip {
                        if signed {
                            (sext_sew(aw, web) >> sh) as u64
                        } else {
                            aw >> sh
                        }
                    } else if !signed {
                        let v = (aw >> sh) as u128 + round_incr(aw as u128, sh, vxrm);
                        if v > mask as u128 {
                            sat = true;
                            mask
                        } else {
                            v as u64
                        }
                    } else {
                        let sa = sext_sew(aw, web) as i128;
                        let v = (sa >> sh) + round_incr(sa as u128, sh, vxrm) as i128;
                        if v > smax {
                            sat = true;
                            smax as u64
                        } else if v < smin {
                            sat = true;
                            smin as u64
                        } else {
                            v as u64
                        }
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
                if sat {
                    self.vxsat = 1;
                }
            }
            Op::Vssrl | Op::Vssra => {
                // Scaling shift right by (amount & (SEW-1)), rounded per vxrm.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let bits = (eb * 8) as u32;
                let shmask = bits - 1;
                let vxrm = self.vxrm;
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1),
                    0b011 => insn.rs1 as u64, // unsigned 5-bit shift immediate
                    _ => 0,
                };
                let is_vv = insn.funct3 == 0b000;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let sh = (if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    }) as u32
                        & shmask;
                    let incr = round_incr(a as u128, sh, vxrm);
                    let res = if insn.op == Op::Vssrl {
                        ((a >> sh) as u128 + incr) as u64
                    } else {
                        (sext_sew(a, eb) >> sh).wrapping_add(incr as i64) as u64
                    };
                    self.set_velem(vd, e, eb, res & mask);
                }
            }
            Op::Vsmul => {
                // Signed fractional multiply: (a*b) >> (SEW-1), rounded + saturated.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let bits = (eb * 8) as u32;
                let smax = (1i128 << (bits - 1)) - 1;
                let smin = -(1i128 << (bits - 1));
                let vxrm = self.vxrm;
                let is_vv = insn.funct3 == 0b000;
                let scalar = self.x(insn.rs1) & mask;
                let mut sat = false;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let b = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let prod = sext_sew(a, eb) as i128 * sext_sew(b, eb) as i128;
                    let incr = round_incr(prod as u128, bits - 1, vxrm) as i128;
                    let mut r = (prod >> (bits - 1)) + incr;
                    if r > smax {
                        r = smax;
                        sat = true;
                    } else if r < smin {
                        r = smin;
                        sat = true;
                    }
                    self.set_velem(vd, e, eb, r as u64 & mask);
                }
                if sat {
                    self.vxsat = 1;
                }
            }
            Op::Vaaddu | Op::Vaadd | Op::Vasubu | Op::Vasub => {
                // Averaging add/subtract: (a +/- b) >> 1, rounded per vxrm.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let bits = (eb * 8) as u32;
                let m2: u128 = if bits >= 64 {
                    u128::MAX
                } else {
                    (1u128 << (2 * bits)) - 1
                };
                let vxrm = self.vxrm;
                let is_vv = insn.funct3 == 0b010;
                let scalar = self.x(insn.rs1) & mask;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let b = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let res = match insn.op {
                        Op::Vaaddu => {
                            let v = a as u128 + b as u128;
                            ((v >> 1) + round_incr(v, 1, vxrm)) as u64
                        }
                        Op::Vasubu => {
                            let v = (a as u128).wrapping_sub(b as u128) & m2;
                            ((v >> 1) + round_incr(v, 1, vxrm)) as u64
                        }
                        Op::Vaadd => {
                            let v = sext_sew(a, eb) as i128 + sext_sew(b, eb) as i128;
                            ((v >> 1) + round_incr(v as u128, 1, vxrm) as i128) as u64
                        }
                        _ => {
                            let v = sext_sew(a, eb) as i128 - sext_sew(b, eb) as i128;
                            ((v >> 1) + round_incr(v as u128, 1, vxrm) as i128) as u64
                        }
                    };
                    self.set_velem(vd, e, eb, res & mask);
                }
            }
            Op::Vsaddu | Op::Vsadd | Op::Vssubu | Op::Vssub => {
                // Saturating fixed-point add/subtract; sets vxsat on clamp.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let bits = (eb * 8) as u32;
                let smax = (1i128 << (bits - 1)) - 1;
                let smin = -(1i128 << (bits - 1));
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1) & mask,
                    0b011 => sext5(insn.rs1) & mask,
                    _ => 0,
                };
                let is_vv = insn.funct3 == 0b000;
                let mut sat = false;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let b = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let (r, s) = match insn.op {
                        Op::Vsaddu => {
                            let full = a as u128 + b as u128;
                            if full > mask as u128 {
                                (mask, true)
                            } else {
                                (full as u64, false)
                            }
                        }
                        Op::Vssubu => {
                            if a < b {
                                (0, true)
                            } else {
                                (a - b, false)
                            }
                        }
                        Op::Vsadd => {
                            let sum = sext_sew(a, eb) as i128 + sext_sew(b, eb) as i128;
                            if sum > smax {
                                (smax as u64 & mask, true)
                            } else if sum < smin {
                                (smin as u64 & mask, true)
                            } else {
                                (sum as u64 & mask, false)
                            }
                        }
                        _ => {
                            let diff = sext_sew(a, eb) as i128 - sext_sew(b, eb) as i128;
                            if diff > smax {
                                (smax as u64 & mask, true)
                            } else if diff < smin {
                                (smin as u64 & mask, true)
                            } else {
                                (diff as u64 & mask, false)
                            }
                        }
                    };
                    self.set_velem(vd, e, eb, r & mask);
                    sat |= s;
                }
                if sat {
                    self.vxsat = 1;
                }
            }
            Op::Vadc | Op::Vsbc => {
                // vd[i] = vs2[i] +/- op[i] +/- v0.mask[i]; every body lane written.
                // These consume the v0 carry/borrow-in and are only defined in
                // the masked (vm=0) form with a non-v0 destination.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1) & mask,
                    0b011 => sext5(insn.rs1) & mask,
                    _ => 0,
                };
                let is_vv = insn.funct3 == 0b000;
                for e in vstart..vl {
                    let a = self.velem(vs2, e, eb);
                    let b = if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar
                    };
                    let cin = self.vmask_bit(e) as u64; // v0 carry/borrow-in
                    let r = if insn.op == Op::Vadc {
                        a.wrapping_add(b).wrapping_add(cin)
                    } else {
                        a.wrapping_sub(b).wrapping_sub(cin)
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
            }
            Op::Vmadc | Op::Vmsbc => {
                // vd.mask[i] = carry/borrow-out; carry-in from v0 only when vm == 0.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb) as u128;
                let source = self.vector_snapshot();
                let scalar = match insn.funct3 {
                    0b100 => self.x(insn.rs1) & Self::sew_mask(eb),
                    0b011 => sext5(insn.rs1) & Self::sew_mask(eb),
                    _ => 0,
                };
                let is_vv = insn.funct3 == 0b000;
                let use_cin = !vm;
                for e in vstart..vl {
                    let a = Self::snapshot_velem(&source, vs2, e, eb) as u128;
                    let b = if is_vv {
                        Self::snapshot_velem(&source, insn.rs1, e, eb)
                    } else {
                        scalar
                    } as u128;
                    let cin = if use_cin {
                        Self::snapshot_mask_bit(&source, e) as u128
                    } else {
                        0
                    };
                    let out = if insn.op == Op::Vmadc {
                        a + b + cin > mask
                    } else {
                        a < b + cin
                    };
                    self.set_vmask_bit(vd, e, out);
                }
            }
            Op::Vfrsqrt7 | Op::Vfrec7 => {
                // 7-bit reciprocal / reciprocal-sqrt estimates.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let rm = RoundingMode::from_bits(self.frm()).unwrap_or(RoundingMode::Rne);
                let mut flags = 0u32;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let a = self.velem(vs2, e, eb);
                    let r = if insn.op == Op::Vfrsqrt7 {
                        super::float::vfrsqrt7(fmt_eb(eb), a, &mut flags)
                    } else {
                        super::float::vfrec7(fmt_eb(eb), a, rm, &mut flags)
                    };
                    self.set_velem(vd, e, eb, r & mask);
                }
                self.accrue(flags);
            }
            Op::Vfclass => {
                // vd[i] = 10-bit IEEE class of vs2[i].
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let r = super::float::fclass_bits(fmt_eb(eb), self.velem(vs2, e, eb));
                    self.set_velem(vd, e, eb, r & mask);
                }
            }
            Op::Vmvr => {
                self.exec_whole_register_move(insn, vm)?;
            }
            Op::Vcompress => {
                // vcompress.vm is unmasked (vm=1), is not restartable (vstart
                // must be 0), and its destination group must not overlap the
                // source vs2 group or the single-register mask source vs1.
                let emul: u8 = match self.vtype & 0x7 {
                    1 => 2,
                    2 => 4,
                    3 => 8,
                    _ => 1, // LMUL=1 and all fractional LMULs occupy one register
                };
                let overlaps = |a: u8, an: u8, b: u8, bn: u8| a < b + bn && b < a + an;
                if !vm
                    || vstart != 0
                    || overlaps(vd, emul, vs2, emul)
                    || overlaps(vd, emul, insn.rs1, 1)
                {
                    return Err(Trap::illegal(insn.raw));
                }
                // Pack vs2 elements whose vs1 mask bit is set into the low lanes of vd.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let mut out = vstart;
                for e in vstart..vl {
                    if self.vbit(insn.rs1, e) {
                        let v = self.velem(vs2, e, eb);
                        self.set_velem(vd, out, eb, v & mask);
                        out += 1;
                    }
                }
            }
            Op::Vrgather | Op::Vrgatherei16 => {
                // vd[i] = vs2[index(i)], or 0 when the index is >= VLMAX.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let vlmax = self.vlmax_elems() as u64;
                let scalar_idx = match insn.funct3 {
                    0b100 => self.x(insn.rs1), // vx
                    0b011 => insn.rs1 as u64,  // vi (zero-extended imm)
                    _ => 0,
                };
                let ei16 = insn.op == Op::Vrgatherei16;
                let is_vv = insn.funct3 == 0b000;
                // The destination group must not overlap the source vs2 group,
                // nor (for vv/ei16) the index vector group; such encodings are
                // reserved and must trap rather than gather in place.
                let data_emul: u8 = match self.vtype & 0x7 {
                    1 => 2,
                    2 => 4,
                    3 => 8,
                    _ => 1,
                };
                let overlaps = |a: u8, an: u8, b: u8, bn: u8| a < b + bn && b < a + an;
                if overlaps(vd, data_emul, vs2, data_emul) {
                    return Err(Trap::illegal(insn.raw));
                }
                if is_vv || ei16 {
                    let idx_regs = if ei16 {
                        // Index EEW=16, so its EMUL (in registers) is
                        // ceil(data_emul * 16 / SEW), at least one register.
                        let sew_bits = 8u32 << ((self.vtype >> 3) & 0x7);
                        ((data_emul as u32 * 16 + sew_bits - 1) / sew_bits).max(1) as u8
                    } else {
                        data_emul
                    };
                    if overlaps(vd, data_emul, insn.rs1, idx_regs) {
                        return Err(Trap::illegal(insn.raw));
                    }
                }
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    let idx = if ei16 {
                        self.velem(insn.rs1, e, 2) // 16-bit index element
                    } else if is_vv {
                        self.velem(insn.rs1, e, eb)
                    } else {
                        scalar_idx
                    };
                    let v = if idx < vlmax {
                        self.velem(vs2, idx as usize, eb)
                    } else {
                        0
                    };
                    self.set_velem(vd, e, eb, v & mask);
                }
            }
            Op::Vcpop => {
                // x[rd] = number of active mask bits set in vs2. This reduction
                // is not restartable: a non-zero vstart is reserved and traps.
                if vstart != 0 {
                    return Err(Trap::illegal(insn.raw));
                }
                let mut count = 0u64;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    if self.vbit(vs2, e) {
                        count += 1;
                    }
                }
                self.set_x(insn.rd, count);
            }
            Op::Vfirst => {
                // x[rd] = index of first active set mask bit, or -1. Not
                // restartable: a non-zero vstart is reserved and traps.
                if vstart != 0 {
                    return Err(Trap::illegal(insn.raw));
                }
                let mut idx: i64 = -1;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    if self.vbit(vs2, e) {
                        idx = e as i64;
                        break;
                    }
                }
                self.set_x(insn.rd, idx as u64);
            }
            Op::Vmsbf | Op::Vmsif | Op::Vmsof => {
                // Set-before / set-including / set-only the first active set bit.
                // Their non-restartable and register-overlap constraints are
                // checked before any vector state can be modified.
                let mut found = false;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue; // masked-off destination undisturbed
                    }
                    let s = self.vbit(vs2, e);
                    let out = if !found {
                        if s {
                            found = true;
                            insn.op != Op::Vmsbf // bf->0, if/of->1 at the first set
                        } else {
                            insn.op != Op::Vmsof // bf/if->1, of->0 before the first set
                        }
                    } else {
                        false
                    };
                    self.set_vmask_bit(vd, e, out);
                }
            }
            Op::Viota => {
                // vd[i] = count of active set bits in vs2 strictly before i.
                // This prefix scan is not restartable: non-zero vstart traps.
                if vstart != 0 {
                    return Err(Trap::illegal(insn.raw));
                }
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                let mut sum = 0u64;
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    self.set_velem(vd, e, eb, sum & mask);
                    if self.vbit(vs2, e) {
                        sum += 1;
                    }
                }
            }
            Op::Vid => {
                // vd[i] = i (element index); source vs2 ignored.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                for e in vstart..vl {
                    if !vm && !self.vmask_bit(e) {
                        continue;
                    }
                    self.set_velem(vd, e, eb, (e as u64) & mask);
                }
            }
            Op::VmvXS => {
                // x[rd] = sign-extended lane 0 of vs2 (ignores vl/vstart).
                let eb = self.sew_bytes();
                let v = sext_sew(self.velem(vs2, 0, eb), eb) as u64;
                self.set_x(insn.rd, v);
            }
            Op::VfmvFS => {
                // f[rd] = NaN-boxed lane 0 of vs2 (ignores vl/vstart).
                let eb = self.sew_bytes();
                let v = self.velem(vs2, 0, eb);
                match eb {
                    2 => self.wf16(insn.rd, v as u16),
                    4 => self.wf32(insn.rd, v as u32),
                    _ => self.wf64(insn.rd, v),
                }
            }
            Op::VmvSX => {
                // vd[0] = x[rs1] (low SEW); no-op when vstart >= vl.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                if vstart < vl {
                    self.set_velem(vd, 0, eb, self.x(insn.rs1) & mask);
                }
            }
            Op::VfmvSF => {
                // vd[0] = f[rs1] (low SEW); no-op when vstart >= vl.
                let eb = self.sew_bytes();
                let mask = Self::sew_mask(eb);
                if vstart < vl {
                    let s = match eb {
                        2 => self.h(insn.rs1),
                        4 => self.s32(insn.rs1),
                        _ => self.f(insn.rs1),
                    };
                    self.set_velem(vd, 0, eb, s & mask);
                }
            }
            _ => return Err(Trap::illegal(insn.raw)),
        }
        self.vstart = 0;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Floating point (F / D).
    // ---------------------------------------------------------------

    /// Dynamic rounding mode field (`fcsr.frm`).
    #[inline]
    fn frm(&self) -> u8 {
        ((self.fcsr >> 5) & 0x7) as u8
    }

    /// Resolve an instruction `rm` field to a concrete rounding mode, honoring
    /// the dynamic (`Dyn`) selection. Returns `None` for reserved encodings.
    fn eff_rm(&self, rm_field: u8) -> Option<RoundingMode> {
        let m = RoundingMode::from_bits(rm_field)?;
        let m = if m == RoundingMode::Dyn {
            RoundingMode::from_bits(self.frm())?
        } else {
            m
        };
        if m == RoundingMode::Dyn {
            None // dynamic field itself selecting dynamic is illegal
        } else {
            Some(m)
        }
    }

    /// OR new exception flags into `fcsr.fflags`.
    #[inline]
    fn accrue(&mut self, flags: u32) {
        self.fcsr |= flags & 0x1f;
    }

    /// Read a single-precision operand, applying NaN-unboxing.
    #[inline]
    fn rf32(&self, i: u8) -> f32 {
        let bits = self.f(i);
        if (bits >> 32) == 0xffff_ffff {
            f32::from_bits(bits as u32)
        } else {
            f32::from_bits(super::float::CANONICAL_NAN_F32)
        }
    }
    #[inline]
    fn rf64(&self, i: u8) -> f64 {
        f64::from_bits(self.f(i))
    }
    /// Unboxed single-precision operand as raw 32-bit pattern (in a u64).
    #[inline]
    fn s32(&self, i: u8) -> u64 {
        self.rf32(i).to_bits() as u64
    }
    /// Read a half-precision operand, applying NaN-unboxing (upper 48 bits == 1).
    #[inline]
    fn rf16(&self, i: u8) -> u16 {
        let bits = self.f(i);
        if (bits >> 16) == 0xffff_ffff_ffff {
            bits as u16
        } else {
            0x7e00 // canonical half qNaN
        }
    }
    /// Write a half-precision result, NaN-boxing into the 64-bit register.
    #[inline]
    fn wf16(&mut self, rd: u8, bits: u16) {
        self.set_f(rd, 0xffff_ffff_ffff_0000 | bits as u64);
    }
    /// Unboxed half-precision operand as a raw 16-bit pattern (in a u64).
    #[inline]
    fn h(&self, i: u8) -> u64 {
        self.rf16(i) as u64
    }
    /// Write a single-precision result, NaN-boxing into the 64-bit register.
    #[inline]
    fn wf32(&mut self, rd: u8, bits: u32) {
        self.set_f(rd, 0xffff_ffff_0000_0000 | bits as u64);
    }
    #[inline]
    fn wf64(&mut self, rd: u8, bits: u64) {
        self.set_f(rd, bits);
    }

    fn exec_fp(&mut self, insn: &Insn, _pc: u64) -> Result<RiscVExit, Trap> {
        use super::float as ff;
        let rd = insn.rd;
        let rs1 = insn.rs1;
        let rs2 = insn.rs2;
        let rs3 = insn.rs3;
        let mut flags = 0u32;

        // Q currently has decode/disassembly parity only; the FP register file
        // is still 64-bit, so executing binary128 instructions is illegal.
        if matches!(
            insn.op,
            Op::Flq
                | Op::Fsq
                | Op::FmaddQ
                | Op::FmsubQ
                | Op::FnmsubQ
                | Op::FnmaddQ
                | Op::FaddQ
                | Op::FsubQ
                | Op::FmulQ
                | Op::FdivQ
                | Op::FsqrtQ
                | Op::FsgnjQ
                | Op::FsgnjnQ
                | Op::FsgnjxQ
                | Op::FminQ
                | Op::FmaxQ
                | Op::FcvtSQ
                | Op::FcvtQS
                | Op::FcvtDQ
                | Op::FcvtQD
                | Op::FcvtHQ
                | Op::FcvtQH
                | Op::FeqQ
                | Op::FltQ
                | Op::FleQ
                | Op::FclassQ
                | Op::FcvtWQ
                | Op::FcvtWuQ
                | Op::FcvtLQ
                | Op::FcvtLuQ
                | Op::FcvtQW
                | Op::FcvtQWu
                | Op::FcvtQL
                | Op::FcvtQLu
        ) {
            return Err(Trap::illegal(insn.raw));
        }

        // Operations whose funct3 encodes a rounding mode.
        let needs_rm = !matches!(
            insn.op,
            Op::Flw
                | Op::Fsw
                | Op::Fld
                | Op::Fsd
                | Op::FsgnjS | Op::FsgnjnS | Op::FsgnjxS
                | Op::FsgnjD | Op::FsgnjnD | Op::FsgnjxD
                | Op::FminS | Op::FmaxS | Op::FminD | Op::FmaxD
                | Op::FeqS | Op::FltS | Op::FleS | Op::FeqD | Op::FltD | Op::FleD
                | Op::FclassS | Op::FclassD
                | Op::FmvXW | Op::FmvWX | Op::FmvXD | Op::FmvDX | Op::FmvhXD | Op::FmvpDX
                // Zfa sub-op encodings (funct3 selects the op, not a rounding mode)
                | Op::FliS | Op::FliD
                | Op::FminmS | Op::FmaxmS | Op::FminmD | Op::FmaxmD
                | Op::FleqS | Op::FltqS | Op::FleqD | Op::FltqD
                | Op::FcvtmodWD
                // Zfh sub-op / non-rounding encodings
                | Op::Flh | Op::Fsh
                | Op::FsgnjH | Op::FsgnjnH | Op::FsgnjxH | Op::FminH | Op::FmaxH
                | Op::FeqH | Op::FltH | Op::FleH | Op::FclassH | Op::FmvXH | Op::FmvHX
                | Op::FliH | Op::FminmH | Op::FmaxmH | Op::FleqH | Op::FltqH
        );
        let rm = if needs_rm {
            match self.eff_rm(insn.rm()) {
                Some(m) => m,
                None => return Err(Trap::illegal(insn.raw)),
            }
        } else {
            RoundingMode::Rne
        };

        match insn.op {
            // ---- loads / stores ----
            Op::Flw => {
                let addr = self.x(rs1).wrapping_add(insn.imm as u64) & self.xmask();
                let v = self
                    .mem
                    .read_u32(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                self.wf32(rd, v);
            }
            Op::Fld => {
                let addr = self.x(rs1).wrapping_add(insn.imm as u64) & self.xmask();
                let v = self
                    .mem
                    .read_u64(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                self.wf64(rd, v);
            }
            Op::Fsw => {
                let addr = self.x(rs1).wrapping_add(insn.imm as u64) & self.xmask();
                self.mem
                    .write_u32(addr, self.f(rs2) as u32)
                    .map_err(|_| acc_fault(true, addr))?;
            }
            Op::Fsd => {
                let addr = self.x(rs1).wrapping_add(insn.imm as u64) & self.xmask();
                self.mem
                    .write_u64(addr, self.f(rs2))
                    .map_err(|_| acc_fault(true, addr))?;
            }

            // ---- single-precision arithmetic ----
            Op::FaddS => {
                let r = ff::add(self.rf32(rs1), self.rf32(rs2), rm, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FsubS => {
                let r = ff::sub(self.rf32(rs1), self.rf32(rs2), rm, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FmulS => {
                let r = ff::sf_mul(ff::F32, self.s32(rs1), self.s32(rs2), rm, &mut flags);
                self.wf32(rd, r as u32);
            }
            Op::FdivS => {
                let r = ff::sf_div(ff::F32, self.s32(rs1), self.s32(rs2), rm, &mut flags);
                self.wf32(rd, r as u32);
            }
            Op::FsqrtS => {
                let r = ff::sf_sqrt(ff::F32, self.s32(rs1), rm, &mut flags);
                self.wf32(rd, r as u32);
            }
            Op::FmaddS => {
                let r = ff::sf_fma(
                    ff::F32,
                    self.s32(rs1),
                    self.s32(rs2),
                    self.s32(rs3),
                    rm,
                    &mut flags,
                );
                self.wf32(rd, r as u32);
            }
            Op::FmsubS => {
                let r = ff::sf_fma(
                    ff::F32,
                    self.s32(rs1),
                    self.s32(rs2),
                    neg32(self.s32(rs3)),
                    rm,
                    &mut flags,
                );
                self.wf32(rd, r as u32);
            }
            Op::FnmsubS => {
                let r = ff::sf_fma(
                    ff::F32,
                    neg32(self.s32(rs1)),
                    self.s32(rs2),
                    self.s32(rs3),
                    rm,
                    &mut flags,
                );
                self.wf32(rd, r as u32);
            }
            Op::FnmaddS => {
                let r = ff::sf_fma(
                    ff::F32,
                    neg32(self.s32(rs1)),
                    self.s32(rs2),
                    neg32(self.s32(rs3)),
                    rm,
                    &mut flags,
                );
                self.wf32(rd, r as u32);
            }

            // ---- double-precision arithmetic ----
            Op::FaddD => {
                let r = ff::add(self.rf64(rs1), self.rf64(rs2), rm, &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FsubD => {
                let r = ff::sub(self.rf64(rs1), self.rf64(rs2), rm, &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FmulD => {
                let r = ff::sf_mul(ff::F64, self.f(rs1), self.f(rs2), rm, &mut flags);
                self.wf64(rd, r);
            }
            Op::FdivD => {
                let r = ff::sf_div(ff::F64, self.f(rs1), self.f(rs2), rm, &mut flags);
                self.wf64(rd, r);
            }
            Op::FsqrtD => {
                let r = ff::sf_sqrt(ff::F64, self.f(rs1), rm, &mut flags);
                self.wf64(rd, r);
            }
            Op::FmaddD => {
                let r = ff::sf_fma(
                    ff::F64,
                    self.f(rs1),
                    self.f(rs2),
                    self.f(rs3),
                    rm,
                    &mut flags,
                );
                self.wf64(rd, r);
            }
            Op::FmsubD => {
                let r = ff::sf_fma(
                    ff::F64,
                    self.f(rs1),
                    self.f(rs2),
                    neg64(self.f(rs3)),
                    rm,
                    &mut flags,
                );
                self.wf64(rd, r);
            }
            Op::FnmsubD => {
                let r = ff::sf_fma(
                    ff::F64,
                    neg64(self.f(rs1)),
                    self.f(rs2),
                    self.f(rs3),
                    rm,
                    &mut flags,
                );
                self.wf64(rd, r);
            }
            Op::FnmaddD => {
                let r = ff::sf_fma(
                    ff::F64,
                    neg64(self.f(rs1)),
                    self.f(rs2),
                    neg64(self.f(rs3)),
                    rm,
                    &mut flags,
                );
                self.wf64(rd, r);
            }

            // ---- sign injection ----
            Op::FsgnjS | Op::FsgnjnS | Op::FsgnjxS => {
                let a = self.rf32(rs1).to_bits();
                let b = self.rf32(rs2).to_bits();
                let sign = match insn.op {
                    Op::FsgnjS => b & 0x8000_0000,
                    Op::FsgnjnS => !b & 0x8000_0000,
                    _ => (a ^ b) & 0x8000_0000,
                };
                self.wf32(rd, (a & 0x7fff_ffff) | sign);
            }
            Op::FsgnjD | Op::FsgnjnD | Op::FsgnjxD => {
                let a = self.f(rs1);
                let b = self.f(rs2);
                let sign = match insn.op {
                    Op::FsgnjD => b & 0x8000_0000_0000_0000,
                    Op::FsgnjnD => !b & 0x8000_0000_0000_0000,
                    _ => (a ^ b) & 0x8000_0000_0000_0000,
                };
                self.wf64(rd, (a & 0x7fff_ffff_ffff_ffff) | sign);
            }

            // ---- min / max ----
            Op::FminS => {
                let r = ff::fmin(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FmaxS => {
                let r = ff::fmax(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FminD => {
                let r = ff::fmin(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FmaxD => {
                let r = ff::fmax(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.wf64(rd, r.to_bits());
            }

            // ---- comparisons ----
            Op::FeqS => {
                let v = ff::feq(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FltS => {
                let v = ff::flt(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FleS => {
                let v = ff::fle(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FeqD => {
                let v = ff::feq(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FltD => {
                let v = ff::flt(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FleD => {
                let v = ff::fle(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }

            // ---- classify ----
            Op::FclassS => self.set_x(rd, ff::fclass(self.rf32(rs1))),
            Op::FclassD => self.set_x(rd, ff::fclass(self.rf64(rs1))),

            // ---- moves between FP and integer registers ----
            Op::FmvXW
            | Op::FmvWX
            | Op::FmvXD
            | Op::FmvDX
            | Op::FmvhXD
            | Op::FmvpDX
            | Op::FmvXH
            | Op::FmvHX => self.exec_fp_move(insn),

            // ---- float -> integer conversions ----
            Op::FcvtWS => self.set_x(rd, ff::ftoi(self.rf32(rs1), true, 32, rm, &mut flags)),
            Op::FcvtWuS => self.set_x(rd, ff::ftoi(self.rf32(rs1), false, 32, rm, &mut flags)),
            Op::FcvtLS => self.set_x(rd, ff::ftoi(self.rf32(rs1), true, 64, rm, &mut flags)),
            Op::FcvtLuS => self.set_x(rd, ff::ftoi(self.rf32(rs1), false, 64, rm, &mut flags)),
            Op::FcvtWD => self.set_x(rd, ff::ftoi(self.rf64(rs1), true, 32, rm, &mut flags)),
            Op::FcvtWuD => self.set_x(rd, ff::ftoi(self.rf64(rs1), false, 32, rm, &mut flags)),
            Op::FcvtLD => self.set_x(rd, ff::ftoi(self.rf64(rs1), true, 64, rm, &mut flags)),
            Op::FcvtLuD => self.set_x(rd, ff::ftoi(self.rf64(rs1), false, 64, rm, &mut flags)),

            // ---- integer -> float conversions ----
            Op::FcvtSW => {
                let v = self.x(rs1) as i32 as i128;
                let r: f32 = ff::itof(v, rm, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FcvtSWu => {
                let v = self.x(rs1) as u32 as i128;
                let r: f32 = ff::itof(v, rm, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FcvtSL => {
                let v = self.x(rs1) as i64 as i128;
                let r: f32 = ff::itof(v, rm, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FcvtSLu => {
                let v = self.x(rs1) as i128; // u64 zero-extended
                let r: f32 = ff::itof(v, rm, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FcvtDW => {
                let v = self.x(rs1) as i32 as i128;
                let r: f64 = ff::itof(v, rm, &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FcvtDWu => {
                let v = self.x(rs1) as u32 as i128;
                let r: f64 = ff::itof(v, rm, &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FcvtDL => {
                let v = self.x(rs1) as i64 as i128;
                let r: f64 = ff::itof(v, rm, &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FcvtDLu => {
                let v = self.x(rs1) as i128;
                let r: f64 = ff::itof(v, rm, &mut flags);
                self.wf64(rd, r.to_bits());
            }

            // ---- float <-> float conversions ----
            Op::FcvtSD => {
                let bits = ff::f64_to_f32(self.rf64(rs1), rm, &mut flags);
                self.wf32(rd, bits);
            }
            Op::FcvtDS => {
                let bits = ff::f32_to_f64(self.rf32(rs1), &mut flags);
                self.wf64(rd, bits);
            }

            // ---- Zfa ----
            Op::FliS => self.wf32(rd, ff::fli(ff::F32, rs1) as u32),
            Op::FliD => self.wf64(rd, ff::fli(ff::F64, rs1)),
            Op::FminmS => {
                let r = ff::fminm(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FmaxmS => {
                let r = ff::fmaxm(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FminmD => {
                let r = ff::fminm(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FmaxmD => {
                let r = ff::fmaxm(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FroundS => {
                let r = ff::fround(self.rf32(rs1), rm, false, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FroundnxS => {
                let r = ff::fround(self.rf32(rs1), rm, true, &mut flags);
                self.wf32(rd, r.to_bits());
            }
            Op::FroundD => {
                let r = ff::fround(self.rf64(rs1), rm, false, &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FroundnxD => {
                let r = ff::fround(self.rf64(rs1), rm, true, &mut flags);
                self.wf64(rd, r.to_bits());
            }
            Op::FleqS => {
                let v = ff::fleq(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FltqS => {
                let v = ff::fltq(self.rf32(rs1), self.rf32(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FleqD => {
                let v = ff::fleq(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FltqD => {
                let v = ff::fltq(self.rf64(rs1), self.rf64(rs2), &mut flags);
                self.set_x(rd, v as u64);
            }
            Op::FcvtmodWD => self.set_x(rd, ff::fcvtmod_w_d(self.rf64(rs1), &mut flags)),

            // ---- Zfh half-precision ----
            Op::Flh => {
                let addr = self.x(rs1).wrapping_add(insn.imm as u64) & self.xmask();
                let v = self
                    .mem
                    .read_u16(addr)
                    .map_err(|_| acc_fault(false, addr))?;
                self.wf16(rd, v);
            }
            Op::Fsh => {
                let addr = self.x(rs1).wrapping_add(insn.imm as u64) & self.xmask();
                self.mem
                    .write_u16(addr, self.f(rs2) as u16)
                    .map_err(|_| acc_fault(true, addr))?;
            }
            Op::FaddH => {
                let r = ff::sf_add(ff::F16, self.h(rs1), self.h(rs2), rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FsubH => {
                let r = ff::sf_sub(ff::F16, self.h(rs1), self.h(rs2), rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FmulH => {
                let r = ff::sf_mul(ff::F16, self.h(rs1), self.h(rs2), rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FdivH => {
                let r = ff::sf_div(ff::F16, self.h(rs1), self.h(rs2), rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FsqrtH => {
                let r = ff::sf_sqrt(ff::F16, self.h(rs1), rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FmaddH => {
                let r = ff::sf_fma(
                    ff::F16,
                    self.h(rs1),
                    self.h(rs2),
                    self.h(rs3),
                    rm,
                    &mut flags,
                );
                self.wf16(rd, r as u16);
            }
            Op::FmsubH => {
                let r = ff::sf_fma(
                    ff::F16,
                    self.h(rs1),
                    self.h(rs2),
                    neg16(self.h(rs3)),
                    rm,
                    &mut flags,
                );
                self.wf16(rd, r as u16);
            }
            Op::FnmsubH => {
                let r = ff::sf_fma(
                    ff::F16,
                    neg16(self.h(rs1)),
                    self.h(rs2),
                    self.h(rs3),
                    rm,
                    &mut flags,
                );
                self.wf16(rd, r as u16);
            }
            Op::FnmaddH => {
                let r = ff::sf_fma(
                    ff::F16,
                    neg16(self.h(rs1)),
                    self.h(rs2),
                    neg16(self.h(rs3)),
                    rm,
                    &mut flags,
                );
                self.wf16(rd, r as u16);
            }
            Op::FsgnjH | Op::FsgnjnH | Op::FsgnjxH => {
                let a = self.rf16(rs1);
                let b = self.rf16(rs2);
                let sign = match insn.op {
                    Op::FsgnjH => b & 0x8000,
                    Op::FsgnjnH => !b & 0x8000,
                    _ => (a ^ b) & 0x8000,
                };
                self.wf16(rd, (a & 0x7fff) | sign);
            }
            Op::FminH => {
                let r = ff::fmin_h(self.rf16(rs1), self.rf16(rs2), &mut flags);
                self.wf16(rd, r);
            }
            Op::FmaxH => {
                let r = ff::fmax_h(self.rf16(rs1), self.rf16(rs2), &mut flags);
                self.wf16(rd, r);
            }
            Op::FminmH => {
                let r = ff::fminm_h(self.rf16(rs1), self.rf16(rs2), &mut flags);
                self.wf16(rd, r);
            }
            Op::FmaxmH => {
                let r = ff::fmaxm_h(self.rf16(rs1), self.rf16(rs2), &mut flags);
                self.wf16(rd, r);
            }
            Op::FeqH => self.set_x(
                rd,
                ff::feq_h(self.rf16(rs1), self.rf16(rs2), &mut flags) as u64,
            ),
            Op::FltH => self.set_x(
                rd,
                ff::flt_h(self.rf16(rs1), self.rf16(rs2), &mut flags) as u64,
            ),
            Op::FleH => self.set_x(
                rd,
                ff::fle_h(self.rf16(rs1), self.rf16(rs2), &mut flags) as u64,
            ),
            Op::FleqH => self.set_x(
                rd,
                ff::fleq_h(self.rf16(rs1), self.rf16(rs2), &mut flags) as u64,
            ),
            Op::FltqH => self.set_x(
                rd,
                ff::fltq_h(self.rf16(rs1), self.rf16(rs2), &mut flags) as u64,
            ),
            Op::FclassH => self.set_x(rd, ff::fclass_bits(ff::F16, self.h(rs1))),
            Op::FroundH => {
                let r = ff::fround_h(self.rf16(rs1), rm, false, &mut flags);
                self.wf16(rd, r);
            }
            Op::FroundnxH => {
                let r = ff::fround_h(self.rf16(rs1), rm, true, &mut flags);
                self.wf16(rd, r);
            }
            Op::FliH => self.wf16(rd, ff::fli(ff::F16, rs1) as u16),
            // half <-> single/double
            Op::FcvtSH => {
                let r = ff::fcvt_round(ff::F16, ff::F32, self.h(rs1), rm, &mut flags);
                self.wf32(rd, r as u32);
            }
            Op::FcvtHS => {
                let r = ff::fcvt_round(ff::F32, ff::F16, self.s32(rs1), rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FcvtDH => {
                let r = ff::fcvt_round(ff::F16, ff::F64, self.h(rs1), rm, &mut flags);
                self.wf64(rd, r);
            }
            Op::FcvtHD => {
                let r = ff::fcvt_round(ff::F64, ff::F16, self.f(rs1), rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            // half <-> integer
            Op::FcvtWH => {
                let w = ff::h_widen(self.rf16(rs1));
                self.set_x(rd, ff::ftoi(w, true, 32, rm, &mut flags));
            }
            Op::FcvtWuH => {
                let w = ff::h_widen(self.rf16(rs1));
                self.set_x(rd, ff::ftoi(w, false, 32, rm, &mut flags));
            }
            Op::FcvtLH => {
                let w = ff::h_widen(self.rf16(rs1));
                self.set_x(rd, ff::ftoi(w, true, 64, rm, &mut flags));
            }
            Op::FcvtLuH => {
                let w = ff::h_widen(self.rf16(rs1));
                self.set_x(rd, ff::ftoi(w, false, 64, rm, &mut flags));
            }
            Op::FcvtHW => {
                let r = ff::itof_fmt(ff::F16, self.x(rs1) as i32 as i128, rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FcvtHWu => {
                let r = ff::itof_fmt(ff::F16, self.x(rs1) as u32 as i128, rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FcvtHL => {
                let r = ff::itof_fmt(ff::F16, self.x(rs1) as i64 as i128, rm, &mut flags);
                self.wf16(rd, r as u16);
            }
            Op::FcvtHLu => {
                let r = ff::itof_fmt(ff::F16, self.x(rs1) as i128, rm, &mut flags);
                self.wf16(rd, r as u16);
            }

            _ => return Err(Trap::illegal(insn.raw)),
        }

        self.accrue(flags);
        Ok(RiscVExit::Continue)
    }
}

// ---------------------------------------------------------------------------
// Free helpers.
// ---------------------------------------------------------------------------

/// Flip the sign bit of a single-precision bit pattern.
#[inline]
fn neg32(bits: u64) -> u64 {
    bits ^ 0x8000_0000
}
/// Flip the sign bit of a double-precision bit pattern.
#[inline]
fn neg64(bits: u64) -> u64 {
    bits ^ 0x8000_0000_0000_0000
}
/// Flip the sign bit of a half-precision bit pattern.
#[inline]
fn neg16(bits: u64) -> u64 {
    bits ^ 0x8000
}

/// Sign-extend the low `size` bytes of `raw` to 64 bits.
#[inline]
fn sign_extend(raw: u64, size: usize) -> u64 {
    match size {
        1 => raw as u8 as i8 as i64 as u64,
        2 => raw as u16 as i16 as i64 as u64,
        4 => raw as u32 as i32 as i64 as u64,
        _ => raw,
    }
}

fn andes_bitfield(a: u64, msb: u8, lsb: u8, signed: bool) -> u64 {
    if msb < lsb {
        return 0;
    }
    let width = (msb - lsb + 1) as u32;
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let v = (a >> lsb) & mask;
    if signed && width > 0 && width < 64 && (v & (1u64 << (width - 1))) != 0 {
        v | !mask
    } else {
        v
    }
}

fn andes_byte_scan(op: Op, a: u64, b: u64, rv32: bool) -> u64 {
    let n = if rv32 { 4 } else { 8 };
    let byte = |v: u64, i: usize| ((v >> (i * 8)) & 0xff) as u8;
    let no_match = n as u64;
    match op {
        Op::NdsFfb => {
            let needle = (b & 0xff) as u8;
            (0..n)
                .find(|&i| byte(a, i) == needle)
                .map(|i| i as u64)
                .unwrap_or(no_match)
        }
        Op::NdsFfmism => (0..n)
            .find(|&i| byte(a, i) != byte(b, i))
            .map(|i| i as u64)
            .unwrap_or(no_match),
        Op::NdsFfzmism => (0..n)
            .find(|&i| {
                let ax = byte(a, i);
                let bx = byte(b, i);
                ax == 0 || bx == 0 || ax != bx
            })
            .map(|i| i as u64)
            .unwrap_or(no_match),
        Op::NdsFlmism => (0..n)
            .rev()
            .find(|&i| byte(a, i) != byte(b, i))
            .map(|i| i as u64)
            .unwrap_or(no_match),
        _ => unreachable!(),
    }
}

#[derive(Clone, Copy)]
struct TheadMemKind {
    load: bool,
    size: usize,
    signed: bool,
    pre: bool,
}

impl TheadMemKind {
    const fn load(size: usize, signed: bool) -> Self {
        Self {
            load: true,
            size,
            signed,
            pre: false,
        }
    }

    const fn store(size: usize) -> Self {
        Self {
            load: false,
            size,
            signed: false,
            pre: false,
        }
    }

    const fn auto_load(size: usize, signed: bool, pre: bool) -> Self {
        Self {
            load: true,
            size,
            signed,
            pre,
        }
    }

    const fn auto_store(size: usize, pre: bool) -> Self {
        Self {
            load: false,
            size,
            signed: false,
            pre,
        }
    }
}

fn thead_auto_mem(op: Op) -> Option<TheadMemKind> {
    use Op::*;
    Some(match op {
        ThLbia => TheadMemKind::auto_load(1, true, false),
        ThLbib => TheadMemKind::auto_load(1, true, true),
        ThLbuia => TheadMemKind::auto_load(1, false, false),
        ThLbuib => TheadMemKind::auto_load(1, false, true),
        ThLhia => TheadMemKind::auto_load(2, true, false),
        ThLhib => TheadMemKind::auto_load(2, true, true),
        ThLhuia => TheadMemKind::auto_load(2, false, false),
        ThLhuib => TheadMemKind::auto_load(2, false, true),
        ThLwia => TheadMemKind::auto_load(4, true, false),
        ThLwib => TheadMemKind::auto_load(4, true, true),
        ThLwuia => TheadMemKind::auto_load(4, false, false),
        ThLwuib => TheadMemKind::auto_load(4, false, true),
        ThLdia => TheadMemKind::auto_load(8, false, false),
        ThLdib => TheadMemKind::auto_load(8, false, true),
        ThSbia => TheadMemKind::auto_store(1, false),
        ThSbib => TheadMemKind::auto_store(1, true),
        ThShia => TheadMemKind::auto_store(2, false),
        ThShib => TheadMemKind::auto_store(2, true),
        ThSwia => TheadMemKind::auto_store(4, false),
        ThSwib => TheadMemKind::auto_store(4, true),
        ThSdia => TheadMemKind::auto_store(8, false),
        ThSdib => TheadMemKind::auto_store(8, true),
        _ => return None,
    })
}

fn thead_reg_mem(op: Op) -> Option<TheadMemKind> {
    use Op::*;
    Some(match op {
        ThLrb | ThLurb => TheadMemKind::load(1, true),
        ThLrbu | ThLurbu => TheadMemKind::load(1, false),
        ThLrh | ThLurh => TheadMemKind::load(2, true),
        ThLrhu | ThLurhu => TheadMemKind::load(2, false),
        ThLrw | ThLurw => TheadMemKind::load(4, true),
        ThLrwu | ThLurwu => TheadMemKind::load(4, false),
        ThLrd | ThLurd => TheadMemKind::load(8, false),
        ThSrb | ThSurb => TheadMemKind::store(1),
        ThSrh | ThSurh => TheadMemKind::store(2),
        ThSrw | ThSurw => TheadMemKind::store(4),
        ThSrd | ThSurd => TheadMemKind::store(8),
        _ => return None,
    })
}

fn thead_pair_mem(op: Op) -> Option<TheadMemKind> {
    use Op::*;
    Some(match op {
        ThLdd => TheadMemKind::load(8, false),
        ThLwd => TheadMemKind::load(4, true),
        ThLwud => TheadMemKind::load(4, false),
        ThSdd => TheadMemKind::store(8),
        ThSwd => TheadMemKind::store(4),
        _ => return None,
    })
}

fn thead_fmem(op: Op) -> Option<TheadMemKind> {
    use Op::*;
    Some(match op {
        ThFlrd | ThFlurd => TheadMemKind::load(8, false),
        ThFlrw | ThFlurw => TheadMemKind::load(4, false),
        ThFsrd | ThFsurd => TheadMemKind::store(8),
        ThFsrw | ThFsurw => TheadMemKind::store(4),
        _ => return None,
    })
}

fn thead_extract(a: u64, msb: u8, lsb: u8, xbits: u32, signed: bool) -> u64 {
    if msb < lsb || lsb as u32 >= xbits {
        return 0;
    }
    let hi = (msb as u32).min(xbits - 1);
    let lo = lsb as u32;
    let width = hi - lo + 1;
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let v = (a >> lo) & mask;
    if signed && width < 64 && (v & (1u64 << (width - 1))) != 0 {
        v | !mask
    } else {
        v
    }
}

fn thead_ff(a: u64, xbits: u32, one: bool) -> u64 {
    if xbits == 32 {
        let v = a as u32;
        if one {
            v.leading_zeros() as u64
        } else {
            (!v).leading_zeros() as u64
        }
    } else if one {
        a.leading_zeros() as u64
    } else {
        (!a).leading_zeros() as u64
    }
}

fn thead_tstnbz(a: u64, rv32: bool) -> u64 {
    let n = if rv32 { 4 } else { 8 };
    let mut out = 0u64;
    for i in 0..n {
        if ((a >> (i * 8)) & 0xff) == 0 {
            out |= 0xffu64 << (i * 8);
        }
    }
    out
}

fn thead_mac(op: Op, rd: u64, a: u64, b: u64) -> u64 {
    match op {
        Op::ThMula => rd.wrapping_add(a.wrapping_mul(b)),
        Op::ThMuls => rd.wrapping_sub(a.wrapping_mul(b)),
        Op::ThMulah => {
            let p = (a as i16 as i32).wrapping_mul(b as i16 as i32) as u32;
            word((rd as u32).wrapping_add(p))
        }
        Op::ThMulsh => {
            let p = (a as i16 as i32).wrapping_mul(b as i16 as i32) as u32;
            word((rd as u32).wrapping_sub(p))
        }
        Op::ThMulaw => {
            let p = (a as i32 as i64).wrapping_mul(b as i32 as i64) as u32;
            word((rd as u32).wrapping_add(p))
        }
        Op::ThMulsw => {
            let p = (a as i32 as i64).wrapping_mul(b as i32 as i64) as u32;
            word((rd as u32).wrapping_sub(p))
        }
        _ => unreachable!(),
    }
}

fn thead_packl(a: u64, b: u64, xbits: u32) -> u64 {
    let half = xbits / 2;
    let mask = if half >= 64 {
        u64::MAX
    } else {
        (1u64 << half) - 1
    };
    ((b & mask) << half) | (a & mask)
}

fn thead_packhl(a: u64, b: u64, xbits: u32) -> u64 {
    let half = xbits / 2;
    let q = half / 2;
    let mask = if q >= 64 { u64::MAX } else { (1u64 << q) - 1 };
    ((b & mask) << q) | ((a >> half) & mask)
}

#[inline]
fn mask_bytes(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// Sign-extend a 32-bit value to 64 bits (RV64 "W"-op result canonicalization).
#[inline]
fn word(v: u32) -> u64 {
    v as i32 as i64 as u64
}

#[inline]
fn acc_fault(store: bool, addr: u64) -> Trap {
    Trap {
        cause: if store {
            cause::STORE_ACCESS_FAULT
        } else {
            cause::LOAD_ACCESS_FAULT
        },
        tval: addr,
    }
}

fn zcmp_reg_count(rlist: u8) -> Option<usize> {
    match rlist {
        4 => Some(1),
        5 => Some(2),
        6 => Some(3),
        7..=14 => Some((rlist - 3) as usize),
        15 => Some(13),
        _ => None,
    }
}

fn zcmp_reg_at(slot: usize) -> Option<u8> {
    match slot {
        0 => Some(1),                          // ra
        1 => Some(8),                          // s0/fp
        2 => Some(9),                          // s1
        3..=12 => Some(18 + (slot as u8 - 3)), // s2..s11
        _ => None,
    }
}

/// 32-bit word division/remainder (RV64 DIVW/DIVUW/REMW/REMUW), sign-extended.
fn divw(a: u32, b: u32, signed: bool, rem: bool) -> u64 {
    if signed {
        let (x, y) = (a as i32, b as i32);
        let r = if rem {
            if y == 0 {
                x
            } else if x == i32::MIN && y == -1 {
                0
            } else {
                x % y
            }
        } else if y == 0 {
            -1
        } else if x == i32::MIN && y == -1 {
            i32::MIN
        } else {
            x / y
        };
        r as i64 as u64
    } else {
        let r = if rem {
            if b == 0 { a } else { a % b }
        } else if b == 0 {
            u32::MAX
        } else {
            a / b
        };
        r as i32 as i64 as u64
    }
}

fn amo_compute32(op: Op, old: u32, src: u32) -> u32 {
    match op {
        Op::AmoswapW => src,
        Op::AmoaddW => old.wrapping_add(src),
        Op::AmoxorW => old ^ src,
        Op::AmoandW => old & src,
        Op::AmoorW => old | src,
        Op::AmominW => (old as i32).min(src as i32) as u32,
        Op::AmomaxW => (old as i32).max(src as i32) as u32,
        Op::AmominuW => old.min(src),
        Op::AmomaxuW => old.max(src),
        _ => unreachable!(),
    }
}

fn amo_compute64(op: Op, old: u64, src: u64) -> u64 {
    match op {
        Op::AmoswapD => src,
        Op::AmoaddD => old.wrapping_add(src),
        Op::AmoxorD => old ^ src,
        Op::AmoandD => old & src,
        Op::AmoorD => old | src,
        Op::AmominD => (old as i64).min(src as i64) as u64,
        Op::AmomaxD => (old as i64).max(src as i64) as u64,
        Op::AmominuD => old.min(src),
        Op::AmomaxuD => old.max(src),
        _ => unreachable!(),
    }
}

/// `ctz`/`clz` of a 32-bit value with the all-zero special case (== 32).
fn clz_ctz_w(v: u32, ctz: bool) -> u64 {
    if ctz {
        v.trailing_zeros() as u64
    } else {
        v.leading_zeros() as u64
    }
}

/// Zbb `orc.b`: each byte becomes 0xFF if any of its bits are set, else 0x00.
fn orc_b(a: u64, xmask: u64) -> u64 {
    let mut out = 0u64;
    for i in 0..8 {
        let byte = (a >> (i * 8)) & 0xff;
        if byte != 0 {
            out |= 0xffu64 << (i * 8);
        }
    }
    out & xmask
}

/// Xsoteria `grev`/`grevi`: 32-bit generalized bit-reverse (standard RISC-V
/// bitmanip GREV). The control takes the low 5 bits; each stage conditionally
/// swaps bit groups of width 1, 2, 4, 8, 16. `grev32(x, 31)` is a full bit
/// reverse; `grev32(x, 24)` is `rev8` (whole-word byte swap).
fn grev32(rs1: u32, ctrl: u32) -> u32 {
    let mut x = rs1;
    let s = ctrl & 31;
    if s & 1 != 0 {
        x = ((x & 0x5555_5555) << 1) | ((x & 0xAAAA_AAAA) >> 1);
    }
    if s & 2 != 0 {
        x = ((x & 0x3333_3333) << 2) | ((x & 0xCCCC_CCCC) >> 2);
    }
    if s & 4 != 0 {
        x = ((x & 0x0F0F_0F0F) << 4) | ((x & 0xF0F0_F0F0) >> 4);
    }
    if s & 8 != 0 {
        x = ((x & 0x00FF_00FF) << 8) | ((x & 0xFF00_FF00) >> 8);
    }
    if s & 16 != 0 {
        x = (x << 16) | (x >> 16);
    }
    x
}

/// Xsoteria `fls`: find last (most-significant) set bit, 1-based; `fls(0) == 0`,
/// `fls(1) == 1`, `fls(0x8000_0000) == 32`. Equivalent to `32 - clz`.
fn fls32(rs1: u32) -> u64 {
    (32 - rs1.leading_zeros()) as u64
}

/// Zbb `rev8`: reverse byte order across the whole register.
fn rev8(a: u64, rv32: bool) -> u64 {
    if rv32 {
        (a as u32).swap_bytes() as u64
    } else {
        a.swap_bytes()
    }
}

/// Sign-extend a 5-bit immediate field to 64 bits (vector OPIVI).
#[inline]
fn sext5(field: u8) -> u64 {
    (((field << 3) as i8) >> 3) as i64 as u64
}
/// Sign-extend an `eb`-byte element value to a signed 64-bit integer.
#[inline]
fn sext_sew(val: u64, eb: usize) -> i64 {
    let shift = 64 - eb * 8;
    if shift == 0 {
        val as i64
    } else {
        ((val << shift) as i64) >> shift
    }
}

#[inline]
fn th_vdot_byte(v: u8, signed: bool) -> i64 {
    if signed { (v as i8) as i64 } else { v as i64 }
}

/// Fixed-point rounding increment for a right shift by `d`, per `vxrm`
/// (0=rnu, 1=rne, 2=rdn, 3=rod). `bits` are the low bits of the value being
/// shifted (sign is irrelevant — only the discarded low bits matter).
#[inline]
fn round_incr(bits: u128, d: u32, vxrm: u64) -> u128 {
    if d == 0 {
        return 0;
    }
    let bit = |i: u32| (bits >> i) & 1;
    let lown = |n: u32| bits & ((1u128 << n) - 1) != 0;
    match vxrm {
        0 => bit(d - 1), // round-to-nearest-up
        1 => bit(d - 1) & (bit(d) | if d >= 2 && lown(d - 1) { 1 } else { 0 }), // round-to-nearest-even
        2 => 0,                                          // round-down (truncate)
        _ => (1 - bit(d)) & if lown(d) { 1 } else { 0 }, // round-to-odd
    }
}

/// Per-element high multiply (unsigned/signed/signed-unsigned) at `bits` width.
#[inline]
fn vmulh_u(a: u64, b: u64, bits: u32) -> u64 {
    ((a as u128).wrapping_mul(b as u128) >> bits) as u64
}
#[inline]
fn vmulh_s(a: u64, b: u64, eb: usize, bits: u32) -> u64 {
    let p = (sext_sew(a, eb) as i128).wrapping_mul(sext_sew(b, eb) as i128);
    (p >> bits) as u64
}
#[inline]
fn vmulh_su(a: u64, b: u64, eb: usize, bits: u32) -> u64 {
    let p = (sext_sew(a, eb) as i128).wrapping_mul(b as i128);
    (p >> bits) as u64
}
/// Per-element signed divide / remainder at SEW with M-extension corner cases.
#[inline]
fn vdiv_sew(a: u64, b: u64, eb: usize, bits: u32, rem: bool) -> u64 {
    let (sa, sb) = (sext_sew(a, eb), sext_sew(b, eb));
    let min = -1i64 << (bits - 1);
    if sb == 0 {
        if rem { sa as u64 } else { -1i64 as u64 }
    } else if sa == min && sb == -1 {
        if rem { 0 } else { min as u64 }
    } else if rem {
        (sa % sb) as u64
    } else {
        (sa / sb) as u64
    }
}

/// Soft-float format for a vector element width (2/4/8 bytes -> F16/F32/F64).
#[inline]
fn fmt_eb(eb: usize) -> super::float::Fmt {
    match eb {
        2 => super::float::F16,
        4 => super::float::F32,
        _ => super::float::F64,
    }
}

/// Per-element vector floating-point binary op at element width `eb`.
/// Reverse ops (`Vfrsub`/`Vfrdiv`) swap the operand order.
fn vfp_bin(op: Op, eb: usize, a: u64, b: u64, rm: RoundingMode, flags: &mut u32) -> u64 {
    use super::float as ff;
    let (x, y) = match op {
        Op::Vfrsub | Op::Vfrdiv => (b, a),
        _ => (a, b),
    };
    match op {
        Op::Vfadd => match eb {
            2 => ff::sf_add(ff::F16, x, y, rm, flags),
            4 => ff::add(
                f32::from_bits(x as u32),
                f32::from_bits(y as u32),
                rm,
                flags,
            )
            .to_bits() as u64,
            _ => ff::add(f64::from_bits(x), f64::from_bits(y), rm, flags).to_bits(),
        },
        Op::Vfsub | Op::Vfrsub => match eb {
            2 => ff::sf_sub(ff::F16, x, y, rm, flags),
            4 => ff::sub(
                f32::from_bits(x as u32),
                f32::from_bits(y as u32),
                rm,
                flags,
            )
            .to_bits() as u64,
            _ => ff::sub(f64::from_bits(x), f64::from_bits(y), rm, flags).to_bits(),
        },
        Op::Vfmul => ff::sf_mul(fmt_eb(eb), x, y, rm, flags),
        Op::Vfdiv | Op::Vfrdiv => ff::sf_div(fmt_eb(eb), x, y, rm, flags),
        Op::Vfmin => match eb {
            2 => ff::fmin_h(x as u16, y as u16, flags) as u64,
            4 => {
                ff::fmin(f32::from_bits(x as u32), f32::from_bits(y as u32), flags).to_bits() as u64
            }
            _ => ff::fmin(f64::from_bits(x), f64::from_bits(y), flags).to_bits(),
        },
        Op::Vfmax => match eb {
            2 => ff::fmax_h(x as u16, y as u16, flags) as u64,
            4 => {
                ff::fmax(f32::from_bits(x as u32), f32::from_bits(y as u32), flags).to_bits() as u64
            }
            _ => ff::fmax(f64::from_bits(x), f64::from_bits(y), flags).to_bits(),
        },
        Op::Vfsgnj | Op::Vfsgnjn | Op::Vfsgnjx => {
            let sb = 1u64 << (eb * 8 - 1);
            let sign = match op {
                Op::Vfsgnj => y & sb,
                Op::Vfsgnjn => !y & sb,
                _ => (x ^ y) & sb,
            };
            (x & (sb - 1)) | sign
        }
        _ => unreachable!(),
    }
}

/// Per-element vector fused multiply-add. `src` is vs1[i] (vv) or the f[rs1]
/// scalar (vf); the multiplicand/addend roles of vs2/vd and the product/sum
/// signs follow the eight macc/madd variants.
fn vfp_fma(
    op: Op,
    eb: usize,
    src: u64,
    vs2: u64,
    vd: u64,
    rm: RoundingMode,
    flags: &mut u32,
) -> u64 {
    let neg = |x: u64| x ^ (1u64 << (eb * 8 - 1));
    let (a, b, c) = match op {
        // accumulator forms: product = src * vs2, addend = vd
        Op::Vfmacc => (src, vs2, vd),
        Op::Vfnmacc => (neg(src), vs2, neg(vd)),
        Op::Vfmsac => (src, vs2, neg(vd)),
        Op::Vfnmsac => (neg(src), vs2, vd),
        // multiplicand forms: product = src * vd, addend = vs2
        Op::Vfmadd => (src, vd, vs2),
        Op::Vfnmadd => (neg(src), vd, neg(vs2)),
        Op::Vfmsub => (src, vd, neg(vs2)),
        Op::Vfnmsub => (neg(src), vd, vs2),
        _ => unreachable!(),
    };
    super::float::sf_fma(fmt_eb(eb), a, b, c, rm, flags)
}

/// Per-element vector floating-point compare; returns the mask bit.
fn vfp_cmp(op: Op, eb: usize, a: u64, b: u64, flags: &mut u32) -> bool {
    use super::float as ff;
    // gt/ge reuse lt/le with swapped operands.
    let (x, y) = match op {
        Op::Vmfgt | Op::Vmfge => (b, a),
        _ => (a, b),
    };
    let eq = |f: &mut u32| match eb {
        2 => ff::feq_h(x as u16, y as u16, f),
        4 => ff::feq(f32::from_bits(x as u32), f32::from_bits(y as u32), f),
        _ => ff::feq(f64::from_bits(x), f64::from_bits(y), f),
    };
    let lt = |f: &mut u32| match eb {
        2 => ff::flt_h(x as u16, y as u16, f),
        4 => ff::flt(f32::from_bits(x as u32), f32::from_bits(y as u32), f),
        _ => ff::flt(f64::from_bits(x), f64::from_bits(y), f),
    };
    let le = |f: &mut u32| match eb {
        2 => ff::fle_h(x as u16, y as u16, f),
        4 => ff::fle(f32::from_bits(x as u32), f32::from_bits(y as u32), f),
        _ => ff::fle(f64::from_bits(x), f64::from_bits(y), f),
    };
    match op {
        Op::Vmfeq => eq(flags),
        Op::Vmfne => !eq(flags),
        Op::Vmflt | Op::Vmfgt => lt(flags),
        Op::Vmfle | Op::Vmfge => le(flags),
        _ => unreachable!(),
    }
}

/// Zbkb `brev8`: reverse the bit order within each byte.
fn brev8(a: u64) -> u64 {
    let mut out = 0u64;
    for i in 0..8 {
        let byte = ((a >> (i * 8)) & 0xff) as u8;
        out |= (byte.reverse_bits() as u64) << (i * 8);
    }
    out
}

/// Zbkb `zip` for RV32: lower-half bits go to even positions, upper-half bits
/// go to odd positions.
fn zip32(a: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..16 {
        out |= ((a >> i) & 1) << (i * 2);
        out |= ((a >> (i + 16)) & 1) << (i * 2 + 1);
    }
    out
}

/// Zbkb `unzip`, the inverse of [`zip32`].
fn unzip32(a: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..16 {
        out |= ((a >> (i * 2)) & 1) << i;
        out |= ((a >> (i * 2 + 1)) & 1) << (i + 16);
    }
    out
}

/// Carry-less multiply (low XLEN bits).
fn clmul(a: u64, b: u64, xbits: u32) -> u64 {
    let mut out: u64 = 0;
    for i in 0..xbits {
        if (b >> i) & 1 != 0 {
            out ^= a << i;
        }
    }
    mask_xbits(out, xbits)
}

/// Carry-less multiply high (bits [2*XLEN-1 : XLEN]).
fn clmulh(a: u64, b: u64, xbits: u32) -> u64 {
    let mut out: u64 = 0;
    for i in 1..xbits {
        if (b >> i) & 1 != 0 {
            out ^= a >> (xbits - i);
        }
    }
    mask_xbits(out, xbits)
}

/// Carry-less multiply reversed.
fn clmulr(a: u64, b: u64, xbits: u32) -> u64 {
    let mut out: u64 = 0;
    for i in 0..xbits {
        if (b >> i) & 1 != 0 {
            out ^= a >> (xbits - i - 1);
        }
    }
    mask_xbits(out, xbits)
}

#[inline]
fn mask_xbits(v: u64, xbits: u32) -> u64 {
    if xbits >= 64 {
        v
    } else {
        v & ((1u64 << xbits) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::memory::FlatMemory;

    fn cpu() -> RiscVCpu {
        RiscVCpu::new(
            RiscVConfig::rv64gc(),
            Box::new(FlatMemory::new(0, 0x1_0000)),
        )
    }

    /// Encode a register-register OP instruction.
    fn r_type(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    fn run_one(c: &mut RiscVCpu, w: u32) -> RiscVExit {
        c.write_memory(c.pc(), &w.to_le_bytes()).unwrap();
        c.step()
    }

    fn run_half(c: &mut RiscVCpu, h: u16) -> RiscVExit {
        c.write_memory(c.pc(), &h.to_le_bytes()).unwrap();
        c.step()
    }

    #[test]
    fn addi_and_add() {
        let mut c = cpu();
        // addi x1, x0, 100
        run_one(&mut c, (100u32 << 20) | (0 << 15) | (3 << 7) | 0x13);
        assert_eq!(c.x(3), 100);
    }

    #[test]
    fn add_sub_words() {
        let mut c = cpu();
        c.set_x(1, 0xffff_ffff_0000_0005);
        c.set_x(2, 7);
        // addw x3, x1, x2 -> (5+7) sign-extended = 12
        run_one(&mut c, r_type(0, 2, 1, 0, 3, 0x3b));
        assert_eq!(c.x(3), 12);
    }

    #[test]
    fn xida_sltw_compares_low_words_signed() {
        let mut cfg = RiscVConfig::rv64gc();
        cfg.isa.xida_sltw = true;
        let mut c = RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 0x1_0000)));
        c.set_x(1, 0x0000_0000_8000_0000);
        c.set_x(2, 0x0000_0000_7fff_ffff);
        run_one(&mut c, r_type(0, 2, 1, 2, 3, 0x3b));
        assert_eq!(c.x(3), 1);

        c.set_x(1, 0x0000_0001_0000_0000);
        c.set_x(2, 0xffff_ffff_ffff_ffff);
        run_one(&mut c, r_type(0, 2, 1, 2, 4, 0x3b));
        assert_eq!(c.x(4), 0);
    }

    #[test]
    fn q_decode_only_ops_trap_on_execute() {
        let mut cfg = RiscVConfig::rv64gc();
        cfg.isa.q = true;
        let mut c = RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 0x1_0000)));
        let fadd_q = r_type(0b0000011, 11, 10, 0, 12, 0x53);

        match run_one(&mut c, fadd_q) {
            RiscVExit::Trap(trap) => {
                assert_eq!(trap.cause, cause::ILLEGAL_INSTR);
                assert_eq!(trap.tval, fadd_q as u64);
            }
            other => panic!("expected illegal-instruction trap, got {other:?}"),
        }
    }

    #[test]
    fn sra_arith() {
        let mut c = cpu();
        c.set_x(1, 0xffff_ffff_ffff_0000);
        c.set_x(2, 4);
        // sra x3, x1, x2
        run_one(&mut c, r_type(0b0100000, 2, 1, 5, 3, 0x33));
        assert_eq!(c.x(3), 0xffff_ffff_ffff_f000);
    }

    #[test]
    fn mul_div_rem() {
        let mut c = cpu();
        c.set_x(1, (-20i64) as u64);
        c.set_x(2, 3);
        run_one(&mut c, r_type(1, 2, 1, 4, 3, 0x33)); // div
        assert_eq!(c.x(3) as i64, -6);
        run_one(&mut c, r_type(1, 2, 1, 6, 4, 0x33)); // rem
        assert_eq!(c.x(4) as i64, -2);
        // div by zero -> -1
        c.set_x(2, 0);
        run_one(&mut c, r_type(1, 2, 1, 4, 5, 0x33));
        assert_eq!(c.x(5), u64::MAX);
    }

    #[test]
    fn div_overflow() {
        let mut c = cpu();
        c.set_x(1, i64::MIN as u64);
        c.set_x(2, (-1i64) as u64);
        run_one(&mut c, r_type(1, 2, 1, 4, 3, 0x33));
        assert_eq!(c.x(3), i64::MIN as u64);
        run_one(&mut c, r_type(1, 2, 1, 6, 4, 0x33));
        assert_eq!(c.x(4), 0);
    }

    #[test]
    fn branch_taken() {
        let mut c = cpu();
        c.set_pc(0x100);
        c.set_x(1, 5);
        c.set_x(2, 5);
        // beq x1,x2,+8
        let b4_1 = 0b0100u32;
        run_one(&mut c, (b4_1 << 8) | (2 << 20) | (1 << 15) | 0x63);
        assert_eq!(c.pc(), 0x108);
    }

    #[test]
    fn load_store_roundtrip() {
        let mut c = cpu();
        c.set_x(1, 0x2000); // base
        c.set_x(2, 0x1122_3344_5566_7788);
        // sd x2, 0(x1)
        let s_imm_lo = 0u32;
        run_one(
            &mut c,
            (0 << 25) | (2 << 20) | (1 << 15) | (3 << 12) | (s_imm_lo << 7) | 0x23,
        );
        // ld x3, 0(x1)
        run_one(
            &mut c,
            (0u32 << 20) | (1 << 15) | (3 << 12) | (3 << 7) | 0x03,
        );
        assert_eq!(c.x(3), 0x1122_3344_5566_7788);
    }

    #[test]
    fn amo_add() {
        let mut c = cpu();
        c.set_x(1, 0x2000);
        c.write_memory(0x2000, &10u64.to_le_bytes()).unwrap();
        c.set_x(2, 5);
        // amoadd.d x3, x2, (x1): funct5=00000, funct3=011
        run_one(
            &mut c,
            (0b00000 << 27) | (2 << 20) | (1 << 15) | (3 << 12) | (3 << 7) | 0x2f,
        );
        assert_eq!(c.x(3), 10); // returns old
        assert_eq!(c.mem_read_u64(0x2000).unwrap(), 15);
    }

    // Encode B/J/U/I-type for control-flow tests.
    fn b_type(imm: i32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
        let u = (imm as u32) & 0x1fff;
        let b12 = (u >> 12) & 1;
        let b11 = (u >> 11) & 1;
        let b10_5 = (u >> 5) & 0x3f;
        let b4_1 = (u >> 1) & 0xf;
        (b12 << 31)
            | (b10_5 << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (funct3 << 12)
            | (b4_1 << 8)
            | (b11 << 7)
            | 0x63
    }
    fn j_type(imm: i32, rd: u32) -> u32 {
        let u = (imm as u32) & 0x1f_ffff;
        let b20 = (u >> 20) & 1;
        let b19_12 = (u >> 12) & 0xff;
        let b11 = (u >> 11) & 1;
        let b10_1 = (u >> 1) & 0x3ff;
        (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | (rd << 7) | 0x6f
    }

    #[test]
    fn branches_all_conditions() {
        let cases: &[(u32, &str, u64, u64, bool)] = &[
            (0, "beq", 5, 5, true),
            (0, "beq", 5, 6, false),
            (1, "bne", 5, 6, true),
            (1, "bne", 5, 5, false),
            (4, "blt", (-1i64) as u64, 1, true), // signed: -1 < 1
            (4, "blt", 1, (-1i64) as u64, false),
            (5, "bge", 1, (-1i64) as u64, true), // signed: 1 >= -1
            (5, "bge", (-1i64) as u64, 1, false),
            (6, "bltu", 1, 2, true), // unsigned
            (6, "bltu", 0xffff_ffff_ffff_ffff, 1, false),
            (7, "bgeu", 0xffff_ffff_ffff_ffff, 1, true),
            (7, "bgeu", 1, 2, false),
        ];
        for &(f3, name, a, b, taken) in cases {
            let mut c = cpu();
            c.set_pc(0x400);
            c.set_x(1, a);
            c.set_x(2, b);
            run_one(&mut c, b_type(0x40, 2, 1, f3)); // imm = +0x40
            let expect = if taken { 0x440 } else { 0x404 };
            assert_eq!(c.pc(), expect, "{name} a={a:#x} b={b:#x} taken={taken}");
        }
        // negative (backward) branch offset
        let mut c = cpu();
        c.set_pc(0x400);
        c.set_x(1, 1);
        c.set_x(2, 1);
        run_one(&mut c, b_type(-0x10, 2, 1, 0)); // beq, imm=-0x10
        assert_eq!(c.pc(), 0x3f0);
    }

    #[test]
    fn branch_alignment_traps_only_when_taken_without_compressed_extension() {
        let mut config = RiscVConfig::rv64gc();
        config.isa.c = false;
        let make_cpu = || RiscVCpu::new(config, Box::new(FlatMemory::new(0, 0x1_0000)));

        let mut taken = make_cpu();
        taken.set_pc(0x400);
        taken.set_x(1, 5);
        taken.set_x(2, 5);
        assert_eq!(
            run_one(&mut taken, b_type(2, 2, 1, 0)),
            RiscVExit::Trap(Trap {
                cause: cause::INSTR_MISALIGNED,
                tval: 0x402,
            })
        );
        assert_eq!(taken.csr_read(0x341), Ok(0x400));

        let mut not_taken = make_cpu();
        not_taken.set_pc(0x400);
        not_taken.set_x(1, 5);
        not_taken.set_x(2, 6);
        assert_eq!(
            run_one(&mut not_taken, b_type(2, 2, 1, 0)),
            RiscVExit::Continue
        );
        assert_eq!(not_taken.pc(), 0x404);
    }

    #[test]
    fn jal_jalr_link_and_target() {
        let mut c = cpu();
        c.set_pc(0x1000);
        // jal x1, +0x20 : x1 = 0x1004, pc = 0x1020
        run_one(&mut c, j_type(0x20, 1));
        assert_eq!(c.x(1), 0x1004);
        assert_eq!(c.pc(), 0x1020);
        // jalr x5, x6, 3 : target = (x6 + 3) & ~1, link = pc+4
        c.set_pc(0x2000);
        c.set_x(6, 0x3001);
        run_one(
            &mut c,
            (3u32 << 20) | (6 << 15) | (0 << 12) | (5 << 7) | 0x67,
        );
        assert_eq!(c.x(5), 0x2004);
        assert_eq!(c.pc(), 0x3004 & !1); // (0x3001+3)=0x3004, &~1 = 0x3004
    }

    #[test]
    fn lui_auipc() {
        let mut c = cpu();
        c.set_pc(0x8000);
        // lui x1, 0xfffff (sign-extended): x1 = 0xfffffffff_ffff000
        run_one(&mut c, (0xfffffu32 << 12) | (1 << 7) | 0x37);
        assert_eq!(c.x(1), 0xffff_ffff_ffff_f000);
        // auipc x2, 0x1 : x2 = pc + 0x1000 = 0x8004 + 0x1000... pc at auipc is 0x8004
        c.set_pc(0x8004);
        run_one(&mut c, (0x1u32 << 12) | (2 << 7) | 0x17);
        assert_eq!(c.x(2), 0x9004);
    }

    #[test]
    fn system_ecall_ebreak_fence() {
        let mut c = cpu();
        c.set_pc(0x200);
        // ecall (funct12=0) -> Ecall exit, PC unchanged.
        assert_eq!(run_one(&mut c, 0x0000_0073), RiscVExit::Ecall);
        assert_eq!(c.pc(), 0x200);
        // ebreak (funct12=1) -> Ebreak exit.
        c.set_pc(0x204);
        assert_eq!(run_one(&mut c, 0x0010_0073), RiscVExit::Ebreak);
        assert_eq!(c.pc(), 0x204);
        // fence -> nop, advances PC.
        c.set_pc(0x208);
        assert_eq!(run_one(&mut c, 0x0ff0_000f), RiscVExit::Continue);
        assert_eq!(c.pc(), 0x20c);
        // wfi -> Wfi exit, advances PC.
        c.set_pc(0x210);
        assert_eq!(run_one(&mut c, 0x1050_0073), RiscVExit::Wfi);
        assert_eq!(c.pc(), 0x214);
    }

    #[test]
    fn privileged_fences_are_flat_memory_noops() {
        let mut c = cpu();
        c.set_pc(0x300);
        c.set_x(10, 0x4000);
        c.set_x(11, 0x22);
        let sys =
            |funct7: u32, rs2: u32, rs1: u32| (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | 0x73;
        for w in [
            sys(0x09, 11, 10), // sfence.vma a0, a1
            sys(0x0b, 11, 10), // sinval.vma a0, a1
            sys(0x0c, 0, 0),   // sfence.w.inval
            sys(0x0c, 1, 0),   // sfence.inval.ir
            sys(0x11, 11, 10), // hfence.vvma a0, a1
            sys(0x13, 11, 10), // hinval.vvma a0, a1
            sys(0x31, 11, 10), // hfence.gvma a0, a1
            sys(0x33, 11, 10), // hinval.gvma a0, a1
        ] {
            assert_eq!(run_one(&mut c, w), RiscVExit::Continue);
        }
        assert_eq!(c.x(10), 0x4000);
        assert_eq!(c.x(11), 0x22);
        assert_eq!(c.pc(), 0x300 + 8 * 4);
    }

    #[test]
    fn hypervisor_virtual_load_store_use_flat_memory() {
        let mut c = cpu();
        c.set_x(1, 0x3000);
        c.write_memory(0x3000, &[0x80, 0x7f, 0x34, 0x12, 0, 0, 0, 0])
            .unwrap();

        // hlv.b x3, (x1)
        assert_eq!(
            run_one(
                &mut c,
                (0x30 << 25) | (1 << 15) | (4 << 12) | (3 << 7) | 0x73
            ),
            RiscVExit::Continue
        );
        assert_eq!(c.x(3), (-128i64) as u64);

        // hlvx.hu x4, (x1)
        assert_eq!(
            run_one(
                &mut c,
                (0x32 << 25) | (3 << 20) | (1 << 15) | (4 << 12) | (4 << 7) | 0x73
            ),
            RiscVExit::Continue
        );
        assert_eq!(c.x(4), 0x7f80);

        // hsv.w x5, (x1)
        c.set_x(5, 0xaabb_ccdd);
        assert_eq!(
            run_one(
                &mut c,
                (0x35 << 25) | (5 << 20) | (1 << 15) | (4 << 12) | 0x73
            ),
            RiscVExit::Continue
        );
        let mut buf = [0u8; 4];
        c.read_memory(0x3000, &mut buf).unwrap();
        assert_eq!(u32::from_le_bytes(buf), 0xaabb_ccdd);
    }

    #[test]
    fn cbo_zero_zeroes_aligned_cache_block() {
        let mut c = cpu();
        let pattern = [0xa5; 0xc0];
        c.write_memory(0x4000, &pattern).unwrap();
        c.set_x(10, 0x4043);
        c.set_pc(0x200);

        let cbo_zero = (0x004u32 << 20) | (10 << 15) | (2 << 12) | 0x0f;
        assert_eq!(run_one(&mut c, cbo_zero), RiscVExit::Continue);

        let mut before = [0u8; 0x40];
        let mut zeroed = [0xffu8; 0x40];
        let mut after = [0u8; 0x40];
        c.read_memory(0x4000, &mut before).unwrap();
        c.read_memory(0x4040, &mut zeroed).unwrap();
        c.read_memory(0x4080, &mut after).unwrap();

        assert_eq!(before, [0xa5; 0x40]);
        assert_eq!(zeroed, [0; 0x40]);
        assert_eq!(after, [0xa5; 0x40]);
    }

    #[test]
    fn cache_and_wait_hints_retire_without_state_changes() {
        let mut c = cpu();
        let pattern = [0xa5; 0x80];
        c.write_memory(0x4000, &pattern).unwrap();
        c.set_x(10, 0x4040);
        c.set_pc(0x200);

        let enc_cbo = |rs2: u32| (rs2 << 20) | (10 << 15) | (2 << 12) | 0x0f;
        for w in [
            0x0100_000f,                               // pause
            0x00d0_0073,                               // wrs.nto
            0x01d0_0073,                               // wrs.sto
            (2 << 20) | 0x33,                          // ntl.p1
            enc_cbo(0),                                // cbo.inval
            enc_cbo(1),                                // cbo.clean
            enc_cbo(2),                                // cbo.flush
            (1 << 20) | (10 << 15) | (6 << 12) | 0x13, // prefetch.r
        ] {
            assert_eq!(run_one(&mut c, w), RiscVExit::Continue);
        }

        let mut out = [0u8; 0x80];
        c.read_memory(0x4000, &mut out).unwrap();
        assert_eq!(out, pattern);
    }

    #[test]
    fn amocas_word_double_and_quad() {
        let mut c = cpu();
        c.set_x(10, 0x5000);
        c.write_memory(0x5000, &0x1122_3344u32.to_le_bytes())
            .unwrap();
        c.set_x(5, 0x1122_3344);
        c.set_x(6, 0xaabb_ccdd);
        let amocas_w = (0b00101 << 27) | (6 << 20) | (10 << 15) | (0b010 << 12) | (5 << 7) | 0x2f;
        assert_eq!(run_one(&mut c, amocas_w), RiscVExit::Continue);
        assert_eq!(c.x(5), 0x1122_3344);
        assert_eq!(c.mem_read_u64(0x5000).unwrap() as u32, 0xaabb_ccdd);

        c.write_memory(0x5008, &0x0123_4567_89ab_cdefu64.to_le_bytes())
            .unwrap();
        c.set_x(10, 0x5008);
        c.set_x(5, 0); // compare mismatch
        c.set_x(6, 0xfedc_ba98_7654_3210);
        let amocas_d = (0b00101 << 27) | (6 << 20) | (10 << 15) | (0b011 << 12) | (5 << 7) | 0x2f;
        assert_eq!(run_one(&mut c, amocas_d), RiscVExit::Continue);
        assert_eq!(c.x(5), 0x0123_4567_89ab_cdef);
        assert_eq!(c.mem_read_u64(0x5008).unwrap(), 0x0123_4567_89ab_cdef);

        let old_lo = 0x1111_2222_3333_4444u64;
        let old_hi = 0x5555_6666_7777_8888u64;
        let new_lo = 0x9999_aaaa_bbbb_ccccu64;
        let new_hi = 0xdddd_eeee_ffff_0001u64;
        c.write_memory(0x5010, &old_lo.to_le_bytes()).unwrap();
        c.write_memory(0x5018, &old_hi.to_le_bytes()).unwrap();
        c.set_x(10, 0x5010);
        c.set_x(6, old_lo);
        c.set_x(7, old_hi);
        c.set_x(8, new_lo);
        c.set_x(9, new_hi);
        let amocas_q = (0b00101 << 27) | (8 << 20) | (10 << 15) | (0b100 << 12) | (6 << 7) | 0x2f;
        assert_eq!(run_one(&mut c, amocas_q), RiscVExit::Continue);
        assert_eq!(c.x(6), old_lo);
        assert_eq!(c.x(7), old_hi);
        assert_eq!(c.mem_read_u64(0x5010).unwrap(), new_lo);
        assert_eq!(c.mem_read_u64(0x5018).unwrap(), new_hi);

        // A pair beginning at x0 reads as 128 zero bits, and an rd=x0 pair
        // discards both result words rather than writing the high word to x1.
        c.write_memory(0x5020, &[0; 16]).unwrap();
        c.set_x(10, 0x5020);
        c.set_x(1, 0xfeed_face_cafe_beef);
        let amocas_q_rd_x0 = (0b00101 << 27) | (8 << 20) | (10 << 15) | (0b100 << 12) | 0x2f;
        assert_eq!(run_one(&mut c, amocas_q_rd_x0), RiscVExit::Continue);
        assert_eq!(c.x(1), 0xfeed_face_cafe_beef);
        assert_eq!(c.mem_read_u64(0x5020).unwrap(), new_lo);
        assert_eq!(c.mem_read_u64(0x5028).unwrap(), new_hi);

        // The same two-zero rule applies to a replacement pair beginning at x0.
        c.write_memory(0x5030, &old_lo.to_le_bytes()).unwrap();
        c.write_memory(0x5038, &old_hi.to_le_bytes()).unwrap();
        c.set_x(10, 0x5030);
        c.set_x(6, old_lo);
        c.set_x(7, old_hi);
        let amocas_q_rs2_x0 = (0b00101 << 27) | (10 << 15) | (0b100 << 12) | (6 << 7) | 0x2f;
        assert_eq!(run_one(&mut c, amocas_q_rs2_x0), RiscVExit::Continue);
        assert_eq!(c.mem_read_u64(0x5030).unwrap(), 0);
        assert_eq!(c.mem_read_u64(0x5038).unwrap(), 0);
    }

    #[test]
    fn csr_readwrite_and_illegal() {
        let mut c = cpu();
        // csrrwi x5, mscratch(0x340), 0 then csrrw to set, read back.
        c.set_x(1, 0xdead_beef);
        // csrrw x2, mscratch, x1
        run_one(&mut c, csr(0x340, 1, 1, 2));
        assert_eq!(c.csr_read(0x340).unwrap(), 0xdead_beef);
        // csrrs x3, mscratch, x0 -> read without modifying
        run_one(&mut c, csr(0x340, 0, 2, 3));
        assert_eq!(c.x(3), 0xdead_beef);
        // Writing a read-only CSR (cycle, 0xC00) must trap illegal.
        c.set_x(4, 1);
        assert!(matches!(
            run_one(&mut c, csr(0xC00, 4, 1, 5)),
            RiscVExit::Trap(_)
        ));
    }

    #[test]
    fn sstatus_preserves_machine_only_mstatus_bits() {
        let mut c = cpu();
        let machine_only = (0b11 << 11) | (1 << 7) | (1 << 3) | (1 << 17);
        let supervisor_visible = (1 << 1) | (1 << 5) | (1 << 8) | (0b11 << 13);

        c.csr_write(0x300, machine_only | supervisor_visible)
            .unwrap();
        let sstatus = c.csr_read(0x100).unwrap();
        assert_eq!(sstatus & machine_only, 0);
        assert_eq!(sstatus & supervisor_visible, supervisor_visible);

        c.csr_write(0x300, 0).unwrap();
        c.csr_write(0x100, 0b11 << 11).unwrap();
        assert_eq!(c.csr_read(0x300).unwrap() & (0b11 << 11), 0);
    }

    #[test]
    fn sstatus_cannot_escalate_sret_via_mpp() {
        let mut c = cpu();
        c.csr_write(0x100, 0b11 << 11).unwrap();
        assert_eq!(c.csr_read(0x300).unwrap() & (0b11 << 11), 0);

        c.priv_ = Priv::Supervisor;
        c.mepc = 0x40;
        c.set_pc(0x100);
        assert_eq!(run_one(&mut c, 0x1020_0073), RiscVExit::Continue); // sret
        assert_ne!(c.priv_, Priv::Machine);
    }

    #[test]
    fn supervisor_interrupt_csrs_are_delegated_views() {
        let mut c = cpu();
        let ssip = 1 << 1;
        let msip = 1 << 3;
        let stip = 1 << 5;
        let mtip = 1 << 7;
        let seip = 1 << 9;

        c.csr_write(0x303, ssip | stip).unwrap(); // mideleg
        c.csr_write(0x304, msip | mtip | seip).unwrap(); // mie
        assert_eq!(c.csr_read(0x104).unwrap(), 0);

        c.csr_write(0x104, ssip | stip | seip | msip | mtip)
            .unwrap();
        assert_eq!(c.csr_read(0x304).unwrap() & (ssip | stip), ssip | stip);
        assert_eq!(
            c.csr_read(0x304).unwrap() & (msip | mtip | seip),
            msip | mtip | seip
        );
        assert_eq!(c.csr_read(0x104).unwrap(), ssip | stip);

        c.csr_write(0x344, msip | ssip | stip).unwrap(); // mip
        c.set_interrupt_pending(mtip, true);
        assert_eq!(c.csr_read(0x144).unwrap(), ssip | stip);
        c.csr_write(0x144, 0).unwrap();
        assert_eq!(c.csr_read(0x344).unwrap() & ssip, 0);
        assert_eq!(
            c.csr_read(0x344).unwrap() & (msip | mtip | stip),
            msip | mtip | stip
        );
    }

    #[test]
    fn ecall_exit_can_be_delivered_as_machine_trap() {
        let mut c = cpu();
        c.set_pc(0x200);
        c.csr_write(0x305, 0x1000).unwrap(); // mtvec

        assert_eq!(run_one(&mut c, 0x0000_0073), RiscVExit::Ecall);
        c.deliver_ecall_trap();

        assert_eq!(c.pc(), 0x1000);
        assert_eq!(c.csr_read(0x341).unwrap(), 0x200); // mepc
        assert_eq!(c.csr_read(0x342).unwrap(), cause::ECALL_M); // mcause
        assert_eq!(c.csr_read(0x343).unwrap(), 0); // mtval
    }

    #[test]
    fn machine_external_interrupt_enters_rv32_vectored_mtvec() {
        let mut c = rv32();
        c.set_pc(0x200);
        c.csr_write(0x305, 0x1001).unwrap(); // mtvec BASE=0x1000, MODE=vectored
        c.csr_write(0x304, MIP_MEIP).unwrap(); // mie.MEIE
        c.csr_write(0x300, MSTATUS_MIE).unwrap(); // mstatus.MIE

        c.set_interrupt_pending(MIP_MEIP, true);

        assert_eq!(c.step(), RiscVExit::Continue);
        assert_eq!(c.pc(), 0x1000 + 4 * cause::INT_M_EXTERNAL);
        assert_eq!(c.csr_read(0x341).unwrap(), 0x200); // mepc
        assert_eq!(
            c.csr_read(0x342).unwrap(),
            (1u64 << 31) | cause::INT_M_EXTERNAL
        );
        assert_eq!(c.csr_read(0x343).unwrap(), 0); // mtval
        assert_eq!(c.csr_read(0x300).unwrap() & MSTATUS_MIE, 0);
        assert_eq!(c.instret(), 0);

        c.set_interrupt_pending(MIP_MEIP, false);
        assert_eq!(c.csr_read(0x344).unwrap() & MIP_MEIP, 0);
    }

    #[test]
    fn fcsr_subfields() {
        let mut c = cpu();
        c.set_fcsr(0xff);
        // frm (0x002) reads bits [7:5] = 0b111 = 7.
        run_one(&mut c, csr(0x002, 0, 2, 6));
        assert_eq!(c.x(6), 7);
        // fflags (0x001) reads bits [4:0] = 0x1f.
        run_one(&mut c, csr(0x001, 0, 2, 7));
        assert_eq!(c.x(7), 0x1f);
    }

    /// Encode a CSR instruction.
    fn csr(addr: u32, rs1: u32, funct3: u32, rd: u32) -> u32 {
        (addr << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x73
    }

    // -- RV32: exercise every XLEN-sensitive branch (32-bit wrap, 5-bit shift
    //    amounts, 32-bit signed/unsigned semantics, 32-bit mulh/div). --

    fn rv32() -> RiscVCpu {
        let cfg = RiscVConfig {
            xlen: Xlen::Rv32,
            isa: Isa::rv64gc(),
        };
        RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 0x1_0000)))
    }

    #[test]
    fn rv32_add_wraps_32() {
        let mut c = rv32();
        c.set_x(1, 0xffff_ffff);
        c.set_x(2, 1);
        run_one(&mut c, r_type(0, 2, 1, 0, 3, 0x33)); // add
        assert_eq!(c.x(3), 0); // wraps at 32 bits, zero-extended
    }

    #[test]
    fn rv32_fallthrough_pc_wraps_at_xlen() {
        let mut c = rv32();
        let addi = (1u32 << 20) | (1 << 15) | (1 << 7) | 0x13;
        let instruction = crate::isa::riscv::decode(addi, Xlen::Rv32, &Isa::rv64gc());
        assert_eq!(
            c.execute_insn(&instruction, 0xffff_fffc),
            Ok(RiscVExit::Continue)
        );
        assert_eq!(c.pc(), 0);
    }

    #[test]
    fn rv32_shift_amount_masked_5_bits() {
        let mut c = rv32();
        c.set_x(1, 1);
        c.set_x(2, 33); // 33 & 31 == 1
        run_one(&mut c, r_type(0, 2, 1, 1, 3, 0x33)); // sll
        assert_eq!(c.x(3), 2);
    }

    #[test]
    fn rv32_zbkb_zip_unzip_interleave_bits() {
        let mut c = rv32();
        c.set_x(1, 0x0001_0002);
        run_one(
            &mut c,
            (0x04 << 25) | (15 << 20) | (1 << 15) | (1 << 12) | (3 << 7) | 0x13,
        );
        assert_eq!(c.x(3), 0x0000_0006);

        c.set_x(4, c.x(3));
        run_one(
            &mut c,
            (0x04 << 25) | (15 << 20) | (4 << 15) | (5 << 12) | (5 << 7) | 0x13,
        );
        assert_eq!(c.x(5), 0x0001_0002);
    }

    #[test]
    fn rv32_aes32_scalar_crypto() {
        let mut c = rv32();
        c.set_x(1, 0x1020_3040);
        c.set_x(2, 0x0011_2233);

        run_one(&mut c, r_type(0x11, 2, 1, 0, 3, 0x33)); // aes32esi bs=0
        run_one(&mut c, r_type(0x33, 2, 1, 0, 4, 0x33)); // aes32esmi bs=1
        run_one(&mut c, r_type(0x55, 2, 1, 0, 5, 0x33)); // aes32dsi bs=2
        run_one(&mut c, r_type(0x77, 2, 1, 0, 6, 0x33)); // aes32dsmi bs=3

        assert_eq!(c.x(3), 0x1020_3083);
        assert_eq!(c.x(4), 0x83b3_0dee);
        assert_eq!(c.x(5), 0x10c3_3040);
        assert_eq!(c.x(6), 0x4170_97b4);
    }

    #[test]
    fn rv32_sha512_pair_crypto() {
        let mut c = rv32();
        c.set_x(1, 0x89ab_cdef);
        c.set_x(2, 0x0123_4567);

        run_one(&mut c, r_type(0x2a, 2, 1, 0, 3, 0x33)); // sha512sig0l
        run_one(&mut c, r_type(0x2e, 2, 1, 0, 4, 0x33)); // sha512sig0h
        run_one(&mut c, r_type(0x2b, 2, 1, 0, 5, 0x33)); // sha512sig1l
        run_one(&mut c, r_type(0x2f, 2, 1, 0, 6, 0x33)); // sha512sig1h
        run_one(&mut c, r_type(0x28, 2, 1, 0, 7, 0x33)); // sha512sum0r
        run_one(&mut c, r_type(0x29, 2, 1, 0, 8, 0x33)); // sha512sum1r

        assert_eq!(c.x(3), 0x6c4f_1aa1);
        assert_eq!(c.x(4), 0xa24f_1aa1);
        assert_eq!(c.x(5), 0xbbd4_317a);
        assert_eq!(c.x(6), 0x27d4_317a);
        assert_eq!(c.x(7), 0x0c7e_c1ab);
        assert_eq!(c.x(8), 0x3347_5567);
    }

    #[test]
    fn rv32_sra_signed_32() {
        let mut c = rv32();
        c.set_x(1, 0xffff_0000); // negative i32
        c.set_x(2, 4);
        run_one(&mut c, r_type(0b0100000, 2, 1, 5, 3, 0x33)); // sra
        assert_eq!(c.x(3), 0xffff_f000);
    }

    #[test]
    fn rv32_slt_signed() {
        let mut c = rv32();
        c.set_x(1, 0xffff_ffff); // -1 as i32
        c.set_x(2, 1);
        run_one(&mut c, r_type(0, 2, 1, 2, 3, 0x33)); // slt -> -1 < 1 == 1
        assert_eq!(c.x(3), 1);
        run_one(&mut c, r_type(0, 2, 1, 3, 4, 0x33)); // sltu -> 0xffffffff < 1 == 0
        assert_eq!(c.x(4), 0);
    }

    #[test]
    fn rv32_mulh_div() {
        let mut c = rv32();
        c.set_x(1, 0x8000_0000); // i32::MIN
        c.set_x(2, 2);
        run_one(&mut c, r_type(1, 2, 1, 1, 3, 0x33)); // mulh (signed high 32)
        // (-2^31) * 2 = -2^32; high 32 bits = 0xffffffff
        assert_eq!(c.x(3), 0xffff_ffff);
        // div overflow: i32::MIN / -1 = i32::MIN
        c.set_x(2, 0xffff_ffff);
        run_one(&mut c, r_type(1, 2, 1, 4, 4, 0x33)); // div
        assert_eq!(c.x(4), 0x8000_0000);
        run_one(&mut c, r_type(1, 2, 1, 6, 5, 0x33)); // rem -> 0
        assert_eq!(c.x(5), 0);
    }

    #[test]
    fn rv32_load_sign_extends_to_32() {
        let mut c = rv32();
        c.set_x(1, 0x100);
        c.write_memory(0x100, &[0x80]).unwrap();
        // lb x2, 0(x1): 0x80 -> sign-extended to 0xffffff80 (32-bit, zero-ext to 64)
        run_one(
            &mut c,
            (0u32 << 20) | (1 << 15) | (0 << 12) | (2 << 7) | 0x03,
        );
        assert_eq!(c.x(2), 0xffff_ff80);
    }

    #[test]
    fn rv32_no_word_ops() {
        // ADDW (OP-32) is illegal on RV32.
        let mut c = rv32();
        assert!(matches!(
            run_one(&mut c, r_type(0, 2, 1, 0, 3, 0x3b)),
            RiscVExit::Trap(_)
        ));
    }

    #[test]
    fn rv32_zilsd_pair_load_store() {
        let mut isa = Isa::rv64gc();
        isa.zilsd = true;
        let mut c = RiscVCpu::new(
            RiscVConfig::rv32(isa),
            Box::new(FlatMemory::new(0, 0x1_0000)),
        );
        c.set_x(10, 0x200);
        c.write_memory(0x208, &0xaabb_ccdd_1122_3344u64.to_le_bytes())
            .unwrap();

        let load_pair = (8u32 << 20) | (10 << 15) | (3 << 12) | (6 << 7) | 0x03;
        run_one(&mut c, load_pair);
        assert_eq!(c.x(6), 0x1122_3344);
        assert_eq!(c.x(7), 0xaabb_ccdd);

        c.set_x(6, 0x5566_7788);
        c.set_x(7, 0x99aa_bbcc);
        let store_pair = (6 << 20) | (10 << 15) | (3 << 12) | (8 << 7) | 0x23;
        run_one(&mut c, store_pair);
        assert_eq!(c.mem_read_u64(0x208).unwrap(), 0x99aa_bbcc_5566_7788);
    }

    #[test]
    fn rv32_zclsd_compressed_pair_load() {
        let mut isa = Isa::rv64gc();
        isa.zclsd = true;
        let mut c = RiscVCpu::new(
            RiscVConfig::rv32(isa),
            Box::new(FlatMemory::new(0, 0x1_0000)),
        );
        c.set_x(2, 0x300);
        c.write_memory(0x300, &0x8877_6655_4433_2211u64.to_le_bytes())
            .unwrap();

        let c_ldsp = ((0b011 << 13) | (8 << 7) | 0b10) as u16;
        run_half(&mut c, c_ldsp);
        assert_eq!(c.x(8), 0x4433_2211);
        assert_eq!(c.x(9), 0x8877_6655);
    }

    #[test]
    fn zcmp_push_pop_and_return() {
        let mut isa = Isa::rv64gc();
        isa.zcmp = true;
        let mut c = RiscVCpu::new(
            RiscVConfig {
                xlen: Xlen::Rv64,
                isa,
            },
            Box::new(FlatMemory::new(0, 0x1_0000)),
        );
        c.set_x(2, 0x8000);
        c.set_x(1, 0x1235);
        c.set_x(8, 0x8888);
        c.set_x(9, 0x9999);

        let cm_push = ((0b101 << 13) | (0x18 << 8) | (5 << 4) | 0b10) as u16;
        run_half(&mut c, cm_push);
        assert_eq!(c.x(2), 0x7ff0);
        assert_eq!(c.mem_read_u64(0x7ff8).unwrap(), 0x8888);
        assert_eq!(c.mem_read_u64(0x7ff0).unwrap(), 0x1235);

        c.set_x(1, 0);
        c.set_x(8, 0);
        c.set_x(9, 0);
        c.set_x(10, 0xffff);
        let cm_popretz = ((0b101 << 13) | (0x1c << 8) | (5 << 4) | 0b10) as u16;
        run_half(&mut c, cm_popretz);
        assert_eq!(c.x(2), 0x8000);
        assert_eq!(c.x(1), 0x1235);
        assert_eq!(c.x(8), 0x8888);
        assert_eq!(c.x(9), 0);
        assert_eq!(c.x(10), 0);
        assert_eq!(c.pc(), 0x1234);
    }

    #[test]
    fn zcmp_register_moves_and_zcmt_table_jumps() {
        let mut isa = Isa::rv64gc();
        isa.zcmp = true;
        isa.zcmt = true;
        let mut c = RiscVCpu::new(
            RiscVConfig {
                xlen: Xlen::Rv64,
                isa,
            },
            Box::new(FlatMemory::new(0, 0x1_0000)),
        );

        c.set_x(10, 0xaaaa);
        c.set_x(11, 0xbbbb);
        let cm_mvsa01 =
            ((0b101 << 13) | (0b011 << 10) | (0 << 7) | (0b01 << 5) | (2 << 2) | 0b10) as u16;
        run_half(&mut c, cm_mvsa01);
        assert_eq!(c.x(8), 0xaaaa);
        assert_eq!(c.x(18), 0xbbbb);

        c.set_x(9, 0x9999);
        c.set_x(19, 0x1919);
        let cm_mva01s =
            ((0b101 << 13) | (0b011 << 10) | (1 << 7) | (0b11 << 5) | (3 << 2) | 0b10) as u16;
        run_half(&mut c, cm_mva01s);
        assert_eq!(c.x(10), 0x9999);
        assert_eq!(c.x(11), 0x1919);

        c.csr_write(0x017, 0x4000).unwrap();
        c.write_memory(0x4000 + 17 * 8, &0x5001u64.to_le_bytes())
            .unwrap();
        let cm_jt = ((0b101 << 13) | (17 << 2) | 0b10) as u16;
        run_half(&mut c, cm_jt);
        assert_eq!(c.pc(), 0x5000);

        c.set_pc(0x200);
        c.write_memory(0x4000 + 32 * 8, &0x6000u64.to_le_bytes())
            .unwrap();
        let cm_jalt = ((0b101 << 13) | (32 << 2) | 0b10) as u16;
        run_half(&mut c, cm_jalt);
        assert_eq!(c.pc(), 0x6000);
        assert_eq!(c.x(1), 0x202);

        c.set_pc(0x300);
        c.csr_write(0x017, 0x4001).unwrap();
        assert_eq!(c.csr_read(0x017), Ok(0x4000));
        assert_eq!(run_half(&mut c, cm_jt), RiscVExit::Continue);
        assert_eq!(c.pc(), 0x5000);
    }

    /// Encode an OP-V vector instruction (funct6/vm/vs2/vs1|rs1/funct3/vd).
    fn op_v(funct6: u32, vm: u32, vs2: u32, src: u32, funct3: u32, vd: u32) -> u32 {
        (funct6 << 26) | (vm << 25) | (vs2 << 20) | (src << 15) | (funct3 << 12) | (vd << 7) | 0x57
    }

    /// Fresh CPU with a valid e8,m1 vtype (vl = VLMAX) so vector ops aren't vill.
    fn cpu_e8m1() -> RiscVCpu {
        let mut c = cpu();
        // vsetvli x1, x0, e8, m1 (rs1=x0 keeps AVL=VLMAX).
        run_one(
            &mut c,
            (0u32 << 20) | (0 << 15) | (7 << 12) | (1 << 7) | 0x57,
        );
        c
    }

    #[test]
    fn vslidedown_oversized_offset_zeroes_lane() {
        // vslidedown.vx v1, v2, x5 with x5 = u64::MAX. Each source index
        // i+offset must be treated as >= VLMAX (zero), not wrap to an in-range
        // element. v2[0] is non-zero, so a wrapped read would be observable.
        let mut c = cpu_e8m1();
        c.set_x(5, u64::MAX);
        c.set_vreg(2, &[0xAAu8; VLENB as usize]);
        c.set_vreg(1, &[0x55u8; VLENB as usize]); // dest pre-filled
        assert!(matches!(
            run_one(&mut c, op_v(0b001111, 1, 2, 5, 0b100, 1)),
            RiscVExit::Continue
        ));
        // Every lane zeroed (no wrap into v2[0]==0xAA).
        assert_eq!(c.vreg(1), [0u8; VLENB as usize]);
    }

    #[test]
    fn vfncvt_fp8_result_rejects_sew8() {
        // vfncvt.f.f.w (funct6 010010, OPFV, vs1=10100) under SEW=8 has no
        // defined FP8 result format and must trap.
        let mut c = cpu_e8m1(); // e8 -> SEW=8
        assert!(matches!(
            run_one(&mut c, op_v(0b010010, 1, 2, 0b10100, 0b001, 1)),
            RiscVExit::Trap(_)
        ));
    }

    #[test]
    fn vrgather_rejects_overlapping_operands() {
        // vrgather.vv (funct6 001100, vv) with vd overlapping vs2 is reserved.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b001100, 1, 1, 2, 0b000, 1)),
            RiscVExit::Trap(_)
        ));
        // vd overlapping the index source vs1 is also reserved.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b001100, 1, 2, 1, 0b000, 1)),
            RiscVExit::Trap(_)
        ));
        // Distinct vd/vs2/vs1 still executes.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b001100, 1, 2, 3, 0b000, 1)),
            RiscVExit::Continue
        ));
    }

    #[test]
    fn vlseg_rejects_oversized_register_group() {
        // vlseg2e8.v under LMUL=8: EMUL=8 per field, so NFIELDS*EMUL=16 > 8.
        // This reserved register-group size must trap before any access.
        let mut c = cpu();
        // vsetvli x1, x0, e8, m8 (vtype = vlmul=011, vsew=000 => 0b00011).
        run_one(
            &mut c,
            (0b00011u32 << 20) | (0 << 15) | (7 << 12) | (1 << 7) | 0x57,
        );
        // vlseg2e8.v v8, (x10): nf field=1, mop=00, lumop=0, width=0, vd=8.
        let vlseg = (1u32 << 29) | (1 << 25) | (10 << 15) | (0 << 12) | (8 << 7) | 0x07;
        assert!(matches!(run_one(&mut c, vlseg), RiscVExit::Trap(_)));
    }

    #[test]
    fn vmask_logical_rejects_masked_encoding() {
        // vmand.mm etc. (funct6 011001, OPMVV funct3=010) are always unmasked;
        // the vm=0 form is reserved and must trap.
        let mut c = cpu_e8m1();
        // vm=0 (masked) vmand.mm v1, v2, v3 -> illegal.
        assert!(matches!(
            run_one(&mut c, op_v(0b011001, 0, 2, 3, 0b010, 1)),
            RiscVExit::Trap(_)
        ));
        // vm=1 (proper) form still executes.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b011001, 1, 2, 3, 0b010, 1)),
            RiscVExit::Continue
        ));
    }

    #[test]
    fn vadc_vsbc_reject_unmasked_encoding() {
        // vadc.vvm (funct6 010000) and vsbc.vvm (010010) consume the v0 carry
        // and are only defined masked (vm=0); the vm=1 form is reserved.
        for funct6 in [0b010000u32, 0b010010] {
            assert!(
                matches!(
                    run_one(&mut cpu_e8m1(), op_v(funct6, 1, 2, 3, 0b000, 1)),
                    RiscVExit::Trap(_)
                ),
                "unmasked funct6={funct6:06b} must trap"
            );
            // Masked (vm=0) form executes (vd=1 avoids overwriting v0 mask).
            assert!(matches!(
                run_one(&mut cpu_e8m1(), op_v(funct6, 0, 2, 3, 0b000, 1)),
                RiscVExit::Continue
            ));
        }
    }

    #[test]
    fn vcompress_rejects_reserved_states() {
        // vcompress.vm (funct6 010111, OPMVV) must be unmasked, vstart==0, and
        // its destination must not overlap vs2 or the vs1 mask source.
        // Masked (vm=0) -> illegal.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b010111, 0, 2, 3, 0b010, 1)),
            RiscVExit::Trap(_)
        ));
        // vd overlaps vs2 -> illegal.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b010111, 1, 1, 3, 0b010, 1)),
            RiscVExit::Trap(_)
        ));
        // vd overlaps vs1 (mask source) -> illegal.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b010111, 1, 2, 1, 0b010, 1)),
            RiscVExit::Trap(_)
        ));
        // Nonzero vstart -> illegal.
        let mut c = cpu_e8m1();
        c.set_vstart(3);
        assert!(matches!(
            run_one(&mut c, op_v(0b010111, 1, 2, 3, 0b010, 1)),
            RiscVExit::Trap(_)
        ));
        // Valid form (distinct vd/vs2/vs1, vm=1, vstart=0) executes.
        assert!(matches!(
            run_one(&mut cpu_e8m1(), op_v(0b010111, 1, 2, 3, 0b010, 1)),
            RiscVExit::Continue
        ));
    }

    #[test]
    fn mask_reductions_reject_nonzero_vstart() {
        // vcpop.m/vfirst.m/vmsbf.m/vmsof.m/vmsif.m/viota.m are not restartable;
        // a guest-set non-zero vstart must raise illegal, not skip elements.
        // funct6 010000 OPMVV with vs1 select: vcpop=10000, vfirst=10001,
        // vmsbf=00001, vmsof=00010, vmsif=00011, viota=10000(funct6 010100).
        let cases: &[(u32, u32, u32)] = &[
            (0b010000, 0b10000, 1), // vcpop.m   -> x1
            (0b010000, 0b10001, 1), // vfirst.m  -> x1
            (0b010100, 0b00001, 2), // vmsbf.m   -> v2
            (0b010100, 0b00010, 2), // vmsof.m   -> v2
            (0b010100, 0b00011, 2), // vmsif.m   -> v2
            (0b010100, 0b10000, 2), // viota.m   -> v2
        ];
        for &(funct6, vs1, vd) in cases {
            let mut c = cpu_e8m1();
            c.set_vstart(2);
            assert!(
                matches!(
                    run_one(&mut c, op_v(funct6, 1, 4, vs1, 0b010, vd)),
                    RiscVExit::Trap(_)
                ),
                "funct6={funct6:06b} vs1={vs1:05b} with vstart!=0 must trap"
            );
        }
    }

    #[test]
    fn vmvr_rejects_reserved_encodings() {
        // vmv<nr>r.v: funct6=0b100111, funct3=0b011, OP-V (0x57). Only nr in
        // {1,2,4,8} (simm 0/1/3/7), unmasked, with vd/vs2 aligned to nr are
        // defined. Reserved simm, masked, or misaligned forms must trap.
        let op_mvr = |vm: u32, vs2: u32, simm: u32, vd: u32| -> u32 {
            (0b100111u32 << 26)
                | (vm << 25)
                | (vs2 << 20)
                | (simm << 15)
                | (0b011 << 12)
                | (vd << 7)
                | 0x57
        };
        let setup = || {
            let mut c = cpu();
            // vsetvli x1, x0, e8, m1 -> valid (non-vill) vtype.
            run_one(
                &mut c,
                (0u32 << 20) | (0 << 15) | (7 << 12) | (1 << 7) | 0x57,
            );
            c
        };

        // Reserved simm=2 (would be a 3-register move): illegal.
        assert!(matches!(
            run_one(&mut setup(), op_mvr(1, 16, 2, 8)),
            RiscVExit::Trap(_)
        ));
        // Masked encoding (vm=0) of an otherwise-valid vmv1r.v: illegal.
        assert!(matches!(
            run_one(&mut setup(), op_mvr(0, 16, 0, 8)),
            RiscVExit::Trap(_)
        ));
        // vmv2r.v with misaligned vd=9 (not a multiple of 2): illegal.
        assert!(matches!(
            run_one(&mut setup(), op_mvr(1, 16, 1, 9)),
            RiscVExit::Trap(_)
        ));

        // Valid vmv1r.v v8, v16 executes and copies the register.
        let mut c = setup();
        let pat: [u8; VLENB as usize] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        c.set_vreg(16, &pat);
        assert!(matches!(
            run_one(&mut c, op_mvr(1, 16, 0, 8)),
            RiscVExit::Continue
        ));
        assert_eq!(c.vreg(8), pat);
    }

    #[test]
    fn vector_config() {
        let mut c = cpu();
        // vsetvli x1, x2(=100), e8,m1 (vtype=0): VLMAX=128/8=16, vl=min(100,16)=16
        c.set_x(2, 100);
        run_one(
            &mut c,
            (0u32 << 20) | (2 << 15) | (7 << 12) | (1 << 7) | 0x57,
        );
        assert_eq!(c.x(1), 16);
        assert_eq!(c.csr_read(0xC20).unwrap(), 16); // vl
        assert_eq!(c.csr_read(0xC21).unwrap(), 0); // vtype
        assert_eq!(c.csr_read(0xC22).unwrap(), 16); // vlenb (VLEN/8)

        // e32,m1: VLMAX = 128/32 = 4. AVL=100 -> vl=4.
        run_one(
            &mut c,
            ((2u32 << 3) << 20) | (2 << 15) | (7 << 12) | (3 << 7) | 0x57,
        );
        assert_eq!(c.x(3), 4);

        // Keep form (rs1=x0, rd=x0): vl unchanged. Set vl=4 first (above), then keep.
        run_one(
            &mut c,
            (0u32 << 20) | (0 << 15) | (7 << 12) | (0 << 7) | 0x57,
        );
        assert_eq!(c.csr_read(0xC20).unwrap(), 4); // vl retained

        // Illegal vtype (vsew=4 -> SEW=128 > ELEN): vill set, vl=0.
        run_one(
            &mut c,
            ((4u32 << 3) << 20) | (0 << 15) | (7 << 12) | (5 << 7) | 0x57,
        );
        assert_eq!(c.x(5), 0);
        assert_eq!(c.csr_read(0xC21).unwrap() >> 63, 1); // vtype.vill

        // vsetivli x6, 3, e64,m1: VLMAX = 128/64 = 2, vl = min(3,2) = 2.
        run_one(
            &mut c,
            (0b11u32 << 30) | ((3u32 << 3) << 20) | (3 << 15) | (7 << 12) | (6 << 7) | 0x57,
        );
        assert_eq!(c.x(6), 2);
    }

    #[test]
    fn clz_cpop() {
        let mut c = cpu();
        c.set_x(1, 0x0000_0000_0000_00ff);
        // clz x2, x1 : funct7=0110000 rs2=0 funct3=1 opcode=0x13
        run_one(
            &mut c,
            (0b0110000u32 << 25) | (0 << 20) | (1 << 15) | (1 << 12) | (2 << 7) | 0x13,
        );
        assert_eq!(c.x(2), 56);
        // cpop x3, x1
        run_one(
            &mut c,
            (0b0110000u32 << 25) | (2 << 20) | (1 << 15) | (1 << 12) | (3 << 7) | 0x13,
        );
        assert_eq!(c.x(3), 8);
    }

    // ------------------------------------------------------------------
    // Xsoteria (Google Soteria/GSC) vendor extension.
    //
    // Encodings and semantics are validated against the ti50-sdk LLVM-15
    // "soteria" backend patch (byte-exact `# encoding:` strings) and the
    // bitmanip GREV definition.
    // ------------------------------------------------------------------

    fn rv32_ti50() -> RiscVCpu {
        let cfg = RiscVConfig {
            xlen: Xlen::Rv32,
            isa: Isa::ti50(),
        };
        RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 0x1_0000)))
    }

    fn rv32_hazard3() -> RiscVCpu {
        let cfg = RiscVConfig {
            xlen: Xlen::Rv32,
            isa: Isa {
                xhazard3: true,
                ..Isa::rv_i()
            },
        };
        RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 0x1_0000)))
    }

    fn rv64_andes() -> RiscVCpu {
        let cfg = RiscVConfig {
            xlen: Xlen::Rv64,
            isa: Isa {
                xandes: true,
                ..Isa::rv64gc()
            },
        };
        RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 0x1_0000)))
    }

    fn rv64_thead() -> RiscVCpu {
        let cfg = RiscVConfig {
            xlen: Xlen::Rv64,
            isa: Isa {
                xthead: true,
                ..Isa::rv64gc()
            },
        };
        RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 0x1_0000)))
    }

    // CUSTOM-1 (0x2b) register form: r_type(funct7, rs2, rs1, funct3, rd, 0x2b).
    // CUSTOM-0 (0x0b) immediate form: r_type(funct7, imm5, rs1, funct3, rd, 0x0b).

    #[test]
    fn xsoteria_decode_golden_bytes() {
        // Byte-exact encodings lifted from the ti50-sdk LLVM soteria patch.
        let cases: &[(u32, Op)] = &[
            (0x00b5_052b, Op::Grev),  // 2b 05 b5 00
            (0x0105_050b, Op::Grevi), // 0b 05 05 01 (imm=16)
            (0x00b5_152b, Op::Bitc),  // 2b 15 b5 00
            (0x0125_150b, Op::Bitci), // 0b 15 25 01 (imm=18)
            (0x40b5_152b, Op::Bits),  // 2b 15 b5 40
            (0x41f5_150b, Op::Bitsi), // 0b 15 f5 41 (imm=31)
            (0x0005_350b, Op::Pcnt),  // 0b 35 05 00
            (0x4005_250b, Op::Clz),   // 0b 25 05 40
            (0x0005_250b, Op::Fls),   // 0b 25 05 00
        ];
        for &(w, op) in cases {
            let insn = crate::isa::riscv::decode::decode(w, Xlen::Rv32, &Isa::ti50());
            assert_eq!(insn.op, op, "encoding {w:#010x} should decode to {op:?}");
        }
    }

    #[test]
    fn xsoteria_decode_gated_rv32_and_flag() {
        let grev = 0x00b5_052bu32;
        // Off without the flag.
        let no_ext = Isa {
            xsoteria: false,
            ..Isa::ti50()
        };
        assert!(crate::isa::riscv::decode::decode(grev, Xlen::Rv32, &no_ext).is_illegal());
        // RV32-only: illegal under RV64 even with the flag set.
        let rv64_ext = Isa {
            xsoteria: true,
            ..Isa::rv64gc()
        };
        assert!(crate::isa::riscv::decode::decode(grev, Xlen::Rv64, &rv64_ext).is_illegal());
        // Enabled under RV32.
        assert_eq!(
            crate::isa::riscv::decode::decode(grev, Xlen::Rv32, &Isa::ti50()).op,
            Op::Grev
        );
    }

    #[test]
    fn xsoteria_grev_full_reverse_and_rev8() {
        let mut c = rv32_ti50();
        // grev x3, x1, x2 with ctrl=31 -> full bit reverse.
        c.set_x(1, 0x0000_0001);
        c.set_x(2, 31);
        run_one(&mut c, r_type(0x00, 2, 1, 0b000, 3, 0x2b));
        assert_eq!(c.x(3), 0x8000_0000);
        // grevi x4, x1, 24 -> rev8 (whole-word byte swap).
        c.set_x(1, 0x1122_3344);
        run_one(&mut c, r_type(0x00, 24, 1, 0b000, 4, 0x0b));
        assert_eq!(c.x(4), 0x4433_2211);
        // Control masks to 5 bits: ctrl 24+32 == 24 -> still rev8.
        c.set_x(2, 24 + 32);
        run_one(&mut c, r_type(0x00, 2, 1, 0b000, 5, 0x2b));
        assert_eq!(c.x(5), 0x4433_2211);
    }

    #[test]
    fn xsoteria_bit_set_clear() {
        let mut c = rv32_ti50();
        // bitci x3, x1, 4 -> clear bit 4.
        c.set_x(1, 0xffff_ffff);
        run_one(&mut c, r_type(0x00, 4, 1, 0b001, 3, 0x0b));
        assert_eq!(c.x(3), 0xffff_ffef);
        // bitsi x4, x0, 31 -> set bit 31.
        run_one(&mut c, r_type(0x20, 31, 0, 0b001, 4, 0x0b));
        assert_eq!(c.x(4), 0x8000_0000);
        // bitc x5, x1, x2 (rs2=36 -> 36&31=4) -> clear bit 4.
        c.set_x(1, 0xffff_ffff);
        c.set_x(2, 36);
        run_one(&mut c, r_type(0x00, 2, 1, 0b001, 5, 0x2b));
        assert_eq!(c.x(5), 0xffff_ffef);
        // bits x6, x0, x2 (rs2=36 -> bit 4) -> 0x10.
        run_one(&mut c, r_type(0x20, 2, 0, 0b001, 6, 0x2b));
        assert_eq!(c.x(6), 0x0000_0010);
    }

    #[test]
    fn xsoteria_pcnt_clz_fls() {
        let mut c = rv32_ti50();
        // pcnt x3, x1
        c.set_x(1, 0xf0f0_f0f0);
        run_one(&mut c, r_type(0x00, 0, 1, 0b011, 3, 0x0b));
        assert_eq!(c.x(3), 16);
        // clz x4, x1 (0x00010000 -> 15); clz(0) -> 32.
        c.set_x(1, 0x0001_0000);
        run_one(&mut c, r_type(0x20, 0, 1, 0b010, 4, 0x0b));
        assert_eq!(c.x(4), 15);
        c.set_x(1, 0);
        run_one(&mut c, r_type(0x20, 0, 1, 0b010, 5, 0x0b));
        assert_eq!(c.x(5), 32);
        // fls (1-based MSB index): fls(0)=0, fls(1)=1, fls(0x80000000)=32,
        // fls(0x00010000)=17.
        for (input, expect) in [(0u64, 0u64), (1, 1), (0x8000_0000, 32), (0x0001_0000, 17)] {
            c.set_x(1, input);
            run_one(&mut c, r_type(0x00, 0, 1, 0b010, 6, 0x0b));
            assert_eq!(c.x(6), expect, "fls({input:#x})");
        }
    }

    #[test]
    fn xsoteria_csr_scratch_permissive_only_when_enabled() {
        // On a ti50 hart, unmodeled/vendor CSRs are store-only scratch.
        let mut c = rv32_ti50();
        for addr in [
            0x7c0u16, 0x7c1, 0x7d0, 0x3a0, /* pmpcfg0 */
            0x3b0, /* pmpaddr0 */
        ] {
            c.csr_write(addr, 0xdead_beef).unwrap();
            assert_eq!(c.csr_read(addr).unwrap(), 0xdead_beef);
        }
        // Never-written vendor CSR reads back 0.
        assert_eq!(c.csr_read(0x7cf).unwrap(), 0);
        // On a strict RV64GC hart, the same CSR is illegal.
        let mut g = cpu();
        assert!(g.csr_write(0x7c0, 1).is_err());
        assert!(g.csr_read(0x7c0).is_err());
    }

    #[test]
    fn xthead_scalar_arithmetic_and_fmv() {
        let mut c = rv64_thead();

        // th.addsl x3, x1, x2, 2 -> x1 + (x2 << 2).
        c.set_x(1, 5);
        c.set_x(2, 3);
        run_one(&mut c, r_type(0x02, 2, 1, 0b001, 3, 0x0b));
        assert_eq!(c.x(3), 17);

        // th.srri x4, x5, 9.
        c.set_x(5, 0x8000_0000_0000_0001);
        run_one(&mut c, r_type(0x08, 9, 5, 0b001, 4, 0x0b));
        assert_eq!(c.x(4), 0x00c0_0000_0000_0000);

        // th.ext sign-extends the extracted field; th.extu zero-extends it.
        c.set_x(10, 0xf0);
        run_one(&mut c, r_type(7 << 1, 4, 10, 0b010, 6, 0x0b));
        assert_eq!(c.x(6), u64::MAX);
        run_one(&mut c, r_type(7 << 1, 4, 10, 0b011, 7, 0x0b));
        assert_eq!(c.x(7), 0xf);

        c.set_x(10, 0x0000_00ff_0000_0000);
        run_one(&mut c, r_type(0x40, 0, 10, 0b001, 8, 0x0b));
        assert_eq!(c.x(8), 0xffff_ff00_ffff_ffff);

        c.set_x(9, 0x11);
        c.set_x(10, 0);
        run_one(&mut c, r_type(0x20, 10, 9, 0b001, 11, 0x0b));
        assert_eq!(c.x(11), 0x11);
        c.set_x(11, 0x55);
        c.set_x(10, 1);
        run_one(&mut c, r_type(0x20, 10, 9, 0b001, 11, 0x0b));
        assert_eq!(c.x(11), 0x55);

        c.set_x(12, 7);
        c.set_x(13, 6);
        c.set_x(14, 100);
        run_one(&mut c, r_type(0x10, 13, 12, 0b001, 14, 0x0b));
        assert_eq!(c.x(14), 142);

        c.set_f(5, 0x1111_2222_3333_4444);
        c.set_x(6, 0xaabb_ccdd);
        run_one(&mut c, r_type(0x50, 0, 6, 0b001, 5, 0x0b));
        assert_eq!(c.f(5), 0xaabb_ccdd_3333_4444);
        run_one(&mut c, r_type(0x60, 0, 5, 0b001, 7, 0x0b));
        assert_eq!(c.x(7), 0xaabb_ccdd);
    }

    #[test]
    fn xthead_indexed_integer_and_fp_memory() {
        let mut c = rv64_thead();

        c.set_x(10, 0x100);
        c.write_memory(0x100, &[0xfe]).unwrap();
        run_one(&mut c, r_type(0x0c, 2, 10, 0b100, 5, 0x0b)); // th.lbia x5,(x10),2,0
        assert_eq!(c.x(5), (-2i64) as u64);
        assert_eq!(c.x(10), 0x102);

        c.set_x(10, 0x120);
        c.set_x(6, 0x1122_3344);
        run_one(&mut c, r_type(0x25, 1, 10, 0b101, 6, 0x0b)); // th.swib x6,(x10),1,1
        assert_eq!(c.x(10), 0x122);
        let mut word = [0u8; 4];
        c.read_memory(0x122, &mut word).unwrap();
        assert_eq!(u32::from_le_bytes(word), 0x1122_3344);

        c.set_x(10, 0x200);
        c.set_x(11, 3);
        c.write_memory(0x20c, &0x8000_0000u32.to_le_bytes())
            .unwrap();
        run_one(&mut c, r_type(0x22, 11, 10, 0b100, 7, 0x0b)); // th.lrw x7,x10,x11,2
        assert_eq!(c.x(7), 0xffff_ffff_8000_0000);

        c.set_x(10, 0x300);
        c.set_x(5, 0xffff_ffff_89ab_cdef);
        c.set_x(6, 0x1122_3344);
        run_one(&mut c, r_type(0x70, 6, 10, 0b101, 5, 0x0b)); // th.swd x5,x6,0(x10)
        run_one(&mut c, r_type(0x78, 8, 10, 0b100, 7, 0x0b)); // th.lwud x7,x8,0(x10)
        assert_eq!(c.x(7), 0x89ab_cdef);
        assert_eq!(c.x(8), 0x1122_3344);

        c.set_x(10, 0x400);
        c.set_x(11, 4);
        c.set_f(5, 0xffff_ffff_aabb_ccdd);
        run_one(&mut c, r_type(0x20, 11, 10, 0b111, 5, 0x0b)); // th.fsrw f5,x10,x11,0
        let mut fp_word = [0u8; 4];
        c.read_memory(0x404, &mut fp_word).unwrap();
        assert_eq!(u32::from_le_bytes(fp_word), 0xaabb_ccdd);
        run_one(&mut c, r_type(0x20, 11, 10, 0b110, 6, 0x0b)); // th.flrw f6,x10,x11,0
        assert_eq!(c.f(6), 0xffff_ffff_aabb_ccdd);
    }

    #[test]
    fn xthead_vdot_documented_vmaqa_executes() {
        let mut c = rv64_thead();
        c.set_vl_vtype(2, 2 << 3); // e32,m1

        let mut vd = [0u8; VLENB as usize];
        vd[0..4].copy_from_slice(&10u32.to_le_bytes());
        vd[4..8].copy_from_slice(&0xffff_ff00u32.to_le_bytes());
        c.set_vreg(1, &vd);

        let mut vs1 = [0u8; VLENB as usize];
        vs1[0..4].copy_from_slice(&[1, 2, 0xff, 0x80]);
        vs1[4..8].copy_from_slice(&[0xff, 0, 1, 2]);
        c.set_vreg(2, &vs1);

        let mut vs2 = [0u8; VLENB as usize];
        vs2[0..4].copy_from_slice(&[3, 4, 5, 0xff]);
        vs2[4..8].copy_from_slice(&[1, 2, 3, 4]);
        c.set_vreg(3, &vs2);

        assert_eq!(
            run_one(&mut c, r_type((0x20 << 1) | 1, 3, 2, 0b110, 1, 0x0b)),
            RiscVExit::Continue
        );

        let out = c.vreg(1);
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 144);
        assert_eq!(
            u32::from_le_bytes(out[4..8].try_into().unwrap()),
            0xffff_ff0a
        );
    }

    #[test]
    fn xthead_vdot_mask_is_byte_granular() {
        let mut c = rv64_thead();
        c.set_vl_vtype(1, 2 << 3); // e32,m1

        let mut vd = [0u8; VLENB as usize];
        vd[0..4].copy_from_slice(&100u32.to_le_bytes());
        c.set_vreg(1, &vd);

        let mut vs2 = [0u8; VLENB as usize];
        vs2[0..4].copy_from_slice(&[5, 6, 7, 8]);
        c.set_vreg(3, &vs2);

        let mut mask = [0u8; VLENB as usize];
        mask[0] = 0b0000_0101; // include source bytes 0 and 2 only.
        c.set_vreg(0, &mask);
        c.set_x(5, 0xfc03_fe01); // signed bytes: 1, -2, 3, -4.

        assert_eq!(
            run_one(&mut c, r_type(0x25 << 1, 3, 5, 0b110, 1, 0x0b)),
            RiscVExit::Continue
        );

        let out = c.vreg(1);
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 126);
    }

    #[test]
    fn xthead_vdot_rejects_bad_sew_and_undocumented_packed_exec() {
        let mut bad_sew = rv64_thead();
        bad_sew.set_vl_vtype(1, 0); // e8,m1 is illegal for documented vmaqa*.
        assert!(matches!(
            run_one(&mut bad_sew, r_type((0x20 << 1) | 1, 3, 2, 0b110, 1, 0x0b)),
            RiscVExit::Trap(_)
        ));

        let mut packed = rv64_thead();
        packed.set_vl_vtype(1, 2 << 3);
        assert!(matches!(
            run_one(&mut packed, r_type((0x20 << 1) | 1, 3, 2, 0b111, 1, 0x0b)),
            RiscVExit::Trap(_)
        ));
    }

    #[test]
    fn hazard3_bextm_and_bextmi_extract_multiple_bits() {
        let mut c = rv32_hazard3();

        // h3.bextm x3, x1, x2, 4 extracts bits [rs2 +: 4].
        c.set_x(1, 0b1101_0110_1001);
        c.set_x(2, 4);
        run_one(&mut c, r_type(0b0000110, 2, 1, 0b000, 3, 0x0b));
        assert_eq!(c.x(3), 0b0110);

        // h3.bextmi x4, x1, 8, 6 extracts an immediate-position field.
        let imm12 = (0b101 << 6) | 8;
        run_one(
            &mut c,
            (imm12 << 20) | (1 << 15) | (0b100 << 12) | (4 << 7) | 0x0b,
        );
        assert_eq!(c.x(4), 0b1101);

        // Register shift amounts use the RV32 low 5 bits.
        c.set_x(2, 36);
        run_one(&mut c, r_type(0b0000010, 2, 1, 0b000, 5, 0x0b));
        assert_eq!(c.x(5), 0b10);
    }

    #[test]
    fn hazard3_power_hints_are_gated() {
        let mut h3 = rv32_hazard3();
        assert_eq!(
            run_one(&mut h3, r_type(0, 0, 0, 0b010, 0, 0x33)),
            RiscVExit::Wfi
        );

        let mut h3_unblock = rv32_hazard3();
        assert_eq!(
            run_one(&mut h3_unblock, r_type(0, 1, 0, 0b010, 0, 0x33)),
            RiscVExit::Continue
        );

        let mut plain = RiscVCpu::new(
            RiscVConfig::rv32(Isa::rv_i()),
            Box::new(FlatMemory::new(0, 0x1_0000)),
        );
        assert_eq!(
            run_one(&mut plain, r_type(0, 0, 0, 0b010, 0, 0x33)),
            RiscVExit::Continue
        );
    }

    #[test]
    fn andes_gp_relative_load_store_and_addigp() {
        let mut c = rv64_andes();
        c.set_x(3, 0x200);
        c.write_memory(0x200, &[0x80, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89, 0x67])
            .unwrap();

        run_one(&mut c, (5 << 7) | 0x0b); // nds.lbgp t0, 0
        assert_eq!(c.x(5), 0xffff_ffff_ffff_ff80);
        run_one(&mut c, (0b10 << 12) | (6 << 7) | 0x0b); // nds.lbugp t1, 0
        assert_eq!(c.x(6), 0x80);
        run_one(&mut c, (0b001 << 12) | (7 << 7) | 0x2b); // nds.lhgp t2, 0
        assert_eq!(c.x(7), 0x3480);
        run_one(&mut c, (0b010 << 12) | (28 << 7) | 0x2b); // nds.lwgp t3, 0
        assert_eq!(c.x(28), 0xffff_ffff_ef12_3480);
        run_one(&mut c, (0b011 << 12) | (29 << 7) | 0x2b); // nds.ldgp t4, 0
        assert_eq!(c.x(29), 0x6789_abcd_ef12_3480);

        c.set_x(30, 0xaa);
        run_one(&mut c, (30 << 20) | (0b11 << 12) | 0x0b); // nds.sbgp t5, 0
        let mut one = [0u8; 1];
        c.read_memory(0x200, &mut one).unwrap();
        assert_eq!(one[0], 0xaa);

        run_one(&mut c, (31 << 7) | (0b01 << 12) | 0x0b); // nds.addigp t6, 0
        assert_eq!(c.x(31), 0x200);
    }

    #[test]
    fn andes_bitfield_lea_branch_and_byte_scans() {
        let mut c = rv64_andes();

        c.set_x(10, 0b1011_0100);
        run_one(
            &mut c,
            (7 << 26) | (4 << 20) | (10 << 15) | (0b010 << 12) | (5 << 7) | 0x5b,
        );
        assert_eq!(c.x(5), 0b1011);
        run_one(
            &mut c,
            (7 << 26) | (4 << 20) | (10 << 15) | (0b011 << 12) | (6 << 7) | 0x5b,
        );
        assert_eq!(c.x(6), 0xffff_ffff_ffff_fffb);

        c.set_x(4, 0x1000);
        c.set_x(5, 3);
        run_one(
            &mut c,
            (0x06 << 25) | (5 << 20) | (4 << 15) | (7 << 7) | 0x5b,
        );
        assert_eq!(c.x(7), 0x100c);
        c.set_x(5, 0xffff_ffff_0000_0003);
        run_one(
            &mut c,
            (0x0a << 25) | (5 << 20) | (4 << 15) | (28 << 7) | 0x5b,
        );
        assert_eq!(c.x(28), 0x100c);

        c.set_x(10, 0);
        let pc = c.pc();
        run_one(
            &mut c,
            (4 << 8) | (1 << 20) | (10 << 15) | (0b111 << 12) | 0x5b,
        );
        assert_eq!(c.pc(), pc + 8);

        c.set_x(1, 0x4433_2211);
        c.set_x(2, 0x33);
        run_one(
            &mut c,
            (0x10 << 25) | (2 << 20) | (1 << 15) | (3 << 7) | 0x5b,
        );
        assert_eq!(c.x(3), 2);

        c.set_x(1, 0x1122_3344);
        c.set_x(2, 0x1122_0044);
        run_one(
            &mut c,
            (0x12 << 25) | (2 << 20) | (1 << 15) | (4 << 7) | 0x5b,
        );
        assert_eq!(c.x(4), 1);
        run_one(
            &mut c,
            (0x11 << 25) | (2 << 20) | (1 << 15) | (5 << 7) | 0x5b,
        );
        assert_eq!(c.x(5), 1);
        run_one(
            &mut c,
            (0x13 << 25) | (2 << 20) | (1 << 15) | (6 << 7) | 0x5b,
        );
        assert_eq!(c.x(6), 1);
    }

    #[test]
    fn warm_reset_clears_arch_state_keeps_nothing() {
        let mut c = rv32_ti50();
        c.set_x(5, 0x1234);
        c.set_pc(0x9999);
        c.csr_write(0x7c0, 0xabcd).unwrap();
        c.reset(0x956b2);
        assert_eq!(c.pc(), 0x956b2);
        assert_eq!(c.x(5), 0);
        // Vendor scratch CSRs are cleared by reset.
        assert_eq!(c.csr_read(0x7c0).unwrap(), 0);
    }
}
