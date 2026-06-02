//! RISC-V hart state and the decode/execute interpreter loop.
//!
//! [`RiscVCpu`] owns the architectural register files, CSRs and PC, and a
//! [`Memory`] backing store. [`step`](RiscVCpu::step) fetches, decodes and
//! executes exactly one instruction, returning a [`RiscVExit`] describing how
//! control left the instruction (normal retire, environment call, breakpoint,
//! wait-for-interrupt, or a synchronous trap).

use super::csr::Csr;
use super::decode::{decode_at, DecodeError, Insn, Op};
use super::float::RoundingMode;
use super::memory::{MemError, Memory};
use super::{Isa, Xlen};

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

/// Standard RISC-V synchronous exception cause codes.
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
}

/// A synchronous trap raised while executing an instruction.
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
    /// A synchronous exception was raised (and delivered to the trap vector).
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
    mcause: u64,
    mtval: u64,
    mscratch: u64,
    mie: u64,
    mip: u64,
    medeleg: u64,
    mideleg: u64,
    mcounteren: u64,
    mhartid: u64,

    // ---- counters ----
    cycle: u64,
    time: u64,
    instret: u64,

    /// Guest memory.
    mem: Box<dyn Memory>,
}

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
            mcause: 0,
            mtval: 0,
            mscratch: 0,
            mie: 0,
            mip: 0,
            medeleg: 0,
            mideleg: 0,
            mcounteren: 0,
            mhartid: 0,
            cycle: 0,
            time: 0,
            instret: 0,
            mem,
        }
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

    /// Current privilege level.
    pub fn privilege(&self) -> Priv {
        self.priv_
    }

    /// Set the current privilege level.
    pub fn set_privilege(&mut self, p: Priv) {
        self.priv_ = p;
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

    // ---------------------------------------------------------------
    // Execution loop.
    // ---------------------------------------------------------------

    /// Fetch, decode and execute one instruction.
    pub fn step(&mut self) -> RiscVExit {
        let pc = self.pc;
        let insn = match decode_at(self.mem.as_ref(), pc, self.cfg.xlen, &self.cfg.isa) {
            Ok(i) => i,
            Err(DecodeError::Fetch(_)) => {
                let trap = Trap {
                    cause: cause::INSTR_ACCESS_FAULT,
                    tval: pc,
                };
                self.deliver_trap(trap, pc);
                return RiscVExit::Trap(trap);
            }
        };
        self.cycle = self.cycle.wrapping_add(1);
        match self.execute(&insn, pc) {
            Ok(exit) => {
                self.instret = self.instret.wrapping_add(1);
                exit
            }
            Err(trap) => {
                self.deliver_trap(trap, pc);
                RiscVExit::Trap(trap)
            }
        }
    }

    /// Run until a non-`Continue` exit or `max_insns` instructions retire.
    /// Returns the exit that stopped the loop (`Continue` only if the budget
    /// was exhausted).
    pub fn run(&mut self, max_insns: u64) -> RiscVExit {
        for _ in 0..max_insns {
            match self.step() {
                RiscVExit::Continue => {}
                other => return other,
            }
        }
        RiscVExit::Continue
    }

    /// Deliver a synchronous trap to M-mode (direct vectoring).
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
        self.pc = self.mtvec & !0b11; // BASE (synchronous -> direct entry)
    }

    // ---------------------------------------------------------------
    // Instruction execution.
    // ---------------------------------------------------------------

    fn execute(&mut self, insn: &Insn, pc: u64) -> Result<RiscVExit, Trap> {
        // Default fall-through PC; control-flow ops override.
        self.pc = pc.wrapping_add(insn.len as u64);

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
            Op::Beq => self.branch(self.sx(a) == self.sx(b), pc, imm),
            Op::Bne => self.branch(self.sx(a) != self.sx(b), pc, imm),
            Op::Blt => self.branch(self.sx(a) < self.sx(b), pc, imm),
            Op::Bge => self.branch(self.sx(a) >= self.sx(b), pc, imm),
            Op::Bltu => self.branch(a < b, pc, imm),
            Op::Bgeu => self.branch(a >= b, pc, imm),

            // ---- loads ----
            Op::Lb => self.load(rd, a, imm, 1, true)?,
            Op::Lh => self.load(rd, a, imm, 2, true)?,
            Op::Lw => self.load(rd, a, imm, 4, true)?,
            Op::Ld => self.load(rd, a, imm, 8, true)?,
            Op::Lbu => self.load(rd, a, imm, 1, false)?,
            Op::Lhu => self.load(rd, a, imm, 2, false)?,
            Op::Lwu => self.load(rd, a, imm, 4, false)?,

            // ---- stores ----
            Op::Sb => self.store(a, imm, b, 1)?,
            Op::Sh => self.store(a, imm, b, 2)?,
            Op::Sw => self.store(a, imm, b, 4)?,
            Op::Sd => self.store(a, imm, b, 8)?,

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
            Op::Srlw => self.set_x(rd, word((a as u32) >> (b & 0x1f))),
            Op::Sraw => self.set_x(rd, word(((a as u32 as i32) >> (b & 0x1f)) as u32)),

            // ---- FENCE / system ----
            Op::Fence | Op::FenceI => {}
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
            Op::Wfi => return Ok(RiscVExit::Wfi),
            Op::Mret => self.mret(),
            Op::Sret => self.mret(), // single-mode model: same restore path

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
    fn branch(&mut self, taken: bool, pc: u64, imm: u64) {
        if taken {
            self.pc = pc.wrapping_add(imm) & self.xmask();
        }
    }

    fn load(
        &mut self,
        rd: u8,
        base: u64,
        imm: u64,
        size: usize,
        signed: bool,
    ) -> Result<(), Trap> {
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
            if b == 0 {
                u64::MAX
            } else {
                a / b
            }
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
            if b == 0 {
                a
            } else {
                a % b
            }
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
            return Err(Trap { cause: c, tval: addr });
        }
        match insn.op {
            Op::LrW => {
                let v = self.mem.read_u32(addr).map_err(|_| acc_fault(false, addr))?;
                self.reservation = Some(addr);
                self.set_x(insn.rd, v as i32 as i64 as u64);
            }
            Op::LrD => {
                let v = self.mem.read_u64(addr).map_err(|_| acc_fault(false, addr))?;
                self.reservation = Some(addr);
                self.set_x(insn.rd, v);
            }
            Op::ScW => {
                let ok = self.reservation == Some(addr);
                if ok {
                    self.mem
                        .write_u32(addr, self.x(insn.rs2) as u32)
                        .map_err(|_| acc_fault(true, addr))?;
                }
                self.reservation = None;
                self.set_x(insn.rd, if ok { 0 } else { 1 });
            }
            Op::ScD => {
                let ok = self.reservation == Some(addr);
                if ok {
                    self.mem
                        .write_u64(addr, self.x(insn.rs2))
                        .map_err(|_| acc_fault(true, addr))?;
                }
                self.reservation = None;
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
            let old = self.mem.read_u64(addr).map_err(|_| acc_fault(false, addr))?;
            let new = amo_compute64(insn.op, old, src);
            self.mem.write_u64(addr, new).map_err(|_| acc_fault(true, addr))?;
            self.set_x(insn.rd, old);
        } else {
            let old = self.mem.read_u32(addr).map_err(|_| acc_fault(false, addr))?;
            let new = amo_compute32(insn.op, old, src as u32);
            self.mem.write_u32(addr, new).map_err(|_| acc_fault(true, addr))?;
            self.set_x(insn.rd, old as i32 as i64 as u64);
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // Zicsr.
    // ---------------------------------------------------------------

    fn exec_csr(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = insn.csr;
        let is_imm = matches!(insn.op, Op::Csrrwi | Op::Csrrsi | Op::Csrrci);
        let src = if is_imm {
            insn.rs1 as u64 // zimm (5-bit, zero-extended)
        } else {
            self.x(insn.rs1)
        };
        let is_write = matches!(insn.op, Op::Csrrw | Op::Csrrwi);
        // For set/clear forms, rs1/zimm == 0 means "do not write".
        let writes = is_write || insn.rs1 != 0;

        if writes && Csr::is_read_only(addr) {
            return Err(Trap::illegal(insn.raw));
        }

        // CSRRW with rd==x0 must not read (avoid read side effects). For the
        // CSRs we model, reads are side-effect-free, but we honor the rule.
        let old = if is_write && insn.rd == 0 {
            0
        } else {
            self.csr_read(addr)?
        };

        if writes {
            let new = match insn.op {
                Op::Csrrw | Op::Csrrwi => src,
                Op::Csrrs | Op::Csrrsi => old | src,
                Op::Csrrc | Op::Csrrci => old & !src,
                _ => unreachable!(),
            };
            self.csr_write(addr, new)?;
        }
        self.set_x(insn.rd, old);
        Ok(())
    }

    /// Read a CSR value (XLEN-wide).
    pub fn csr_read(&self, addr: u16) -> Result<u64, Trap> {
        let csr = match Csr::from_addr(addr) {
            Some(c) => c,
            None => return Err(Trap::illegal(0)),
        };
        let v = match csr {
            Csr::Fflags => (self.fcsr & 0x1f) as u64,
            Csr::Frm => ((self.fcsr >> 5) & 0x7) as u64,
            Csr::Fcsr => (self.fcsr & 0xff) as u64,
            Csr::Cycle => self.cycle & self.xmask(),
            Csr::Time => self.time & self.xmask(),
            Csr::Instret => self.instret & self.xmask(),
            Csr::CycleH => (self.cycle >> 32) & 0xffff_ffff,
            Csr::TimeH => (self.time >> 32) & 0xffff_ffff,
            Csr::InstretH => (self.instret >> 32) & 0xffff_ffff,
            Csr::Mstatus => self.mstatus,
            Csr::Misa => self.misa(),
            Csr::Medeleg => self.medeleg,
            Csr::Mideleg => self.mideleg,
            Csr::Mie => self.mie,
            Csr::Mtvec => self.mtvec,
            Csr::Mcounteren => self.mcounteren,
            Csr::Mscratch => self.mscratch,
            Csr::Mepc => self.mepc,
            Csr::Mcause => self.mcause,
            Csr::Mtval => self.mtval,
            Csr::Mip => self.mip,
            Csr::Mvendorid | Csr::Marchid | Csr::Mimpid => 0,
            Csr::Mhartid => self.mhartid,
        };
        Ok(v & self.xmask())
    }

    /// Write a CSR value (XLEN-wide).
    pub fn csr_write(&mut self, addr: u16, value: u64) -> Result<(), Trap> {
        let csr = match Csr::from_addr(addr) {
            Some(c) => c,
            None => return Err(Trap::illegal(0)),
        };
        match csr {
            Csr::Fflags => self.fcsr = (self.fcsr & !0x1f) | (value as u32 & 0x1f),
            Csr::Frm => self.fcsr = (self.fcsr & !0xe0) | (((value as u32) & 0x7) << 5),
            Csr::Fcsr => self.fcsr = value as u32 & 0xff,
            Csr::Mstatus => self.mstatus = value,
            Csr::Medeleg => self.medeleg = value,
            Csr::Mideleg => self.mideleg = value,
            Csr::Mie => self.mie = value,
            Csr::Mtvec => self.mtvec = value,
            Csr::Mcounteren => self.mcounteren = value,
            Csr::Mscratch => self.mscratch = value,
            Csr::Mepc => self.mepc = value & !1,
            Csr::Mcause => self.mcause = value,
            Csr::Mtval => self.mtval = value,
            Csr::Mip => self.mip = value,
            // Read-only / counters: writes ignored (caught earlier for RO addrs).
            _ => {}
        }
        Ok(())
    }

    fn misa(&self) -> u64 {
        // MXL field in the top two bits, extension bitmap in the low 26.
        let mxl: u64 = if self.rv32() { 1 } else { 2 };
        let shift = self.xbits() as u64 - 2;
        let mut bits: u64 = 1 << 8; // 'I'
        let isa = &self.cfg.isa;
        if isa.m {
            bits |= 1 << 12;
        }
        if isa.a {
            bits |= 1 << 0;
        }
        if isa.f {
            bits |= 1 << 5;
        }
        if isa.d {
            bits |= 1 << 3;
        }
        if isa.c {
            bits |= 1 << 2;
        }
        (mxl << shift) | bits
    }

    fn mret(&mut self) {
        // pc <- mepc; MIE <- MPIE; MPIE <- 1; priv <- MPP; MPP <- U.
        self.pc = self.mepc;
        let mpie = (self.mstatus >> 7) & 1;
        self.mstatus &= !(1 << 3);
        self.mstatus |= mpie << 3; // MIE = MPIE
        self.mstatus |= 1 << 7; // MPIE = 1
        let mpp = (self.mstatus >> 11) & 0b11;
        self.priv_ = match mpp {
            3 => Priv::Machine,
            1 => Priv::Supervisor,
            _ => Priv::User,
        };
        self.mstatus &= !(0b11 << 11); // MPP = U (0)
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
                | Op::FmvXW | Op::FmvWX | Op::FmvXD | Op::FmvDX
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
                let v = self.mem.read_u32(addr).map_err(|_| acc_fault(false, addr))?;
                self.wf32(rd, v);
            }
            Op::Fld => {
                let addr = self.x(rs1).wrapping_add(insn.imm as u64) & self.xmask();
                let v = self.mem.read_u64(addr).map_err(|_| acc_fault(false, addr))?;
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
                let r = ff::sf_fma(ff::F32, self.s32(rs1), self.s32(rs2), self.s32(rs3), rm, &mut flags);
                self.wf32(rd, r as u32);
            }
            Op::FmsubS => {
                let r = ff::sf_fma(ff::F32, self.s32(rs1), self.s32(rs2), neg32(self.s32(rs3)), rm, &mut flags);
                self.wf32(rd, r as u32);
            }
            Op::FnmsubS => {
                let r = ff::sf_fma(ff::F32, neg32(self.s32(rs1)), self.s32(rs2), self.s32(rs3), rm, &mut flags);
                self.wf32(rd, r as u32);
            }
            Op::FnmaddS => {
                let r = ff::sf_fma(ff::F32, neg32(self.s32(rs1)), self.s32(rs2), neg32(self.s32(rs3)), rm, &mut flags);
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
                let r = ff::sf_fma(ff::F64, self.f(rs1), self.f(rs2), self.f(rs3), rm, &mut flags);
                self.wf64(rd, r);
            }
            Op::FmsubD => {
                let r = ff::sf_fma(ff::F64, self.f(rs1), self.f(rs2), neg64(self.f(rs3)), rm, &mut flags);
                self.wf64(rd, r);
            }
            Op::FnmsubD => {
                let r = ff::sf_fma(ff::F64, neg64(self.f(rs1)), self.f(rs2), self.f(rs3), rm, &mut flags);
                self.wf64(rd, r);
            }
            Op::FnmaddD => {
                let r = ff::sf_fma(ff::F64, neg64(self.f(rs1)), self.f(rs2), neg64(self.f(rs3)), rm, &mut flags);
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
            Op::FmvXW => self.set_x(rd, self.f(rs1) as u32 as i32 as i64 as u64),
            Op::FmvWX => self.wf32(rd, self.x(rs1) as u32),
            Op::FmvXD => self.set_x(rd, self.f(rs1)),
            Op::FmvDX => self.wf64(rd, self.x(rs1)),

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
            if b == 0 {
                a
            } else {
                a % b
            }
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

/// Zbb `rev8`: reverse byte order across the whole register.
fn rev8(a: u64, rv32: bool) -> u64 {
    if rv32 {
        (a as u32).swap_bytes() as u64
    } else {
        a.swap_bytes()
    }
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
    use crate::riscv::memory::FlatMemory;

    fn cpu() -> RiscVCpu {
        RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(FlatMemory::new(0, 0x1_0000)))
    }

    /// Encode a register-register OP instruction.
    fn r_type(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    fn run_one(c: &mut RiscVCpu, w: u32) -> RiscVExit {
        c.write_memory(c.pc(), &w.to_le_bytes()).unwrap();
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
        run_one(&mut c, (0u32 << 20) | (1 << 15) | (3 << 12) | (3 << 7) | 0x03);
        assert_eq!(c.x(3), 0x1122_3344_5566_7788);
    }

    #[test]
    fn amo_add() {
        let mut c = cpu();
        c.set_x(1, 0x2000);
        c.write_memory(0x2000, &10u64.to_le_bytes()).unwrap();
        c.set_x(2, 5);
        // amoadd.d x3, x2, (x1): funct5=00000, funct3=011
        run_one(&mut c, (0b00000 << 27) | (2 << 20) | (1 << 15) | (3 << 12) | (3 << 7) | 0x2f);
        assert_eq!(c.x(3), 10); // returns old
        assert_eq!(c.mem_read_u64(0x2000).unwrap(), 15);
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
        assert!(matches!(run_one(&mut c, csr(0xC00, 4, 1, 5)), RiscVExit::Trap(_)));
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

    #[test]
    fn clz_cpop() {
        let mut c = cpu();
        c.set_x(1, 0x0000_0000_0000_00ff);
        // clz x2, x1 : funct7=0110000 rs2=0 funct3=1 opcode=0x13
        run_one(&mut c, (0b0110000u32 << 25) | (0 << 20) | (1 << 15) | (1 << 12) | (2 << 7) | 0x13);
        assert_eq!(c.x(2), 56);
        // cpop x3, x1
        run_one(&mut c, (0b0110000u32 << 25) | (2 << 20) | (1 << 15) | (1 << 12) | (3 << 7) | 0x13);
        assert_eq!(c.x(3), 8);
    }
}
