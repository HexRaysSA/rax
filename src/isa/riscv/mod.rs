//! Self-contained RISC-V architecture interpreter.
//!
//! This module provides a foundational, spec-faithful software interpreter for
//! the RISC-V instruction set, structured to parallel [`crate::isa::arm`]. It is
//! intentionally decoupled from the VMM/backend layer so that it can be driven
//! directly by unit tests and the differential oracle in
//! `tests/suites/differential/riscv/scalar.rs`
//! (which checks every instruction against `qemu-riscv64`).
//!
//! # Scope
//!
//! The interpreter targets the unprivileged RV64GC base (and the embeddable
//! RV32 variant) with the standard general-purpose extensions:
//!
//! - **I** — base integer ISA (RV32I / RV64I)
//! - **M** — integer multiply/divide
//! - **A** — atomic memory operations (LR/SC, AMO)
//! - **F / D** — single / double precision floating point (IEEE-754)
//! - **C** — compressed 16-bit encodings
//! - **Zicsr / Zifencei** — control/status registers and instruction-fence
//! - **Zba / Zbb / Zbc / Zbs** — bit-manipulation
//!
//! # Design
//!
//! [`decode`] turns raw bytes into a fully-resolved [`Insn`]; [`cpu::RiscVCpu`]
//! holds architectural state ([`x`](cpu::RiscVCpu) registers, FP registers,
//! CSRs, PC) and executes one decoded instruction per [`step`](cpu::RiscVCpu::step).
//! Memory is abstracted by the [`Memory`] trait, with [`FlatMemory`] as the
//! default backing store.

pub mod compressed;
pub mod cpu;
pub mod crypto;
pub mod csr;
pub mod decode;
pub mod disasm;
pub mod float;
pub mod memory;

/// Compatibility alias for the former compressed-decoder module name.
pub use compressed as rvc;

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use cpu::RiscVJitStats;
pub use cpu::{RiscVConfig, RiscVCpu, RiscVExit, Trap};
pub use csr::{Csr, csr_name};
pub use decode::{DecodeError, Insn, Op, decode, decode_at};
pub use float::RoundingMode;
pub use memory::{FlatMemory, MemError, MemResult, Memory};

/// Register width of the hart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Xlen {
    /// 32-bit registers (RV32).
    Rv32,
    /// 64-bit registers (RV64).
    Rv64,
}

impl Xlen {
    /// Width in bits.
    #[inline]
    pub fn bits(self) -> u32 {
        match self {
            Xlen::Rv32 => 32,
            Xlen::Rv64 => 64,
        }
    }

    /// Mask covering all valid register bits (`0xffff_ffff` for RV32).
    #[inline]
    pub fn mask(self) -> u64 {
        match self {
            Xlen::Rv32 => 0xffff_ffff,
            Xlen::Rv64 => u64::MAX,
        }
    }
}

/// Enabled standard extensions. A `false` field means the corresponding
/// encodings decode as illegal instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Isa {
    /// M: integer multiply/divide.
    pub m: bool,
    /// A: atomic memory operations.
    pub a: bool,
    /// F: single-precision floating point.
    pub f: bool,
    /// D: double-precision floating point (implies F).
    pub d: bool,
    /// Q: quad-precision floating point (decode/disassembly parity only today).
    pub q: bool,
    /// C: compressed instructions.
    pub c: bool,
    /// Zicsr: control and status register access.
    pub zicsr: bool,
    /// Zifencei: instruction-stream fence.
    pub zifencei: bool,
    /// Zihintpause: PAUSE hint.
    pub zihintpause: bool,
    /// Zihintntl: non-temporal locality hints.
    pub zihintntl: bool,
    /// Zacas: atomic compare-and-swap.
    pub zacas: bool,
    /// Zawrs: wait-on-reservation-set hints.
    pub zawrs: bool,
    /// Zicbom: cache-block clean/flush/invalidate.
    pub zicbom: bool,
    /// Zicboz: cache-block zero.
    pub zicboz: bool,
    /// Zicbop: cache-block prefetch hints.
    pub zicbop: bool,
    /// Zba: address generation.
    pub zba: bool,
    /// Zbb: basic bit manipulation.
    pub zbb: bool,
    /// Zbc: carry-less multiplication.
    pub zbc: bool,
    /// Zbs: single-bit instructions.
    pub zbs: bool,
    /// Zicond: integer conditional operations.
    pub zicond: bool,
    /// Zfa: additional floating-point instructions.
    pub zfa: bool,
    /// Zbkb: bit-manipulation for cryptography.
    pub zbkb: bool,
    /// Zfh: half-precision floating point.
    pub zfh: bool,
    /// Zbkx: crossbar permutations (crypto).
    pub zbkx: bool,
    /// Zknh: NIST SHA-256/512 hash transforms.
    pub zknh: bool,
    /// Zksh: ShangMi SM3 hash transforms.
    pub zksh: bool,
    /// Zksed: ShangMi SM4 block cipher.
    pub zksed: bool,
    /// Zkne: NIST AES encryption.
    pub zkne: bool,
    /// Zknd: NIST AES decryption.
    pub zknd: bool,
    /// Zcb: additional compressed instructions.
    pub zcb: bool,
    /// Zcmp: compressed PUSH/POP and double-move instructions.
    pub zcmp: bool,
    /// Zcmt: compressed table-jump instructions.
    pub zcmt: bool,
    /// Zclsd: RV32 compressed load/store register-pair instructions.
    pub zclsd: bool,
    /// Zilsd: RV32 load/store register-pair instructions.
    pub zilsd: bool,
    /// H: hypervisor privileged instructions.
    pub h: bool,
    /// Svinval: fine-grained address-translation cache invalidation.
    pub svinval: bool,
    /// V: vector extension (RVV 1.0 — full data path: arithmetic, fixed-point,
    /// FP, reductions, permutes, conversions, and all load/store modes).
    pub v: bool,
    /// Xsoteria: Google Soteria/GSC (Ti50/Dauntless) vendor bit-manipulation
    /// extension. Two custom opcodes (CUSTOM-0 = 0x0b, CUSTOM-1 = 0x2b), RV32
    /// only. See [`crate::machine::gsc::runtime`].
    pub xsoteria: bool,
    /// XAndesPerf: Andes performance extension custom instructions.
    pub xandes: bool,
    /// XThead: T-Head/Xuantie vendor scalar custom instructions.
    pub xthead: bool,
    /// XHazard3: Hazard3/RP2350 vendor power hints and bit-extract-multiple
    /// instructions.
    pub xhazard3: bool,
    /// XidaSltw: Hex-Rays/IDA compatibility decode for the non-standard
    /// OP-32 `sltw` table entry. Disabled by default because standard
    /// hardware treats the encoding as reserved.
    pub xida_sltw: bool,
}

impl Isa {
    /// Standard test/differential configuration used by this crate.
    pub const fn rv64gc() -> Self {
        Isa {
            m: true,
            a: true,
            f: true,
            d: true,
            q: false,
            c: true,
            zicsr: true,
            zifencei: true,
            zihintpause: true,
            zihintntl: true,
            zacas: true,
            zawrs: true,
            zicbom: true,
            zicboz: true,
            zicbop: true,
            zba: true,
            zbb: true,
            zbc: true,
            zbs: true,
            zicond: true,
            zfa: true,
            zbkb: true,
            zfh: true,
            zbkx: true,
            zknh: true,
            zksh: true,
            zksed: true,
            zkne: true,
            zknd: true,
            zcb: true,
            zcmp: false,
            zcmt: false,
            zclsd: false,
            zilsd: false,
            h: true,
            svinval: true,
            v: true,
            xsoteria: false,
            xandes: false,
            xthead: false,
            xhazard3: false,
            xida_sltw: false,
        }
    }

    /// Minimal base integer ISA, nothing optional enabled.
    pub const fn rv_i() -> Self {
        Isa {
            m: false,
            a: false,
            f: false,
            d: false,
            q: false,
            c: false,
            zicsr: false,
            zifencei: false,
            zihintpause: false,
            zihintntl: false,
            zacas: false,
            zawrs: false,
            zicbom: false,
            zicboz: false,
            zicbop: false,
            zba: false,
            zbb: false,
            zbc: false,
            zbs: false,
            zicond: false,
            zfa: false,
            zbkb: false,
            zfh: false,
            zbkx: false,
            zknh: false,
            zksh: false,
            zksed: false,
            zkne: false,
            zknd: false,
            zcb: false,
            zcmp: false,
            zcmt: false,
            zclsd: false,
            zilsd: false,
            h: false,
            svinval: false,
            v: false,
            xsoteria: false,
            xandes: false,
            xthead: false,
            xhazard3: false,
            xida_sltw: false,
        }
    }

    /// IMAC — common embedded profile.
    pub const fn imac() -> Self {
        Isa {
            m: true,
            a: true,
            c: true,
            zicsr: true,
            zifencei: true,
            ..Isa::rv_i()
        }
    }

    /// Google Ti50/Dauntless GSC profile: RV32 IMC + Zicsr/Zifencei plus the
    /// Zbb bit-manipulation primitives the Xsoteria ops reuse (`clz`), and the
    /// Xsoteria vendor extension itself.
    pub const fn ti50() -> Self {
        Isa {
            m: true,
            a: true,
            c: true,
            zicsr: true,
            zifencei: true,
            zba: true,
            zbb: true,
            zbs: true,
            xsoteria: true,
            ..Isa::rv_i()
        }
    }
}

impl Default for Isa {
    fn default() -> Self {
        Isa::rv64gc()
    }
}

/// ABI register names indexed by architectural register number (`x0..x31`).
pub const ABI_X_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// ABI register names for the floating-point register file (`f0..f31`).
pub const ABI_F_NAMES: [&str; 32] = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
    "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
    "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
];

/// ABI name for integer register `x{n}` (`n` masked to 5 bits).
#[inline]
pub fn x_name(n: u8) -> &'static str {
    ABI_X_NAMES[(n & 31) as usize]
}

/// ABI name for floating-point register `f{n}` (`n` masked to 5 bits).
#[inline]
pub fn f_name(n: u8) -> &'static str {
    ABI_F_NAMES[(n & 31) as usize]
}
