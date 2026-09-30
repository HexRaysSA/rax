//! Architecture and CPU-mode mapping between the C ABI and the engine.

use rax_engine::config::{ArchKind, Endianness, HexagonIsa};
use rax_engine::cpu::{
    Aarch32Registers, Aarch64Registers, CortexMRegisters, CpuState, HexagonRegisters, Registers,
    RiscVRegisters, SystemRegisters,
};
use rax_engine::riscv::RiscVConfig;

use crate::vcpu::Vcpu;

/// Architecture selector, ABI-stable. Mirrors `rax_arch` in `rax.h`.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaxArch {
    X86 = 1,
    Arm64 = 2,
    Arm = 3,
    Riscv64 = 4,
    Hexagon = 5,
    CortexM = 6,
}

impl RaxArch {
    pub fn from_i32(v: i32) -> Option<RaxArch> {
        Some(match v {
            1 => RaxArch::X86,
            2 => RaxArch::Arm64,
            3 => RaxArch::Arm,
            4 => RaxArch::Riscv64,
            5 => RaxArch::Hexagon,
            6 => RaxArch::CortexM,
            _ => return None,
        })
    }

    pub fn to_kind(self) -> ArchKind {
        match self {
            RaxArch::X86 => ArchKind::X86_64,
            RaxArch::Arm64 => ArchKind::Aarch64,
            RaxArch::Arm => ArchKind::Armv7a,
            RaxArch::Riscv64 => ArchKind::Riscv64,
            RaxArch::Hexagon => ArchKind::Hexagon,
            RaxArch::CortexM => ArchKind::CortexM,
        }
    }
}

// Backend selector. Mirrors `RAX_BACKEND_*` in `rax.h`. Only the portable,
// deterministic software emulator is exposed through the C API.
pub const RAX_BACKEND_DEFAULT: i32 = 0;
pub const RAX_BACKEND_EMULATOR: i32 = 1;

// CPU mode flags (bitmask). Mirrors `RAX_MODE_*` in `rax.h`.
pub const RAX_MODE_16: u32 = 1 << 0;
pub const RAX_MODE_32: u32 = 1 << 1;
pub const RAX_MODE_64: u32 = 1 << 2;
pub const RAX_MODE_ARM: u32 = 1 << 3;
pub const RAX_MODE_THUMB: u32 = 1 << 4;
pub const RAX_MODE_BIG_ENDIAN: u32 = 1 << 5;
pub const RAX_MODE_LITTLE_ENDIAN: u32 = 1 << 6;
/// Process-level (user-mode) execution; see `crate::user`. Valid for x86 in
/// 64-bit or 32-bit (compatibility) mode, AArch64, and RV64.
pub const RAX_MODE_USER: u32 = 1 << 7;

// RISC-V extension flags. Mirror `RAX_RISCV_EXT_*` in `rax.h`.
pub const RAX_RISCV_EXT_ZCMP: u64 = 1 << 0;
pub const RAX_RISCV_EXT_ZCMT: u64 = 1 << 1;
pub const RAX_RISCV_EXT_ZCLSD: u64 = 1 << 2;
pub const RAX_RISCV_EXT_ZILSD: u64 = 1 << 3;
pub const RAX_RISCV_EXT_XHAZARD3: u64 = 1 << 4;
pub const RAX_RISCV_EXT_XANDES: u64 = 1 << 5;
pub const RAX_RISCV_EXT_XTHEAD: u64 = 1 << 6;
pub const RAX_RISCV_EXT_XIDA_SLTW: u64 = 1 << 7;
pub const RAX_RISCV_EXT_SUPPORTED: u64 = RAX_RISCV_EXT_ZCMP
    | RAX_RISCV_EXT_ZCMT
    | RAX_RISCV_EXT_ZCLSD
    | RAX_RISCV_EXT_ZILSD
    | RAX_RISCV_EXT_XHAZARD3
    | RAX_RISCV_EXT_XANDES
    | RAX_RISCV_EXT_XTHEAD
    | RAX_RISCV_EXT_XIDA_SLTW;

/// Validates a mode bitmask against an architecture, returning the normalized
/// mode (defaults filled in) or `None` if invalid.
pub fn normalize_mode(arch: RaxArch, mode: u32) -> Option<u32> {
    let bitness = mode & (RAX_MODE_16 | RAX_MODE_32 | RAX_MODE_64);
    let armstate = mode & (RAX_MODE_ARM | RAX_MODE_THUMB);
    let user = mode & RAX_MODE_USER;
    if user != 0
        && !matches!(
            arch,
            RaxArch::X86 | RaxArch::Arm | RaxArch::Arm64 | RaxArch::Riscv64
        )
    {
        return None;
    }
    match arch {
        RaxArch::X86 => {
            // Exactly one bitness, default to 64-bit.
            let b = if bitness == 0 { RAX_MODE_64 } else { bitness };
            if b.count_ones() != 1 {
                return None;
            }
            // User mode runs ring-3 code in long mode: 64-bit or
            // compatibility mode, never real mode.
            if user != 0 && b == RAX_MODE_16 {
                return None;
            }
            Some(b | user | (mode & RAX_MODE_LITTLE_ENDIAN))
        }
        RaxArch::CortexM => {
            // Always Thumb, and the engine is little-endian only.
            if mode & RAX_MODE_BIG_ENDIAN != 0 || armstate == RAX_MODE_ARM {
                return None;
            }
            Some(RAX_MODE_THUMB | (mode & RAX_MODE_LITTLE_ENDIAN))
        }
        RaxArch::Arm => {
            if user != 0 && mode & RAX_MODE_BIG_ENDIAN != 0 {
                return None;
            }
            // ARM/AArch32 default to ARM state.
            let st = if armstate == 0 {
                RAX_MODE_ARM
            } else if armstate.count_ones() == 1 {
                armstate
            } else {
                return None;
            };
            Some(st | user | (mode & (RAX_MODE_BIG_ENDIAN | RAX_MODE_LITTLE_ENDIAN)))
        }
        RaxArch::Arm64 => Some(user | (mode & (RAX_MODE_BIG_ENDIAN | RAX_MODE_LITTLE_ENDIAN))),
        RaxArch::Hexagon => Some(mode & (RAX_MODE_BIG_ENDIAN | RAX_MODE_LITTLE_ENDIAN)),
        RaxArch::Riscv64 => Some(user),
    }
}

/// Whether a normalized mode selects user-mode execution.
#[inline]
pub fn is_user(mode: u32) -> bool {
    mode & RAX_MODE_USER != 0
}

/// Endianness implied by a normalized mode.
pub fn endianness(mode: u32) -> Endianness {
    if mode & RAX_MODE_BIG_ENDIAN != 0 {
        Endianness::Big
    } else {
        Endianness::Little
    }
}

/// Builds the RV64GC C-API default plus any requested opt-in runtime
/// extensions. These bits only add to the default profile; they do not disable
/// extensions that are already part of the default RV64GC emulator config.
pub fn riscv_config_from_ext(ext: u64) -> Option<RiscVConfig> {
    if ext & !RAX_RISCV_EXT_SUPPORTED != 0 {
        return None;
    }
    let mut cfg = RiscVConfig::rv64gc();
    if ext & RAX_RISCV_EXT_ZCMP != 0 {
        cfg.isa.zcmp = true;
    }
    if ext & RAX_RISCV_EXT_ZCMT != 0 {
        cfg.isa.zcmt = true;
    }
    if ext & RAX_RISCV_EXT_ZCLSD != 0 {
        cfg.isa.zclsd = true;
    }
    if ext & RAX_RISCV_EXT_ZILSD != 0 {
        cfg.isa.zilsd = true;
    }
    if ext & RAX_RISCV_EXT_XHAZARD3 != 0 {
        cfg.isa.xhazard3 = true;
    }
    if ext & RAX_RISCV_EXT_XANDES != 0 {
        cfg.isa.xandes = true;
    }
    if ext & RAX_RISCV_EXT_XTHEAD != 0 {
        cfg.isa.xthead = true;
    }
    if ext & RAX_RISCV_EXT_XIDA_SLTW != 0 {
        cfg.isa.xida_sltw = true;
    }
    Some(cfg)
}

/// Builds a fresh, self-contained emulator vCPU for `arch` over `mem`. A
/// user-mode `mode` requires `translation`, the engine's address space.
pub(crate) fn build_vcpu(
    arch: RaxArch,
    mode: u32,
    mem: std::sync::Arc<rax_engine::memory::vm::GuestMemoryMmap>,
    riscv_config: Option<RiscVConfig>,
    translation: Option<&std::sync::Arc<crate::user::RegionTranslation>>,
) -> rax_engine::Result<Vcpu> {
    if is_user(mode) {
        let translation = translation.cloned().ok_or_else(|| {
            rax_engine::Error::InvalidConfig("user mode requires an address space".to_string())
        })?;
        return Ok(match arch {
            RaxArch::X86 => {
                let mut core = rax_engine::isa::x86_64::X86_64Vcpu::new(0, mem);
                core.enable_user_mode(translation);
                core.set_user_compat(mode & RAX_MODE_32 != 0);
                Vcpu::X86User(Box::new(core))
            }
            RaxArch::Arm64 => Vcpu::Arm64User(Box::new(
                rax_engine::backend::emulator::aarch64::Aarch64Vcpu::new_user(0, mem, translation),
            )),
            RaxArch::Arm => Vcpu::ArmUser(Box::new(crate::arm_user::ArmUserVcpu::new(
                mem,
                translation,
                mode & RAX_MODE_THUMB != 0,
            ))),
            RaxArch::Riscv64 => Vcpu::RiscvUser(Box::new(
                rax_engine::backend::emulator::riscv::RiscVVcpu::new_user(
                    0,
                    mem,
                    riscv_config.unwrap_or_else(RiscVConfig::rv64gc),
                    translation,
                ),
            )),
            _ => {
                return Err(rax_engine::Error::InvalidConfig(format!(
                    "user mode is not available for {arch:?}"
                )));
            }
        });
    }
    // The C API is an instruction engine: every vCPU returns guest faults to
    // the embedder at the retry PC and owns no devices, so the whole address
    // space is the embedder's memory. The choice depends only on `arch` and
    // `mode`, never on the process environment (`RAX_MACHINE` selects board
    // vCPUs for full-machine runs only).
    use rax_engine::backend::emulator::{aarch32, aarch64, cortex_m, riscv};
    let vcpu: Box<dyn rax_engine::cpu::VCpu> = match arch {
        RaxArch::X86 => Box::new(rax_engine::isa::x86_64::X86_64Vcpu::new(0, mem)),
        RaxArch::Arm64 => Box::new(aarch64::Aarch64Vcpu::new_micro(0, mem)),
        RaxArch::Arm => Box::new(aarch32::Aarch32Vcpu::new(0, mem)),
        RaxArch::CortexM => Box::new(cortex_m::CortexMVcpu::new(0, mem)),
        RaxArch::Riscv64 => Box::new(riscv::RiscVVcpu::new_embedded(
            0,
            mem,
            riscv_config.unwrap_or_else(RiscVConfig::rv64gc),
        )),
        RaxArch::Hexagon => Box::new(rax_engine::isa::hexagon::HexagonVcpu::new(
            0,
            mem,
            HexagonIsa::default(),
            endianness(mode),
        )),
    };
    Ok(Vcpu::System(vcpu))
}

/// Produces a sensible power-on [`CpuState`] for an architecture and mode.
///
/// For x86 this establishes a flat segment model in the requested bitness so a
/// freshly-opened engine can execute immediately after loading code and setting
/// `RIP`/`RSP` (mirroring the canonical bring-up used by the test runner). For
/// other architectures the engine's architectural default is used.
pub fn default_state(arch: RaxArch, mode: u32) -> CpuState {
    match arch {
        RaxArch::X86 => CpuState::x86_64(Registers::default(), default_x86_sregs(mode)),
        RaxArch::Arm64 => CpuState::aarch64(Aarch64Registers::default(), Default::default()),
        RaxArch::Arm => CpuState::aarch32(default_aarch32_regs(mode), Default::default()),
        RaxArch::CortexM => CpuState::cortex_m(CortexMRegisters::default(), Default::default()),
        RaxArch::Riscv64 => CpuState::riscv(RiscVRegisters::default()),
        RaxArch::Hexagon => CpuState::hexagon(HexagonRegisters::default()),
    }
}

fn default_aarch32_regs(mode: u32) -> Aarch32Registers {
    let mut r = Aarch32Registers::default();
    if mode & RAX_MODE_THUMB != 0 {
        r.set_thumb(true);
    }
    if mode & RAX_MODE_BIG_ENDIAN != 0 {
        r.cpsr |= Aarch32Registers::CPSR_E;
    }
    r
}

/// Flat-model x86 system registers for the requested bitness.
fn default_x86_sregs(mode: u32) -> SystemRegisters {
    use rax_engine::cpu::Segment;
    let mut s = SystemRegisters::default();

    let flat_data = |selector: u16, db: bool| Segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector,
        type_: 0x3, // data: read/write, accessed
        present: true,
        dpl: 0,
        db,
        s: true,
        l: false,
        g: true,
        avl: false,
        unusable: false,
    };

    if mode & RAX_MODE_64 != 0 {
        // 64-bit long mode: PE | NE, PAE, LME | LMA, flat 64-bit code segment.
        s.cr0 = 0x21;
        s.cr4 = 0x20;
        s.efer = 0x500;
        s.cs = Segment {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x8,
            type_: 0xB, // code: execute/read, accessed
            present: true,
            dpl: 0,
            db: false,
            s: true,
            l: true, // 64-bit code segment
            g: true,
            avl: false,
            unusable: false,
        };
        s.ds = flat_data(0x10, true);
    } else if mode & RAX_MODE_32 != 0 {
        // 32-bit protected mode, flat segments, no paging.
        s.cr0 = 0x21;
        s.cs = Segment {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector: 0x8,
            type_: 0xB,
            present: true,
            dpl: 0,
            db: true, // 32-bit operand/address default
            s: true,
            l: false,
            g: true,
            avl: false,
            unusable: false,
        };
        s.ds = flat_data(0x10, true);
    } else {
        // 16-bit real mode: base-0 segments, no protection.
        s.cr0 = 0;
        s.cs = Segment {
            base: 0,
            limit: 0xFFFF,
            selector: 0,
            type_: 0xB,
            present: true,
            dpl: 0,
            db: false,
            s: true,
            l: false,
            g: false,
            avl: false,
            unusable: false,
        };
        s.ds = flat_data(0, false);
        s.ds.limit = 0xFFFF;
        s.ds.g = false;
    }

    s.es = s.ds.clone();
    s.fs = s.ds.clone();
    s.gs = s.ds.clone();
    s.ss = s.ds.clone();
    s
}
