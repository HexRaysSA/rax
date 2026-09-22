//! Architecture and CPU-mode mapping between the C ABI and the engine.

use rax_engine::config::{ArchKind, Endianness, HexagonIsa};
use rax_engine::cpu::{
    Aarch32Registers, Aarch64Registers, CortexMRegisters, CpuState, HexagonRegisters, Registers,
    RiscVRegisters, SystemRegisters,
};
use rax_engine::riscv::RiscVConfig;

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
    match arch {
        RaxArch::X86 => {
            // Exactly one bitness, default to 64-bit.
            let b = if bitness == 0 { RAX_MODE_64 } else { bitness };
            if b.count_ones() != 1 {
                return None;
            }
            Some(b | (mode & RAX_MODE_LITTLE_ENDIAN))
        }
        RaxArch::Arm | RaxArch::CortexM => {
            // Cortex-M is always Thumb; ARM/AArch32 default to ARM state.
            let st = if matches!(arch, RaxArch::CortexM) {
                RAX_MODE_THUMB
            } else if armstate == 0 {
                RAX_MODE_ARM
            } else if armstate.count_ones() == 1 {
                armstate
            } else {
                return None;
            };
            Some(st | (mode & (RAX_MODE_BIG_ENDIAN | RAX_MODE_LITTLE_ENDIAN)))
        }
        RaxArch::Arm64 => Some(mode & (RAX_MODE_BIG_ENDIAN | RAX_MODE_LITTLE_ENDIAN)),
        RaxArch::Hexagon => Some(mode & (RAX_MODE_BIG_ENDIAN | RAX_MODE_LITTLE_ENDIAN)),
        RaxArch::Riscv64 => Some(0),
    }
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

/// Builds a fresh, self-contained emulator vCPU for `arch` over `mem`.
pub fn build_vcpu(
    arch: RaxArch,
    mode: u32,
    mem: std::sync::Arc<rax_engine::memory::vm::GuestMemoryMmap>,
    riscv_config: Option<RiscVConfig>,
) -> rax_engine::Result<Box<dyn rax_engine::cpu::VCpu>> {
    use rax_engine::backend::Backend;
    // The C API is an instruction engine: return guest faults to the embedder
    // at the retry PC. Full-machine VMM construction still uses system mode.
    if arch == RaxArch::Arm64 {
        return Ok(Box::new(
            rax_engine::backend::emulator::aarch64::Aarch64Vcpu::new_micro(0, mem),
        ));
    }
    let backend = match riscv_config {
        Some(cfg) => rax_engine::backend::emulator::EmulatorBackend::with_riscv_config(
            arch.to_kind(),
            HexagonIsa::default(),
            endianness(mode),
            cfg,
        ),
        None => rax_engine::backend::emulator::EmulatorBackend::new(
            arch.to_kind(),
            HexagonIsa::default(),
            endianness(mode),
        ),
    };
    let vm = backend.create_vm()?;
    vm.create_vcpu(0, mem)
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
