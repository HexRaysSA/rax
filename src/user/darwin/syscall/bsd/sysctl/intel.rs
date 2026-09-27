//! An Intel kernel's `machdep` subtree (`bsd/dev/i386/sysctl.c`,
//! `bsd/kern/sys_generic.c`, `bsd/kern/kern_sysctl.c`) and the CPU
//! description it reports, derived from the emulated CPU's `CPUID` as
//! `cpuid_set_generic_info`, `cpuid_set_cache_info`, and `cpuid_set_info`
//! derive it (`osfmk/i386/cpuid.c`).
//!
//! Automatic OIDs follow declaration order, the Bridge time node first and
//! the idle-level node last as in the arm64 kernel. The kernel's own
//! statistics and controls (`pmap`, `memmap`, `misc`, the timer-evaluation
//! and FP/SIMD-in-interrupt counters, `insn_copy_optout_task`) keep their
//! numbers but are not modeled. The emulated `CPUID` has no cache leaves
//! (2, 4, and 0x80000006 are empty, which a real kernel would not accept):
//! the cache nodes report the machine's cache profile, as `hw` does.

use super::Value;
use super::tree::Row;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::DarwinCpu;
use crate::user::darwin::syscall::Ctx;

/// A static node's kind: its flags, `CTLFLAG_OID2`, and
/// `CTLFLAG_PERMANENT`.
const fn kind(flags: u32) -> u32 {
    flags | 0x0040_0000 | 0x0020_0000
}

const RD: u32 = 0x8000_0000;
const WR: u32 = 0x4000_0000;
const KERN: u32 = 0x0100_0000;
const LOCKED: u32 = 0x0080_0000;
const NODE: u32 = 1;
const INT: u32 = 2;
const STRING: u32 = 3;
const QUAD: u32 = 4;
const STRUCT: u32 = 5;

const RW_NODE: u32 = kind(RD | WR | LOCKED | NODE);
const RD_NODE: u32 = kind(RD | LOCKED | NODE);
const RD_INT: u32 = kind(RD | LOCKED | INT);
const RD_STRING: u32 = kind(RD | LOCKED | STRING);
const RD_QUAD: u32 = kind(RD | LOCKED | QUAD);
const KERN_INT: u32 = kind(RD | KERN | LOCKED | INT);

macro_rules! row {
    ($oid:expr, $name:expr, $kind:expr, $fmt:expr, $descr:expr) => {
        Row {
            oid: &$oid,
            name: $name,
            kind: $kind,
            fmt: $fmt,
            descr: $descr,
        }
    };
}

/// The nodes, sorted by OID.
#[rustfmt::skip]
pub static ROWS: &[Row] = &[
    row!([7], "machdep", RW_NODE, "N", "machine dependent"),
    row!([7, 100], "machdep.remotetime", RD_NODE, "N", "Remote time api"),
    row!([7, 100, 100], "machdep.remotetime.conversion_params", kind(RD | LOCKED | STRUCT), "S,bt_params", ""),
    row!([7, 101], "machdep.cpu", RW_NODE, "N", "CPU info"),
    row!([7, 101, 100], "machdep.cpu.max_basic", RD_INT, "IU", "Max Basic Information value"),
    row!([7, 101, 101], "machdep.cpu.max_ext", RD_INT, "IU", "Max Extended Function Information value"),
    row!([7, 101, 102], "machdep.cpu.vendor", RD_STRING, "A", "CPU vendor"),
    row!([7, 101, 103], "machdep.cpu.brand_string", RD_STRING, "A", "CPU brand string"),
    row!([7, 101, 104], "machdep.cpu.family", RD_INT, "I", "CPU family"),
    row!([7, 101, 105], "machdep.cpu.model", RD_INT, "I", "CPU model"),
    row!([7, 101, 106], "machdep.cpu.extmodel", RD_INT, "I", "CPU extended model"),
    row!([7, 101, 107], "machdep.cpu.extfamily", RD_INT, "I", "CPU extended family"),
    row!([7, 101, 108], "machdep.cpu.stepping", RD_INT, "I", "CPU stepping"),
    row!([7, 101, 109], "machdep.cpu.feature_bits", RD_QUAD, "IU", "CPU features"),
    row!([7, 101, 110], "machdep.cpu.leaf7_feature_bits", RD_INT, "IU", "CPU Leaf7 features [EBX ECX]"),
    row!([7, 101, 111], "machdep.cpu.leaf7_feature_bits_edx", RD_INT, "IU", "CPU Leaf7 features [EDX]"),
    row!([7, 101, 112], "machdep.cpu.extfeature_bits", RD_QUAD, "IU", "CPU extended features"),
    row!([7, 101, 113], "machdep.cpu.signature", RD_INT, "I", "CPU signature"),
    row!([7, 101, 114], "machdep.cpu.brand", RD_INT, "I", "CPU brand"),
    row!([7, 101, 115], "machdep.cpu.features", RD_STRING, "A", "CPU feature names"),
    row!([7, 101, 116], "machdep.cpu.leaf7_features", RD_STRING, "A", "CPU Leaf7 feature names"),
    row!([7, 101, 117], "machdep.cpu.extfeatures", RD_STRING, "A", "CPU extended feature names"),
    row!([7, 101, 118], "machdep.cpu.logical_per_package", RD_INT, "I", "CPU logical cpus per package"),
    row!([7, 101, 119], "machdep.cpu.cores_per_package", RD_INT, "I", "CPU cores per package"),
    row!([7, 101, 120], "machdep.cpu.microcode_version", RD_INT, "I", "Microcode version number"),
    row!([7, 101, 121], "machdep.cpu.processor_flag", RD_INT, "I", "CPU processor flag"),
    row!([7, 101, 122], "machdep.cpu.mwait", RW_NODE, "N", "mwait"),
    row!([7, 101, 122, 100], "machdep.cpu.mwait.linesize_min", RD_INT, "I", "Monitor/mwait minimum line size"),
    row!([7, 101, 122, 101], "machdep.cpu.mwait.linesize_max", RD_INT, "I", "Monitor/mwait maximum line size"),
    row!([7, 101, 122, 102], "machdep.cpu.mwait.extensions", RD_INT, "I", "Monitor/mwait extensions"),
    row!([7, 101, 122, 103], "machdep.cpu.mwait.sub_Cstates", RD_INT, "I", "Monitor/mwait sub C-states"),
    row!([7, 101, 123], "machdep.cpu.thermal", RW_NODE, "N", "thermal"),
    row!([7, 101, 123, 100], "machdep.cpu.thermal.sensor", RD_INT, "I", "Thermal sensor present"),
    row!([7, 101, 123, 101], "machdep.cpu.thermal.dynamic_acceleration", RD_INT, "I", "Dynamic Acceleration Technology (Turbo Mode)"),
    row!([7, 101, 123, 102], "machdep.cpu.thermal.invariant_APIC_timer", RD_INT, "I", "Invariant APIC Timer"),
    row!([7, 101, 123, 103], "machdep.cpu.thermal.thresholds", RD_INT, "I", "Number of interrupt thresholds"),
    row!([7, 101, 123, 104], "machdep.cpu.thermal.ACNT_MCNT", RD_INT, "I", "ACNT_MCNT capability"),
    row!([7, 101, 123, 105], "machdep.cpu.thermal.core_power_limits", RD_INT, "I", "Power Limit Notifications at a Core Level"),
    row!([7, 101, 123, 106], "machdep.cpu.thermal.fine_grain_clock_mod", RD_INT, "I", "Fine Grain Clock Modulation"),
    row!([7, 101, 123, 107], "machdep.cpu.thermal.package_thermal_intr", RD_INT, "I", "Package Thermal interrupt and Status"),
    row!([7, 101, 123, 108], "machdep.cpu.thermal.hardware_feedback", RD_INT, "I", "Hardware Coordination Feedback"),
    row!([7, 101, 123, 109], "machdep.cpu.thermal.energy_policy", RD_INT, "I", "Energy Efficient Policy Support"),
    row!([7, 101, 124], "machdep.cpu.xsave", RW_NODE, "N", "xsave"),
    row!([7, 101, 124, 100], "machdep.cpu.xsave.extended_state", RD_INT, "IU", "XSAVE Extended State Main Leaf"),
    row!([7, 101, 124, 101], "machdep.cpu.xsave.extended_state1", RD_INT, "IU", "XSAVE Extended State Sub-leaf 1"),
    row!([7, 101, 125], "machdep.cpu.arch_perf", RW_NODE, "N", "arch_perf"),
    row!([7, 101, 125, 100], "machdep.cpu.arch_perf.version", RD_INT, "I", "Architectural Performance Version Number"),
    row!([7, 101, 125, 101], "machdep.cpu.arch_perf.number", RD_INT, "I", "Number of counters per logical cpu"),
    row!([7, 101, 125, 102], "machdep.cpu.arch_perf.width", RD_INT, "I", "Bit width of counters"),
    row!([7, 101, 125, 103], "machdep.cpu.arch_perf.events_number", RD_INT, "I", "Number of monitoring events"),
    row!([7, 101, 125, 104], "machdep.cpu.arch_perf.events", RD_INT, "I", "Bit vector of events"),
    row!([7, 101, 125, 105], "machdep.cpu.arch_perf.fixed_number", RD_INT, "I", "Number of fixed-function counters"),
    row!([7, 101, 125, 106], "machdep.cpu.arch_perf.fixed_width", RD_INT, "I", "Bit-width of fixed-function counters"),
    row!([7, 101, 126], "machdep.cpu.cache", RW_NODE, "N", "cache"),
    row!([7, 101, 126, 100], "machdep.cpu.cache.linesize", RD_INT, "I", "Cacheline size"),
    row!([7, 101, 126, 101], "machdep.cpu.cache.L2_associativity", RD_INT, "I", "L2 cache associativity"),
    row!([7, 101, 126, 102], "machdep.cpu.cache.size", RD_INT, "I", "Cache size (in Kbytes)"),
    row!([7, 101, 127], "machdep.cpu.tlb", RW_NODE, "N", "tlb"),
    row!([7, 101, 127, 100], "machdep.cpu.tlb.inst", RW_NODE, "N", "inst"),
    row!([7, 101, 127, 100, 100], "machdep.cpu.tlb.inst.small", RD_INT, "I", "Number of small page instruction TLBs"),
    row!([7, 101, 127, 100, 101], "machdep.cpu.tlb.inst.large", RD_INT, "I", "Number of large page instruction TLBs"),
    row!([7, 101, 127, 101], "machdep.cpu.tlb.data", RW_NODE, "N", "data"),
    row!([7, 101, 127, 101, 100], "machdep.cpu.tlb.data.small", RD_INT, "I", "Number of small page data TLBs (1st level)"),
    row!([7, 101, 127, 101, 101], "machdep.cpu.tlb.data.small_level1", RD_INT, "I", "Number of small page data TLBs (2nd level)"),
    row!([7, 101, 127, 101, 102], "machdep.cpu.tlb.data.large", RD_INT, "I", "Number of large page data TLBs (1st level)"),
    row!([7, 101, 127, 101, 103], "machdep.cpu.tlb.data.large_level1", RD_INT, "I", "Number of large page data TLBs (2nd level)"),
    row!([7, 101, 127, 102], "machdep.cpu.tlb.shared", RD_INT, "I", "Number of shared TLBs"),
    row!([7, 101, 128], "machdep.cpu.address_bits", RW_NODE, "N", "address_bits"),
    row!([7, 101, 128, 100], "machdep.cpu.address_bits.physical", RD_INT, "I", "Number of physical address bits"),
    row!([7, 101, 128, 101], "machdep.cpu.address_bits.virtual", RD_INT, "I", "Number of virtual address bits"),
    row!([7, 101, 129], "machdep.cpu.core_count", RD_INT, "I", "Number of enabled cores per package"),
    row!([7, 101, 130], "machdep.cpu.thread_count", RD_INT, "I", "Number of enabled threads per package"),
    row!([7, 101, 131], "machdep.cpu.flex_ratio", RW_NODE, "N", "Flex ratio"),
    row!([7, 101, 131, 100], "machdep.cpu.flex_ratio.desired", RD_INT, "I", "Flex ratio desired (0 disabled)"),
    row!([7, 101, 131, 101], "machdep.cpu.flex_ratio.min", RD_INT, "I", "Flex ratio min (efficiency)"),
    row!([7, 101, 131, 102], "machdep.cpu.flex_ratio.max", RD_INT, "I", "Flex ratio max (non-turbo)"),
    row!([7, 101, 132], "machdep.cpu.ucupdate", kind(WR | LOCKED | INT), "S", "Microcode update interface"),
    row!([7, 101, 133], "machdep.cpu.tsc_ccc", RW_NODE, "N", "TSC/CCC frequency information"),
    row!([7, 101, 133, 100], "machdep.cpu.tsc_ccc.numerator", RD_INT, "I", "Numerator of TSC/CCC ratio"),
    row!([7, 101, 133, 101], "machdep.cpu.tsc_ccc.denominator", RD_INT, "I", "Denominator of TSC/CCC ratio"),
    row!([7, 102], "machdep.vectors", RD_NODE, "N", "Interrupt vector assignments"),
    row!([7, 102, 100], "machdep.vectors.timer", KERN_INT, "IU", ""),
    row!([7, 102, 101], "machdep.vectors.IPI", KERN_INT, "IU", ""),
    row!([7, 105], "machdep.tsc", RD_NODE, "N", "Timestamp counter parameters"),
    row!([7, 105, 100], "machdep.tsc.frequency", RD_QUAD, "Q", ""),
    row!([7, 105, 101], "machdep.tsc.deep_idle_rebase", RD_INT, "IU", ""),
    row!([7, 105, 102], "machdep.tsc.at_boot", RD_QUAD, "Q", ""),
    row!([7, 105, 103], "machdep.tsc.rebase_abs_time", RD_QUAD, "Q", ""),
    row!([7, 105, 104], "machdep.tsc.nanotime", RD_NODE, "N", "TSC to ns conversion"),
    row!([7, 105, 104, 100], "machdep.tsc.nanotime.tsc_base", RD_QUAD, "Q", ""),
    row!([7, 105, 104, 101], "machdep.tsc.nanotime.ns_base", RD_QUAD, "Q", ""),
    row!([7, 105, 104, 102], "machdep.tsc.nanotime.scale", RD_INT, "IU", ""),
    row!([7, 105, 104, 103], "machdep.tsc.nanotime.shift", RD_INT, "IU", ""),
    row!([7, 105, 104, 104], "machdep.tsc.nanotime.generation", RD_INT, "IU", ""),
    row!([7, 107], "machdep.x2apic_enabled", KERN_INT, "I", ""),
    row!([7, 112], "machdep.user_idle_level", kind(RD | WR | LOCKED | INT), "I", "User idle level heuristic, 0-128"),
];

/// The emulated TSC's rate (`X86_64Vcpu::tsc` counts 3 GHz).
pub const TSC_HZ: u64 = 3_000_000_000;

/// `LAPIC_DEFAULT_INTERRUPT_BASE` plus `LAPIC_TIMER_INTERRUPT` and
/// `LAPIC_INTERPROCESSOR_INTERRUPT`.
const TIMER_VECTOR: i32 = 0xdd;
const IPI_VECTOR: i32 = 0xde;

/// The machine's cache profile: line size, L2 associativity, and L2 size
/// in KiB (as `hw`: 64-byte lines, an 8-way 256 KiB L2).
const CACHE_LINE: u32 = 64;
const L2_WAYS: u32 = 8;
const L2_KIB: u32 = 256;

/// `i386_cpu_info_t`, the fields the nodes report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuInfo {
    max_basic: u32,
    max_ext: u32,
    vendor: Vec<u8>,
    brand_string: Vec<u8>,
    signature: u32,
    stepping: u8,
    model: u8,
    family: u8,
    extmodel: u8,
    extfamily: u8,
    brand: u8,
    features: u64,
    extfeatures: u64,
    logical_per_package: u32,
    cores_per_package: u32,
    address_bits: (u32, u32),
    mwait: Option<[u32; 4]>,
    thermal: Option<[u32; 10]>,
    arch_perf: Option<[u32; 7]>,
    xsave: Option<[[u32; 4]; 2]>,
    leaf7_features: u64,
    leaf7_extfeatures: u32,
    tsc_leaf: (u32, u32),
    tlb: [[[u32; 2]; 2]; 2],
    stlb: u32,
}

/// `CPUID_FEATURE_HTT`.
const FEATURE_HTT: u64 = 1 << 28;
/// `CPUID_EXTFEATURE_TSCI` (folded in from leaf 0x80000007).
const EXTFEATURE_TSCI: u64 = 1 << 8;

fn bits(v: u32, hi: u32, lo: u32) -> u32 {
    (v >> lo) & (u32::MAX >> (31 - (hi - lo)))
}

fn quad(hi: u32, lo: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

/// `cpuid_set_generic_info`, `cpuid_set_cache_info`'s leaf-2 TLB
/// descriptors, and `cpuid_set_info`'s counts, over `cpuid`.
pub fn cpu_info(cpuid: impl Fn(u32, u32) -> (u32, u32, u32, u32)) -> CpuInfo {
    let mut i = CpuInfo::default();
    let (a, b, c, d) = cpuid(0, 0);
    i.max_basic = a;
    i.vendor = [b, d, c].iter().flat_map(|r| r.to_le_bytes()).collect();
    trim_nul(&mut i.vendor);
    i.max_ext = cpuid(0x8000_0000, 0).0;
    if i.max_ext >= 0x8000_0004 {
        let mut s: Vec<u8> = (0x8000_0002..=0x8000_0004)
            .flat_map(|l| {
                let (a, b, c, d) = cpuid(l, 0);
                [a, b, c, d].into_iter().flat_map(u32::to_le_bytes)
            })
            .collect();
        trim_nul(&mut s);
        let lead = s.iter().take_while(|&&c| c == b' ').count();
        i.brand_string = s[lead..].to_vec();
        // CPUID_STRING_UNKNOWN: firmware could not name the CPU.
        if i.brand_string == b"Unknown CPU Typ" {
            i.brand_string.clear();
        }
    }
    if i.max_ext >= 0x8000_0006 {
        let a = cpuid(0x8000_0008, 0).0;
        i.address_bits = (bits(a, 7, 0), bits(a, 15, 8));
    }
    let (a, b, c, d) = cpuid(1, 0);
    i.signature = a;
    i.stepping = bits(a, 3, 0) as u8;
    i.model = bits(a, 7, 4) as u8;
    i.family = bits(a, 11, 8) as u8;
    i.extmodel = bits(a, 19, 16) as u8;
    i.extfamily = bits(a, 27, 20) as u8;
    i.brand = bits(b, 7, 0) as u8;
    i.features = quad(c, d);
    if i.family == 0x0f || i.family == 0x06 {
        i.model = i.model.wrapping_add(i.extmodel << 4);
        if i.family == 0x0f {
            i.family = i.family.wrapping_add(i.extfamily);
        }
    }
    i.logical_per_package = if i.features & FEATURE_HTT != 0 {
        bits(b, 23, 16)
    } else {
        1
    };
    if i.max_ext >= 0x8000_0001 {
        let (_, _, c, d) = cpuid(0x8000_0001, 0);
        i.extfeatures = quad(c, d);
    }
    if i.max_ext >= 0x8000_0007 {
        i.extfeatures |= u64::from(cpuid(0x8000_0007, 0).3) & EXTFEATURE_TSCI;
    }
    if i.max_basic >= 5 {
        let (a, b, c, d) = cpuid(5, 0);
        i.mwait = Some([a, b, c, d]);
    }
    if i.max_basic >= 6 {
        let (a, b, c, _) = cpuid(6, 0);
        i.thermal = Some([
            bits(a, 0, 0),
            bits(a, 1, 1),
            bits(a, 2, 2),
            bits(b, 3, 0),
            bits(c, 0, 0),
            bits(a, 4, 4),
            bits(a, 5, 5),
            bits(a, 6, 6),
            bits(c, 1, 1),
            bits(c, 3, 3),
        ]);
    }
    if i.max_basic >= 0xa {
        let (a, b, _, d) = cpuid(0xa, 0);
        i.arch_perf = Some([
            bits(a, 7, 0),
            bits(a, 15, 8),
            bits(a, 23, 16),
            bits(a, 31, 24),
            b,
            bits(d, 4, 0),
            bits(d, 12, 5),
        ]);
    }
    if i.max_basic >= 0xd {
        let leaf = |s| {
            let (a, b, c, d) = cpuid(0xd, s);
            [a, b, c, d]
        };
        i.xsave = Some([leaf(0), leaf(1)]);
    }
    if i.max_basic >= 7 {
        let (_, b, c, d) = cpuid(7, 0);
        i.leaf7_features = quad(c, b);
        i.leaf7_extfeatures = d;
    }
    if i.max_basic >= 0x15 {
        let (a, b, _, _) = cpuid(0x15, 0);
        i.tsc_leaf = (b, a);
    }
    tlbs(&mut i, &cpuid);
    // No deterministic cache leaf (leaf 4 reports no cache): one core.
    i.cores_per_package = 1;
    i
}

/// The TLB counts of the leaf-2 descriptors (`cpuid_set_cache_info`).
fn tlbs(i: &mut CpuInfo, cpuid: &impl Fn(u32, u32) -> (u32, u32, u32, u32)) {
    let mut desc: Vec<u8> = Vec::with_capacity(64);
    for n in 0..4 {
        if n > 0 && desc.first().is_some_and(|&count| n >= u32::from(count)) {
            break;
        }
        let (a, b, c, d) = cpuid(2, 0);
        for r in [a, b, c, d] {
            if r >> 31 == 0 {
                desc.extend_from_slice(&r.to_le_bytes());
            }
        }
    }
    for &byte in desc.iter().skip(1) {
        if let Some(&(_, stlb, inst, large, level1, entries)) =
            TLB_DESCRIPTORS.iter().find(|d| d.0 == byte)
        {
            if stlb {
                i.stlb = entries;
            } else {
                i.tlb[usize::from(!inst)][usize::from(large)][usize::from(level1)] = entries;
            }
        }
    }
}

/// `intel_cpuid_leaf2_descriptor_table`'s TLB entries: descriptor, a
/// shared TLB, an instruction TLB, large (or both) pages, the second data
/// level (`DATA1`), and the entries.
#[rustfmt::skip]
const TLB_DESCRIPTORS: &[(u8, bool, bool, bool, bool, u32)] = &[
    (0x01, false, true, false, false, 32), (0x02, false, true, true, false, 2),
    (0x03, false, false, false, false, 64), (0x04, false, false, true, false, 8),
    (0x05, false, false, true, true, 32), (0x0B, false, true, true, false, 4),
    (0x4F, false, true, false, false, 32), (0x50, false, true, true, false, 64),
    (0x51, false, true, true, false, 128), (0x52, false, true, true, false, 256),
    (0x55, false, true, true, false, 7), (0x56, false, false, true, false, 16),
    (0x57, false, false, false, false, 16), (0x59, false, false, false, false, 16),
    (0x5A, false, false, true, false, 32), (0x5B, false, false, true, false, 64),
    (0x5C, false, false, true, false, 128), (0x5D, false, false, true, false, 256),
    (0x76, false, true, true, false, 8), (0xB0, false, true, false, false, 128),
    (0xB1, false, true, true, false, 8), (0xB2, false, true, false, false, 64),
    (0xB3, false, false, false, false, 128), (0xB4, false, false, false, true, 256),
    (0xB5, false, false, false, true, 64), (0xB6, false, false, false, true, 128),
    (0xBA, false, false, true, true, 64), (0xC1, true, false, false, true, 1024),
    (0xCA, true, false, false, true, 512),
];

fn trim_nul(s: &mut Vec<u8>) {
    if let Some(z) = s.iter().position(|&c| c == 0) {
        s.truncate(z);
    }
}

/// `cpuid_get_names` over a feature map.
fn names(map: &[(u32, &str)], bits: u64) -> Vec<u8> {
    map.iter()
        .filter(|&&(b, _)| bits & (1 << b) != 0)
        .map(|&(_, n)| n)
        .collect::<Vec<_>>()
        .join(" ")
        .into_bytes()
}

/// `feature_map`: bit numbers in `(ECX << 32) | EDX` of leaf 1.
#[rustfmt::skip]
const FEATURES: &[(u32, &str)] = &[
    (0, "FPU"), (1, "VME"), (2, "DE"), (3, "PSE"), (4, "TSC"), (5, "MSR"), (6, "PAE"),
    (7, "MCE"), (8, "CX8"), (9, "APIC"), (11, "SEP"), (12, "MTRR"), (13, "PGE"), (14, "MCA"),
    (15, "CMOV"), (16, "PAT"), (17, "PSE36"), (18, "PSN"), (19, "CLFSH"), (21, "DS"),
    (22, "ACPI"), (23, "MMX"), (24, "FXSR"), (25, "SSE"), (26, "SSE2"), (27, "SS"),
    (28, "HTT"), (29, "TM"), (31, "PBE"), (32, "SSE3"), (33, "PCLMULQDQ"), (34, "DTES64"),
    (35, "MON"), (36, "DSCPL"), (37, "VMX"), (38, "SMX"), (39, "EST"), (40, "TM2"),
    (41, "SSSE3"), (42, "CID"), (44, "FMA"), (45, "CX16"), (46, "TPR"), (47, "PDCM"),
    (51, "SSE4.1"), (52, "SSE4.2"), (53, "x2APIC"), (54, "MOVBE"), (55, "POPCNT"),
    (57, "AES"), (63, "VMM"), (49, "PCID"), (58, "XSAVE"), (59, "OSXSAVE"), (43, "SEGLIM64"),
    (56, "TSCTMR"), (60, "AVX1.0"), (62, "RDRAND"), (61, "F16C"),
];

/// `extfeature_map`: bit numbers in `(ECX << 32) | EDX` of leaf
/// 0x80000001, with the invariant TSC folded in.
const EXTFEATURES: &[(u32, &str)] = &[
    (11, "SYSCALL"),
    (20, "XD"),
    (26, "1GBPAGE"),
    (29, "EM64T"),
    (32, "LAHF"),
    (37, "LZCNT"),
    (40, "PREFETCHW"),
    (27, "RDTSCP"),
    (8, "TSCI"),
];

/// `leaf7_feature_map`: bit numbers in `(ECX << 32) | EBX` of leaf 7.
#[rustfmt::skip]
const LEAF7_FEATURES: &[(u32, &str)] = &[
    (0, "RDWRFSGS"), (1, "TSC_THREAD_OFFSET"), (2, "SGX"), (3, "BMI1"), (4, "HLE"),
    (5, "AVX2"), (6, "FDPEO"), (7, "SMEP"), (8, "BMI2"), (9, "ERMS"), (10, "INVPCID"),
    (11, "RTM"), (12, "PQM"), (13, "FPU_CSDS"), (14, "MPX"), (15, "PQE"), (16, "AVX512F"),
    (17, "AVX512DQ"), (18, "RDSEED"), (19, "ADX"), (20, "SMAP"), (21, "AVX512IFMA"),
    (23, "CLFSOPT"), (24, "CLWB"), (25, "IPT"), (28, "AVX512CD"), (29, "SHA"),
    (30, "AVX512BW"), (31, "AVX512VL"), (32, "PREFETCHWT1"), (33, "AVX512VBMI"),
    (34, "UMIP"), (35, "PKU"), (36, "OSPKE"), (37, "WAITPKG"), (40, "GFNI"), (41, "VAES"),
    (42, "VPCLMULQDQ"), (43, "AVX512VNNI"), (44, "AVX512BITALG"), (46, "AVX512VPOPCNTDQ"),
    (54, "RDPID"), (57, "CLDEMOTE"), (59, "MOVDIRI"), (60, "MOVDIRI64B"), (62, "SGXLC"),
];

/// `leaf7_extfeature_map`: bit numbers in EDX of leaf 7.
#[rustfmt::skip]
const LEAF7_EXTFEATURES: &[(u32, &str)] = &[
    (2, "AVX5124VNNIW"), (3, "AVX5124FMAPS"), (4, "FSREPMOV"), (10, "MDCLEAR"),
    (13, "TSXFA"), (26, "IBRS"), (27, "STIBP"), (28, "L1DF"), (29, "ACAPMSR"),
    (30, "CCAPMSR"), (31, "SSBD"),
];

/// The CPU description of `ctx`'s vCPU.
pub fn this_cpu(ctx: &Ctx<'_>) -> CpuInfo {
    match &ctx.thread.cpu {
        DarwinCpu::X86_64(cpu) => cpu_info(|l, s| cpu.vcpu().cpuid(l, s)),
        DarwinCpu::Arm64(_) => CpuInfo::default(),
    }
}

/// `_i386_cpu_info`: a 32-bit field.
fn u32_out(v: u32) -> Value {
    Value::Out(v.to_le_bytes().to_vec())
}

/// `_i386_cpu_info`: a string, absent when empty.
fn str_out(s: &[u8]) -> Value {
    if s.is_empty() {
        Value::Err(Errno::ENOENT)
    } else {
        Value::string(s)
    }
}

/// `i386_cpu_info_nonzero`: absent when the first 32 bits are zero.
fn nonzero(v: u32, out: Value) -> Value {
    if v == 0 {
        Value::Err(Errno::ENOENT)
    } else {
        out
    }
}

/// The value of `name` (a node of [`ROWS`]).
pub fn value(ctx: &Ctx<'_>, name: &str) -> Value {
    let Some(leaf) = name.strip_prefix("machdep.") else {
        return Value::Err(Errno::ENOENT);
    };
    if let Some(cpu) = leaf.strip_prefix("cpu.") {
        return cpu_value(&this_cpu(ctx), cpu);
    }
    match leaf {
        "remotetime.conversion_params" => Value::Out(vec![0; 24]),
        "vectors.timer" => Value::io_int(TIMER_VECTOR),
        "vectors.IPI" => Value::io_int(IPI_VECTOR),
        "tsc.frequency" => Value::io_quad(TSC_HZ),
        "tsc.deep_idle_rebase" => Value::io_int(1),
        // The TSC starts with the emulator: no boot offset or rebase.
        "tsc.at_boot" | "tsc.rebase_abs_time" => Value::io_quad(0),
        // The commpage's nanotime parameters.
        "tsc.nanotime.tsc_base" | "tsc.nanotime.ns_base" => Value::io_quad(0),
        "tsc.nanotime.scale" => Value::io_int(((1u64 << 32) / 3) as i32),
        "tsc.nanotime.shift" => Value::io_int(0),
        "tsc.nanotime.generation" => Value::io_int(1),
        "x2apic_enabled" => Value::io_int(i32::from(this_cpu(ctx).features & (1 << 53) != 0)),
        "user_idle_level" => Value::Host,
        _ => Value::Err(Errno::ENOENT),
    }
}

fn cpu_value(i: &CpuInfo, leaf: &str) -> Value {
    let byte = |v: u8| u32_out(u32::from(v));
    match leaf {
        "max_basic" => u32_out(i.max_basic),
        "max_ext" => u32_out(i.max_ext),
        "vendor" => str_out(&i.vendor),
        "brand_string" => str_out(&i.brand_string),
        "family" => byte(i.family),
        "model" => byte(i.model),
        "extmodel" => byte(i.extmodel),
        "extfamily" => byte(i.extfamily),
        "stepping" => byte(i.stepping),
        "feature_bits" => Value::Out(i.features.to_le_bytes().to_vec()),
        "leaf7_feature_bits" => nonzero(
            i.leaf7_features as u32,
            Value::Out(i.leaf7_features.to_le_bytes().to_vec()),
        ),
        "leaf7_feature_bits_edx" => nonzero(i.leaf7_extfeatures, u32_out(i.leaf7_extfeatures)),
        "extfeature_bits" => Value::Out(i.extfeatures.to_le_bytes().to_vec()),
        "signature" => u32_out(i.signature),
        "brand" => byte(i.brand),
        "features" => Value::string(&names(FEATURES, i.features)),
        "leaf7_features" => {
            if i.leaf7_features == 0 && i.leaf7_extfeatures == 0 {
                return Value::Err(Errno::ENOENT);
            }
            let mut s = names(LEAF7_FEATURES, i.leaf7_features);
            if i.leaf7_extfeatures != 0 {
                s.push(b' ');
                s.extend(names(LEAF7_EXTFEATURES, u64::from(i.leaf7_extfeatures)));
            }
            Value::string(&s)
        }
        "extfeatures" => Value::string(&names(EXTFEATURES, i.extfeatures)),
        "logical_per_package" if i.features & FEATURE_HTT == 0 => Value::Err(Errno::ENOENT),
        "logical_per_package" => u32_out(i.logical_per_package),
        "cores_per_package" => u32_out(i.cores_per_package),
        // No microcode or platform-ID MSR.
        "microcode_version" | "processor_flag" => u32_out(0),
        "cache.linesize" => u32_out(CACHE_LINE),
        "cache.L2_associativity" => u32_out(L2_WAYS),
        "cache.size" => u32_out(L2_KIB),
        "tlb.inst.small" => nonzero(i.tlb[0][0][0], u32_out(i.tlb[0][0][0])),
        "tlb.inst.large" => nonzero(i.tlb[0][1][0], u32_out(i.tlb[0][1][0])),
        "tlb.data.small" => nonzero(i.tlb[1][0][0], u32_out(i.tlb[1][0][0])),
        "tlb.data.small_level1" => nonzero(i.tlb[1][0][1], u32_out(i.tlb[1][0][1])),
        "tlb.data.large" => nonzero(i.tlb[1][1][0], u32_out(i.tlb[1][1][0])),
        "tlb.data.large_level1" => nonzero(i.tlb[1][1][1], u32_out(i.tlb[1][1][1])),
        "tlb.shared" => nonzero(i.stlb, u32_out(i.stlb)),
        "address_bits.physical" => u32_out(i.address_bits.0),
        "address_bits.virtual" => u32_out(i.address_bits.1),
        // One core, one thread (MSR_CORE_THREAD_COUNT's VMM default).
        "core_count" | "thread_count" => u32_out(1),
        // A Nehalem (model 26) only.
        "flex_ratio.desired" | "flex_ratio.min" | "flex_ratio.max" if i.model != 26 => {
            Value::Err(Errno::ENOENT)
        }
        "flex_ratio.desired" | "flex_ratio.min" | "flex_ratio.max" => u32_out(0),
        // cpu_ucode_update: a read has no address.
        "ucupdate" if i.features & (1 << 63) != 0 => Value::Err(Errno::ENODEV),
        "ucupdate" => Value::Err(Errno::EINVAL),
        "tsc_ccc.numerator" => u32_out(i.tsc_leaf.0),
        "tsc_ccc.denominator" => u32_out(i.tsc_leaf.1),
        _ => sub_leaf(i, leaf),
    }
}

/// The `mwait`, `thermal`, `arch_perf`, and `xsave` leaves: absent
/// without their `CPUID` leaf.
fn sub_leaf(i: &CpuInfo, leaf: &str) -> Value {
    let (group, field) = leaf.split_once('.').unwrap_or((leaf, ""));
    let pick = |v: Option<&[u32]>, names: &[&str]| match v {
        None => Value::Err(Errno::ENOENT),
        Some(v) => names
            .iter()
            .position(|&n| n == field)
            .map_or(Value::Err(Errno::ENOENT), |k| u32_out(v[k])),
    };
    match group {
        "mwait" => pick(
            i.mwait.as_ref().map(|v| &v[..]),
            &["linesize_min", "linesize_max", "extensions", "sub_Cstates"],
        ),
        "thermal" => pick(
            i.thermal.as_ref().map(|v| &v[..]),
            &[
                "sensor",
                "dynamic_acceleration",
                "invariant_APIC_timer",
                "thresholds",
                "ACNT_MCNT",
                "core_power_limits",
                "fine_grain_clock_mod",
                "package_thermal_intr",
                "hardware_feedback",
                "energy_policy",
            ],
        ),
        "arch_perf" => pick(
            i.arch_perf.as_ref().map(|v| &v[..]),
            &[
                "version",
                "number",
                "width",
                "events_number",
                "events",
                "fixed_number",
                "fixed_width",
            ],
        ),
        "xsave" => match (&i.xsave, field) {
            (None, _) => Value::Err(Errno::ENOENT),
            (Some(x), "extended_state") => words(&x[0]),
            (Some(x), "extended_state1") => words(&x[1]),
            _ => Value::Err(Errno::ENOENT),
        },
        _ => Value::Err(Errno::ENOENT),
    }
}

fn words(v: &[u32; 4]) -> Value {
    Value::Out(v.iter().flat_map(|w| w.to_le_bytes()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Haswell's CPUID (i7-4770, family 6 model 0x3c stepping 3).
    fn haswell(l: u32, s: u32) -> (u32, u32, u32, u32) {
        match (l, s) {
            (0, _) => (0xd, 0x756e_6547, 0x6c65_746e, 0x4965_6e69),
            (1, _) => (0x306c3, 0x0010_0800, 0x7ffa_fbff, 0xbfeb_fbff),
            (2, _) => (0x7603_6301, 0x00f0_b5ff, 0, 0x00c1_0000),
            (7, 0) => (0, 0x27ab, 0, 0),
            (0x8000_0000, _) => (0x8000_0008, 0, 0, 0),
            (0x8000_0001, _) => (0, 0, 0x21, 0x2c10_0800),
            (0x8000_0002, _) => (0x6574_6e49, 0x2952_286c, 0x726f_4320, 0x4d54_2865),
            (0x8000_0003, _) => (0x3769_2029, 0x3737_342d, 0x5043_2030, 0x2040_2055),
            (0x8000_0004, _) => (0x3034_2e33, 0x007a_4847, 0, 0),
            (0x8000_0007, _) => (0, 0, 0, 0x100),
            (0x8000_0008, _) => (0x3027, 0, 0, 0),
            _ => (0, 0, 0, 0),
        }
    }

    #[test]
    fn cpu_info_follows_cpuid_c() {
        let i = cpu_info(haswell);
        assert_eq!(i.vendor, b"GenuineIntel");
        assert_eq!(i.brand_string, b"Intel(R) Core(TM) i7-4770 CPU @ 3.40GHz");
        assert_eq!((i.family, i.model, i.extmodel, i.stepping), (6, 0x3c, 3, 3));
        assert_eq!(i.address_bits, (39, 48));
        assert_eq!(i.logical_per_package, 16);
        assert_eq!(i.extfeatures & EXTFEATURE_TSCI, EXTFEATURE_TSCI);
        // Leaf 2: 0x63 is no TLB, 0x76 an 8-entry instruction TLB for
        // both page sizes (counted as large), 0xb5 a 64-entry second-level
        // data TLB, 0xc1 a 1024-entry shared TLB.
        assert_eq!(i.tlb[0][1][0], 8);
        assert_eq!(i.tlb[1][0][1], 64);
        assert_eq!(i.stlb, 1024);
        let s = |v| match v {
            Value::Out(b) => String::from_utf8(b).unwrap(),
            other => panic!("{other:?}"),
        };
        assert!(
            s(cpu_value(&i, "features")).starts_with("FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP")
        );
        assert_eq!(
            s(cpu_value(&i, "extfeatures")),
            "SYSCALL XD 1GBPAGE EM64T LAHF LZCNT RDTSCP TSCI\0"
        );
        assert_eq!(
            s(cpu_value(&i, "leaf7_features")),
            "RDWRFSGS TSC_THREAD_OFFSET BMI1 AVX2 SMEP BMI2 ERMS INVPCID FPU_CSDS\0"
        );
        assert_eq!(
            cpu_value(&i, "family"),
            Value::Out(6u32.to_le_bytes().to_vec())
        );
        assert_eq!(cpu_value(&i, "flex_ratio.max"), Value::Err(Errno::ENOENT));
        // Leaf 5 exists (max_basic 0xd); without it the mwait nodes do not.
        assert_eq!(cpu_value(&i, "mwait.extensions"), u32_out(0));
        let old = cpu_info(|l, s| match l {
            0 => (4, 0x756e_6547, 0x6c65_746e, 0x4965_6e69),
            _ => haswell(l, s),
        });
        assert_eq!(
            cpu_value(&old, "mwait.extensions"),
            Value::Err(Errno::ENOENT)
        );
        assert_eq!(
            cpu_value(&old, "xsave.extended_state"),
            Value::Err(Errno::ENOENT)
        );
    }

    #[test]
    fn rows_are_sorted_and_numbered_under_their_parents() {
        assert!(ROWS.windows(2).all(|w| w[0].oid < w[1].oid));
        for r in ROWS.iter().skip(1) {
            let parent = &r.oid[..r.oid.len() - 1];
            let p = ROWS.iter().find(|p| p.oid == parent).expect("parent row");
            assert!(p.is_node(), "{}", r.name);
            assert_eq!(r.name.rsplit_once('.').map(|x| x.0), Some(p.name));
        }
    }
}
