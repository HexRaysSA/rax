//! The values of the emulated machine's `hw` and `machdep` nodes, each
//! produced as its kernel handler produces it (`kern_mib.c`,
//! `bsd/dev/arm64/sysctl.c`): an exact copy-out (`SYSCTL_RETURN`,
//! `SYSCTL_OUT`), a number a 32-bit buffer may take (`sysctl_io_number`:
//! `SYSCTL_INT`, `SYSCTL_QUAD`, and the handlers built on it), an error, or
//! the host's node (the platform's identity and configuration, which the
//! guest shares with the host).
//!
//! The emulated machine has one CPU with one level of performance, the
//! caches below, and no L3 cache; an arm64 guest reports the host's model
//! and brand, an x86-64 guest a Mac Pro's.

use super::Value;
use crate::user::darwin::abi::{DarwinAbi, Errno};
use crate::user::darwin::arch::ARM64_COUNTER_HZ;
use crate::user::darwin::commpage;
use crate::user::darwin::process::{MEMSIZE, memsize_usable};
use crate::user::darwin::syscall::Ctx;

/// The arm64 features the emulated CPU has (`hw.optional.arm.*`): the
/// `apple_arm64_config` profile.
const ARM_FEATURES: &[&str] = &[
    "FEAT_CRC32",
    "FEAT_FlagM",
    "FEAT_FlagM2",
    "FEAT_FHM",
    "FEAT_DotProd",
    "FEAT_SHA3",
    "FEAT_RDM",
    "FEAT_LSE",
    "FEAT_SHA256",
    "FEAT_SHA512",
    "FEAT_SHA1",
    "FEAT_AES",
    "FEAT_PMULL",
    "FEAT_SB",
    "FEAT_FRINTTS",
    "FEAT_PACIMP",
    "FEAT_LRCPC",
    "FEAT_LRCPC2",
    "FEAT_FCMA",
    "FEAT_JSCVT",
    "FEAT_PAuth",
    "FEAT_DPB",
    "FEAT_DPB2",
    "FEAT_LSE2",
    "FEAT_CSV2",
    "FEAT_CSV3",
    "FEAT_DIT",
    "AdvSIMD",
    "AdvSIMD_HPFPCvt",
    "FEAT_FP16",
    "FEAT_BTI",
];

/// `CAP_BIT_*` (`osfmk/arm/cpu_capabilities_public.h`): each feature's
/// bit in `hw.optional.arm.caps`.
const CAP_BITS: &[(&str, u32)] = &[
    ("FEAT_FlagM", 0),
    ("FEAT_FlagM2", 1),
    ("FEAT_FHM", 2),
    ("FEAT_DotProd", 3),
    ("FEAT_SHA3", 4),
    ("FEAT_RDM", 5),
    ("FEAT_LSE", 6),
    ("FEAT_SHA256", 7),
    ("FEAT_SHA512", 8),
    ("FEAT_SHA1", 9),
    ("FEAT_AES", 10),
    ("FEAT_PMULL", 11),
    ("FEAT_SPECRES", 12),
    ("FEAT_SB", 13),
    ("FEAT_FRINTTS", 14),
    ("FEAT_LRCPC", 15),
    ("FEAT_LRCPC2", 16),
    ("FEAT_FCMA", 17),
    ("FEAT_JSCVT", 18),
    ("FEAT_PAuth", 19),
    ("FEAT_PAuth2", 20),
    ("FEAT_FPAC", 21),
    ("FEAT_DPB", 22),
    ("FEAT_DPB2", 23),
    ("FEAT_BF16", 24),
    ("FEAT_I8MM", 25),
    ("FEAT_WFxT", 26),
    ("FEAT_RPRES", 27),
    ("FEAT_ECV", 28),
    ("FEAT_AFP", 29),
    ("FEAT_LSE2", 30),
    ("FEAT_CSV2", 31),
    ("FEAT_CSV3", 32),
    ("FEAT_DIT", 33),
    ("FEAT_FP16", 34),
    ("FEAT_SSBS", 35),
    ("FEAT_BTI", 36),
    ("AdvSIMD", 49),
    ("AdvSIMD_HPFPCvt", 50),
    ("FEAT_CRC32", 51),
    ("FEAT_PACIMP", 58),
];

/// The bytes of `hw.optional.arm.caps` the host kernel reports (one bit per
/// feature it knows, `CAP_BYTE_NB`).
const CAP_BYTES: usize = 13;

/// The legacy names of arm64 features (`LEGACY_ARM_SYSCTL`).
const LEGACY_ARM: &[(&str, &str)] = &[
    ("neon", "AdvSIMD"),
    ("neon_hpfp", "AdvSIMD_HPFPCvt"),
    ("neon_fp16", "FEAT_FP16"),
    ("armv8_crc32", "FEAT_CRC32"),
    ("armv8_gpi", "FEAT_PACIMP"),
    ("armv8_1_atomics", "FEAT_LSE"),
    ("armv8_2_fhm", "FEAT_FHM"),
    ("armv8_2_sha512", "FEAT_SHA512"),
    ("armv8_2_sha3", "FEAT_SHA3"),
    ("armv8_3_compnum", "FEAT_FCMA"),
];

/// The x86 features the emulated CPU has (`hw.optional.*`): the Haswell
/// profile of the commpage.
const X86_FEATURES: &[&str] = &[
    "mmx",
    "sse",
    "sse2",
    "sse3",
    "supplementalsse3",
    "sse4_1",
    "sse4_2",
    "x86_64",
    "aes",
    "avx1_0",
    "rdrand",
    "f16c",
    "enfstrg",
    "fma",
    "avx2_0",
    "bmi1",
    "bmi2",
    "adx",
];

/// The x86 capabilities `hw.optional` reports (`sysctl_cpu_capability`).
const X86_OPTIONAL: &[&str] = &[
    "mmx",
    "sse",
    "sse2",
    "sse3",
    "supplementalsse3",
    "sse4_1",
    "sse4_2",
    "x86_64",
    "aes",
    "avx1_0",
    "rdrand",
    "f16c",
    "enfstrg",
    "fma",
    "avx2_0",
    "bmi1",
    "bmi2",
    "rtm",
    "hle",
    "adx",
    "mpx",
    "sgx",
    "avx512f",
    "avx512cd",
    "avx512dq",
    "avx512bw",
    "avx512vl",
    "avx512ifma",
    "avx512vbmi",
];

/// A cache geometry: line, L1 instruction, L1 data, and L2 sizes.
struct Caches {
    line: u64,
    l1i: u64,
    l1d: u64,
    l2: u64,
}

fn caches(abi: DarwinAbi) -> Caches {
    match abi {
        DarwinAbi::Arm64 => Caches {
            line: 128,
            l1i: 131_072,
            l1d: 65_536,
            l2: 4_194_304,
        },
        DarwinAbi::X86_64 => Caches {
            line: 64,
            l1i: 32_768,
            l1d: 32_768,
            l2: 262_144,
        },
    }
}

/// `hw.cpusubfamily` of the emulated arm64 CPU (`CPUSUBFAMILY_ARM_HG`).
const CPUSUBFAMILY_ARM_HG: i32 = 2;
/// The CPU and bus clocks of the emulated Intel machine.
const X86_CPU_HZ: u64 = 3_000_000_000;
const X86_BUS_HZ: u64 = 100_000_000;

/// The value of the node `name`.
pub fn value(ctx: &Ctx<'_>, name: &str) -> Value {
    let abi = ctx.proc.abi;
    let arm = abi == DarwinAbi::Arm64;
    let ncpu = i32::from(commpage::NCPUS);
    let page = abi.user_page_size();
    let c = caches(abi);
    let tb = if arm { ARM64_COUNTER_HZ } else { 1_000_000_000 };
    let usable = memsize_usable(abi);
    if let Some(v) = optional(abi, name) {
        return v;
    }
    if let Some(level) = name.strip_prefix("hw.perflevel") {
        return perflevel(level, &c);
    }
    match name {
        "hw.machine" => Value::string(abi.name().as_bytes()),
        "hw.model" | "hw.product" if !arm => Value::string(b"MacPro7,1"),
        "hw.target" if !arm => Value::string(b"Mac-27AD2F918AE68F61"),
        "hw.ncpu" | "hw.activecpu" | "hw.physicalcpu" | "hw.physicalcpu_max" | "hw.logicalcpu"
        | "hw.logicalcpu_max" => Value::int(ncpu),
        "hw.byteorder" => Value::io_int(1234),
        // SYSCTL_COMPAT_UINT over mem_size: its low 32 bits.
        "hw.physmem" => Value::io_int(usable as u32 as i32),
        // No memory is wired.
        "hw.usermem" => Value::int(usable as i32),
        "hw.pagesize_compat" => Value::int(page as i32),
        "hw.epoch" => Value::int(1),
        "hw.vectorunit" => Value::int(i32::from(!arm)),
        "hw.busfrequency_compat" if !arm => Value::Out((X86_BUS_HZ as u32).to_le_bytes().to_vec()),
        "hw.cpufrequency_compat" if !arm => Value::Out((X86_CPU_HZ as u32).to_le_bytes().to_vec()),
        "hw.busfrequency_compat" | "hw.cpufrequency_compat" => Value::Err(Errno::ENOENT),
        "hw.cachelinesize_compat" => Value::int(c.line as i32),
        "hw.l1icachesize_compat" => Value::int(c.l1i as i32),
        "hw.l1dcachesize_compat" => Value::int(c.l1d as i32),
        "hw.l2cachesize_compat" => Value::int(c.l2 as i32),
        "hw.l2settings" => Value::quad(1),
        // No L3 cache (its size reads as UINT32_MAX).
        "hw.l3settings" | "hw.l3cachesize_compat" | "hw.l3cachesize" => Value::Err(Errno::EINVAL),
        "hw.tbfrequency_compat" => Value::int(tb as i32),
        "hw.memsize" => Value::io_quad(MEMSIZE),
        "hw.memsize_usable" => Value::io_quad(usable),
        "hw.features.allows_security_research" => Value::io_int(0),
        "hw.nperflevels" => Value::int(1),
        "hw.cputype" => Value::int(abi.host_cpu().cputype as i32),
        "hw.cpusubtype" => Value::int(abi.host_cpu().cpusubtype as i32),
        "hw.cpu64bit_capable" => Value::io_int(1),
        "hw.cpufamily" => Value::int(if arm {
            commpage::CPUFAMILY_ARM_FIRESTORM_ICESTORM as i32
        } else {
            commpage::CPUFAMILY_INTEL_HASWELL as i32
        }),
        "hw.cpusubfamily" => Value::int(if arm { CPUSUBFAMILY_ARM_HG } else { 0 }),
        // CPUs, then CPUs sharing each cache level.
        "hw.cacheconfig" => quads(&[ncpu as u64, 1, 1]),
        // Memory, then the L1 data and L2 cache sizes (arm64's memory is
        // machine_info.memory_size, 32 bits wide).
        "hw.cachesize" => quads(&[if arm { usable as u32 as u64 } else { usable }, c.l1d, c.l2]),
        "hw.pagesize" | "hw.pagesize32" => Value::io_quad(page),
        "hw.busfrequency" | "hw.busfrequency_min" | "hw.busfrequency_max" if !arm => {
            Value::quad(X86_BUS_HZ)
        }
        "hw.cpufrequency" | "hw.cpufrequency_min" | "hw.cpufrequency_max" if !arm => {
            Value::quad(X86_CPU_HZ)
        }
        "hw.busfrequency"
        | "hw.busfrequency_min"
        | "hw.busfrequency_max"
        | "hw.cpufrequency"
        | "hw.cpufrequency_min"
        | "hw.cpufrequency_max" => Value::Err(Errno::ENOENT),
        "hw.cachelinesize" => Value::quad(c.line),
        "hw.l1icachesize" => Value::quad(c.l1i),
        "hw.l1dcachesize" => Value::quad(c.l1d),
        "hw.l2cachesize" => Value::quad(c.l2),
        "hw.tbfrequency" => Value::io_quad(tb),
        "hw.packages" => Value::io_int(1),
        // arm_host_info: counts of the one CPU.
        "machdep.cpu.cores_per_package"
        | "machdep.cpu.core_count"
        | "machdep.cpu.logical_per_package"
        | "machdep.cpu.thread_count" => Value::Out((ncpu as u32).to_le_bytes().to_vec()),
        // x86 only.
        "machdep.cpu.features" | "machdep.cpu.feature_bits" | "machdep.cpu.family" => {
            Value::Err(Errno::ENOENT)
        }
        // The platform's identity and configuration.
        _ => Value::Host,
    }
}

/// `hw.optional` and `hw.optional.arm` nodes.
fn optional(abi: DarwinAbi, name: &str) -> Option<Value> {
    let rest = name.strip_prefix("hw.optional.")?;
    let has = |f: &str| i32::from(ARM_FEATURES.contains(&f));
    Some(match (abi, rest) {
        (_, "floatingpoint") => Value::io_int(1),
        // sysctl_cpu_capability: a boolean_t; an arm64 kernel has no
        // x86 capabilities to report.
        (DarwinAbi::X86_64, f) if X86_OPTIONAL.contains(&f) => {
            Value::int(i32::from(X86_FEATURES.contains(&f)))
        }
        (DarwinAbi::Arm64, f) if X86_OPTIONAL.contains(&f) => Value::Err(Errno::ENOTSUP),
        (DarwinAbi::Arm64, "arm.caps") => {
            let mut b = vec![0u8; CAP_BYTES];
            for &(f, bit) in CAP_BITS {
                if ARM_FEATURES.contains(&f) {
                    b[bit as usize / 8] |= 1 << (bit % 8);
                }
            }
            Value::Out(b)
        }
        (DarwinAbi::Arm64, "arm.sme_max_svl_b") => Value::io_int(0),
        (DarwinAbi::Arm64, f) if f.starts_with("arm.") => Value::io_int(has(&f[4..])),
        (DarwinAbi::Arm64, f) if LEGACY_ARM.iter().any(|&(l, _)| l == f) => {
            let feat = LEGACY_ARM.iter().find(|&&(l, _)| l == f).expect("found").1;
            Value::io_int(has(feat))
        }
        // No hardware watchpoints or breakpoints are emulated.
        (DarwinAbi::Arm64, "watchpoint" | "breakpoint") => Value::io_int(0),
        (DarwinAbi::Arm64, "ucnormal_mem" | "arm64") => Value::io_int(1),
        _ => return None,
    })
}

/// `hw.perflevel<n>.<name>` (`rest` is `<n>.<name>`): the one level, 0.
fn perflevel(rest: &str, c: &Caches) -> Value {
    let (level, leaf) = rest.split_once('.').unwrap_or((rest, ""));
    if level != "0" {
        return Value::Err(Errno::ENOENT);
    }
    let ncpu = i32::from(commpage::NCPUS);
    match leaf {
        "physicalcpu" | "physicalcpu_max" | "logicalcpu" | "logicalcpu_max" | "cpusperl2" => {
            Value::int(ncpu)
        }
        "l1icachesize" => Value::int(c.l1i as i32),
        "l1dcachesize" => Value::int(c.l1d as i32),
        "l2cachesize" => Value::int(c.l2 as i32),
        "l3cachesize" | "cpusperl3" => Value::Err(Errno::EINVAL),
        "name" => Value::string(b"Performance"),
        _ => Value::Err(Errno::ENOENT),
    }
}

/// Ten 64-bit values, the given ones first (`hw.cacheconfig`,
/// `hw.cachesize`).
fn quads(v: &[u64]) -> Value {
    let mut b = Vec::with_capacity(80);
    for i in 0..10 {
        b.extend_from_slice(&v.get(i).copied().unwrap_or(0).to_le_bytes());
    }
    Value::Out(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_set_the_features_bits() {
        let Some(Value::Out(b)) = optional(DarwinAbi::Arm64, "hw.optional.arm.caps") else {
            panic!("caps");
        };
        assert_eq!(b.len(), CAP_BYTES);
        // FEAT_FlagM (0), AdvSIMD (49), FEAT_CRC32 (51); not FEAT_SPECRES (12).
        assert_eq!(b[0] & 1, 1);
        assert_eq!(b[6] & 0b1010, 0b1010);
        assert_eq!(b[1] & 0b10000, 0);
    }

    #[test]
    fn optional_features_follow_the_cpu_profiles() {
        let int = |v| match v {
            Some(Value::Number(n, 4)) => n,
            Some(Value::Out(b)) if b.len() == 4 => {
                i64::from(i32::from_le_bytes(b.try_into().unwrap()))
            }
            _ => -1,
        };
        assert_eq!(
            int(optional(DarwinAbi::Arm64, "hw.optional.arm.FEAT_PAuth")),
            1
        );
        assert_eq!(
            int(optional(DarwinAbi::Arm64, "hw.optional.arm.FEAT_SME")),
            0
        );
        assert_eq!(
            int(optional(DarwinAbi::Arm64, "hw.optional.armv8_1_atomics")),
            1
        );
        assert_eq!(int(optional(DarwinAbi::X86_64, "hw.optional.avx2_0")), 1);
        assert_eq!(int(optional(DarwinAbi::X86_64, "hw.optional.avx512f")), 0);
        assert!(matches!(
            optional(DarwinAbi::Arm64, "hw.optional.sse"),
            Some(Value::Err(Errno::ENOTSUP))
        ));
        assert!(optional(DarwinAbi::X86_64, "hw.optional.neon").is_none());
    }
}
