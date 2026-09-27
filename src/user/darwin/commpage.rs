//! The commpage: the kernel data page mapped read-only into every process.
//!
//! libSystem reads machine facts (CPU capabilities and counts, page sizes,
//! cache-line size, memory size) and time bases from fixed addresses instead
//! of making system calls. The layouts are `osfmk/i386/cpu_capabilities.h`
//! (version 14) and `osfmk/arm/cpu_capabilities.h` (version 3, layout 1,
//! with its separate read-only page), filled as `osfmk/*/commpage/commpage.c`
//! fill them for the machine RAX emulates: one CPU executing every guest
//! thread, the ISA profile of [`super::arch`], and the host's clocks.
//!
//! Time data:
//!
//! - x86-64 `mach_absolute_time` is `((rdtsc - NT_TSC_BASE) << NT_SHIFT) *
//!   NT_SCALE >> 32 + NT_NS_BASE` nanoseconds. The emulated TSC counts
//!   3 GHz host time (`X86_64Vcpu::tsc`), so `NT_SCALE = floor(2^32 / 3)`
//!   with a zero base: the result runs slow by `(2^32/3 - floor(2^32/3)) /
//!   (2^32/3)`, about 2.3e-10 (0.23 ns per second).
//! - arm64 `mach_absolute_time` reads `CNTVCT_EL0` plus
//!   `_COMM_PAGE_TIMEBASE_OFFSET` (`USER_TIMEBASE_SPEC`); the counter runs at
//!   [`ARM64_COUNTER_HZ`] from the emulator's clock epoch, so the offset is
//!   zero.
//! - `gettimeofday`'s commpage data is left zero (`TimeStamp_tick == 0`),
//!   which sends libSystem to the `gettimeofday` system call.
//! - `mach_approximate_time` is not supported (it falls back to
//!   `mach_absolute_time`).

use super::abi::DarwinAbi;
use super::arch::ARM64_COUNTER_HZ;

/// `_COMM_PAGE64_SIGNATURE_STRING`.
const SIGNATURE: &[u8] = b"commpage 64-bit";

/// CPUs the emulated machine has: one executes every guest thread.
pub const NCPUS: u8 = 1;

/// `CPUFAMILY_INTEL_HASWELL`.
pub const CPUFAMILY_INTEL_HASWELL: u32 = 0x10b2_82dc;
/// `CPUFAMILY_ARM_FIRESTORM_ICESTORM` (Apple M1).
pub const CPUFAMILY_ARM_FIRESTORM_ICESTORM: u32 = 0x1b58_8bb3;

/// x86 `_cpu_capabilities` bits (`osfmk/i386/cpu_capabilities.h`).
pub mod x86_caps {
    pub const MMX: u64 = 0x0000_0001;
    pub const SSE: u64 = 0x0000_0002;
    pub const SSE2: u64 = 0x0000_0004;
    pub const SSE3: u64 = 0x0000_0008;
    pub const CACHE64: u64 = 0x0000_0020;
    pub const FAST_TLS: u64 = 0x0000_0080;
    pub const SUPPLEMENTAL_SSE3: u64 = 0x0000_0100;
    pub const BIT64: u64 = 0x0000_0200;
    pub const SSE4_1: u64 = 0x0000_0400;
    pub const SSE4_2: u64 = 0x0000_0800;
    pub const AES: u64 = 0x0000_1000;
    pub const UP: u64 = 0x0000_8000;
    pub const AVX1_0: u64 = 0x0100_0000;
    pub const RDRAND: u64 = 0x0200_0000;
    pub const F16C: u64 = 0x0400_0000;
    pub const ENFSTRG: u64 = 0x0800_0000;
    pub const FMA: u64 = 0x1000_0000;
    pub const AVX2_0: u64 = 0x2000_0000;
    pub const BMI1: u64 = 0x4000_0000;
    pub const BMI2: u64 = 0x8000_0000;
    pub const ADX: u64 = 0x0000_0004_0000_0000;
    pub const RDSEED: u64 = 0x0000_0008_0000_0000;
}

/// arm `_cpu_capabilities` bits (`osfmk/arm/cpu_capabilities.h`).
pub mod arm_caps {
    pub const FEAT_FP16: u64 = 0x0000_0008;
    pub const CACHE128: u64 = 0x0000_0040;
    pub const FAST_TLS: u64 = 0x0000_0080;
    pub const ADV_SIMD: u64 = 0x0000_0100;
    pub const ADV_SIMD_HPFP_CVT: u64 = 0x0000_0200;
    pub const VFP: u64 = 0x0000_0400;
    pub const UC_NORMAL_MEMORY: u64 = 0x0000_0800;
    pub const EVENT: u64 = 0x0000_1000;
    pub const FMA: u64 = 0x0000_2000;
    pub const FEAT_FHM: u64 = 0x0000_4000;
    pub const UP: u64 = 0x0000_8000;
    pub const ARMV8_CRYPTO: u64 = 0x0100_0000;
    pub const FEAT_LSE: u64 = 0x0200_0000;
    pub const ARMV8_CRC32: u64 = 0x0400_0000;
    pub const FEAT_SHA512: u64 = 0x8000_0000;
    pub const FEAT_SHA3: u64 = 0x0000_0001_0000_0000;
    pub const FEAT_FCMA: u64 = 0x0000_0002_0000_0000;
    pub const FEAT_FLAGM: u64 = 0x0000_0100_0000_0000;
    pub const FEAT_FLAGM2: u64 = 0x0000_0200_0000_0000;
    pub const FEAT_DOTPROD: u64 = 0x0000_0400_0000_0000;
    pub const FEAT_RDM: u64 = 0x0000_0800_0000_0000;
    pub const FEAT_SB: u64 = 0x0000_2000_0000_0000;
    pub const FEAT_FRINTTS: u64 = 0x0000_4000_0000_0000;
    pub const FEAT_LRCPC: u64 = 0x0001_0000_0000_0000;
    pub const FEAT_LRCPC2: u64 = 0x0002_0000_0000_0000;
    pub const FEAT_JSCVT: u64 = 0x0004_0000_0000_0000;
    pub const FEAT_PAUTH: u64 = 0x0008_0000_0000_0000;
    pub const FEAT_DPB: u64 = 0x0010_0000_0000_0000;
    pub const FEAT_DPB2: u64 = 0x0020_0000_0000_0000;
    pub const FEAT_LSE2: u64 = 0x0040_0000_0000_0000;
    pub const FEAT_CSV2: u64 = 0x0080_0000_0000_0000;
    pub const FEAT_CSV3: u64 = 0x0100_0000_0000_0000;
    pub const FEAT_DIT: u64 = 0x0200_0000_0000_0000;
}

/// `kNumCPUsShift`.
const NUM_CPUS_SHIFT: u64 = 16;

/// The capability word for `abi`.
pub fn cpu_capabilities(abi: DarwinAbi) -> u64 {
    let ncpus = u64::from(NCPUS) << NUM_CPUS_SHIFT;
    match abi {
        DarwinAbi::X86_64 => {
            use x86_caps::*;
            MMX | SSE
                | SSE2
                | SSE3
                | SUPPLEMENTAL_SSE3
                | SSE4_1
                | SSE4_2
                | AES
                | AVX1_0
                | RDRAND
                | F16C
                | ENFSTRG
                | FMA
                | AVX2_0
                | BMI1
                | BMI2
                | ADX
                | RDSEED
                | BIT64
                | CACHE64
                | FAST_TLS
                | UP
                | ncpus
        }
        DarwinAbi::Arm64 => {
            use arm_caps::*;
            FEAT_FP16
                | CACHE128
                | FAST_TLS
                | ADV_SIMD
                | ADV_SIMD_HPFP_CVT
                | VFP
                | UC_NORMAL_MEMORY
                | EVENT
                | FMA
                | FEAT_FHM
                | UP
                | ARMV8_CRYPTO
                | FEAT_LSE
                | ARMV8_CRC32
                | FEAT_SHA512
                | FEAT_SHA3
                | FEAT_FCMA
                | FEAT_FLAGM
                | FEAT_FLAGM2
                | FEAT_DOTPROD
                | FEAT_RDM
                | FEAT_SB
                | FEAT_FRINTTS
                | FEAT_LRCPC
                | FEAT_LRCPC2
                | FEAT_JSCVT
                | FEAT_PAUTH
                | FEAT_DPB
                | FEAT_DPB2
                | FEAT_LSE2
                | FEAT_CSV2
                | FEAT_CSV3
                | FEAT_DIT
                | ncpus
        }
    }
}

/// A page of the commpage area to map: its address, contents, and whether
/// it holds code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommPage {
    /// Guest address (page-aligned).
    pub addr: u64,
    /// Contents, one kernel page.
    pub bytes: Vec<u8>,
    /// Map executable (the text page).
    pub exec: bool,
}

/// Machine facts the commpage publishes.
#[derive(Clone, Copy, Debug)]
pub struct MachineInfo {
    /// Physical memory in bytes (`hw.memsize`).
    pub memory_size: u64,
    /// Boot time in microseconds since the Unix epoch.
    pub boottime_usec: u64,
}

fn put(page: &mut [u8], off: usize, bytes: &[u8]) {
    page[off..off + bytes.len()].copy_from_slice(bytes);
}

/// `BRK #666`, filling the unused text of the arm64 commpage text page.
const BRK_666: u32 = 0xd420_0000 | (666 << 5);

/// The commpage pages for `abi`.
pub fn build(abi: DarwinAbi, info: &MachineInfo) -> Vec<CommPage> {
    let page = abi.page_size() as usize;
    let caps = cpu_capabilities(abi);
    match abi {
        DarwinAbi::X86_64 => {
            let mut p = vec![0u8; page];
            put(&mut p, 0x000, SIGNATURE);
            put(&mut p, 0x010, &caps.to_le_bytes());
            put(&mut p, 0x01E, &14u16.to_le_bytes());
            put(&mut p, 0x020, &(caps as u32).to_le_bytes());
            p[0x022] = NCPUS;
            put(&mut p, 0x026, &64u16.to_le_bytes());
            p[0x034] = NCPUS;
            p[0x035] = NCPUS;
            p[0x036] = NCPUS;
            p[0x037] = 1;
            put(&mut p, 0x038, &info.memory_size.to_le_bytes());
            put(&mut p, 0x040, &CPUFAMILY_INTEL_HASWELL.to_le_bytes());
            p[0x04D] = 12;
            p[0x04E] = 12;
            // Nanotime: TSC base, scale, shift, ns base, generation.
            put(&mut p, 0x050, &0u64.to_le_bytes());
            put(&mut p, 0x058, &((1u64 << 32) / 3).to_le_bytes()[..4]);
            put(&mut p, 0x05C, &0u32.to_le_bytes());
            put(&mut p, 0x060, &0u64.to_le_bytes());
            put(&mut p, 0x068, &1u32.to_le_bytes());
            put(&mut p, 0x0C8, &info.boottime_usec.to_le_bytes());
            // The text page (_COMM_PAGE_TEXT_START) holds the preemption-free
            // zone's FIFO routines; RAX does not provide them, so every byte
            // is UD2's first byte pair repeated: any call traps.
            let mut text = vec![0u8; page];
            for pair in text.chunks_mut(2) {
                pair.copy_from_slice(&[0x0F, 0x0B]);
            }
            vec![
                CommPage {
                    addr: abi.commpage_base(),
                    bytes: p,
                    exec: false,
                },
                CommPage {
                    addr: abi.commpage_base() + 0x1000,
                    bytes: text,
                    exec: true,
                },
            ]
        }
        DarwinAbi::Arm64 => {
            let mut rw = vec![0u8; page];
            put(&mut rw, 0x000, SIGNATURE);
            put(&mut rw, 0x010, &caps.to_le_bytes());
            put(&mut rw, 0x01E, &3u16.to_le_bytes());
            put(&mut rw, 0x020, &(caps as u32).to_le_bytes());
            rw[0x022] = NCPUS;
            rw[0x024] = 14; // legacy user page shift (32-bit)
            rw[0x025] = 14; // legacy user page shift (64-bit)
            put(&mut rw, 0x026, &128u16.to_le_bytes());
            rw[0x02F] = 1; // clusters
            rw[0x034] = NCPUS;
            rw[0x035] = NCPUS;
            rw[0x036] = NCPUS;
            rw[0x037] = 14; // legacy kernel page shift
            put(&mut rw, 0x038, &info.memory_size.to_le_bytes());
            put(
                &mut rw,
                0x080,
                &CPUFAMILY_ARM_FIRESTORM_ICESTORM.to_le_bytes(),
            );
            put(&mut rw, 0x088, &0u64.to_le_bytes()); // timebase offset
            rw[0x090] = 1; // USER_TIMEBASE_SPEC
            rw[0x091] = 0; // no always-on hardware clock
            put(&mut rw, 0x0A0, &info.boottime_usec.to_le_bytes());
            let mut ro = vec![0u8; page];
            ro[0x024] = 14;
            ro[0x025] = 14;
            ro[0x037] = 14;
            // The text page: BRK #666 where the kernel places no routines.
            let mut text = vec![0u8; page];
            for w in text.chunks_mut(4) {
                w.copy_from_slice(&BRK_666.to_le_bytes());
            }
            vec![
                CommPage {
                    addr: abi.commpage_base(),
                    bytes: rw,
                    exec: false,
                },
                CommPage {
                    addr: ARM64_COMMPAGE_RO,
                    bytes: ro,
                    exec: false,
                },
                CommPage {
                    addr: ARM64_COMMPAGE_TEXT,
                    bytes: text,
                    exec: true,
                },
            ]
        }
    }
}

/// `_COMM_PAGE64_RO_ADDRESS`.
pub const ARM64_COMMPAGE_RO: u64 = 0x0000_000F_FFFF_4000;
/// Where RAX places the arm64 commpage text page (the kernel chooses a
/// random page in the commpage nesting region; libSystem learns it from the
/// `pfz=` apple string).
pub const ARM64_COMMPAGE_TEXT: u64 = 0x0000_000F_FFFF_8000;

/// Where the commpage text page is, for the `pfz=` apple string.
pub fn text_address(abi: DarwinAbi) -> u64 {
    match abi {
        DarwinAbi::X86_64 => abi.commpage_base() + 0x1000,
        DarwinAbi::Arm64 => ARM64_COMMPAGE_TEXT,
    }
}

/// `mach_timebase_info` for `abi`: nanoseconds per tick as a fraction.
pub fn timebase(abi: DarwinAbi) -> (u32, u32) {
    match abi {
        DarwinAbi::X86_64 => (1, 1),
        DarwinAbi::Arm64 => {
            // 1e9 / 24e6 = 125 / 3.
            let g = gcd(1_000_000_000, ARM64_COUNTER_HZ);
            ((1_000_000_000 / g) as u32, (ARM64_COUNTER_HZ / g) as u32)
        }
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> MachineInfo {
        MachineInfo {
            memory_size: 16 << 30,
            boottime_usec: 1_700_000_000_000_000,
        }
    }

    #[test]
    fn x86_64_layout_matches_cpu_capabilities_h() {
        let pages = build(DarwinAbi::X86_64, &info());
        assert_eq!(pages.len(), 2);
        let p = &pages[0].bytes;
        assert_eq!(pages[0].addr, 0x7fff_ffe0_0000);
        assert_eq!(&p[..15], b"commpage 64-bit");
        assert_eq!(u16::from_le_bytes([p[0x1e], p[0x1f]]), 14);
        let caps = u64::from_le_bytes(p[0x10..0x18].try_into().unwrap());
        assert_eq!((caps >> 16) & 0xff, 1, "kNumCPUs");
        assert_ne!(caps & x86_caps::AVX2_0, 0);
        assert_eq!(p[0x22], 1);
        assert_eq!(u16::from_le_bytes([p[0x26], p[0x27]]), 64);
        assert_eq!(
            u64::from_le_bytes(p[0x38..0x40].try_into().unwrap()),
            16 << 30
        );
        // A nonzero nanotime generation, or mach_absolute_time spins.
        assert_ne!(u32::from_le_bytes(p[0x68..0x6c].try_into().unwrap()), 0);
        // floor(2^32 / 3)
        assert_eq!(
            u32::from_le_bytes(p[0x58..0x5c].try_into().unwrap()),
            1_431_655_765
        );
        assert_eq!((p[0x4d], p[0x4e]), (12, 12));
        assert!(pages[1].exec);
        assert_eq!(pages[1].addr, text_address(DarwinAbi::X86_64));
    }

    #[test]
    fn arm64_layout_matches_cpu_capabilities_h() {
        let pages = build(DarwinAbi::Arm64, &info());
        assert_eq!(pages.len(), 3);
        let (rw, ro) = (&pages[0], &pages[1]);
        assert_eq!(rw.addr, 0xf_ffff_c000);
        assert_eq!(ro.addr, 0xf_ffff_4000);
        assert_eq!(rw.bytes.len(), 16 << 10);
        assert_eq!(u16::from_le_bytes([rw.bytes[0x1e], rw.bytes[0x1f]]), 3);
        assert_eq!(rw.bytes[0x90], 1, "USER_TIMEBASE_SPEC");
        assert_eq!(
            (ro.bytes[0x24], ro.bytes[0x25], ro.bytes[0x37]),
            (14, 14, 14)
        );
        let caps = u64::from_le_bytes(rw.bytes[0x10..0x18].try_into().unwrap());
        assert_ne!(caps & arm_caps::FEAT_PAUTH, 0);
        assert_eq!(
            caps as u32,
            u32::from_le_bytes(rw.bytes[0x20..0x24].try_into().unwrap())
        );
        assert!(pages[2].exec);
        assert_eq!(
            u32::from_le_bytes(pages[2].bytes[..4].try_into().unwrap()),
            0xd420_5340
        );
    }

    #[test]
    fn timebases() {
        assert_eq!(timebase(DarwinAbi::X86_64), (1, 1));
        assert_eq!(timebase(DarwinAbi::Arm64), (125, 3));
    }
}
