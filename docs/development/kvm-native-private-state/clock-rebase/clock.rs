//! Shared native clock sample and exact phase rebasing for unscaled TSCs.
use super::bank::Bank;
use kvm_bindings::{Msrs, kvm_clock_data, kvm_device_attr, kvm_msr_entry};
use kvm_ioctls::{VcpuFd, VmFd};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::os::fd::AsRawFd;

const MAX_CPUS: usize = u8::MAX as usize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CpuClock {
    id: u32,
    khz: u32,
    offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Image {
    version: u16,
    clock: Bank<kvm_clock_data>,
    clock_before: u64,
    anchor: u64,
    #[serde(deserialize_with = "bounded_cpus")]
    cpus: Vec<CpuClock>,
}

#[derive(Debug)]
pub(super) struct Applied {
    pub(super) resume_tsc: u64,
    pub(super) offsets: Vec<(u32, u64)>,
    pub(super) clock_publication_interval: (u64, u64),
    pub(super) elapsed_while_rebasing_ns: u64,
}

fn invalid(message: impl fmt::Display) -> String {
    format!("native KVM clock: {message}")
}

fn host_tsc() -> u64 {
    // SAFETY: this module is x86-64-only, where SSE2 and RDTSC are architectural
    // baseline instructions. Its native profile requires permitted user TSC
    // reads. Fences order this sample around synchronous KVM transfers; no
    // guest or optional vector instruction runs and no pointer is accessed.
    unsafe {
        std::arch::x86_64::_mm_lfence();
        let value = std::arch::x86_64::_rdtsc();
        std::arch::x86_64::_mm_lfence();
        value
    }
}

fn raw_ns() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: this exclusive initialized output lives through the synchronous
    // query. CLOCK_MONOTONIC_RAW supplies x86-64 KVM's elapsed raw-clock rate;
    // its absolute boot offset cancels in the interval. libc retains no pointer
    // and no clock or process policy is changed.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut value) } != 0 {
        return Err(invalid(std::io::Error::last_os_error()));
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid("invalid host raw clock sample"));
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("host raw clock exceeds 64-bit nanoseconds"))
}

fn offset(cpu: &VcpuFd, desired: Option<u64>) -> Result<u64, String> {
    let mut value = desired.unwrap_or(0);
    let attribute = kvm_device_attr {
        group: kvm_bindings::KVM_VCPU_TSC_CTRL,
        attr: u64::from(kvm_bindings::KVM_VCPU_TSC_OFFSET),
        addr: (&mut value as *mut u64) as u64,
        flags: 0,
    };
    let operation = if desired.is_some() {
        libc::_IOW::<kvm_device_attr>(kvm_bindings::KVMIO, 0xe1)
    } else {
        libc::_IOW::<kvm_device_attr>(kvm_bindings::KVMIO, 0xe2)
    };
    // SAFETY: the retained x86 UAPI defines this device-attribute group and
    // synchronous getter/setter. The attribute and initialized aligned u64
    // remain live and exclusive for the complete copy. The kernel retains no
    // pointers. The caller owns the stopped FD and excludes native mutations.
    let status = unsafe { libc::ioctl(cpu.as_raw_fd(), operation, &attribute) };
    if status < 0 {
        return Err(invalid(std::io::Error::last_os_error()));
    }
    Ok(value)
}

fn check_unscaled(cpu: &VcpuFd, native_khz: u32) -> Result<(), String> {
    if native_khz == 0 || cpu.get_tsc_khz().map_err(invalid)? != native_khz {
        return Err(invalid(
            "TSC rate differs from the retained unscaled native profile",
        ));
    }
    let current_offset = offset(cpu, None)?;
    let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
        index: 0x10,
        ..Default::default()
    }])
    .map_err(invalid)?;
    let before = host_tsc();
    if cpu.get_msrs(&mut msrs).map_err(invalid)? != 1 {
        return Err(invalid("native TSC read was incomplete"));
    }
    let after = host_tsc();
    let actual = msrs.as_slice()[0].data;
    if after < before || actual.wrapping_sub(before.wrapping_add(current_offset)) > after - before {
        return Err(invalid("native TSC does not fit its unscaled host sample"));
    }
    Ok(())
}

impl Image {
    /// Native entry and all backend mutation must be excluded. `native_khz`
    /// comes from the managed CPU's original unscaled profile, before any
    /// caller-controlled frequency changes. Scaled/unstable profiles require
    /// a separate producer; they must not be silently treated as unscaled.
    pub(super) fn capture(
        vm: &VmFd,
        cpus: &[(u32, &VcpuFd)],
        native_khz: u32,
    ) -> Result<Self, String> {
        if cpus.is_empty() || cpus.len() > MAX_CPUS {
            return Err(invalid("CPU count is outside the managed profile"));
        }
        let mut clocks = Vec::with_capacity(cpus.len());
        for &(id, cpu) in cpus {
            check_unscaled(cpu, native_khz)?;
            clocks.push(CpuClock {
                id,
                khz: native_khz,
                offset: offset(cpu, None)?,
            });
        }
        let clock_before = host_tsc();
        let clock = vm.get_clock().map_err(invalid)?;
        let anchor = host_tsc();
        let image = Self {
            version: 1,
            clock: Bank::capture(&clock)?,
            clock_before,
            anchor,
            cpus: clocks,
        };
        image.validate_envelope()?;
        Ok(image)
    }

    pub(super) fn validate_envelope(&self) -> Result<(), String> {
        let clock = self.clock.decode()?;
        let known_flags = kvm_bindings::KVM_CLOCK_TSC_STABLE
            | kvm_bindings::KVM_CLOCK_REALTIME
            | kvm_bindings::KVM_CLOCK_HOST_TSC;
        if self.version != 1
            || self.anchor < self.clock_before
            || clock.flags & !known_flags != 0
            || self.cpus.is_empty()
            || self.cpus.len() > MAX_CPUS
            || self.cpus.iter().any(|cpu| cpu.khz == 0)
            || self.cpus.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || self.cpus.iter().any(|cpu| cpu.khz != self.cpus[0].khz)
        {
            return Err(invalid(
                "clock envelope, CPU identities or rates are invalid",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_target(
        &self,
        cpus: &[(u32, &VcpuFd)],
        native_khz: u32,
    ) -> Result<(), String> {
        self.validate_envelope()?;
        if self.cpus.len() != cpus.len()
            || self
                .cpus
                .iter()
                .zip(cpus)
                .any(|(saved, (id, _))| saved.id != *id || saved.khz != native_khz)
        {
            return Err(invalid("target CPU identities or native rate differ"));
        }
        for &(_, cpu) in cpus {
            check_unscaled(cpu, native_khz)?;
        }
        Ok(())
    }

    pub(super) fn captured_clock_ns(&self) -> Result<u64, String> {
        self.validate_envelope()?;
        Ok(self.clock.decode()?.clock)
    }

    /// Call at the common resume gate while every CPU remains excluded, on a
    /// disposable graph or inside a complete rollback transaction. A failed
    /// native setter can leave a changed prefix. This helper neither provides
    /// rollback nor establishes the full producer's first-entry gate.
    ///
    /// Offset_i' = Offset_i + captured_anchor - resume_anchor (modulo 2^64).
    /// The same delta retains exact inter-CPU phases without SET_TSC matching
    /// heuristics. The VM clock excludes paused wall time. Its original read
    /// interval remains represented; cross-domain sampling is not atomic.
    pub(super) fn restore_at_resume(
        &self,
        vm: &VmFd,
        cpus: &[(u32, &VcpuFd)],
        native_khz: u32,
    ) -> Result<Applied, String> {
        self.validate_target(cpus, native_khz)?;
        let resume_clock_ns = raw_ns()?;
        let resume_tsc = host_tsc();
        let delta = self.anchor.wrapping_sub(resume_tsc);
        let mut offsets = Vec::with_capacity(cpus.len());
        for (saved, &(_, cpu)) in self.cpus.iter().zip(cpus) {
            let desired = saved.offset.wrapping_add(delta);
            offset(cpu, Some(desired))?;
            if offset(cpu, None)? != desired {
                return Err(invalid("TSC offset readback differs after publication"));
            }
            offsets.push((saved.id, desired));
        }
        let elapsed_while_rebasing_ns = raw_ns()?
            .checked_sub(resume_clock_ns)
            .ok_or_else(|| invalid("host raw clock moved backwards"))?;
        let clock_publication_before = host_tsc();
        vm.set_clock(&kvm_clock_data {
            // Preserve elapsed publication work rather than resetting this
            // domain behind TSC by an amount growing with the CPU count.
            clock: self
                .captured_clock_ns()?
                .wrapping_add(elapsed_while_rebasing_ns),
            ..Default::default()
        })
        .map_err(invalid)?;
        let clock_publication_after = host_tsc();
        Ok(Applied {
            resume_tsc,
            offsets,
            clock_publication_interval: (clock_publication_before, clock_publication_after),
            elapsed_while_rebasing_ns,
        })
    }
}

fn bounded_cpus<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<CpuClock>, D::Error> {
    struct Cpus;
    impl<'de> Visitor<'de> for Cpus {
        type Value = Vec<CpuClock>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 255 native CPU clock records")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let hint = sequence.size_hint().unwrap_or(0);
            if hint > MAX_CPUS {
                return Err(A::Error::custom("native CPU clock count exceeds 255"));
            }
            let mut cpus = Vec::with_capacity(hint);
            while let Some(cpu) = sequence.next_element()? {
                if cpus.len() == MAX_CPUS {
                    return Err(A::Error::custom("native CPU clock count exceeds 255"));
                }
                cpus.push(cpu);
            }
            Ok(cpus)
        }
    }
    deserializer.deserialize_seq(Cpus)
}
