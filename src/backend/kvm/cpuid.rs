//! Per-VM native CPU geometry, independent of the host's package layout.
use crate::error::{Error, Result};
use kvm_bindings::{CpuId, KVM_CPUID_FLAG_SIGNIFCANT_INDEX, kvm_cpuid_entry2};

#[derive(Default)]
pub(super) struct Configuration {
    pub(super) count: Option<u8>,
    pub(super) created: bool,
}

fn has_kvm_signature(entries: &[kvm_cpuid_entry2]) -> bool {
    entries.iter().any(|entry| {
        entry.function == 0x4000_0000
            && (entry.eax == 0 || entry.eax >= 0x4000_0001)
            && [entry.ebx, entry.ecx, entry.edx] == [0x4b4d_564b, 0x564b_4d56, 0x4d]
    })
}

/// Preserve the native SDK's existing unconfigured geometry and CPU-ID API.
/// Explicit VMM topology uses the complete virtual projection below instead.
pub(super) fn sdk_profile(base: &CpuId, id: u32) -> Result<CpuId> {
    let mut entries = base.as_slice().to_vec();
    let kvm = has_kvm_signature(&entries);
    for entry in &mut entries {
        (entry.eax, entry.ebx, entry.ecx, entry.edx) = crate::isa::x86_64::identity::project_cpuid(
            entry.function,
            (entry.eax, entry.ebx, entry.ecx, entry.edx),
            id,
        );
        if kvm && entry.function == 1 {
            entry.ecx |= 1 << 31;
        }
    }
    CpuId::from_entries(&entries)
        .map_err(|error| Error::InvalidConfig(format!("native SDK CPUID profile: {error:?}")))
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Topology {
    count: u8,
    cores: u32,
    package_shift: u32,
}

impl Topology {
    pub(super) fn new(count: u8) -> Result<Self> {
        if count == 0 {
            return Err(Error::InvalidConfig("native CPU topology is empty".into()));
        }
        // CPUID.4 has six bits for cores/package minus one. Keep that legacy
        // interface truthful for all255 configured IDs by using additional
        // packages above64 cores; the final package may be partly populated.
        let cores = u32::from(count).min(64);
        Ok(Self {
            count,
            cores,
            package_shift: u32::BITS - (cores - 1).leading_zeros(),
        })
    }

    pub(super) fn project(&self, base: &CpuId, id: u32) -> Result<CpuId> {
        if id >= u32::from(self.count) {
            return Err(Error::InvalidConfig(format!(
                "native CPU ID{id} is outside configured count{}",
                self.count
            )));
        }
        let entries = base.as_slice();
        let basic = entries
            .iter()
            .find(|entry| entry.function == 0 && entry.index == 0)
            .ok_or_else(|| Error::InvalidConfig("native CPUID leaf0 is missing".into()))?;
        let vendor = [basic.ebx, basic.edx, basic.ecx]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let amd = vendor == b"AuthenticAMD" || vendor == b"HygonGenuine";
        let kvm = has_kvm_signature(entries);
        let v2 = entries
            .iter()
            .any(|entry| entry.function == 0x1f && entry.index == 0 && entry.ebx & 0xffff != 0);
        let amd_extended = amd
            && entries
                .iter()
                .any(|entry| entry.function == 0x8000_0026 && entry.ebx & 0xffff != 0);
        let amd_core_properties = entries
            .iter()
            .find(|entry| entry.function == 0x8000_0026 && (entry.ecx >> 8) & 255 == 1)
            .map_or(0, |entry| entry.ebx & 0xffff_0000);
        let amd_topology = amd
            && entries
                .iter()
                .any(|entry| entry.function == 0x8000_0001 && entry.ecx & (1 << 22) != 0);
        let mut projected = Vec::with_capacity(entries.len() + 10);
        for original in entries {
            if original.function == 0xb
                || v2 && original.function == 0x1f
                || amd_extended && original.function == 0x8000_0026
            {
                continue;
            }
            let mut entry = *original;
            match entry.function {
                0 => entry.eax = entry.eax.max(0xb),
                1 => {
                    entry.ebx = (entry.ebx & 0xffff) | (self.cores << 16) | (id << 24);
                    entry.edx = (entry.edx & !(1 << 28)) | (u32::from(self.cores > 1) << 28);
                    if kvm {
                        entry.ecx |= 1 << 31;
                    }
                }
                4 if entry.eax & 31 != 0 => {
                    entry.eax = (entry.eax & 0x3fff)
                        | ((self.cache_sharing(entry.eax) - 1) << 14)
                        | ((self.cores - 1) << 26);
                }
                0x8000_0001 if amd => {
                    entry.ecx = (entry.ecx & !(1 << 1)) | (u32::from(self.cores > 1) << 1);
                }
                0x8000_0008 if amd => {
                    entry.ecx =
                        (entry.ecx & !0xf0ff) | (self.package_shift << 12) | (self.cores - 1);
                }
                0x8000_001d if amd_topology && entry.eax & 31 != 0 => {
                    // Unlike Intel.4, AMD.8000001D reserves EAX[31:26].
                    entry.eax =
                        (entry.eax & !(0xfff << 14)) | ((self.cache_sharing(entry.eax) - 1) << 14);
                }
                0x8000_001e if amd_topology => {
                    entry.eax = id;
                    entry.ebx = id & ((1 << self.package_shift) - 1);
                    // One die per package; node IDs are unique system-wide.
                    entry.ecx = id >> self.package_shift;
                    entry.edx = 0;
                }
                _ => {}
            }
            projected.push(entry);
        }
        self.append_topology(&mut projected, 0xb, id, 2, 0);
        if v2 {
            self.append_topology(&mut projected, 0x1f, id, 2, 0);
        }
        if amd_extended {
            // AMD's Core domain contains threads; Socket contains cores.
            // Intermediate Complex/Die domains need not be enumerated.
            self.append_topology(&mut projected, 0x8000_0026, id, 4, amd_core_properties);
        }
        CpuId::from_entries(&projected)
            .map_err(|error| Error::InvalidConfig(format!("native CPUID profile: {error:?}")))
    }

    fn cache_sharing(&self, eax: u32) -> u32 {
        if (eax >> 5) & 7 <= 2 { 1 } else { self.cores }
    }

    fn append_topology(
        &self,
        entries: &mut Vec<kvm_cpuid_entry2>,
        function: u32,
        id: u32,
        package_domain: u32,
        core_properties: u32,
    ) {
        for index in 0..=2 {
            let (shift, count, domain) = match index {
                0 => (0, 1 | core_properties, 1),
                1 => (self.package_shift, self.cores, package_domain),
                _ => (0, 0, 0),
            };
            entries.push(kvm_cpuid_entry2 {
                function,
                index,
                flags: KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
                eax: shift,
                ebx: count,
                ecx: (domain << 8) | index,
                edx: id,
                ..Default::default()
            });
        }
    }
}

#[cfg(test)]
#[path = "cpuid_tests.rs"]
mod tests;
