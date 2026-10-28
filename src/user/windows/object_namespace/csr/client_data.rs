//! Opaque installed USER connection data and its two owned readonly mappings.
//! Addresses are protocol values resolved only in guest-owned address spaces.
use crate::user::windows::memory::{VirtualMemory, VmError, prot};
use crate::user::windows::object_namespace::{DataSection, invalid};
use std::io;
use std::sync::Arc;

pub(crate) const INFORMATION_BYTES: usize = 584;
// Observed 64-bit SHAREDINFO slots, including the WoW64 CSR conversion. These
// are fixed fields, not a scan for integer values that resemble addresses.
const POINTER_SLOTS: [usize; 18] = [
    8, 16, 32, 40, 56, 88, 104, 168, 184, 200, 216, 232, 248, 280, 296, 312, 552, 568,
];

#[derive(Debug)]
pub(crate) struct ClientView {
    pub(crate) base: u64,
    pub(crate) section: Arc<DataSection>,
}

#[derive(Debug)]
pub(crate) struct CsrClientData {
    pub(crate) information: [u8; INFORMATION_BYTES],
    pub(crate) views: [ClientView; 2],
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed CSR field"),
    )
}

impl CsrClientData {
    /// O(R) metadata validation; retained bytes are bounded by the selected
    /// 2 MiB handle-table allocation and the 32 KiB shared-data allocation.
    /// Pointer-bearing bytes retain their exact addresses; whole selected views
    /// are mapped there, with no heuristic relocation or host dereference.
    pub(crate) fn selected(
        information: [u8; INFORMATION_BYTES],
        views: [ClientView; 2],
    ) -> io::Result<Arc<Self>> {
        for (index, view) in views.iter().enumerate() {
            let expected_size = if index == 0 { 1 << 21 } else { 32768 };
            let section = &view.section;
            // USER commits more handle-table pages as the session grows.
            // The allocation identity/extent and readonly snapshot stay fixed;
            // its nonempty committed prefix is not an ABI-sized field.
            let valid_runs = if index == 0 {
                matches!(section.regions.len(), 1 | 2)
                    && section.regions.first().is_some_and(|prefix| {
                        prefix.offset == 0
                            && prefix.size != 0
                            && prefix.size % 4096 == 0
                            && prefix.size <= expected_size
                            && prefix.bytes.is_some()
                    })
                    && section
                        .regions
                        .get(1)
                        .is_none_or(|tail| tail.bytes.is_none())
            } else {
                section.regions.len() == 1
                    && section.regions[0].offset == 0
                    && section.regions[0].size == expected_size
                    && section.regions[0].bytes.is_some()
            };
            if !section.path.is_empty()
                || view.base == 0
                || view.base % 65536 != 0
                || view
                    .base
                    .checked_add(section.size)
                    .is_none_or(|end| end > 1 << 47)
                || section.size != expected_size
                || !valid_runs
            {
                return Err(invalid(
                    "CSR client data differs from measured readonly view profile",
                ));
            }
        }
        let [first, second] = &views;
        if first.base < second.base + second.section.size
            && second.base < first.base + first.section.size
        {
            return Err(invalid("CSR client data views overlap"));
        }
        if word(&information, 16) != first.base
            || word(&information, 40) != second.base
            || word(&information, 8) != second.base + 0x1040
            || word(&information, 24) != 32
        {
            return Err(invalid("CSR client SHAREDINFO mapping identities differ"));
        }
        for offset in POINTER_SLOTS {
            let address = word(&information, offset);
            if address != 0
                && !views.iter().any(|view| {
                    view.section.regions.iter().any(|region| {
                        region.bytes.is_some()
                            && address >= view.base + region.offset
                            && address < view.base + region.offset + region.size
                    })
                })
            {
                return Err(invalid(
                    "CSR client data pointer leaves selected committed views",
                ));
            }
        }
        Ok(Arc::new(Self { information, views }))
    }

    /// Map both immutable views transactionally. A collision is reported, never
    /// overwritten or repaired by selecting unrelated guest address ranges.
    pub(crate) fn map(&self, vm: &mut VirtualMemory) -> Result<Vec<u64>, VmError> {
        let mut allocated = Vec::with_capacity(2);
        for view in &self.views {
            if vm.owns_readonly_data_view(view.base, &view.section) {
                continue;
            }
            if let Err(error) = vm.map_data_section(
                view.section.clone(),
                view.base,
                0,
                view.section.size,
                prot::READONLY,
            ) {
                for &base in allocated.iter().rev() {
                    vm.release(base)?;
                }
                return Err(error);
            }
            allocated.push(view.base);
        }
        Ok(allocated)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn native_fixture(index: usize) -> Arc<CsrClientData> {
    tests::fixture(index)
}
