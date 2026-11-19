//! Immutable system cursor/icon cache for the selected native GUI session.
use std::num::NonZeroU32;

pub(crate) const MODULE: [u16; 6] = [85, 83, 69, 82, 51, 50]; // USER32
pub(crate) const CURSOR: u32 = 1;
pub(crate) const ICON: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Resource {
    pub(crate) ordinal: u16,
    pub(crate) selector: u32,
    /// The default format and the explicit depths which return this identity.
    pub(crate) depths: u32,
    /// Animated stock entries can match independently of the requested format.
    pub(crate) any_format: bool,
}

impl Resource {
    fn matches(self, ordinal: u16, selector: u32, format: [u32; 3]) -> bool {
        self.ordinal == ordinal
            && self.selector == selector
            && (self.any_format
                || matches!(format, [0, 0, 0])
                || matches!(format, [0, 0, depth @ 1..=32] if self.depths & (1 << (depth - 1)) != 0))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Catalog {
    // Native enumeration priority, lowest first. An entry's position supplies
    // its guest handle; native handles are discarded during capture.
    resources: Vec<Resource>,
}

impl Catalog {
    pub(crate) fn new(resources: Vec<Resource>) -> Self {
        Self { resources }
    }

    pub(crate) fn hint(&self, value: u32) -> Option<NonZeroU32> {
        let index = value.checked_sub(FIRST_HANDLE)?;
        if index % 2 != 0 || index as usize / 2 >= self.resources.len() {
            return None;
        }
        NonZeroU32::new(value)
    }

    pub(crate) fn find(
        &self,
        ordinal: Option<u16>,
        selector: u32,
        format: [u32; 3],
        hint: Option<NonZeroU32>,
    ) -> u32 {
        if selector == 0 {
            return 0;
        }
        let resource = ordinal.and_then(|ordinal| {
            self.resources
                .iter()
                .rposition(|entry| entry.matches(ordinal, selector, format))
                .map(|index| FIRST_HANDLE + 2 * index as u32)
        });
        resource.unwrap_or(0).max(hint.map_or(0, NonZeroU32::get))
    }
}

// Opaque handles belong to the guest USER namespace. The cache is immutable
// for the process lifetime, so each entry keeps its handle on repeated lookup.
const FIRST_HANDLE: u32 = 0x1601_0003;
