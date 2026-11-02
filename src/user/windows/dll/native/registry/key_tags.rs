//! Native key-body inheritance and WoW64 relative-open tag conversion.
use crate::user::windows::registry::RegistryView;

pub(super) struct RelativeOpen {
    wow: bool,
    parent: u32,
    effective: u32,
}

impl RelativeOpen {
    pub(super) fn flags(&self) -> u32 {
        self.effective
    }

    pub(super) fn parent_flags(&self) -> u32 {
        self.parent & 0x300
    }

    pub(super) fn new(wow: bool, parent: u32, requested: u32) -> Option<Self> {
        let effective = if requested == 0 {
            parent & 0x300
        } else {
            requested
        };
        if wow && effective == 0x300 {
            return None;
        }
        Some(Self {
            wow,
            parent,
            effective,
        })
    }

    pub(super) fn view(&self) -> RegistryView {
        if !self.wow || self.parent & 0x400 != 0 || self.effective == 0x100 {
            RegistryView::Native64
        } else {
            RegistryView::Wow32
        }
    }

    pub(super) fn tags(
        &self,
        machine_self: bool,
        physical_wow: bool,
        control_set_alias: bool,
    ) -> u32 {
        if !self.wow {
            return if control_set_alias { 0 } else { self.parent };
        }
        let inherited = self.parent & 0x300;
        if self.view() == RegistryView::Native64 {
            // Native inheritance retains all bits. The thunk rewrites tags
            // after a changed view or a physical-path marker (bit 0x800),
            // retaining only bit 0 and the redirection suppression bit.
            if self.parent & 0x800 != 0 || self.effective != inherited {
                return (self.parent & 0x401) | self.effective;
            }
            return if control_set_alias { 0 } else { self.parent };
        }
        if machine_self {
            // An empty MACHINE reopen stays at the physical hive. A 32-bit
            // conversion with bit 0 or 0x800 still replaces its metadata.
            return if self.effective != inherited || self.effective != 0 && self.parent & 0x801 != 0
            {
                self.effective
            } else {
                self.parent
            };
        }
        if physical_wow {
            0xE00
        } else {
            0x400 | self.effective
        }
    }
}
