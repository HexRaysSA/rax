//! Snapshot of the selected installed CSR data section. Bytes remain opaque:
//! the native CSR client owns server/client address-delta interpretation.
use super::{LookupError, Namespace, SelectedObject, invalid, is};
use crate::user::windows::nt::status::*;
use std::io;
use std::sync::Arc;

pub(crate) const MAX_SIZE: u64 = 64 << 20;
const MAX_COMMITTED: u64 = 16 << 20;
const MAX_REGIONS: usize = 16384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataRegion {
    pub(crate) offset: u64,
    pub(crate) size: u64,
    /// Committed page bytes; `None` describes reserved, inaccessible pages.
    pub(crate) bytes: Option<Arc<[u8]>>,
}

/// Immutable host-input snapshot. Guest handles and views own references;
/// no guest pointer or handle is forwarded to the host object manager.
#[derive(Debug)]
pub struct DataSection {
    pub(crate) path: Vec<u16>,
    pub(crate) size: u64,
    pub(crate) regions: Vec<DataRegion>,
    maximum_access: u32,
    system_security_status: u32,
    force_case_insensitive: bool,
}
impl DataSection {
    /// O(R) validation time and retained metadata for R region runs, plus B
    /// immutable committed bytes. No pointer interpretation or relocation.
    pub(crate) fn selected(
        maximum_access: u32,
        system_security_status: u32,
        force_case_insensitive: bool,
        size: u64,
        regions: Vec<DataRegion>,
    ) -> io::Result<Arc<Self>> {
        Self::selected_for_session(
            None,
            maximum_access,
            system_security_status,
            force_case_insensitive,
            size,
            regions,
        )
    }

    /// None denotes the global object. Some(id) denotes an independently
    /// captured session directory; a followed link keeps its target's name.
    pub(crate) fn path_for_session(session: Option<u32>) -> Vec<u16> {
        match session {
            None => "\\Windows\\SharedSection".encode_utf16().collect(),
            Some(session) => format!("\\Sessions\\{session}\\Windows\\SharedSection")
                .encode_utf16()
                .collect(),
        }
    }

    pub(crate) fn selected_for_session(
        session: Option<u32>,
        maximum_access: u32,
        system_security_status: u32,
        force_case_insensitive: bool,
        size: u64,
        regions: Vec<DataRegion>,
    ) -> io::Result<Arc<Self>> {
        Self::selected_inner(
            Self::path_for_session(session),
            maximum_access,
            system_security_status,
            force_case_insensitive,
            size,
            regions,
        )
    }

    /// An unnamed, immutable client-data view, never published as an NT name.
    pub(crate) fn private_readonly(size: u64, regions: Vec<DataRegion>) -> io::Result<Arc<Self>> {
        Self::selected_inner(Vec::new(), 4, STATUS_ACCESS_DENIED, false, size, regions)
    }

    fn selected_inner(
        path: Vec<u16>,
        maximum_access: u32,
        system_security_status: u32,
        force_case_insensitive: bool,
        size: u64,
        regions: Vec<DataRegion>,
    ) -> io::Result<Arc<Self>> {
        if maximum_access & 4 == 0
            || maximum_access & !0x000F_001F != 0
            || maximum_access & 0x1B != 0
            || !matches!(
                system_security_status,
                0 | STATUS_ACCESS_DENIED | STATUS_PRIVILEGE_NOT_HELD
            )
            || size == 0
            || size > MAX_SIZE
            || size % 4096 != 0
            || regions.is_empty()
            || regions.len() > MAX_REGIONS
        {
            return Err(invalid(
                "selected CSR data section exceeds its access/extent profile",
            ));
        }
        let (mut cursor, mut committed) = (0u64, 0u64);
        for region in &regions {
            if region.offset != cursor || region.size == 0 || region.size % 4096 != 0 {
                return Err(invalid(
                    "selected data section has a gap, overlap or unaligned run",
                ));
            }
            cursor = cursor
                .checked_add(region.size)
                .filter(|&end| end <= size)
                .ok_or_else(|| invalid("selected data section run exceeds its extent"))?;
            if let Some(bytes) = &region.bytes {
                if bytes.len() as u64 != region.size {
                    return Err(invalid(
                        "selected data section committed byte count differs",
                    ));
                }
                committed = committed
                    .checked_add(region.size)
                    .filter(|&n| n <= MAX_COMMITTED)
                    .ok_or_else(|| {
                        invalid("selected data section committed storage exceeds bounds")
                    })?;
            }
        }
        if cursor != size || committed == 0 {
            return Err(invalid(
                "selected data section does not cover its extent/commitment",
            ));
        }
        Ok(Arc::new(Self {
            path,
            size,
            regions,
            maximum_access,
            system_security_status,
            force_case_insensitive,
        }))
    }
    pub(crate) fn grant(&self, access: u32, duplicate: bool) -> Result<u32, u32> {
        super::section::grant(
            self.maximum_access,
            self.system_security_status,
            access,
            duplicate,
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SelectedSection {
    Image(Arc<super::ImageSection>),
    Data(Arc<DataSection>),
}
impl SelectedSection {
    pub(crate) fn grant(
        &self,
        access: u32,
        duplicate: bool,
    ) -> Result<u32, super::SectionGrantError> {
        match self {
            Self::Image(section) => section.grant(access, duplicate),
            Self::Data(section) => section
                .grant(access, duplicate)
                .map_err(super::SectionGrantError::Status),
        }
    }
}
impl Namespace {
    /// Attach only to the captured fixed directory/entry before publishing the
    /// namespace. Other section entries remain explicit unselected frontiers.
    pub(crate) fn select_data_section(&mut self, section: Arc<DataSection>) -> io::Result<()> {
        if self
            .section_case
            .is_some_and(|case| case != section.force_case_insensitive)
        {
            return Err(invalid(
                "selected image/data section case policies disagree",
            ));
        }
        if section.path.first() != Some(&92) {
            return Err(invalid("selected data section has no absolute NT name"));
        }
        let components: Vec<_> = section.path[1..].split(|unit| *unit == 92).collect();
        let shared_name: Vec<_> = "SharedSection".encode_utf16().collect();
        if components.len() < 2
            || components.iter().any(|part| part.is_empty())
            || components.last().copied() != Some(shared_name.as_slice())
        {
            return Err(invalid(
                "selected data section is outside the fixed SharedSection name",
            ));
        }
        let mut directory = Arc::get_mut(
            self.root
                .as_mut()
                .ok_or_else(|| invalid("data section root absent"))?,
        )
        .ok_or_else(|| invalid("data section namespace already published"))?;
        for component in &components[..components.len() - 1] {
            let key = super::fold(&directory.upcase, component);
            directory = directory
                .entries
                .get_mut(&key)
                .and_then(|entry| entry.child.as_mut())
                .and_then(Arc::get_mut)
                .ok_or_else(|| invalid("selected Windows directory absent or published"))?;
        }
        let key = super::fold(
            &directory.upcase,
            components.last().expect("validated path"),
        );
        let entry = directory
            .entries
            .get_mut(&key)
            .ok_or_else(|| invalid("selected SharedSection directory entry absent"))?;
        if !is(&entry.captured.kind, "Section") || entry.section.is_some() {
            return Err(invalid(
                "selected SharedSection entry type/identity differs",
            ));
        }
        self.section_case = Some(section.force_case_insensitive);
        entry.section = Some(SelectedSection::Data(section));
        Ok(())
    }
    pub(crate) fn lookup_installed_section(
        &self,
        root: Option<Arc<super::Directory>>,
        name: &[u16],
        flags: u32,
        wow: bool,
    ) -> Result<SelectedSection, LookupError> {
        if self.section_case.is_none() {
            return Err(LookupError::Unselected);
        }
        let root = if wow && root.as_ref().is_some_and(|d| is(&d.path, "\\KnownDlls32")) {
            self.wow_section_root.clone().or(root)
        } else {
            root
        };
        match self.lookup_object(root, name, flags, false, true, false)? {
            SelectedObject::Section(section) => Ok(section),
            _ => unreachable!("section lookup"),
        }
    }
}
#[cfg(test)]
pub(crate) mod tests;
