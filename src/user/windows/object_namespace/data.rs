//! Snapshot of the selected installed CSR data section. Bytes remain opaque:
//! the native CSR client owns server/client address-delta interpretation.
use super::{Entry, LookupError, Namespace, SelectedObject, invalid, is};
use crate::user::windows::nt::status::*;
use std::io;
use std::sync::Arc;

pub(crate) const MAX_SIZE: u64 = 64 << 20;
pub(crate) const THEME_ATTRIBUTES: u32 = 0x0800_0000;
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
    pub(crate) basic_attributes: Option<u32>,
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
            None,
        )
    }

    /// The current desktop's read-only theme directory and referenced data.
    pub(crate) fn selected_theme(
        session: u32,
        path: Vec<u16>,
        maximum_access: u32,
        system_security_status: u32,
        force_case_insensitive: bool,
        size: u64,
        regions: Vec<DataRegion>,
    ) -> io::Result<Arc<Self>> {
        if !theme_path(session, &path) {
            return Err(invalid(
                "selected theme section is outside the current Windows directories",
            ));
        }
        Self::selected_inner(
            path,
            maximum_access,
            system_security_status,
            force_case_insensitive,
            size,
            regions,
            Some(THEME_ATTRIBUTES),
        )
    }

    /// An unnamed, immutable client-data view, never published as an NT name.
    pub(crate) fn private_readonly(size: u64, regions: Vec<DataRegion>) -> io::Result<Arc<Self>> {
        Self::selected_inner(
            Vec::new(),
            4,
            STATUS_ACCESS_DENIED,
            false,
            size,
            regions,
            None,
        )
    }

    fn selected_inner(
        path: Vec<u16>,
        maximum_access: u32,
        system_security_status: u32,
        force_case_insensitive: bool,
        size: u64,
        regions: Vec<DataRegion>,
        basic_attributes: Option<u32>,
    ) -> io::Result<Arc<Self>> {
        let unselected_rights = if basic_attributes.is_some() {
            0x1a
        } else {
            0x1b
        };
        if maximum_access & 4 == 0
            || maximum_access & !0x000F_001F != 0
            || maximum_access & unselected_rights != 0
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
                "selected data section exceeds its access/extent profile",
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
            basic_attributes,
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

pub(crate) fn theme_header_path(session: u32) -> Vec<u16> {
    format!("\\Sessions\\{session}\\Windows\\ThemeSection")
        .encode_utf16()
        .collect()
}

fn numbered_theme_path(path: &[u16], prefix: &[u16]) -> bool {
    let Some(number) = path.strip_prefix(prefix) else {
        return false;
    };
    if number.is_empty() || number.len() > 10 {
        return false;
    }
    let decimal = |property: u32, &unit: &u16| {
        let digit = unit.checked_sub(b'0' as u16).filter(|&digit| digit < 10)?;
        property.checked_mul(10)?.checked_add(u32::from(digit))
    };
    number.iter().try_fold(0, decimal).is_some()
}

fn theme_path(session: u32, path: &[u16]) -> bool {
    let global: Vec<_> = "\\Windows\\Theme".encode_utf16().collect();
    let local: Vec<_> = format!("\\Sessions\\{session}\\Windows\\Theme")
        .encode_utf16()
        .collect();
    path == theme_header_path(session)
        || numbered_theme_path(path, &global)
        || numbered_theme_path(path, &local)
}

/// Read both duplicated resource names and mapping lengths from the measured
/// one-page theme directory. Only its current-session and global theme names
/// can be passed back to the native object provider.
pub(crate) fn theme_directory(session: u32, bytes: &[u8]) -> io::Result<[(Vec<u16>, u64); 2]> {
    const FIELD: usize = 260 * 2;
    if bytes.len() != 4096 {
        return Err(invalid(
            "selected theme directory differs from its native page extent",
        ));
    }
    let field = |start: usize| -> io::Result<Vec<u16>> {
        let mut units = bytes[start..start + FIELD]
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]));
        let value: Vec<_> = units.by_ref().take_while(|&unit| unit != 0).collect();
        if value.is_empty() || value.len() >= FIELD / 2 {
            return Err(invalid(
                "selected theme directory contains an invalid name field",
            ));
        }
        Ok(value)
    };
    let global = field(0)?;
    let local = field(0x208)?;
    let prefix_global: Vec<_> = "\\Windows\\Theme".encode_utf16().collect();
    let prefix_local: Vec<_> = format!("\\Sessions\\{session}\\Windows\\Theme")
        .encode_utf16()
        .collect();
    if !numbered_theme_path(&global, &prefix_global)
        || !numbered_theme_path(&local, &prefix_local)
        || global != field(0x428)?
        || local != field(0x630)?
    {
        return Err(invalid(
            "selected theme directory contains unmeasured resource paths",
        ));
    }
    let size = |start: usize| -> io::Result<u64> {
        let length = u64::from_le_bytes(
            bytes[start..start + 8]
                .try_into()
                .expect("fixed theme directory field"),
        );
        if length == 0 || length % 4096 != 0 || length > MAX_COMMITTED {
            return Err(invalid(
                "selected theme directory declares an invalid resource extent",
            ));
        }
        Ok(length)
    };
    Ok([(global, size(0x838)?), (local, size(0x840)?)])
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
    /// Attach only the selected CSR section before publishing its namespace.
    pub(crate) fn select_data_section(&mut self, section: Arc<DataSection>) -> io::Result<()> {
        let shared_name: Vec<_> = "SharedSection".encode_utf16().collect();
        if section.path.rsplit(|&unit| unit == 92).next() != Some(shared_name.as_slice())
            || section.basic_attributes.is_some()
        {
            return Err(invalid(
                "selected data section is outside the fixed SharedSection name",
            ));
        }
        let force_case_insensitive = section.force_case_insensitive;
        let entry = self.section_entry(&section)?;
        entry.section = Some(SelectedSection::Data(section));
        self.section_case = Some(force_case_insensitive);
        Ok(())
    }

    /// Publish the three installed theme sections as one coherent snapshot.
    pub(crate) fn select_theme_sections(
        &mut self,
        sections: [Arc<DataSection>; 3],
    ) -> io::Result<()> {
        for (index, section) in sections.iter().enumerate() {
            if section.basic_attributes != Some(THEME_ATTRIBUTES)
                || sections[..index]
                    .iter()
                    .any(|older| older.path == section.path)
            {
                return Err(invalid("invalid selected theme section snapshot"));
            }
            self.section_entry(section)?;
        }
        for section in sections {
            // The exclusive namespace has not changed since validation and
            // every section names a distinct entry.
            let entry = self.section_entry(&section)?;
            entry.section = Some(SelectedSection::Data(section));
        }
        Ok(())
    }

    fn section_entry(&mut self, section: &DataSection) -> io::Result<&mut Entry> {
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
        if components.len() < 2 || components.iter().any(|part| part.is_empty()) {
            return Err(invalid("selected data section has an invalid NT name"));
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
            .ok_or_else(|| invalid("selected data section directory entry absent"))?;
        if !is(&entry.captured.kind, "Section") || entry.section.is_some() {
            return Err(invalid("selected data section entry type/identity differs"));
        }
        Ok(entry)
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
