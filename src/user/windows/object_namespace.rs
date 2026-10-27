//! Bounded, immutable selection of the installed NT object namespace.
//! NT UTF-16 names retain their protocol grammar; they are not filesystem paths.
//! Directory/link host handles close during selection. Selected image sections
//! pin their native identity; guest namespace lookup itself never calls the host.
use super::nt::status::*;
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
pub(crate) const PATHS: [&str; 6] = [
    "\\",
    "\\KnownDlls",
    "\\KnownDlls32",
    "\\KnownDllsChpe32",
    "\\Windows",
    "\\BaseNamedObjects",
];
/// Fixed installation roots plus the selected primary token's session roots.
/// Object-manager names use NT separators independently of host filesystem paths.
pub(crate) fn selection_paths(session: Option<u32>) -> Vec<Vec<u16>> {
    let mut result: Vec<Vec<u16>> = PATHS.iter().map(|s| s.encode_utf16().collect()).collect();
    if let Some(session) = session {
        for path in ["\\Sessions".to_owned(), format!("\\Sessions\\{session}")] {
            result.push(path.encode_utf16().collect());
        }
        if session != 0 {
            result.push(
                format!("\\Sessions\\{session}\\BaseNamedObjects")
                    .encode_utf16()
                    .collect(),
            );
        }
        result.push(
            format!("\\Sessions\\{session}\\Windows")
                .encode_utf16()
                .collect(),
        );
    }
    result
}

pub(crate) fn image_directory(path: &[u16]) -> bool {
    PATHS[1..4].iter().any(|name| is(path, name))
}

/// Both lists must describe the same unique names and types. The native
/// enumeration API may repeat entries while its live namespace changes.
#[cfg(any(windows, test))]
pub(crate) fn entries_coherent(
    upcase: &[u16],
    first: &[CapturedEntry],
    second: &[CapturedEntry],
) -> bool {
    if upcase.len() != 65536
        || first.len() != second.len()
        || !first
            .iter()
            .zip(second)
            .all(|(a, b)| a.name == b.name && a.kind == b.kind)
    {
        return false;
    }
    let mut names = std::collections::BTreeSet::new();
    first
        .iter()
        .all(|entry| names.insert(fold(upcase, &entry.name)))
}

/// Retain only unambiguous names/types observed in both bounded lists.
/// Missing members of the resulting partial directory remain unselected.
#[cfg(any(windows, test))]
pub(crate) fn stable_volatile_entries(
    upcase: &[u16],
    first: &[CapturedEntry],
    second: &[CapturedEntry],
) -> Option<Vec<CapturedEntry>> {
    if upcase.len() != 65536 || first.len() > MAX_ENTRIES || second.len() > MAX_ENTRIES {
        return None;
    }
    let unique = |entries: &[CapturedEntry]| {
        let mut names: BTreeMap<Vec<u16>, Option<CapturedEntry>> = BTreeMap::new();
        for entry in entries {
            let key = fold(upcase, &entry.name);
            names
                .entry(key)
                .and_modify(|old| *old = None)
                .or_insert_with(|| Some(entry.clone()));
        }
        names
    };
    let first = unique(first);
    let second = unique(second);
    Some(
        first
            .into_iter()
            .filter_map(|(key, entry)| {
                let entry = entry?;
                let other = second.get(&key)?.as_ref()?;
                (entry.name == other.name && entry.kind == other.kind).then_some(entry)
            })
            .collect(),
    )
}

/// A disappearing or inaccessible sample supplies no case-policy evidence.
#[cfg(any(windows, test))]
pub(crate) fn case_probe_policy(original: u32, folded: u32, explicit: u32) -> Option<bool> {
    if !matches!(original, STATUS_SUCCESS | STATUS_OBJECT_TYPE_MISMATCH) || explicit != original {
        return None;
    }
    if folded == original {
        Some(true)
    } else if folded == STATUS_OBJECT_NAME_NOT_FOUND {
        Some(false)
    } else {
        None
    }
}

pub(crate) mod csr;
pub(crate) mod data;
mod directory_alias;
pub(crate) mod file_image;
mod image;
mod named;
mod section;
pub use data::DataSection;
pub(crate) use data::SelectedSection;
pub(crate) use image::{ExtensionQuery, ImageExtension, ImageRegion, ImageTemplate};
pub(crate) use named::Name as NativeName;
pub(crate) use section::CapturedSection;
pub(crate) use section::GrantError as SectionGrantError;
pub use section::ImageSection;

#[cfg(windows)]
pub(crate) fn gui_snapshot(
    arch: super::arch::WinArch,
    user: &std::path::Path,
    win32u: &std::path::Path,
) -> io::Result<Arc<super::gui::Inputs>> {
    installed::gui::snapshot(arch, user, win32u)
}

#[cfg(not(windows))]
pub(crate) fn gui_snapshot(
    _: super::arch::WinArch,
    _: &std::path::Path,
    _: &std::path::Path,
) -> io::Result<Arc<super::gui::Inputs>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native GUI metadata requires a Windows host",
    ))
}
pub(crate) const MAX_ENTRIES: usize = 8192;
const MAX_UNITS: usize = 32766;
const MAX_TOTAL_BYTES: usize = 16 << 20;
const ALL_ACCESS: u32 = 0x000F_000F;
#[derive(Debug, Clone)]
pub(crate) struct CapturedEntry {
    pub(crate) name: Vec<u16>,
    pub(crate) kind: Vec<u16>,
    pub(crate) target: Option<Vec<u16>>,
    pub(crate) link_access: Option<LinkAccess>,
    pub(crate) section: Option<CapturedSection>,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkAccess {
    pub(crate) maximum_access: u32,
    pub(crate) system_security_status: u32,
}
/// Selected immutable link metadata. No guest handle refers to a host HANDLE.
#[derive(Debug)]
pub struct SymbolicLink {
    pub(crate) path: Vec<u16>,
    pub(crate) target: Vec<u16>,
    access: LinkAccess,
}
#[derive(Debug, Clone)]
pub(crate) struct SelectedDirectory {
    pub(crate) path: Vec<u16>,
    pub(crate) maximum_access: u32,
    pub(crate) force_case_insensitive: bool,
    pub(crate) system_security_status: u32,
    pub(crate) entries: Vec<CapturedEntry>,
}
#[derive(Debug)]
struct Entry {
    captured: CapturedEntry,
    child: Option<Arc<Directory>>,
    // Independently verified selected identity reached through a symbolic link.
    resolved_directory: Option<Arc<Directory>>,
    link: Option<Arc<SymbolicLink>>,
    section: Option<SelectedSection>,
}
enum SelectedObject {
    Directory(Arc<Directory>),
    Link(Arc<SymbolicLink>),
    Section(SelectedSection),
    Port,
}
/// Guest-owned immutable directory metadata, independent of native HANDLEs.
#[derive(Debug)]
pub struct Directory {
    pub(crate) path: Vec<u16>,
    pub(crate) maximum_access: u32,
    system_security_status: u32,
    force_case_insensitive: bool,
    entries_complete: bool,
    upcase: Arc<[u16]>,
    entries: BTreeMap<Vec<u16>, Entry>,
}
#[derive(Debug, Clone, Default)]
pub(crate) struct Namespace {
    root: Option<Arc<Directory>>,
    pub(crate) wow_system_prefix: Vec<u16>,
    pub(crate) native_machine: Option<u16>,
    pub(crate) image_extension_query: Option<image::ExtensionQuery>,
    section_case: Option<bool>,
    wow_section_root: Option<Arc<Directory>>,
    csr_server: Option<Arc<csr::CsrServer>>,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LookupError {
    Status(u32),
    Unselected,
}
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn fold(upcase: &[u16], s: &[u16]) -> Vec<u16> {
    s.iter().map(|&u| upcase[usize::from(u)]).collect()
}
fn is(s: &[u16], text: &str) -> bool {
    s.iter().copied().eq(text.encode_utf16())
}
impl Namespace {
    /// O(E log E + U) time and O(E + U) retained storage for E entries and U UTF-16 units.
    pub(crate) fn selected(
        upcase: Arc<[u16]>,
        selected: Vec<SelectedDirectory>,
    ) -> io::Result<Self> {
        Self::selected_for_session(upcase, selected, None)
    }
    pub(crate) fn selected_for_session(
        upcase: Arc<[u16]>,
        selected: Vec<SelectedDirectory>,
        session: Option<u32>,
    ) -> io::Result<Self> {
        Self::selected_for_session_partial(upcase, selected, session, &[])
    }
    pub(crate) fn selected_for_session_partial(
        upcase: Arc<[u16]>,
        selected: Vec<SelectedDirectory>,
        session: Option<u32>,
        incomplete: &[Vec<u16>],
    ) -> io::Result<Self> {
        Self::selected_with_directory_aliases(upcase, selected, session, incomplete, &[])
    }

    /// Alias pairs are trusted acquisition results, never guest-supplied paths.
    pub(crate) fn selected_with_directory_aliases(
        upcase: Arc<[u16]>,
        selected: Vec<SelectedDirectory>,
        session: Option<u32>,
        incomplete: &[Vec<u16>],
        aliases: &[(Vec<u16>, Vec<u16>)],
    ) -> io::Result<Self> {
        let allowed = selection_paths(session);
        let mut seen = std::collections::BTreeSet::new();
        if incomplete.iter().any(|p| {
            !allowed.contains(p)
                || image_directory(p)
                || !selected.iter().any(|s| s.path == *p)
                || !seen.insert(p.clone())
        }) {
            return Err(invalid("invalid partial NT directory selection"));
        }
        if upcase.len() != 65536 || selected.is_empty() || selected.len() > allowed.len() {
            return Err(invalid("NT directory selection/table exceeds bounds"));
        }
        let mut dirs = BTreeMap::new();
        let mut section_case = None;
        let (mut count, mut bytes) = (0usize, 0usize);
        for s in selected {
            if !allowed.contains(&s.path)
                || s.maximum_access & !ALL_ACCESS != 0
                || !matches!(
                    s.system_security_status,
                    0 | STATUS_PRIVILEGE_NOT_HELD | STATUS_ACCESS_DENIED
                )
            {
                return Err(invalid("NT directory outside fixed selection/access mask"));
            }
            let mut entries = BTreeMap::new();
            for e in s.entries {
                if e.name.is_empty()
                    || e.name.len() > MAX_UNITS
                    || e.name.contains(&(b'\\' as u16))
                    || e.kind.is_empty()
                    || e.kind.len() > 255
                    || e.kind.contains(&0)
                    || e.target
                        .as_ref()
                        .is_some_and(|t| t.len() > MAX_UNITS || t.contains(&0))
                    || e.target.is_some() && !is(&e.kind, "SymbolicLink")
                    || e.section
                        .is_some_and(|a| !is(&e.kind, "Section") || s.path.len() == 1 || !a.valid())
                    || e.link_access.is_some_and(|a| {
                        e.target.is_none()
                            || a.maximum_access & !0x000F_0001 != 0
                            || !matches!(
                                a.system_security_status,
                                0 | STATUS_PRIVILEGE_NOT_HELD | STATUS_ACCESS_DENIED
                            )
                    })
                {
                    return Err(invalid(
                        "NT directory entry exceeds its name/type/target bounds",
                    ));
                }
                count = count
                    .checked_add(1)
                    .ok_or_else(|| invalid("NT directory count overflow"))?;
                bytes = bytes
                    .checked_add(
                        2 * (e.name.len() + e.kind.len() + e.target.as_ref().map_or(0, Vec::len)),
                    )
                    .ok_or_else(|| invalid("NT directory byte count overflow"))?;
                if count > MAX_ENTRIES || bytes > MAX_TOTAL_BYTES {
                    return Err(invalid("NT directory aggregate exceeds bounds"));
                }
                let section = e.section.map(|access| {
                    let mut path = s.path.clone();
                    path.push(92);
                    path.extend_from_slice(&e.name);
                    SelectedSection::Image(ImageSection::selected(path, access))
                });
                if let Some(access) = e.section {
                    if section_case
                        .is_some_and(|previous| previous != access.force_case_insensitive)
                    {
                        return Err(invalid("selected section case policies disagree"));
                    }
                    section_case = Some(access.force_case_insensitive);
                }
                let link = e.link_access.map(|access| {
                    let mut path = s.path.clone();
                    if path.len() != 1 {
                        path.push(b'\\' as u16);
                    }
                    path.extend_from_slice(&e.name);
                    Arc::new(SymbolicLink {
                        path,
                        target: e
                            .target
                            .as_ref()
                            .expect("validated selected target")
                            .clone(),
                        access,
                    })
                });
                if entries
                    .insert(
                        fold(&upcase, &e.name),
                        Entry {
                            captured: e,
                            child: None,
                            resolved_directory: None,
                            link,
                            section,
                        },
                    )
                    .is_some()
                {
                    return Err(invalid("colliding NT directory names"));
                }
            }
            let key = s.path.clone();
            let dir = Directory {
                path: s.path,
                maximum_access: s.maximum_access,
                system_security_status: s.system_security_status,
                force_case_insensitive: s.force_case_insensitive,
                entries_complete: !incomplete.contains(&key),
                upcase: upcase.clone(),
                entries,
            };
            if dirs.insert(key, dir).is_some() {
                return Err(invalid("duplicate NT directory selection"));
            }
        }
        let alias = directory_alias::prepare(&mut dirs, &upcase, session, aliases)?;
        // Attach deepest nodes first so every Arc already owns its selected
        // descendants. A selected child requires an independently captured parent.
        let mut paths: Vec<_> = dirs.keys().filter(|p| p.len() != 1).cloned().collect();
        paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
        for path in paths {
            let separator = path
                .iter()
                .rposition(|&unit| unit == 92)
                .ok_or_else(|| invalid("selected NT directory has no parent separator"))?;
            let parent_path = if separator == 0 {
                vec![92]
            } else {
                path[..separator].to_vec()
            };
            let name = &path[separator + 1..];
            let child = dirs
                .remove(&path)
                .expect("selected directory key is present");
            let parent = dirs
                .get_mut(&parent_path)
                .ok_or_else(|| invalid("selected NT directory parent is not captured"))?;
            let entry = parent
                .entries
                .get_mut(&fold(&upcase, name))
                .ok_or_else(|| invalid("selected NT directory is absent from captured parent"))?;
            if !is(&entry.captured.kind, "Directory")
                || entry.captured.name != name
                || entry.child.is_some()
            {
                return Err(invalid(&format!(
                    concat!(
                        "selected NT directory parent type/name changed: ",
                        "selected_path={:?} parent_path={:?} selected_name={:?} ",
                        "captured_name={:?} captured_type={:?} existing_child={}"
                    ),
                    String::from_utf16_lossy(&path),
                    String::from_utf16_lossy(&parent_path),
                    String::from_utf16_lossy(name),
                    String::from_utf16_lossy(&entry.captured.name),
                    String::from_utf16_lossy(&entry.captured.kind),
                    entry.child.is_some(),
                )));
            }
            entry.child = Some(Arc::new(child));
        }
        let mut root = dirs
            .remove(&vec![92])
            .ok_or_else(|| invalid("NT directory root is not selected"))?;
        if let Some(alias) = alias {
            alias.attach(&mut root, &upcase)?;
        }
        Ok(Self {
            root: Some(Arc::new(root)),
            wow_system_prefix: Vec::new(),
            section_case,
            wow_section_root: None,
            csr_server: None,
            native_machine: None,
            image_extension_query: None,
        })
    }
    pub(crate) fn select_wow_system_root(&mut self, root: &[u16]) -> io::Result<()> {
        if root.is_empty() || root.len() > 32752 || root.contains(&0) {
            return Err(invalid("selected WoW64 system root exceeds bounds"));
        }
        // This is the NT protocol prefix used by the installed redirection
        // pass, rather than a native filesystem path to be normalized.
        self.wow_system_prefix = "\\??\\"
            .encode_utf16()
            .chain(root.iter().copied())
            .collect();
        Ok(())
    }
    pub(crate) fn equal_unit(&self, a: u16, b: u16, insensitive: bool) -> bool {
        if insensitive {
            self.root
                .as_ref()
                .is_some_and(|r| r.upcase[usize::from(a)] == r.upcase[usize::from(b)])
        } else {
            a == b
        }
    }
    pub(crate) fn lookup(
        &self,
        root: Option<Arc<Directory>>,
        name: &[u16],
        flags: u32,
    ) -> Result<Arc<Directory>, LookupError> {
        match self.lookup_object(root, name, flags, false, false, false)? {
            SelectedObject::Directory(d) => Ok(d),
            _ => unreachable!("directory lookup"),
        }
    }
    pub(crate) fn lookup_link(
        &self,
        root: Option<Arc<Directory>>,
        name: &[u16],
        flags: u32,
    ) -> Result<Arc<SymbolicLink>, LookupError> {
        match self.lookup_object(root, name, flags, true, false, false)? {
            SelectedObject::Link(l) => Ok(l),
            _ => unreachable!("link lookup"),
        }
    }
    /// Resolve captured ALPC-port presence without making a native connection.
    /// A present entry supplies identity only; the caller still needs a selected
    /// guest server before admitting a successful connection.
    pub(crate) fn lookup_port(&self, name: &[u16]) -> Result<(), LookupError> {
        match self.lookup_object(None, name, 0, false, false, true)? {
            SelectedObject::Port => Ok(()),
            _ => unreachable!("port lookup"),
        }
    }
    fn lookup_object(
        &self,
        root: Option<Arc<Directory>>,
        name: &[u16],
        flags: u32,
        link: bool,
        section: bool,
        port: bool,
    ) -> Result<SelectedObject, LookupError> {
        self.lookup_object_reparsed(root, name, flags, link, section, port, 0)
    }

    /// Native object-manager parsing admits63 reparses. Keep every expansion
    /// within the selected name budget; guest execution never opens host handles.
    fn lookup_object_reparsed(
        &self,
        root: Option<Arc<Directory>>,
        name: &[u16],
        flags: u32,
        link: bool,
        section: bool,
        port: bool,
        reparses: u8,
    ) -> Result<SelectedObject, LookupError> {
        let (mut dir, path) = if let Some(root) = root {
            if name.first() == Some(&(b'\\' as u16)) {
                return Err(LookupError::Status(STATUS_OBJECT_PATH_SYNTAX_BAD));
            }
            (root, name)
        } else {
            if name.first() != Some(&(b'\\' as u16)) {
                return Err(LookupError::Status(STATUS_OBJECT_PATH_SYNTAX_BAD));
            }
            (
                self.root.as_ref().ok_or(LookupError::Unselected)?.clone(),
                &name[1..],
            )
        };
        if path.is_empty() {
            return if link || section || port {
                Err(LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH))
            } else {
                Ok(SelectedObject::Directory(dir))
            };
        }
        let mut parts = path.split(|&u| u == b'\\' as u16).peekable();
        while let Some(part) = parts.next() {
            if part.is_empty() {
                return Err(LookupError::Status(STATUS_OBJECT_NAME_INVALID));
            }
            let entry = dir
                .entries
                .get(&fold(&dir.upcase, part))
                .filter(|e| {
                    (if section {
                        self.section_case.unwrap_or(false)
                    } else {
                        dir.force_case_insensitive
                    }) || flags & 0x40 != 0
                        || e.captured.name == part
                })
                .ok_or_else(|| {
                    if !dir.entries_complete {
                        LookupError::Unselected
                    } else {
                        LookupError::Status(if parts.peek().is_some() {
                            STATUS_OBJECT_PATH_NOT_FOUND
                        } else {
                            STATUS_OBJECT_NAME_NOT_FOUND
                        })
                    }
                })?;
            if is(&entry.captured.kind, "Directory") {
                if (link || section || port) && parts.peek().is_none() {
                    return Err(LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH));
                }
                dir = entry.child.as_ref().ok_or(LookupError::Unselected)?.clone();
            } else if is(&entry.captured.kind, "SymbolicLink") {
                if link && parts.peek().is_none() {
                    return entry
                        .link
                        .clone()
                        .map(SelectedObject::Link)
                        .ok_or(LookupError::Unselected);
                }
                if flags & 0x1000 != 0 {
                    return Err(LookupError::Status(STATUS_REPARSE_POINT_ENCOUNTERED));
                }
                let target = entry
                    .captured
                    .target
                    .as_ref()
                    .ok_or(LookupError::Unselected)?;
                // DOS KnownDllPath values remain outside object-manager parsing.
                if target.first() != Some(&(b'\\' as u16)) {
                    return Err(LookupError::Status(STATUS_OBJECT_NAME_INVALID));
                }
                // The64th reparse fails even when a previously selected target
                // exists. DONT_REPARSE above has independent earlier precedence.
                if reparses == 63 {
                    return Err(LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND));
                }
                if let Some(resolved) = &entry.resolved_directory {
                    let mut suffix = parts.peekable();
                    if suffix.peek().is_some_and(|part| part.is_empty()) {
                        return Err(LookupError::Status(STATUS_OBJECT_NAME_INVALID));
                    }
                    let mut remaining = Vec::new();
                    for (index, part) in suffix.enumerate() {
                        if index != 0 {
                            remaining.push(b'\\' as u16);
                        }
                        remaining.extend_from_slice(part);
                        if target.len() + 1 + remaining.len() > MAX_UNITS {
                            return Err(LookupError::Unselected);
                        }
                    }
                    return self.lookup_object_reparsed(
                        Some(resolved.clone()),
                        &remaining,
                        flags,
                        link,
                        section,
                        port,
                        reparses + 1,
                    );
                }
                let mut expanded = target.clone();
                for remaining in parts {
                    expanded.push(b'\\' as u16);
                    expanded.extend_from_slice(remaining);
                    if expanded.len() > MAX_UNITS {
                        return Err(LookupError::Unselected);
                    }
                }
                return self.lookup_object_reparsed(
                    None,
                    &expanded,
                    flags,
                    link,
                    section,
                    port,
                    reparses + 1,
                );
            } else if section && parts.peek().is_none() && is(&entry.captured.kind, "Section") {
                return entry
                    .section
                    .clone()
                    .map(SelectedObject::Section)
                    .ok_or(LookupError::Unselected);
            } else if port && parts.peek().is_none() && is(&entry.captured.kind, "ALPC Port") {
                return Ok(SelectedObject::Port);
            } else {
                return Err(LookupError::Status(STATUS_OBJECT_TYPE_MISMATCH));
            }
        }
        Ok(SelectedObject::Directory(dir))
    }
}
impl SymbolicLink {
    pub(crate) fn grant(&self, access: u32, duplicate: bool) -> Result<u32, u32> {
        let mut requested = access & 0x0DFF_FFFF;
        if duplicate {
            requested &= !0x0010_0000;
        }
        for (generic, specific) in [
            (0x8000_0000, 0x0002_0001),
            (0x4000_0000, 0x0002_0000),
            (0x2000_0000, 0x0002_0001),
            (0x1000_0000, 0x000F_0001),
        ] {
            if access & generic != 0 {
                requested |= specific;
            }
        }
        if requested & !(0x000F_0001 | 0x0100_0000) != 0
            || requested & 0x000F_0001 & !self.access.maximum_access != 0
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if requested & 0x0100_0000 != 0 && self.access.system_security_status != 0 {
            return Err(self.access.system_security_status);
        }
        if !duplicate && access & 0x0200_0000 != 0 {
            requested |= self.access.maximum_access;
        }
        if !duplicate && requested == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(requested)
    }
}
impl Directory {
    /// Shared mapping plus the selected caller's captured authorization ceiling.
    /// Duplication permits zero rights and discards SYNCHRONIZE/MAXIMUM_ALLOWED;
    /// opening applies MAXIMUM_ALLOWED and refuses a zero grant.
    pub(crate) fn grant(&self, access: u32, duplicate: bool) -> Result<u32, u32> {
        let mut requested = access & 0x0DFF_FFFF;
        if duplicate {
            // The independent directory control strips unassigned low
            // specific rights as well as SYNCHRONIZE/MAXIMUM_ALLOWED.
            requested &= 0x010F_000F;
        }
        for (generic, specific) in [
            (0x8000_0000, 0x0002_0003),
            (0x4000_0000, 0x0002_000C),
            (0x2000_0000, 0x0002_0003),
            (0x1000_0000, ALL_ACCESS),
        ] {
            if access & generic != 0 {
                requested |= specific;
            }
        }
        if requested & !(ALL_ACCESS | 0x0100_0000) != 0
            || requested & ALL_ACCESS & !self.maximum_access != 0
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if requested & 0x0100_0000 != 0 && self.system_security_status != 0 {
            return Err(self.system_security_status);
        }
        if !duplicate && access & 0x0200_0000 != 0 {
            requested |= self.maximum_access;
        }
        if !duplicate && requested == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(requested)
    }
}
#[cfg(windows)]
mod installed;
#[cfg(windows)]
pub(crate) use installed::snapshot;
#[cfg(not(windows))]
pub(crate) fn snapshot(_: Arc<[u16]>, _: u32) -> io::Result<Namespace> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "installed NT object namespace requires a Windows host",
    ))
}
#[cfg(test)]
pub(crate) mod image_extension_tests;
#[cfg(test)]
pub(crate) mod image_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod base_named_object_tests;

#[cfg(test)]
pub(crate) mod reparse_tests;

#[cfg(test)]
mod session_windows_tests;
