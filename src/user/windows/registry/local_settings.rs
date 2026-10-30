//! The captured creator's complete shared Classes-hive Local Settings subject.
use super::*;

pub(super) const SUFFIX: &str = "\\Software\\Classes\\Local Settings";

pub(super) fn path(sid: &[u8]) -> io::Result<Vec<u16>> {
    Ok(user_policy::user_hive_path(sid)?
        .into_iter()
        .chain(SUFFIX.encode_utf16())
        .collect())
}

impl Key {
    fn is_local_settings_subject(&self) -> bool {
        let Some(logical) = self.logical_path.as_deref() else {
            return false;
        };
        if self.command_access.is_none() {
            return false;
        }
        let logical = self.fold(logical);
        let prefix = self.fold(&"\\Registry\\User\\".encode_utf16().collect::<Vec<_>>());
        let Some(relative) = logical.strip_prefix(prefix.as_slice()) else {
            return false;
        };
        let Some(hive_end) = relative.iter().position(|&unit| unit == 92) else {
            return false;
        };
        if hive_end == 0 {
            return false;
        }
        // Logical paths come from fixed-subject construction. Match directly
        // below the creator hive; adjacent subjects may contain this suffix
        // deeper in their own trees without inheriting Local Settings policy.
        let path = &relative[hive_end..];
        let suffix = self.fold(&SUFFIX.encode_utf16().collect::<Vec<_>>());
        path.starts_with(&suffix) && (path.len() == suffix.len() || path[suffix.len()] == 92)
    }

    pub(crate) fn local_settings_classes_hive(&self) -> bool {
        let classes = self.fold(&"_Classes".encode_utf16().collect::<Vec<_>>());
        self.is_local_settings_subject()
            && self
                .path
                .split(|&unit| unit == 92)
                .filter(|part| !part.is_empty())
                .nth(2)
                .is_some_and(|hive| self.fold(hive).ends_with(&classes))
    }

    /// The independent three-ABI controls distinguish entry through a USER
    /// hive from reopening an existing Local Settings key body. The latter
    /// keeps the ordinary relative-open inheritance policy.
    pub(crate) fn initial_local_settings_tags(
        &self,
        name: &[u16],
        requested: u32,
        absolute: bool,
        primary_default: Option<bool>,
        parent_view: u32,
    ) -> Option<u32> {
        if !absolute && primary_default.is_none() {
            return None;
        }
        if !self.is_local_settings_subject() {
            return None;
        }
        if requested == 0x100 {
            let crosses_classes_hive = self.local_settings_classes_hive();
            // A native-view creator-hive handle enters the separate Classes
            // hive without the thunk's changed-view tag rewrite. The native
            // open therefore clears its inherited view bit at that link.
            return Some(
                if !absolute && parent_view == 0x100 && crosses_classes_hive {
                    0
                } else {
                    0x100
                },
            );
        }
        let default = primary_default.unwrap_or_else(|| {
            let normalized: Vec<_> = name
                .split(|u| *u == 92)
                .filter(|part| !part.is_empty())
                .flat_map(|part| std::iter::once(92).chain(part.iter().copied()))
                .collect();
            self.fold(&normalized).starts_with(
                &self.fold(
                    &"\\Registry\\User\\.DEFAULT\\"
                        .encode_utf16()
                        .collect::<Vec<_>>(),
                ),
            )
        });
        Some(0x400 | requested | u32::from(!default))
    }
}

impl Registry {
    pub(crate) fn with_local_settings_tree(
        self,
        sid: &[u8],
        view: RegistryView,
        tree: Result<CommandTree, u32>,
    ) -> io::Result<Self> {
        self.with_snapshot_selection(
            SnapshotRoot::LocalSettings,
            sid,
            view,
            tree.map(|tree| (tree.header, Some(tree.children))),
        )
    }

    pub(super) fn check_local_settings_name(
        &self,
        sid: &[u8],
        canonical: &[u16],
    ) -> io::Result<()> {
        if canonical.len() > MAX_NAME_UNITS || canonical.contains(&0) {
            return Err(invalid("Local Settings canonical name exceeds bounds"));
        }
        let mut allowed = vec![path(sid)?];
        if let Some(hive) = &self.primary_hive {
            if let Some(key) = &hive.root {
                allowed.push(
                    key.path
                        .iter()
                        .copied()
                        .chain(SUFFIX.encode_utf16())
                        .collect(),
                );
            }
        }
        allowed.push(
            user_policy::user_hive_path(sid)?
                .into_iter()
                .chain("_Classes\\Local Settings".encode_utf16())
                .collect(),
        );
        let fold = |units: &[u16]| {
            units
                .iter()
                .map(|&unit| self.upcase[usize::from(unit)])
                .collect::<Vec<_>>()
        };
        if !allowed.iter().any(|path| fold(path) == fold(canonical)) {
            return Err(invalid(
                "Local Settings canonical name is outside creator selection",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "local_settings_tests.rs"]
mod tests;

#[cfg(all(test, windows))]
#[path = "local_settings_digest_tests.rs"]
mod digest_tests;
