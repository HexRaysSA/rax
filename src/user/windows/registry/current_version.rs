//! Paired immutable CurrentVersion headers and routes to selected shared keys.
//! Ordered child metadata distinguishes absence from an uncaptured descendant.
use super::*;
use crate::user::windows::nt::status::{
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};

pub(crate) const CURRENT_VERSION_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion";
pub(crate) const CURRENT_VERSION_WOW_KEY: &str =
    "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion";
pub(crate) const WINDOWS_NT_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT";
const WINDOWS_NT_WOW_KEY: &str =
    "\\Registry\\Machine\\Software\\WOW6432Node\\Microsoft\\Windows NT";

pub(crate) struct CurrentVersionHeader {
    pub(crate) key: CommandHeader,
    pub(crate) information: KeyInformation,
}

impl Registry {
    /// O(V log V + E log E + S) for V values, E ordered entries and S selected
    /// routes. No descendant is acquired, and no native handle is retained.
    pub(crate) fn with_current_version(
        self,
        view: RegistryView,
        header: Result<CurrentVersionHeader, u32>,
    ) -> io::Result<Self> {
        self.with_version_subject(view, false, header)
    }

    pub(crate) fn with_current_version_parent(
        self,
        view: RegistryView,
        header: Result<CurrentVersionHeader, u32>,
    ) -> io::Result<Self> {
        self.with_version_subject(view, true, header)
    }

    fn with_version_subject(
        mut self,
        view: RegistryView,
        parent: bool,
        header: Result<CurrentVersionHeader, u32>,
    ) -> io::Result<Self> {
        let kind = if parent {
            ViewRoot::WindowsNt
        } else {
            ViewRoot::CurrentVersion
        };
        if self.upcase.len() != 65_536 || self.views.roots.contains_key(&(kind, view)) {
            return Err(invalid("invalid or duplicate CurrentVersion view"));
        }
        let logical: Vec<_> = if parent {
            WINDOWS_NT_KEY
        } else {
            CURRENT_VERSION_KEY
        }
        .encode_utf16()
        .collect();
        let physical: Vec<_> = if parent {
            WINDOWS_NT_WOW_KEY
        } else {
            CURRENT_VERSION_WOW_KEY
        }
        .encode_utf16()
        .collect();
        let fold = |name: &[u16]| {
            name.iter()
                .map(|&u| self.upcase[usize::from(u)])
                .collect::<Vec<_>>()
        };
        let mut routes = BTreeMap::new();
        if parent {
            let child = self
                .views
                .roots
                .get(&(ViewRoot::CurrentVersion, view))
                .ok_or_else(|| {
                    invalid("Windows NT parent requires selected CurrentVersion view")
                })?;
            routes.insert(
                fold(&"CurrentVersion".encode_utf16().collect::<Vec<_>>()),
                child.clone(),
            );
        } else {
            for root in [TreeRoot::Ifeo, TreeRoot::GreInitialize] {
                if !self.selected_trees.contains(&root) {
                    continue;
                }
                let path: Vec<_> = root.path().encode_utf16().collect();
                let suffix = path
                    .strip_prefix(logical.as_slice())
                    .and_then(|tail| tail.strip_prefix(&[92]))
                    .expect("fixed CurrentVersion descendant");
                routes.insert(fold(suffix), self.keys.get(&fold(&path)).cloned());
            }
        }
        let missing_path = matches!(&header, Err(STATUS_OBJECT_PATH_NOT_FOUND));
        let selected = match header {
            Ok(CurrentVersionHeader { key, information }) => {
                let canonical = fold(&key.canonical);
                let allowed = canonical == fold(&logical)
                    || view == RegistryView::Wow32 && canonical == fold(&physical);
                if !allowed
                    || key.canonical.contains(&0)
                    || information.canonical() != key.canonical
                    || key.access.maximum_access & !access::KEY_ALL_ACCESS != 0
                    || key.access.system_security_status != 0
                        && key.access.system_security_status & 0x8000_0000 == 0
                {
                    return Err(invalid("CurrentVersion header escapes its fixed subject"));
                }
                let entries = key
                    .enumeration
                    .ok_or_else(|| invalid("CurrentVersion requires ordered child metadata"))?;
                let mut values = self.value_budget()?;
                let contents = bounded_values(&self.upcase, key.values, &mut values)?;
                let entries = key_enumeration::bounded(
                    &self.upcase,
                    Some(entries),
                    key.children,
                    &mut values,
                )?;
                let mut paths = self.view_budget()?;
                paths.charge(&key.canonical, 0)?;
                paths.charge_alias(&logical)?;
                let order = entries
                    .as_ref()
                    .ok_or_else(|| invalid("CurrentVersion lost ordered child metadata"))?;
                for (name, child) in &routes {
                    if order.iter().any(|entry| fold(&entry.name) == *name) != child.is_some() {
                        return Err(invalid(
                            "CurrentVersion metadata contradicts a selected child",
                        ));
                    }
                }
                let mut result = Key {
                    information: None,
                    enumeration: entries,
                    path: key.canonical,
                    redirected_view: Some(view),
                    children: key.children,
                    upcase: self.upcase.clone(),
                    values: Arc::new(contents),
                    subkeys: None,
                    selected_child: None,
                    selected_paths: routes,
                    command_access: Some(key.access),
                    open_denial: None,
                    logical_path: Some(logical.clone().into()),
                    root_views: None,
                    machine: None,
                };
                information.check_contents(&result)?;
                values.charge_information(&information)?;
                result.information = Some(Arc::new(information));
                for ((other_kind, _), other) in &self.views.roots {
                    if *other_kind == kind
                        && let Some(other) = other
                        && result.fold(&result.path) == other.fold(&other.path)
                        && (!command_processor::subtree::same_physical_contents(&result, other)
                            || result.information != other.information)
                    {
                        return Err(invalid("CurrentVersion shared view changed during capture"));
                    }
                }
                Some(Arc::new(result))
            }
            Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => {
                if routes.values().any(Option::is_some) {
                    return Err(invalid("absent CurrentVersion parent has a selected child"));
                }
                None
            }
            Err(_) => return Err(invalid("CurrentVersion absence is not native not-found")),
        };
        let views = Arc::make_mut(&mut self.views);
        views.upcase = self.upcase.clone();
        views.paths.insert(kind, logical.into());
        views.roots.insert((kind, view), selected);
        if missing_path {
            views.missing_paths.insert((kind, view));
        }
        self.relink_machine_hive()?;
        Ok(self)
    }
}

impl Key {
    fn is_current_version(&self) -> bool {
        self.logical_path.as_deref().is_some_and(|path| {
            path.iter().copied().eq(CURRENT_VERSION_KEY.encode_utf16())
                || path.iter().copied().eq(WINDOWS_NT_KEY.encode_utf16())
        })
    }

    pub(super) fn current_version_missing_child(&self, component: &[u16]) -> bool {
        self.is_current_version()
            && self.enumeration.as_ref().is_some_and(|entries| {
                !entries
                    .iter()
                    .any(|entry| self.fold(&entry.name) == self.fold(component))
            })
    }

    pub(crate) fn current_version_shared_alias(&self, selected: &Key) -> bool {
        if !self.is_current_version() {
            return false;
        }
        let parent = self.fold(&self.path);
        let child = selected.fold(&selected.path);
        child != parent && (!child.starts_with(&parent) || child.get(parent.len()) != Some(&92))
    }

    pub(crate) fn current_version_physical_name(&self, name: &[u16]) -> bool {
        if !self.is_current_version() || self.redirected_view != Some(RegistryView::Wow32) {
            return false;
        }
        let mut normalized = Vec::with_capacity(name.len() + 1);
        for component in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
            normalized.push(92);
            normalized.extend_from_slice(component);
        }
        let name = self.fold(&normalized);
        let parent = self
            .logical_path
            .as_deref()
            .is_some_and(|path| path.iter().copied().eq(WINDOWS_NT_KEY.encode_utf16()));
        let absolute: Vec<_> = if parent {
            WINDOWS_NT_WOW_KEY
        } else {
            CURRENT_VERSION_WOW_KEY
        }
        .encode_utf16()
        .collect();
        let suffix = &absolute[MACHINE_HIVE_KEY.encode_utf16().count()..];
        [absolute.as_slice(), suffix].into_iter().any(|prefix| {
            let prefix = self.fold(prefix);
            name.starts_with(&prefix)
                && (name.len() == prefix.len() || name.get(prefix.len()) == Some(&92))
        })
    }

    pub(crate) fn physical_wow_name(&self, name: &[u16]) -> bool {
        self.command_physical_name(name) || self.current_version_physical_name(name)
    }
}

#[cfg(test)]
#[path = "current_version_tests.rs"]
pub(crate) mod tests;
