//! Fixed machine and creator-SID CMD headers. Descendants remain unselected.
use super::super::nt::status::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND};
use super::*;

pub(crate) const COMMAND_PROCESSOR_KEY: &str =
    "\\Registry\\Machine\\Software\\Microsoft\\Command Processor";
pub(super) const COMMAND_SUFFIX: &str = "\\Software\\Microsoft\\Command Processor";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandRoot {
    Machine,
    User,
}
impl CommandRoot {
    pub(super) fn selection(self) -> ViewRoot {
        match self {
            Self::Machine => ViewRoot::CommandMachine,
            Self::User => ViewRoot::CommandUser,
        }
    }
    pub(crate) fn path(self, sid: &[u8]) -> io::Result<Vec<u16>> {
        match self {
            Self::Machine => Ok(COMMAND_PROCESSOR_KEY.encode_utf16().collect()),
            Self::User => Ok(user_policy::user_hive_path(sid)?
                .into_iter()
                .chain(COMMAND_SUFFIX.encode_utf16())
                .collect()),
        }
    }
}

pub(crate) struct CommandHeader {
    pub(crate) canonical: Vec<u16>,
    pub(crate) children: u32,
    pub(crate) values: Vec<Value>,
    pub(crate) access: KeyAccess,
}

impl Registry {
    pub(crate) fn with_command_view(
        mut self,
        root: CommandRoot,
        sid: &[u8],
        view: RegistryView,
        header: Result<CommandHeader, u32>,
    ) -> io::Result<Self> {
        let selected = root.selection();
        if self.upcase.len() != 65_536 || self.views.roots.contains_key(&(selected, view)) {
            return Err(invalid(
                "invalid or duplicate Command Processor registry view",
            ));
        }
        if root == CommandRoot::User {
            self.check_primary_hive_sid(sid)?;
        }
        let logical = root.path(sid)?;
        if self
            .views
            .paths
            .get(&selected)
            .is_some_and(|path| path.as_ref() != logical)
        {
            return Err(invalid("Command Processor views select different subjects"));
        }
        let missing_path =
            matches!(&header, Err(status) if *status == STATUS_OBJECT_PATH_NOT_FOUND);
        let key = match header {
            Ok(header) => {
                self.check_command_name(root, sid, view, &header.canonical)?;
                if header.access.maximum_access & !super::access::KEY_ALL_ACCESS != 0
                    || header.access.system_security_status != 0
                        && header.access.system_security_status & 0x8000_0000 == 0
                {
                    return Err(invalid("invalid Command Processor access ceiling"));
                }
                let mut metadata = self.view_budget()?;
                metadata.charge(&header.canonical, 0)?;
                let values =
                    bounded_values(&self.upcase, header.values, &mut self.value_budget()?)?;
                Some(Arc::new(Key {
                    path: header.canonical,
                    redirected_view: Some(view),
                    children: header.children,
                    upcase: self.upcase.clone(),
                    values: Arc::new(values),
                    subkeys: None,
                    selected_child: None,
                    selected_paths: BTreeMap::new(),
                    command_access: Some(header.access),
                    logical_path: Some(logical.clone().into()),
                    root_views: None,
                    machine: None,
                }))
            }
            Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => None,
            Err(_) => {
                return Err(invalid(
                    "Command Processor absence is not a native not-found result",
                ));
            }
        };
        if let Some(key) = &key {
            for ((kind, _), other) in &self.views.roots {
                if *kind != selected {
                    continue;
                }
                if let Some(other) = other {
                    if key.fold(&key.path) == other.fold(&other.path)
                        && (key.children != other.children
                            || key.values != other.values
                            || key.command_access != other.command_access)
                    {
                        return Err(invalid(
                            "Command Processor shared physical key changed between view captures",
                        ));
                    }
                }
            }
        }
        let views = Arc::make_mut(&mut self.views);
        views.upcase = self.upcase.clone();
        views.paths.insert(selected, logical.into());
        views.roots.insert((selected, view), key);
        if missing_path {
            views.missing_paths.insert((selected, view));
        }
        self.relink_machine_hive()?;
        self.link_primary_hive_policy()?;
        Ok(self)
    }

    pub(super) fn check_command_name(
        &self,
        root: CommandRoot,
        sid: &[u8],
        view: RegistryView,
        canonical: &[u16],
    ) -> io::Result<()> {
        if canonical.len() > MAX_NAME_UNITS || canonical.contains(&0) {
            return Err(invalid("Command Processor canonical name exceeds bounds"));
        }
        let mut bases = vec![root.path(sid)?];
        if root == CommandRoot::User {
            if let Some(hive) = &self.primary_hive {
                if let Some(key) = &hive.root {
                    bases.push(
                        key.path
                            .iter()
                            .copied()
                            .chain(COMMAND_SUFFIX.encode_utf16())
                            .collect(),
                    );
                }
            }
        }
        if view == RegistryView::Wow32 {
            let redirected: Vec<Vec<u16>> = bases
                .iter()
                .map(|base| {
                    let suffix: Vec<_> = COMMAND_SUFFIX.encode_utf16().collect();
                    base[..base.len() - suffix.len()]
                        .iter()
                        .copied()
                        .chain(
                            "\\Software\\WOW6432Node\\Microsoft\\Command Processor".encode_utf16(),
                        )
                        .collect()
                })
                .collect();
            bases.extend(redirected);
        }
        let fold = |path: &[u16]| {
            path.iter()
                .map(|&u| self.upcase[usize::from(u)])
                .collect::<Vec<_>>()
        };
        if !bases.iter().any(|base| fold(base) == fold(canonical)) {
            return Err(invalid(
                "Command Processor canonical name is outside fixed selection",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "command_processor_tests.rs"]
mod tests;

impl Key {
    pub(crate) fn command_access(&self) -> Option<KeyAccess> {
        self.command_access
    }
    pub(crate) fn command_physical_name(&self, name: &[u16]) -> bool {
        if self.command_access.is_none() {
            return false;
        }
        let mut normalized = Vec::with_capacity(name.len());
        for part in name.split(|u| *u == 92).filter(|part| !part.is_empty()) {
            normalized.push(92);
            normalized.extend_from_slice(part);
        }
        let suffix: Vec<_> = "\\Software\\WOW6432Node\\Microsoft\\Command Processor"
            .encode_utf16()
            .collect();
        self.fold(&normalized).ends_with(&self.fold(&suffix))
    }
}
