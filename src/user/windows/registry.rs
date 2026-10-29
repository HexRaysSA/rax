//! Immutable, explicitly selected runtime registry metadata. Guest key handles
//! reference these records; they never contain or forward a host HKEY.
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

pub(crate) const NLS_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage";
pub(crate) const SESSION_MANAGER_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager";
pub(crate) const WNF_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Notifications";
pub(crate) const MAX_VALUES: usize = 4096;
pub(crate) const MAX_NAME_UNITS: usize = 16_383;
pub(crate) const MAX_VALUE_BYTES: usize = 1 << 20;
const MAX_TOTAL_BYTES: usize = 16 << 20;

#[path = "registry/tree.rs"]
mod tree;
#[cfg(test)]
pub(crate) use tree::KeyTree as IfeoTree;
pub(crate) use tree::{
    COMMON_GLOB_USER_SETTINGS_KEY, DISPLAY_POLICY_KEY, ERROR_MESSAGE_INSTRUMENT_KEY,
    FILESYSTEM_KEY, GRE_INITIALIZE_KEY, IFEO_KEY, KeyTree, LANGUAGE_OVERLAY_PACKAGES_KEY, Lookup,
    MUI_SETTINGS_KEY, MUI_SYSTEM_KEY, NLS_SORTING_VERSIONS_KEY, REDIRECTION_KEYS_KEY,
    SAFEBOOT_OPTION_KEY, SAFER_CODE_IDENTIFIERS_KEY, SRP_DLL_KEY, TreeRoot,
};
#[path = "registry/user_policy.rs"]
mod user_policy;
pub(crate) use user_policy::{UserPolicyRoot, user_policy_path};
#[path = "registry/primary_hive.rs"]
mod primary_hive;
#[cfg(test)]
pub(crate) use primary_hive::HiveHeader;
use primary_hive::PrimaryHive;
#[path = "registry/appmodel.rs"]
mod appmodel;
pub(crate) use appmodel::AppModelRoot;
#[path = "registry/redirected.rs"]
mod redirected;
pub(crate) use redirected::{RegistryView, RegistryViews, ViewRoot};
#[path = "registry/command_processor.rs"]
mod command_processor;
pub(crate) use command_processor::{COMMAND_PROCESSOR_KEY, CommandHeader, CommandRoot};
#[path = "registry/fixed.rs"]
mod fixed;
pub(crate) use fixed::SEGMENT_HEAP_KEY;
#[path = "registry/machine_hive.rs"]
mod machine_hive;
use machine_hive::MachineKey;
pub(crate) use machine_hive::{MACHINE_HIVE_KEY, MachineHeader};
#[path = "registry/access.rs"]
mod access;
pub(crate) use access::KeyAccess;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Value {
    pub(crate) name: Vec<u16>,
    pub(crate) kind: u32,
    pub(crate) data: Vec<u8>,
}

pub(crate) struct SelectedKey {
    pub(crate) path: &'static str,
    pub(crate) children: u32,
    pub(crate) values: Vec<Value>,
}

/// A guest-owned immutable registry key, shared by reference-counted handles.
/// No native handle or host-operation callback is stored in this object.
#[derive(Debug)]
pub struct Key {
    pub(crate) path: Vec<u16>,
    pub(crate) redirected_view: Option<RegistryView>,
    pub(crate) children: u32,
    upcase: Arc<[u16]>,
    values: Arc<BTreeMap<Vec<u16>, Value>>,
    subkeys: Option<BTreeMap<Vec<u16>, Arc<Key>>>,
    selected_child: Option<(Vec<u16>, Option<Arc<Key>>)>,
    selected_paths: BTreeMap<Vec<u16>, Option<Arc<Key>>>,
    command_access: Option<KeyAccess>,
    logical_path: Option<Arc<[u16]>>,
    root_views: Option<Arc<RegistryViews>>,
    machine: Option<MachineKey>,
}
impl Key {
    #[cfg(test)]
    pub(crate) fn captured_children(&self) -> Option<impl Iterator<Item = &Arc<Key>>> {
        self.subkeys.as_ref().map(|children| children.values())
    }
    pub(crate) fn fold(&self, units: &[u16]) -> Vec<u16> {
        units.iter().map(|&u| self.upcase[usize::from(u)]).collect()
    }
    pub(crate) fn value(&self, name: &[u16]) -> Option<&Value> {
        self.values.get(&self.fold(name))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Registry {
    keys: BTreeMap<Vec<u16>, Arc<Key>>,
    upcase: Arc<[u16]>,
    selected_trees: BTreeSet<TreeRoot>,
    user_policies: BTreeMap<UserPolicyRoot, Arc<[u16]>>,
    primary_hive: Option<PrimaryHive>,
    machine_hive: Option<Arc<Key>>,
    pub(crate) views: Arc<RegistryViews>,
}
impl Registry {
    #[cfg(test)]
    pub(crate) fn nls(upcase: Vec<u16>, values: Vec<Value>, children: u32) -> io::Result<Self> {
        Self::selected(
            upcase,
            vec![SelectedKey {
                path: NLS_KEY,
                children,
                values,
            }],
        )
    }
    pub(crate) fn selected(upcase: Vec<u16>, selected: Vec<SelectedKey>) -> io::Result<Self> {
        if upcase.len() != 65_536 || selected.len() > 2 {
            return Err(invalid("runtime registry table exceeds bounds"));
        }
        let mut result = Self {
            keys: BTreeMap::new(),
            upcase: upcase.into(),
            selected_trees: BTreeSet::new(),
            user_policies: BTreeMap::new(),
            primary_hive: None,
            machine_hive: None,
            views: Arc::default(),
        };
        let mut budget = ValueBudget::default();
        for selected in selected {
            if !matches!(selected.path, NLS_KEY | SESSION_MANAGER_KEY) {
                return Err(invalid("registry key outside fixed runtime selection"));
            }
            let key = Key {
                path: selected.path.encode_utf16().collect(),
                redirected_view: None,
                children: selected.children,
                upcase: result.upcase.clone(),
                values: Arc::new(bounded_values(
                    &result.upcase,
                    selected.values,
                    &mut budget,
                )?),
                subkeys: None,
                selected_child: None,
                selected_paths: BTreeMap::new(),
                command_access: None,
                logical_path: None,
                root_views: None,
                machine: None,
            };
            if result
                .keys
                .insert(key.fold(&key.path), Arc::new(key))
                .is_some()
            {
                return Err(invalid("duplicate selected runtime registry key"));
            }
        }
        Ok(result)
    }
    pub(crate) fn upcase_table(&self) -> Arc<[u16]> {
        self.upcase.clone()
    }
    pub(crate) fn codepages(&self) -> std::collections::BTreeSet<u32> {
        // Session Manager numeric names are not codepage declarations.
        let key = self.key(&NLS_KEY.encode_utf16().collect::<Vec<_>>());
        key.as_ref()
            .into_iter()
            .flat_map(|key| key.values.values())
            .filter_map(|value| {
                if value.name.is_empty() {
                    return None;
                }
                value.name.iter().try_fold(0u32, |n, &u| {
                    if !(48..=57).contains(&u) {
                        return None;
                    }
                    n.checked_mul(10)?.checked_add(u32::from(u - 48))
                })
            })
            .collect()
    }
    pub(crate) fn key(&self, name: &[u16]) -> Option<Arc<Key>> {
        match self.lookup(name) {
            Lookup::Present(key) => Some(key),
            _ => None,
        }
    }
    pub(crate) fn lookup(&self, name: &[u16]) -> Lookup {
        self.lookup_view(name, RegistryView::Native64)
    }
    pub(crate) fn lookup_view(&self, name: &[u16], view: RegistryView) -> Lookup {
        match self.views.lookup(name, view) {
            Lookup::Unselected => {}
            selected => return selected,
        }
        if self.keys.is_empty()
            && self.selected_trees.is_empty()
            && self.user_policies.is_empty()
            && self.primary_hive.is_none()
            && self.machine_hive.is_none()
        {
            return Lookup::Unselected;
        }
        let folded: Vec<_> = name.iter().map(|&u| self.upcase[usize::from(u)]).collect();
        if let Some(key) = self.keys.get(&folded) {
            return Lookup::Present(key.clone());
        }
        match self.machine_hive_lookup(&folded, name, view) {
            Lookup::Unselected => {}
            selected => return selected,
        }
        match self.tree_lookup(&folded, name) {
            Lookup::Unselected => match self.primary_hive_lookup(&folded, name, view) {
                Lookup::Unselected => self.segment_heap_lookup(&folded, name),
                selected => selected,
            },
            selected => selected,
        }
    }
}

#[derive(Default)]
struct ValueBudget {
    count: usize,
    bytes: usize,
}
impl ValueBudget {
    fn charge(&mut self, value: &Value) -> io::Result<()> {
        if value.name.len() > MAX_NAME_UNITS || value.data.len() > MAX_VALUE_BYTES {
            return Err(invalid("runtime registry value exceeds bounds"));
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("runtime registry count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(value.name.len() * 2 + value.data.len())
            .ok_or_else(|| invalid("runtime registry size overflow"))?;
        if self.count > MAX_VALUES || self.bytes > MAX_TOTAL_BYTES {
            return Err(invalid("runtime registry aggregate exceeds bounds"));
        }
        Ok(())
    }
}
fn bounded_values(
    upcase: &[u16],
    values: Vec<Value>,
    budget: &mut ValueBudget,
) -> io::Result<BTreeMap<Vec<u16>, Value>> {
    let mut result = BTreeMap::new();
    for value in values {
        budget.charge(&value)?;
        let name: Vec<_> = value.name.iter().map(|&u| upcase[usize::from(u)]).collect();
        if result.insert(name, value).is_some() {
            return Err(invalid("duplicate runtime registry values"));
        }
    }
    Ok(result)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(windows)]
#[path = "registry/installed.rs"]
mod installed;
#[cfg(windows)]
pub(crate) use installed::wnf_values;
#[cfg(windows)]
pub(crate) use installed::{capture_primary_user, snapshot};
#[cfg(not(windows))]
pub(crate) fn snapshot() -> io::Result<Registry> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "installed runtime registry metadata requires Windows",
    ))
}

#[cfg(not(windows))]
pub(crate) fn capture_primary_user(_: Registry, _: &[u8]) -> io::Result<Registry> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "installed primary-user registry metadata requires Windows",
    ))
}

#[cfg(test)]
#[path = "registry/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "registry/safeboot_tests.rs"]
mod safeboot_tests;

#[cfg(test)]
#[path = "registry/srp_tests.rs"]
mod srp_tests;

#[cfg(test)]
#[path = "registry/safer_tests.rs"]
mod safer_tests;

#[cfg(test)]
#[path = "registry/user_policy_tests.rs"]
mod user_policy_tests;

#[cfg(test)]
#[path = "registry/filesystem_tests.rs"]
mod filesystem_tests;

#[cfg(test)]
#[path = "registry/nls_sorting_tests.rs"]
mod nls_sorting_tests;

#[cfg(test)]
#[path = "registry/error_message_instrument_tests.rs"]
mod error_message_instrument_tests;

#[cfg(test)]
#[path = "registry/display_policy_tests.rs"]
mod display_policy_tests;

#[cfg(test)]
#[path = "registry/gre_initialize_tests.rs"]
pub(crate) mod gre_initialize_tests;

#[cfg(test)]
#[path = "registry/common_glob_user_settings_tests.rs"]
mod common_glob_user_settings_tests;

#[cfg(test)]
#[path = "registry/mui_settings_tests.rs"]
mod mui_settings_tests;

#[cfg(test)]
#[path = "registry/mui_system_tests.rs"]
mod mui_system_tests;

#[cfg(test)]
#[path = "registry/language_overlay_packages_tests.rs"]
mod language_overlay_packages_tests;
