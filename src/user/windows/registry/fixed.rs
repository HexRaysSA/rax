//! Fixed Session Manager descendants selected independently under the parent.
use super::*;

pub(crate) const SEGMENT_HEAP_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
#[cfg(any(windows, test))]
pub(crate) const APPCERT_DLLS_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls";
const CHILD: &str = "Segment Heap";

impl Registry {
    pub(crate) fn with_session_manager_children(
        mut self,
        selected: Option<SelectedKey>,
        appcert_absent: bool,
    ) -> io::Result<Self> {
        if self.upcase.len() != 65_536 {
            return Err(invalid("Segment Heap lacks selected ordinal case table"));
        }
        let name: Vec<_> = SESSION_MANAGER_KEY
            .encode_utf16()
            .map(|u| self.upcase[usize::from(u)])
            .collect();
        let parent = self
            .keys
            .get(&name)
            .ok_or_else(|| invalid("Segment Heap lacks selected parent"))?;
        if parent.selected_child.is_some() {
            return Err(invalid("duplicate Segment Heap selection"));
        }
        let child = match selected {
            Some(selected) => {
                if selected.path != SEGMENT_HEAP_KEY || parent.children == 0 {
                    return Err(invalid("invalid or contradictory Segment Heap capture"));
                }
                Some(Arc::new(Key {
                    information: None,
                    enumeration: None,
                    path: SEGMENT_HEAP_KEY.encode_utf16().collect(),
                    redirected_view: None,
                    children: selected.children,
                    upcase: self.upcase.clone(),
                    values: Arc::new(bounded_values(
                        &self.upcase,
                        selected.values,
                        &mut self.value_budget()?,
                    )?),
                    subkeys: None,
                    selected_child: None,
                    selected_paths: BTreeMap::new(),
                    command_access: None,
                    open_denial: None,
                    logical_path: None,
                    root_views: None,
                    machine: None,
                }))
            }
            None => None,
        };
        let mut selected_paths = BTreeMap::new();
        if appcert_absent {
            let component = "AppCertDlls".encode_utf16().collect::<Vec<_>>();
            selected_paths.insert(parent.fold(&component), Lookup::Missing);
        }
        let key = Key {
            information: None,
            enumeration: parent.enumeration.clone(),
            path: parent.path.clone(),
            redirected_view: None,
            children: parent.children,
            upcase: parent.upcase.clone(),
            values: parent.values.clone(),
            subkeys: None,
            selected_child: Some((
                parent.fold(&CHILD.encode_utf16().collect::<Vec<_>>()),
                child,
            )),
            selected_paths,
            command_access: None,
            open_denial: None,
            logical_path: None,
            root_views: None,
            machine: None,
        };
        self.keys.insert(name, Arc::new(key));
        self.relink_machine_hive()?;
        Ok(self)
    }
    pub(super) fn session_manager_lookup(&self, folded: &[u16], original: &[u16]) -> Lookup {
        let parent_name: Vec<_> = SESSION_MANAGER_KEY
            .encode_utf16()
            .map(|u| self.upcase[usize::from(u)])
            .collect();
        if !folded.starts_with(&parent_name) {
            return Lookup::Unselected;
        }
        let Some(parent) = self.keys.get(&parent_name) else {
            return Lookup::Unselected;
        };
        let offset = parent_name.len();
        if original.get(offset) != Some(&92) {
            return Lookup::Unselected;
        }
        let path = &original[offset + 1..];
        let relative = parent.fold(path.split(|&u| u == 92).next().unwrap_or(&[]));
        let selected_child = parent
            .selected_child
            .as_ref()
            .map(|(name, _)| name.as_slice());
        if selected_child == Some(relative.as_slice())
            || parent.selected_paths.contains_key(&relative)
        {
            parent.relative(path)
        } else {
            Lookup::Unselected
        }
    }
}

#[cfg(test)]
#[path = "fixed_tests.rs"]
mod tests;
