//! The one optional, partially captured fixed Session Manager descendant.
//! Present/absent selection is owned by the parent; other siblings stay unknown.
use super::*;

pub(crate) const SEGMENT_HEAP_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
const CHILD: &str = "Segment Heap";

impl Registry {
    pub(crate) fn with_segment_heap(mut self, selected: Option<SelectedKey>) -> io::Result<Self> {
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
                    path: SEGMENT_HEAP_KEY.encode_utf16().collect(),
                    children: selected.children,
                    upcase: self.upcase.clone(),
                    values: Arc::new(bounded_values(
                        &self.upcase,
                        selected.values,
                        &mut self.value_budget()?,
                    )?),
                    subkeys: None,
                    selected_child: None,
                }))
            }
            None => None,
        };
        let key = Key {
            path: parent.path.clone(),
            children: parent.children,
            upcase: parent.upcase.clone(),
            values: parent.values.clone(),
            subkeys: None,
            selected_child: Some((
                parent.fold(&CHILD.encode_utf16().collect::<Vec<_>>()),
                child,
            )),
        };
        self.keys.insert(name, Arc::new(key));
        Ok(self)
    }
    pub(super) fn segment_heap_lookup(&self, folded: &[u16], original: &[u16]) -> Lookup {
        let prefix: Vec<_> = SEGMENT_HEAP_KEY
            .encode_utf16()
            .map(|u| self.upcase[usize::from(u)])
            .collect();
        if folded != prefix
            && (!folded.starts_with(&prefix) || original.get(prefix.len()) != Some(&92))
        {
            return Lookup::Unselected;
        }
        let parent_name: Vec<_> = SESSION_MANAGER_KEY.encode_utf16().collect();
        let Some(parent) = self.keys.get(
            &parent_name
                .iter()
                .map(|&u| self.upcase[usize::from(u)])
                .collect::<Vec<_>>(),
        ) else {
            return Lookup::Unselected;
        };
        if parent.selected_child.is_none() {
            return Lookup::Unselected;
        }
        parent.relative(&original[parent_name.len() + 1..])
    }
}

#[cfg(test)]
#[path = "fixed_tests.rs"]
mod tests;
