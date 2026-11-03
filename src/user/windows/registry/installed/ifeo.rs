//! Fixed IFEO acquisition keeps parent metadata when a child denies all access.
use super::*;
use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;
use crate::user::windows::registry::tree::{TreeBudget, child_path};
use crate::user::windows::registry::{BasicChild, CapturedTree, CapturedTreeNode, KeyTree};
use std::collections::BTreeMap;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtEnumerateKey(
        key: Hkey,
        index: u32,
        class: u32,
        output: *mut u8,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

#[cfg(test)]
#[path = "ifeo_tests.rs"]
mod tests;

struct Child {
    entry: BasicChild,
    children: u32,
}

pub(super) fn capture(registry: &Registry) -> io::Result<Option<CapturedTree>> {
    capture_with(
        registry,
        |path| super::tree::open(super::super::TreeRoot::Ifeo, path),
        super::native_key::open,
    )
}

fn capture_with(
    registry: &Registry,
    mut read: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
    maximum: impl FnMut(&[u16], u32) -> Result<OwnedKey, u32>,
) -> io::Result<Option<CapturedTree>> {
    let path: Vec<_> = super::super::IFEO_KEY.encode_utf16().collect();
    let key = match read(&path) {
        Ok(key) => key,
        Err(error) if error.raw_os_error() == Some(2) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut capture = Capture {
        values: registry.value_budget()?,
        paths: TreeBudget::default(),
        reserved: 1,
        nodes: BTreeMap::new(),
        read,
        maximum,
    };
    let tree = capture.node(path, 0, Some(key), None)?;
    Ok(Some(CapturedTree {
        tree,
        nodes: capture.nodes,
    }))
}

/// The fully defined KEY_FULL_INFORMATION header is readable through the
/// parent even when the child cannot be opened. Keep only its subkey count.
fn child_count(key: &OwnedKey, index: u32, child: &BasicChild) -> io::Result<u32> {
    let mut samples = Vec::new();
    for poison in [0xA5u8, 0x5A] {
        let mut words = [u64::from_le_bytes([poison; 8]); 6];
        let mut returned = u32::from_le_bytes([poison; 4]);
        // SAFETY: query/enumerate parent, fixed selector and native index,
        // initialized 8-byte-aligned storage of at least44 bytes, exclusive
        // ULONG output. No guest data or pointers reach the host operation.
        let status = unsafe {
            NtEnumerateKey(
                key.0,
                index,
                2,
                words.as_mut_ptr().cast(),
                44,
                &mut returned,
            )
        } as u32;
        if !matches!(status, 0 | 0x8000_0005) || !(44..=131_072).contains(&returned) {
            return Err(invalid(&format!(
                "IFEO child header is unavailable: {status:#010x}, length {returned}"
            )));
        }
        let bytes: Vec<_> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        if bytes[44..].iter().any(|byte| *byte != poison) {
            return Err(invalid("IFEO child header exceeded its declared output"));
        }
        samples.push(bytes[..44].to_vec());
    }
    if samples[0] != samples[1]
        || u64::from_le_bytes(samples[0][..8].try_into().unwrap()) != child.last_write
    {
        return Err(invalid("IFEO child metadata changed during capture"));
    }
    Ok(u32::from_le_bytes(samples[0][20..24].try_into().unwrap()))
}

fn stable(
    key: &OwnedKey,
    values: &super::super::ValueBudget,
    reserved: usize,
) -> io::Result<(Vec<Value>, Vec<Child>)> {
    for _ in 0..3 {
        let before = info(key)?;
        let (raw, entries) = super::key_enumeration::stable(key, values, reserved)?;
        let mut children = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            children.push(Child {
                entry: entry.clone(),
                children: child_count(key, index as u32, entry)?,
            });
        }
        let again = super::key_enumeration::stable(key, values, reserved)?;
        if raw == again.0 && entries == again.1 && before == info(key)? {
            return Ok((raw, children));
        }
    }
    Err(invalid("IFEO parent changed during bounded capture"))
}

struct Capture<R, M> {
    values: super::super::ValueBudget,
    paths: TreeBudget,
    reserved: usize,
    nodes: BTreeMap<Vec<u16>, CapturedTreeNode>,
    read: R,
    maximum: M,
}

impl<R, M> Capture<R, M>
where
    R: FnMut(&[u16]) -> io::Result<OwnedKey>,
    M: FnMut(&[u16], u32) -> Result<OwnedKey, u32>,
{
    fn denied(&mut self, path: &[u16], child: &Child) -> io::Result<KeyTree> {
        // A failed QUERY|ENUMERATE open alone does not prove all opens fail.
        // MAXIMUM_ALLOWED must independently deny, twice. SYSTEM_SECURITY
        // must also report the same denial rather than a privilege failure.
        // Conditional grants/failures remain uncaptured, never misclassified.
        for access in [0x0200_0000, 0x0100_0000, 0x0200_0000] {
            match (self.maximum)(path, access) {
                Err(STATUS_ACCESS_DENIED) => {}
                Err(status) if access == 0x0100_0000 => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "IFEO child has uncaptured system-security open status: {status:#010x}"
                        ),
                    ));
                }
                Err(status) => {
                    return Err(invalid(&format!(
                        "IFEO child access changed during capture: {status:#010x}"
                    )));
                }
                Ok(_key) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "IFEO child has uncaptured access-dependent body availability",
                    ));
                }
            }
        }
        self.nodes.insert(
            path.to_vec(),
            CapturedTreeNode::Denied {
                children: child.children,
            },
        );
        Ok(KeyTree::default())
    }

    fn node(
        &mut self,
        path: Vec<u16>,
        depth: usize,
        supplied: Option<OwnedKey>,
        expected: Option<Child>,
    ) -> io::Result<KeyTree> {
        self.paths.charge(&path, depth)?;
        let key = match supplied {
            Some(key) => key,
            None => match (self.read)(&path) {
                Ok(key) => key,
                Err(error) if error.raw_os_error() == Some(5) => {
                    return self.denied(
                        &path,
                        expected
                            .as_ref()
                            .ok_or_else(|| invalid("denied IFEO child has no parent metadata"))?,
                    );
                }
                Err(error) => return Err(error),
            },
        };
        if let Some(expected) = &expected {
            let info = info(&key)?;
            let time = u64::from(info.time[0]) | u64::from(info.time[1]) << 32;
            if info.children != expected.children || time != expected.entry.last_write {
                return Err(invalid("IFEO descendant changed after parent capture"));
            }
        }
        let (values, children) = stable(&key, &self.values, self.reserved)?;
        drop(key); // No native parent survives while descendant bodies open.
        self.reserved += children.len();
        let entries: Vec<_> = children.iter().map(|child| child.entry.clone()).collect();
        self.values.charge_enumeration(&entries)?;
        for value in &values {
            self.values.charge(value)?;
        }
        self.nodes
            .insert(path.clone(), CapturedTreeNode::Readable(entries));
        let mut selected = Vec::new();
        for child in children {
            let name = child.entry.name.clone();
            let next = child_path(&path, &name)?;
            selected.push((name, self.node(next, depth + 1, None, Some(child))?));
        }
        Ok(KeyTree {
            values,
            children: selected,
        })
    }
}
