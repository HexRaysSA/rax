//! TOKEN_PRIVILEGES buffer geometry shared by the native capture and guest query.

use crate::user::windows::security::Privilege;
use std::collections::HashMap;

pub(crate) const TOKEN_PRIVILEGES: u32 = 3;
pub(crate) const ENABLED: u32 = 2;
const REMOVED: u32 = 4;
pub(crate) const HEADER_BYTES: usize = 4;
pub(crate) const ENTRY_BYTES: usize = 12;

/// Returns the required capacity and the number of bytes published. An empty
/// array still requires sizeof(TOKEN_PRIVILEGES), which includes one entry.
pub(crate) fn sizes(count: usize) -> Option<(usize, usize)> {
    if count > 4096 {
        return None;
    }
    let data_bytes = HEADER_BYTES + ENTRY_BYTES * count;
    Some((data_bytes.max(HEADER_BYTES + ENTRY_BYTES), data_bytes))
}

pub(crate) struct Change {
    pub(crate) privileges: Vec<Privilege>,
    pub(crate) previous: Vec<Privilege>,
    pub(crate) required: usize,
    pub(crate) changed: bool,
    pub(crate) missing: bool,
}

impl Change {
    /// Computes native previous-state capacity from the original token and
    /// then applies the entries in caller order. Duplicate input LUIDs can
    /// therefore make the required capacity and actual record size differ.
    /// Expected O(P + N) time and O(P + N) storage for P owned and N input
    /// privileges. Both counts are bounded by the token capture limit.
    pub(crate) fn plan(original: &[Privilege], requested: Option<&[Privilege]>) -> Self {
        let Some(requested) = requested else {
            let mut privileges = original.to_vec();
            let mut previous = Vec::new();
            for entry in &mut privileges {
                if entry.attributes & ENABLED != 0 {
                    previous.push(entry.clone());
                    entry.attributes &= !ENABLED;
                }
            }
            return Self {
                privileges,
                required: record_bytes(previous.len()),
                changed: !previous.is_empty(),
                previous,
                missing: false,
            };
        };

        let mut positions: HashMap<u64, usize> = original
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.luid, index))
            .collect();
        let projected = requested
            .iter()
            .filter(|entry| {
                entry.attributes & REMOVED == 0
                    && positions.get(&entry.luid).is_some_and(|&index| {
                        (original[index].attributes ^ entry.attributes) & ENABLED != 0
                    })
            })
            .count();
        let mut privileges: Vec<_> = original.iter().cloned().map(Some).collect();
        let mut previous = Vec::new();
        let (mut changed, mut missing) = (false, false);
        for entry in requested {
            let Some(&index) = positions.get(&entry.luid) else {
                missing = true;
                continue;
            };
            if entry.attributes & REMOVED != 0 {
                positions.remove(&entry.luid);
                privileges[index] = None;
                changed = true;
            } else {
                let current = privileges[index].as_mut().expect("live privilege index");
                let attributes = (current.attributes & !ENABLED) | (entry.attributes & ENABLED);
                if attributes != current.attributes {
                    previous.push(current.clone());
                    current.attributes = attributes;
                    changed = true;
                }
            }
        }
        Self {
            privileges: privileges.into_iter().flatten().collect(),
            previous,
            required: record_bytes(projected),
            changed,
            missing,
        }
    }
}

/// Capacity occupied by a native TOKEN_PRIVILEGES result, including its
/// first, zero-filled record when no previous privilege is reported.
pub(crate) fn record_bytes(count: usize) -> usize {
    HEADER_BYTES + ENTRY_BYTES * count.max(1)
}
