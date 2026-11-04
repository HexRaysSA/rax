//! Fixed-width pointer-free NT directory records on a mapped local volume.
use super::super::Layout;
use crate::user::windows::hle::ApiErr;
use crate::user::windows::objects::DirectoryEntry;

pub(super) fn record(
    entry: &DirectoryEntry,
    class: u32,
    layout: Layout,
) -> Result<Vec<u8>, ApiErr> {
    let mut bytes = vec![0; layout.name + entry.name.len() * 2];
    let name_length = u32::try_from(entry.name.len() * 2)
        .map_err(|_| ApiErr::Unimplemented("directory filename exceeds ULONG".into()))?;
    bytes[layout.length..layout.length + 4].copy_from_slice(&name_length.to_le_bytes());
    for (raw, unit) in bytes[layout.name..].chunks_exact_mut(2).zip(&entry.name) {
        raw.copy_from_slice(&unit.to_le_bytes());
    }
    if class == 12 {
        return Ok(bytes);
    }
    for (raw, time) in bytes[8..40].chunks_exact_mut(8).zip(entry.times) {
        raw.copy_from_slice(&time.to_le_bytes());
    }
    bytes[40..48].copy_from_slice(&entry.size.to_le_bytes());
    bytes[48..56].copy_from_slice(&entry.allocation.to_le_bytes());
    bytes[56..60].copy_from_slice(&entry.attributes.to_le_bytes());
    if class != 1 {
        let ea = ea_size(entry.ea.as_deref())?;
        bytes[64..68].copy_from_slice(&ea.to_le_bytes());
    }
    let id = match class {
        37 => Some(96),
        38 => Some(72),
        60 | 63 => Some(72),
        _ => None,
    };
    if let Some(id) = id {
        bytes[id..id + 8].copy_from_slice(&entry.file_id.to_le_bytes());
    }
    let short = match class {
        3 | 37 => Some(68),
        63 => Some(88),
        _ => None,
    };
    if let Some(short) = short {
        if entry.short_name.len() > 12 {
            return Err(ApiErr::Unimplemented(
                "directory alternate filename exceeds12 UTF-16 units".into(),
            ));
        }
        bytes[short] = (entry.short_name.len() * 2) as u8;
        for (raw, unit) in bytes[short + 2..short + 26]
            .chunks_exact_mut(2)
            .zip(&entry.short_name)
        {
            raw.copy_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(bytes)
}

fn ea_size(record: Option<&[u8]>) -> Result<u32, ApiErr> {
    let Some(record) = record.filter(|record| !record.is_empty()) else {
        return Ok(0);
    };
    let invalid = || ApiErr::Unimplemented("invalid retained Windows EA record".into());
    let mut at = 0usize;
    let mut total = 0usize;
    loop {
        let header = record.get(at..at + 8).ok_or_else(invalid)?;
        let next = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let name = usize::from(header[5]);
        let value = usize::from(u16::from_le_bytes(header[6..8].try_into().unwrap()));
        let extent = 8 + name + 1 + value;
        let end = at.checked_add(extent).ok_or_else(invalid)?;
        if end > record.len() || record[at + 8 + name] != 0 {
            return Err(invalid());
        }
        total = total
            .checked_add(extent.next_multiple_of(4))
            .ok_or_else(invalid)?;
        if next == 0 {
            if end != record.len() {
                return Err(invalid());
            }
            return u32::try_from(total).map_err(|_| invalid());
        }
        if next % 4 != 0 || next < extent || next > record.len() - at {
            return Err(invalid());
        }
        at += next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_ea_extent_matches_closed_writer_native_controls_and_rejects_bad_records() {
        let mut stored = Vec::new();
        for (name, value, expected) in [
            ("X", b"x".as_slice(), 12),
            ("ONE", b"xyz".as_slice(), 28),
            ("FOUR", b"abcde".as_slice(), 48),
        ] {
            if !stored.is_empty() {
                let mut at = 0;
                loop {
                    let next = u32::from_le_bytes(stored[at..at + 4].try_into().unwrap()) as usize;
                    if next == 0 {
                        let extent = stored.len() - at;
                        let next = extent.next_multiple_of(4);
                        stored[at..at + 4].copy_from_slice(&(next as u32).to_le_bytes());
                        stored.resize(at + next, 0);
                        break;
                    }
                    at += next;
                }
            }
            let mut record = vec![0; 8];
            record[5] = name.len() as u8;
            record[6..8].copy_from_slice(&(value.len() as u16).to_le_bytes());
            record.extend_from_slice(name.as_bytes());
            record.push(0);
            record.extend_from_slice(value);
            stored.extend_from_slice(&record);
            assert_eq!(ea_size(Some(&stored)).unwrap(), expected);
        }
        for bytes in [
            vec![0; 7],
            vec![0; 8],
            vec![4, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 1, 0, 0, b'X', b'!'],
        ] {
            assert!(ea_size(Some(&bytes)).is_err(), "{bytes:x?}");
        }
        assert_eq!(ea_size(None).unwrap(), 0);
        assert_eq!(ea_size(Some(&[])).unwrap(), 0);
    }
}
