//! The installed API-set namespace (version 6), selected with native DLLs.
//!
//! Layout is decoded from the installed `.apiset` section. Contract semantics:
//! <https://learn.microsoft.com/windows/win32/apiindex/windows-apisets>.
//! Parent aliases take precedence over the default value; no family inference.

use std::collections::BTreeMap;
use std::sync::Arc;

const MAX_SCHEMA: usize = 4 << 20;
const MAX_ENTRIES: usize = 1 << 16;

#[derive(Clone, Debug)]
pub(crate) struct ApiSetSchema {
    pub(crate) bytes: Arc<[u8]>,
    contracts: BTreeMap<String, BTreeMap<String, String>>,
}

fn malformed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "malformed installed API-set namespace",
    )
}
fn u32_at(bytes: &[u8], at: usize) -> std::io::Result<u32> {
    let end = at.checked_add(4).ok_or_else(malformed)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(at..end)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn extent(bytes: &[u8], at: u32, count: u32, width: usize) -> std::io::Result<&[u8]> {
    let start = at as usize;
    let len = (count as usize).checked_mul(width).ok_or_else(malformed)?;
    bytes
        .get(start..start.checked_add(len).ok_or_else(malformed)?)
        .ok_or_else(malformed)
}
fn wide(bytes: &[u8], at: u32, len: u32) -> std::io::Result<String> {
    if len > 8192 || len % 2 != 0 {
        return Err(malformed());
    }
    let units = extent(bytes, at, len / 2, 2)?
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    let value = String::from_utf16(&units).map_err(|_| malformed())?;
    if value.contains('\0') {
        return Err(malformed());
    }
    Ok(value.to_ascii_lowercase())
}

impl ApiSetSchema {
    pub(crate) fn parse(bytes: &[u8]) -> std::io::Result<Self> {
        if bytes.len() < 28 || u32_at(bytes, 0)? != 6 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "installed API-set namespace requires version 6",
            ));
        }
        let size = u32_at(bytes, 4)? as usize;
        if !(28..=MAX_SCHEMA).contains(&size) {
            return Err(malformed());
        }
        let bytes = bytes.get(..size).ok_or_else(malformed)?;
        let count = u32_at(bytes, 12)?;
        if count as usize > MAX_ENTRIES {
            return Err(malformed());
        }
        let entries = extent(bytes, u32_at(bytes, 16)?, count, 24)?;
        let mut contracts = BTreeMap::new();
        let mut total_values = 0usize;
        let mut text_bytes = 0usize;
        for entry in entries.chunks_exact(24) {
            let name = wide(bytes, u32_at(entry, 4)?, u32_at(entry, 8)?)?;
            text_bytes = text_bytes
                .checked_add(u32_at(entry, 8)? as usize)
                .ok_or_else(malformed)?;
            if text_bytes > MAX_SCHEMA {
                return Err(malformed());
            }
            if name.is_empty()
                || !super::apiset::is_api_set(&name)
                || name.ends_with(".dll")
                || name.contains(['\\', '/', ':'])
            {
                return Err(malformed());
            }
            let hashed = u32_at(entry, 12)?;
            if hashed % 2 != 0 || hashed > u32_at(entry, 8)? {
                return Err(malformed());
            }
            let values = u32_at(entry, 20)?;
            total_values = total_values
                .checked_add(values as usize)
                .ok_or_else(malformed)?;
            if total_values > MAX_ENTRIES {
                return Err(malformed());
            }
            let mut hosts = BTreeMap::new();
            for value in extent(bytes, u32_at(entry, 16)?, values, 20)?.chunks_exact(20) {
                let alias = wide(bytes, u32_at(value, 4)?, u32_at(value, 8)?)?;
                let host = wide(bytes, u32_at(value, 12)?, u32_at(value, 16)?)?;
                text_bytes = text_bytes
                    .checked_add(u32_at(value, 8)? as usize)
                    .and_then(|n| n.checked_add(u32_at(value, 16).ok()? as usize))
                    .ok_or_else(malformed)?;
                if text_bytes > MAX_SCHEMA {
                    return Err(malformed());
                }
                // An empty host is an explicitly unavailable contract. It must
                // remain unavailable rather than infer a neighboring family.
                if host.contains(['\\', '/', ':']) || alias.contains(['\\', '/', ':']) {
                    return Err(malformed());
                }
                if hosts.insert(alias, host).is_some() {
                    return Err(malformed());
                }
            }
            if contracts.insert(name, hosts).is_some() {
                return Err(malformed());
            }
        }
        Ok(Self {
            bytes: Arc::from(bytes),
            contracts,
        })
    }

    pub(crate) fn host(&self, name: &str, parent: Option<&str>) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        let contract = lower.strip_suffix(".dll").unwrap_or(&lower);
        let hosts = self.contracts.get(contract)?;
        let parent = parent.map(str::to_ascii_lowercase);
        let host = parent
            .as_ref()
            .and_then(|parent| hosts.get(parent))
            .or_else(|| hosts.get(""))?;
        (!host.is_empty()).then_some(host.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; 112];
        for (at, value) in [
            (0, 6),
            (12, 1),
            (16, 28),
            (32, 112),
            (36, 42),
            (40, 42),
            (44, 52),
            (48, 3),
        ] {
            b[at..at + 4].copy_from_slice(&u32::to_le_bytes(value));
        }
        let name = "api-test-core-l1-1-0";
        let name_bytes: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        b[36..40].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        b[40..44].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        b.extend(name_bytes);
        for (slot, alias, host) in [
            (52, "", "default.dll"),
            (72, "caller.dll", "redirect.dll"),
            (92, "absent.dll", ""),
        ] {
            for (field, value) in [(4, alias), (12, host)] {
                let at = b.len() as u32;
                let text: Vec<_> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
                b[slot + field..slot + field + 4].copy_from_slice(&at.to_le_bytes());
                b[slot + field + 4..slot + field + 8]
                    .copy_from_slice(&(text.len() as u32).to_le_bytes());
                b.extend(text);
            }
        }
        let size = b.len() as u32;
        b[4..8].copy_from_slice(&size.to_le_bytes());
        b
    }
    #[test]
    fn exact_contract_default_alias_and_unavailable_paths() {
        let b = fixture();
        let s = ApiSetSchema::parse(&b).unwrap();
        assert_eq!(
            s.host("API-TEST-CORE-L1-1-0.DLL", None),
            Some("default.dll")
        );
        assert_eq!(
            s.host("api-test-core-l1-1-0", Some("CALLER.DLL")),
            Some("redirect.dll")
        );
        assert_eq!(s.host("api-test-core-l1-1-0", Some("absent.dll")), None);
        assert_eq!(s.host("api-test-core-l1-2-0", None), None);
        assert_eq!(&*s.bytes, &b);
    }
    #[test]
    fn truncated_overflowing_invalid_utf16_and_unsupported_namespaces_fail() {
        let valid = fixture();
        for n in 0..valid.len() {
            assert!(ApiSetSchema::parse(&valid[..n]).is_err());
        }
        for (at, value) in [
            (0, 7),
            (4, u32::MAX),
            (12, u32::MAX),
            (16, u32::MAX),
            (32, u32::MAX),
            (36, 1),
            (48, u32::MAX),
        ] {
            let mut b = valid.clone();
            b[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                ApiSetSchema::parse(&b).is_err(),
                "accepted invalid field at {at}"
            );
        }
        let mut b = valid.clone();
        b[112..114].copy_from_slice(&0xD800u16.to_le_bytes());
        assert!(ApiSetSchema::parse(&b).is_err());
    }
}
