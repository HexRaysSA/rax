//! Installed glibc linker-cache paths. The guest loader still interprets the
//! original cache and chooses the ABI and hardware-capability variant.
use crate::user::supplied_fs::{NAME_MAX, PATH_MAX};

const LEGACY_MAGIC: &[u8] = b"ld.so-1.7.0";
const LEGACY_HEADER: usize = 16;
const LEGACY_ENTRY: usize = 12;
const CURRENT_MAGIC: &[u8] = b"glibc-ld.so.cache1.1";
const CURRENT_HEADER: usize = 48;
const CURRENT_ENTRY: usize = 24;

pub(super) fn paths(cache: &[u8]) -> impl Iterator<Item = &str> {
    table(cache)
        .into_iter()
        .flat_map(|(entries, entry_size, strings, string_base)| {
            entries.chunks_exact(entry_size).filter_map(move |entry| {
                let offset = word(entry, 8)?.checked_sub(string_base)?;
                let value = strings.get(offset..)?;
                let bounded = &value[..value.len().min(PATH_MAX)];
                let end = bounded.iter().position(|&byte| byte == 0)?;
                let path = std::str::from_utf8(&bounded[..end]).ok()?;
                let name = path.strip_prefix('/')?;
                if name.split('/').any(|part| {
                    part.is_empty() || part == "." || part == ".." || part.len() > NAME_MAX
                }) {
                    return None;
                }
                Some(path)
            })
        })
}

fn word(bytes: &[u8], offset: usize) -> Option<usize> {
    Some(u32::from_ne_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize)
}

// Modern string indices are relative to the start of their header. Legacy
// string indices are relative to the end of their entry array. A compatibility
// cache embeds the modern header at the aligned end of its legacy entries.
fn table(cache: &[u8]) -> Option<(&[u8], usize, &[u8], usize)> {
    let current = if cache.starts_with(LEGACY_MAGIC) {
        let legacy_end = LEGACY_HEADER.checked_add(word(cache, 12)?.checked_mul(LEGACY_ENTRY)?)?;
        let strings = cache.get(legacy_end..)?;
        let aligned = legacy_end.checked_add(7)? & !7;
        match cache
            .get(aligned..)
            .filter(|bytes| bytes.starts_with(CURRENT_MAGIC))
        {
            Some(current) => current,
            None if strings.starts_with(CURRENT_MAGIC) => strings,
            None => {
                return Some((
                    cache.get(LEGACY_HEADER..legacy_end)?,
                    LEGACY_ENTRY,
                    strings,
                    0,
                ));
            }
        }
    } else if cache.starts_with(CURRENT_MAGIC) {
        cache
    } else {
        return None;
    };
    let endian = current.get(28)? & 3;
    let native = if cfg!(target_endian = "little") { 2 } else { 3 };
    if endian != 0 && endian != native {
        return None;
    }
    let string_base = CURRENT_HEADER.checked_add(word(current, 20)?.checked_mul(CURRENT_ENTRY)?)?;
    let string_end = string_base.checked_add(word(current, 24)?)?;
    Some((
        current.get(CURRENT_HEADER..string_base)?,
        CURRENT_ENTRY,
        current.get(string_base..string_end)?,
        string_base,
    ))
}

#[cfg(test)]
pub(super) fn fixture(paths: &[&str]) -> Vec<u8> {
    let start = CURRENT_HEADER + paths.len() * CURRENT_ENTRY;
    let mut bytes = vec![0; start];
    bytes[..CURRENT_MAGIC.len()].copy_from_slice(CURRENT_MAGIC);
    bytes[20..24].copy_from_slice(&(paths.len() as u32).to_ne_bytes());
    for (index, path) in paths.iter().enumerate() {
        let value = CURRENT_HEADER + index * CURRENT_ENTRY + 8;
        let offset = bytes.len() as u32;
        bytes[value..value + 4].copy_from_slice(&offset.to_ne_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
    }
    let strings = (bytes.len() - start) as u32;
    bytes[24..28].copy_from_slice(&strings.to_ne_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIBRARY: &str = "/opt/runtime/libplugin.so.1";

    #[test]
    fn linker_cache_paths_support_legacy_current_and_combined_caches() {
        let mut legacy = vec![0; LEGACY_HEADER + LEGACY_ENTRY];
        legacy[..LEGACY_MAGIC.len()].copy_from_slice(LEGACY_MAGIC);
        legacy[12..16].copy_from_slice(&1u32.to_ne_bytes());
        let mut combined = legacy.clone();
        combined.resize(combined.len().next_multiple_of(8), 0);
        let current = fixture(&[LIBRARY]);
        combined.extend_from_slice(&current);
        legacy.extend_from_slice(LIBRARY.as_bytes());
        legacy.push(0);
        for cache in [legacy, current, combined] {
            assert_eq!(paths(&cache).collect::<Vec<_>>(), [LIBRARY]);
        }
    }

    #[test]
    fn linker_cache_paths_ignore_invalid_bounds_endian_and_path_components() {
        let mut cache = fixture(&[LIBRARY]);
        let mut wrong_endian = cache.clone();
        wrong_endian[28] = if cfg!(target_endian = "little") { 3 } else { 2 };
        assert!(paths(&wrong_endian).next().is_none());
        assert!(paths(&cache[..cache.len() - 1]).next().is_none());

        let string = CURRENT_HEADER + CURRENT_ENTRY;
        cache[string + 1..string + 5].copy_from_slice(b"../x");
        assert!(paths(&cache).next().is_none());
        cache[CURRENT_HEADER + 8..CURRENT_HEADER + 12].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(paths(&cache).next().is_none());
    }
}
