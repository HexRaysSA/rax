//! The shared region: the dyld shared cache mapped into a process.
//!
//! On macOS the shared region is set up by the first process's `dyld`
//! through `shared_region_map_and_slide_2_np` and reused by later ones
//! through `shared_region_check_np`. Here every process has a region of its
//! own: `check_np` reports none until the process's `dyld` maps the cache,
//! which it then does exactly as the first process on a Mac does.
//!
//! Data pages of the cache hold pointers in a chained format that the
//! kernel rewrites as each page is first touched
//! (`vm_shared_region_slide_page`); [`SlidSource`] does the same for the
//! two formats current caches use: version 2 (x86-64: a delta chain per
//! page with extra chains, pointers `value & ~delta_mask` plus
//! `value_add`) and version 5 (arm64e: 34-bit runtime offsets with high
//! bits, authenticated pointers written unsigned, as the implementation's
//! pointer-authentication algorithm leaves pointers unchanged). The slide
//! is zero: ASLR is disabled.
//!
//! Sources: `bsd/vm/vm_unix.c` (`shared_region_check_np`,
//! `shared_region_map_and_slide_2_np`), `osfmk/vm/vm_shared_region.c`
//! (`rebase_chain_64`, `vm_shared_region_slide_page_v2`,
//! `vm_shared_region_slide_page_v5`), `osfmk/vm/vm_shared_region_xnu.h`.

use std::fmt;
use std::fs::File;
use std::sync::{Arc, Mutex};

use crate::user::mm::{HostFileSource, PageSource, SourceIdentity};

/// `DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA`.
const V2_ATTR_EXTRA: u16 = 0x8000;
/// `DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE`.
const V2_ATTR_NO_REBASE: u16 = 0x4000;
/// `DYLD_CACHE_SLIDE_PAGE_ATTR_END`.
const V2_ATTR_END: u16 = 0x8000;
/// `DYLD_CACHE_SLIDE_PAGE_VALUE`.
const V2_PAGE_VALUE: u16 = 0x3FFF;
/// `DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT`.
const V2_OFFSET_SHIFT: u32 = 2;
/// `DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE`.
const V5_NO_REBASE: u16 = 0xFFFF;

/// A process's shared region.
#[derive(Clone, Debug)]
pub struct SharedRegion {
    /// Address of the first mapping (the cache header).
    pub base: u64,
    /// The slide applied to the cache.
    pub slide: u64,
    /// The mappings, `(address, size)`.
    pub mappings: Vec<(u64, u64)>,
}

/// Parsed slide information for one mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlideInfo {
    /// Version 2.
    V2 {
        /// Bytes per slid page.
        page_size: u32,
        /// Per-page chain starts.
        page_starts: Vec<u16>,
        /// Extra chain starts.
        page_extras: Vec<u16>,
        /// Bits holding the delta to the next pointer.
        delta_mask: u64,
        /// Added to every non-zero pointer value.
        value_add: u64,
    },
    /// Version 5.
    V5 {
        /// Bytes per slid page.
        page_size: u32,
        /// Per-page offset of the first pointer.
        page_starts: Vec<u16>,
        /// The cache's unslid base, added to every runtime offset.
        value_add: u64,
    },
}

/// Why slide information was refused (`vm_shared_region_slide_sanity_check`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlideError {
    /// Too short for its header or arrays.
    Truncated,
    /// A version this implementation does not handle.
    Version(u32),
    /// A page size other than 4 KiB or 16 KiB.
    PageSize(u32),
    /// A chain ran past its page.
    Chain,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

impl SlideInfo {
    /// Parses a `vm_shared_region_slide_info_entry`.
    pub fn parse(b: &[u8]) -> Result<Self, SlideError> {
        let version = u32_at(b, 0).ok_or(SlideError::Truncated)?;
        let page_size = u32_at(b, 4).ok_or(SlideError::Truncated)?;
        if page_size != 4096 && page_size != 16384 {
            return Err(SlideError::PageSize(page_size));
        }
        match version {
            2 => {
                let starts_off = u32_at(b, 8).ok_or(SlideError::Truncated)? as usize;
                let starts_n = u32_at(b, 12).ok_or(SlideError::Truncated)? as usize;
                let extras_off = u32_at(b, 16).ok_or(SlideError::Truncated)? as usize;
                let extras_n = u32_at(b, 20).ok_or(SlideError::Truncated)? as usize;
                let delta_mask = u64_at(b, 24).ok_or(SlideError::Truncated)?;
                let value_add = u64_at(b, 32).ok_or(SlideError::Truncated)?;
                let read = |off: usize, n: usize| -> Result<Vec<u16>, SlideError> {
                    (0..n)
                        .map(|i| u16_at(b, off + 2 * i).ok_or(SlideError::Truncated))
                        .collect()
                };
                if delta_mask == 0 {
                    return Err(SlideError::Chain);
                }
                Ok(SlideInfo::V2 {
                    page_size,
                    page_starts: read(starts_off, starts_n)?,
                    page_extras: read(extras_off, extras_n)?,
                    delta_mask,
                    value_add,
                })
            }
            5 => {
                let starts_n = u32_at(b, 8).ok_or(SlideError::Truncated)? as usize;
                let value_add = u64_at(b, 16).ok_or(SlideError::Truncated)?;
                let page_starts = (0..starts_n)
                    .map(|i| u16_at(b, 24 + 2 * i).ok_or(SlideError::Truncated))
                    .collect::<Result<_, _>>()?;
                Ok(SlideInfo::V5 {
                    page_size,
                    page_starts,
                    value_add,
                })
            }
            v => Err(SlideError::Version(v)),
        }
    }

    /// Bytes per slid page.
    pub fn page_size(&self) -> u32 {
        match self {
            SlideInfo::V2 { page_size, .. } | SlideInfo::V5 { page_size, .. } => *page_size,
        }
    }

    /// Rewrites the pointers of page `index` (`page` is the whole page).
    pub fn slide_page(&self, index: usize, page: &mut [u8], slide: u64) -> Result<(), SlideError> {
        match self {
            SlideInfo::V2 {
                page_starts,
                page_extras,
                delta_mask,
                value_add,
                ..
            } => {
                let Some(&entry) = page_starts.get(index) else {
                    return Err(SlideError::Chain);
                };
                if entry == V2_ATTR_NO_REBASE {
                    return Ok(());
                }
                let mut chain =
                    |start: u32| rebase_chain_64(page, start, slide, *delta_mask, *value_add);
                if entry & V2_ATTR_EXTRA != 0 {
                    let mut i = usize::from(entry & V2_PAGE_VALUE);
                    loop {
                        let info = *page_extras.get(i).ok_or(SlideError::Chain)?;
                        chain(u32::from(info & V2_PAGE_VALUE) << V2_OFFSET_SHIFT)?;
                        if info & V2_ATTR_END != 0 {
                            break;
                        }
                        i += 1;
                    }
                    Ok(())
                } else {
                    chain(u32::from(entry) << V2_OFFSET_SHIFT)
                }
            }
            SlideInfo::V5 {
                page_starts,
                value_add,
                ..
            } => {
                let Some(&entry) = page_starts.get(index) else {
                    return Err(SlideError::Chain);
                };
                if entry == V5_NO_REBASE {
                    return Ok(());
                }
                let mut off = usize::from(entry);
                loop {
                    let raw = u64::from_le_bytes(
                        page.get(off..off + 8)
                            .ok_or(SlideError::Chain)?
                            .try_into()
                            .expect("8 bytes"),
                    );
                    let delta = ((raw & 0x7FF0_0000_0000_0000) >> 52) as usize * 8;
                    let high8 = (raw << 22) & 0xFF00_0000_0000_0000;
                    let auth = raw & (1 << 63) != 0;
                    let mut value = (raw & 0x3_FFFF_FFFF)
                        .wrapping_add(*value_add)
                        .wrapping_add(slide);
                    if !auth {
                        value = value.wrapping_add(high8);
                    }
                    page[off..off + 8].copy_from_slice(&value.to_le_bytes());
                    if delta == 0 {
                        return Ok(());
                    }
                    off += delta;
                }
            }
        }
    }
}

/// `rebase_chain_64`.
fn rebase_chain_64(
    page: &mut [u8],
    start: u32,
    slide: u64,
    delta_mask: u64,
    value_add: u64,
) -> Result<(), SlideError> {
    let page_len = page.len() as u32;
    let last = page_len - 8;
    let value_mask = !delta_mask;
    let delta_shift = delta_mask.trailing_zeros() - 2;
    let mut off = start;
    let mut delta = 1u32;
    while delta != 0 && off <= last {
        let at = off as usize;
        let mut value = u64::from_le_bytes(page[at..at + 8].try_into().expect("8 bytes"));
        delta = ((value & delta_mask) >> delta_shift) as u32;
        value &= value_mask;
        if value != 0 {
            value = value.wrapping_add(value_add).wrapping_add(slide);
        }
        page[at..at + 8].copy_from_slice(&value.to_le_bytes());
        off += delta;
    }
    if off + 4 == page_len {
        // A pointer straddling the page boundary: the slide goes into the
        // lower half, which is on this page.
        let at = off as usize;
        let v = u32::from_le_bytes(page[at..at + 4].try_into().expect("4 bytes"));
        page[at..at + 4].copy_from_slice(&v.wrapping_add(slide as u32).to_le_bytes());
    } else if off > last {
        return Err(SlideError::Chain);
    }
    Ok(())
}

/// A file mapping of the cache whose pages are slid on first touch.
pub struct SlidSource {
    source: Arc<dyn PageSource>,
    identity: SourceIdentity,
    /// File offset of the mapping's first byte.
    map_offset: u64,
    /// Bytes the mapping covers.
    map_size: u64,
    info: SlideInfo,
    slide: u64,
    /// The last slid page (page index and contents), for sources whose
    /// slide pages are larger than a guest page.
    last: Mutex<Option<(u64, Vec<u8>)>>,
}

impl fmt::Debug for SlidSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlidSource")
            .field("map_offset", &self.map_offset)
            .field("map_size", &self.map_size)
            .field("slide", &self.slide)
            .finish_non_exhaustive()
    }
}

impl SlidSource {
    /// A source for the mapping of `file` at `map_offset` of `map_size`
    /// bytes with slide information `info`.
    pub fn new(
        file: File,
        map_offset: u64,
        map_size: u64,
        info: SlideInfo,
        slide: u64,
    ) -> std::io::Result<Self> {
        Self::from_source(
            Arc::new(HostFileSource::new(file)?),
            map_offset,
            map_size,
            info,
            slide,
        )
    }

    /// A cache mapping backed by supplied bytes or another portable page source.
    pub fn from_source(
        source: Arc<dyn PageSource>,
        map_offset: u64,
        map_size: u64,
        info: SlideInfo,
        slide: u64,
    ) -> std::io::Result<Self> {
        map_offset
            .checked_add(map_size)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        if !matches!(info.page_size(), 4096 | 16384) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        Ok(SlidSource {
            identity: source.identity(),
            source,
            map_offset,
            map_size,
            info,
            slide,
            last: Mutex::new(None),
        })
    }

    fn read_raw(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            let at = offset
                .checked_add(done as u64)
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            let n = self.source.read_at(at, &mut buf[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    /// The slid contents of slide page `index` of the mapping.
    fn page(&self, index: u64) -> std::io::Result<Vec<u8>> {
        {
            let last = self.last.lock().unwrap();
            if let Some((i, p)) = last.as_ref()
                && *i == index
            {
                return Ok(p.clone());
            }
        }
        let ps = u64::from(self.info.page_size());
        let mut page = vec![0u8; ps as usize];
        self.read_raw(self.map_offset + index * ps, &mut page)?;
        if let Err(e) = self.info.slide_page(index as usize, &mut page, self.slide) {
            return Err(std::io::Error::other(format!(
                "invalid slide information for page {index}: {e:?}"
            )));
        }
        *self.last.lock().unwrap() = Some((index, page.clone()));
        Ok(page)
    }
}

impl PageSource for SlidSource {
    fn len(&self) -> u64 {
        self.source.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = (self.len().saturating_sub(offset)).min(buf.len() as u64) as usize;
        let buf = &mut buf[..count];
        if offset < self.map_offset {
            let before = (self.map_offset - offset).min(count as u64) as usize;
            let n = self.read_raw(offset, &mut buf[..before])?;
            if n < before || n == count {
                return Ok(n);
            }
            return Ok(n + self.read_at(offset + n as u64, &mut buf[n..])?);
        }
        if offset >= self.map_offset + self.map_size {
            return self.read_raw(offset, buf);
        }
        let ps = u64::from(self.info.page_size());
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            if at >= self.map_offset + self.map_size {
                done += self.read_raw(at, &mut buf[done..])?;
                break;
            }
            let rel = at - self.map_offset;
            let index = rel / ps;
            let page = self.page(index)?;
            let in_page = (rel % ps) as usize;
            let n = (page.len() - in_page)
                .min(buf.len() - done)
                .min((self.map_offset + self.map_size - at) as usize);
            buf[done..done + n].copy_from_slice(&page[in_page..in_page + n]);
            done += n;
        }
        Ok(done)
    }

    fn identity(&self) -> SourceIdentity {
        self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_info(starts: &[u16], extras: &[u16]) -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[0..4].copy_from_slice(&2u32.to_le_bytes());
        b[4..8].copy_from_slice(&4096u32.to_le_bytes());
        b[8..12].copy_from_slice(&40u32.to_le_bytes());
        b[12..16].copy_from_slice(&(starts.len() as u32).to_le_bytes());
        let extras_off = 40 + 2 * starts.len();
        b[16..20].copy_from_slice(&(extras_off as u32).to_le_bytes());
        b[20..24].copy_from_slice(&(extras.len() as u32).to_le_bytes());
        // The x86-64 cache's mask and base (its slide information header
        // has delta_mask 0x00FFFF0000000000 and value_add 0x7FF800000000).
        b[24..32].copy_from_slice(&0x00FF_FF00_0000_0000u64.to_le_bytes());
        b[32..40].copy_from_slice(&0x7FF8_0000_0000u64.to_le_bytes());
        for s in starts.iter().chain(extras) {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    #[test]
    fn supplied_cache_pages_slide_without_host_files_or_mutating_input() {
        use crate::user::mm::BytesSource;
        let mut bytes = vec![0u8; 4 * 4096];
        bytes[4096..4104].copy_from_slice(&0x10u64.to_le_bytes());
        bytes[8192] = 0x55;
        bytes[12288] = 0x66;
        let bytes: Arc<[u8]> = bytes.into();
        let backing: Arc<dyn PageSource> = Arc::new(BytesSource::new(bytes.clone()));
        let info = SlideInfo::parse(&v2_info(&[0, V2_ATTR_NO_REBASE], &[])).unwrap();
        let source =
            SlidSource::from_source(backing.clone(), 4096, 8192, info.clone(), 0x1000).unwrap();
        assert_eq!(source.len(), bytes.len() as u64);
        assert_eq!(source.identity(), backing.identity());
        for _ in 0..2 {
            let mut value = [0; 8];
            assert_eq!(source.read_at(4096, &mut value).unwrap(), 8);
            assert_eq!(u64::from_le_bytes(value), 0x7ff8_0000_1010);
        }
        assert_eq!(
            u64::from_le_bytes(bytes[4096..4104].try_into().unwrap()),
            0x10
        );
        let mut before_mapping = [0; 9];
        assert_eq!(source.read_at(4095, &mut before_mapping).unwrap(), 9);
        assert_eq!(before_mapping[0], 0);
        assert_eq!(
            u64::from_le_bytes(before_mapping[1..].try_into().unwrap()),
            0x7ff8_0000_1010
        );
        let mut cross_page = [0; 2];
        assert_eq!(source.read_at(8191, &mut cross_page).unwrap(), 2);
        assert_eq!(cross_page, [0, 0x55]);
        assert_eq!(source.read_at(12287, &mut cross_page).unwrap(), 2);
        assert_eq!(cross_page, [0, 0x66]);
        assert_eq!(
            source.read_at(bytes.len() as u64, &mut cross_page).unwrap(),
            0
        );
        assert!(
            matches!(SlidSource::from_source(backing, u64::MAX, 1, info, 0),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn v2_chains_follow_rebase_chain_64() {
        let info = SlideInfo::parse(&v2_info(
            &[0x0002, V2_ATTR_NO_REBASE, V2_ATTR_EXTRA],
            &[0x0001, 0x8004],
        ))
        .unwrap();
        // delta_shift = ctz(0x00FFFF0000000000) - 2 = 38; delta counts
        // bytes. Page 0: a chain at offset 8 (start 2 << 2), next at +16.
        let mut page = vec![0u8; 4096];
        let delta16 = 16u64 << 38;
        page[8..16].copy_from_slice(&(0x1234_5678u64 | delta16).to_le_bytes());
        page[24..32].copy_from_slice(&0x10u64.to_le_bytes());
        info.slide_page(0, &mut page, 0x1000).unwrap();
        assert_eq!(
            u64::from_le_bytes(page[8..16].try_into().unwrap()),
            0x7ff8_1234_6678
        );
        assert_eq!(
            u64::from_le_bytes(page[24..32].try_into().unwrap()),
            0x7ff8_0000_1010
        );
        // A zero value stays zero.
        let mut z = vec![0u8; 4096];
        info.slide_page(0, &mut z, 0x1000).unwrap();
        assert!(z.iter().all(|&b| b == 0));
        // Page 1 has no rebases.
        let mut p1 = vec![0xAAu8; 4096];
        info.slide_page(1, &mut p1, 0x1000).unwrap();
        assert!(p1.iter().all(|&b| b == 0xAA));
        // Page 2 uses two extra chains, at 4 and 16.
        let mut p2 = vec![0u8; 4096];
        p2[4..12].copy_from_slice(&5u64.to_le_bytes());
        p2[16..24].copy_from_slice(&6u64.to_le_bytes());
        info.slide_page(2, &mut p2, 0x10).unwrap();
        assert_eq!(
            u64::from_le_bytes(p2[4..12].try_into().unwrap()),
            0x7ff8_0000_0015
        );
        assert_eq!(
            u64::from_le_bytes(p2[16..24].try_into().unwrap()),
            0x7ff8_0000_0016
        );
        // A page past the table is refused.
        assert_eq!(info.slide_page(3, &mut p2, 0), Err(SlideError::Chain));
    }

    #[test]
    fn v5_pointers_follow_slide_page_v5() {
        let mut b = vec![0u8; 24];
        b[0..4].copy_from_slice(&5u32.to_le_bytes());
        b[4..8].copy_from_slice(&16384u32.to_le_bytes());
        b[8..12].copy_from_slice(&2u32.to_le_bytes());
        b[16..24].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        b.extend_from_slice(&0x10u16.to_le_bytes());
        b.extend_from_slice(&V5_NO_REBASE.to_le_bytes());
        let info = SlideInfo::parse(&b).unwrap();
        let mut page = vec![0u8; 16384];
        // Plain pointer: offset 0x1234, high8 0xAB, next 1 (8 bytes on).
        let plain = 0x1234u64 | (0xABu64 << 34) | (1u64 << 52);
        // Authenticated: offset 0x40, diversity 0x77, auth bit, next 0.
        let auth = 0x40u64 | (0x77 << 34) | (1u64 << 63);
        page[0x10..0x18].copy_from_slice(&plain.to_le_bytes());
        page[0x18..0x20].copy_from_slice(&auth.to_le_bytes());
        info.slide_page(0, &mut page, 0).unwrap();
        assert_eq!(
            u64::from_le_bytes(page[0x10..0x18].try_into().unwrap()),
            0xAB00_0001_8000_1234
        );
        assert_eq!(
            u64::from_le_bytes(page[0x18..0x20].try_into().unwrap()),
            0x1_8000_0040
        );
        let mut p1 = vec![0x55u8; 16384];
        info.slide_page(1, &mut p1, 0).unwrap();
        assert!(p1.iter().all(|&x| x == 0x55));
    }

    #[test]
    fn unknown_versions_and_page_sizes_are_refused() {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&3u32.to_le_bytes());
        b[4..8].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(SlideInfo::parse(&b), Err(SlideError::Version(3)));
        b[4..8].copy_from_slice(&8192u32.to_le_bytes());
        assert_eq!(SlideInfo::parse(&b), Err(SlideError::PageSize(8192)));
        assert_eq!(SlideInfo::parse(&b[..4]), Err(SlideError::Truncated));
    }
}
