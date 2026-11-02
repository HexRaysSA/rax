//! Immutable observations required by future NAND page reads and VFL discovery.
use super::{
    NAND_BYTES_PER_PAGE, NAND_BYTES_PER_SPARE, NAND_NUM_BANKS, NAND_PAGES_PER_BLOCK,
    NAND_VFL_CONTEXT_SPARE_TYPE,
};
use crate::error::{Error, Result};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) const PAGE_BYTES: usize = NAND_BYTES_PER_PAGE + NAND_BYTES_PER_SPARE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NandPolicy {
    pub bbt_all_good: bool,
    pub bbt_good_upto: Option<u32>,
    pub rewrite_pmbr: bool,
    pub fdisk_relsect: Option<u32>,
    pub fdisk_numsect: Option<u32>,
}
impl NandPolicy {
    pub(super) fn from_environment() -> Self {
        fn number(name: &str) -> Option<u32> {
            std::env::var(name).ok()?.parse().ok()
        }
        Self {
            bbt_all_good: std::env::var_os("RAX_S5L_BBT_ALL_GOOD").is_some(),
            bbt_good_upto: number("RAX_S5L_BBT_GOOD_UPTO"),
            rewrite_pmbr: std::env::var_os("RAX_S5L_REWRITE_PMBR_AS_FDISK").is_some(),
            fdisk_relsect: number("RAX_S5L_FDISK_RELSECT"),
            fdisk_numsect: number("RAX_S5L_FDISK_NUMSECT"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BackingImage {
    // Empty present files remain distinct from absent files.
    pub pages: BTreeMap<(u32, u32), Vec<u8>>,
    // The live scanner also accepts noncanonical numeric names such as 00128.page.
    // Such files affect this index but cannot be read by canonical page lookup.
    pub vfl_blocks: [Vec<u32>; NAND_NUM_BANKS as usize],
}

pub(super) enum NandBacking {
    Files(Option<PathBuf>),
    Frozen(Arc<BackingImage>),
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("S5L NAND backing: {message}"))
}

fn read_prefix(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("page is not a regular file"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(PAGE_BYTES)
        .map_err(std::io::Error::other)?;
    file.take(PAGE_BYTES as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn is_context(data: &[u8]) -> bool {
    data.get(NAND_BYTES_PER_PAGE + 8) == Some(&0)
        && data.get(NAND_BYTES_PER_PAGE + 9) == Some(&NAND_VFL_CONTEXT_SPARE_TYPE)
}

impl NandBacking {
    pub(super) fn page(&self, bank: u32, page: u32) -> Option<Cow<'_, [u8]>> {
        match self {
            Self::Files(Some(root)) => read_prefix(&root.join(format!("bank{bank}/{page}.page")))
                .ok()
                .map(Cow::Owned),
            Self::Files(None) => None,
            Self::Frozen(image) => image
                .pages
                .get(&(bank, page))
                .map(|data| Cow::Borrowed(data.as_slice())),
        }
    }

    pub(super) fn vfl_blocks(&self, bank: u32) -> Vec<u32> {
        match self {
            Self::Frozen(image) => image
                .vfl_blocks
                .get(bank as usize)
                .cloned()
                .unwrap_or_default(),
            Self::Files(None) => Vec::new(),
            Self::Files(Some(root)) => {
                let mut blocks = Vec::new();
                if let Ok(entries) = fs::read_dir(root.join(format!("bank{bank}"))) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) != Some("page") {
                            continue;
                        }
                        let Some(page) = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .and_then(|s| s.parse::<u32>().ok())
                        else {
                            continue;
                        };
                        if read_prefix(&path).is_ok_and(|bytes| is_context(&bytes)) {
                            blocks.push(page / NAND_PAGES_PER_BLOCK);
                        }
                    }
                }
                blocks.sort_unstable();
                blocks.dedup();
                blocks
            }
        }
    }

    /// Caller must keep external media stable during capture. Two complete
    /// observations detect directory/content changes between passes; no live
    /// controller buffer/cache is populated or replaced. Frozen bindings need no I/O.
    pub(super) fn capture(&self, limit: usize) -> Result<Arc<BackingImage>> {
        match self {
            Self::Frozen(image) => Ok(image.clone()),
            Self::Files(None) => Ok(Arc::new(BackingImage {
                pages: BTreeMap::new(),
                vfl_blocks: std::array::from_fn(|_| Vec::new()),
            })),
            Self::Files(Some(root)) => {
                let first = capture_files(root, limit)?;
                if first != capture_files(root, limit)? {
                    return Err(invalid("media changed during capture"));
                }
                Ok(Arc::new(first))
            }
        }
    }
}

fn capture_files(root: &Path, limit: usize) -> Result<BackingImage> {
    let mut image = BackingImage {
        pages: BTreeMap::new(),
        vfl_blocks: std::array::from_fn(|_| Vec::new()),
    };
    let mut used = 0usize;
    for bank in 0..NAND_NUM_BANKS {
        let mut blocks = BTreeSet::new();
        let entries = match fs::read_dir(root.join(format!("bank{bank}"))) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(invalid(error)),
        };
        for entry in entries {
            let entry = entry.map_err(invalid)?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("page") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(page) = stem.parse::<u32>() else {
                continue;
            };
            // Avoid blocking on FIFOs/devices. Live reads treat unreadable pages
            // as missing; capture rejects uncertain media rather than silently
            // freezing a transient access failure as permanently absent.
            if !fs::metadata(&path).map_err(invalid)?.is_file() {
                return Err(invalid("numeric page is not a regular file"));
            }
            let data = read_prefix(&path).map_err(invalid)?;
            if is_context(&data) && blocks.insert(page / NAND_PAGES_PER_BLOCK) {
                used = used
                    .checked_add(4)
                    .ok_or_else(|| invalid("size overflow"))?;
            }
            if stem == page.to_string() {
                used = used
                    .checked_add(12 + data.len())
                    .ok_or_else(|| invalid("size overflow"))?;
                image.pages.insert((bank, page), data);
            }
            if used > limit {
                return Err(invalid("media exceeds checkpoint byte budget"));
            }
        }
        image.vfl_blocks[bank as usize] = blocks.into_iter().collect();
    }
    Ok(image)
}
