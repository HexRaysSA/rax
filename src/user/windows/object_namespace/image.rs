//! A byte-exact kernel image template, before user-loader imports or relocation.
use super::invalid;
use crate::user::image::pe::{DataDirectory, relocs};
use crate::user::windows::memory::{mem, prot, valid_protection};
use std::borrow::Cow;
use std::io;
use std::sync::Arc;

pub(crate) const MAX_IMAGE_BYTES: u64 = 64 << 20;
pub(crate) const MAX_EXTENSION_BYTES: u64 = 64 << 10;
pub(crate) const MAX_IMAGE_TAIL_BYTES: u64 = 64 << 10;
pub(crate) mod extension_query;
#[cfg(any(windows, test))]
pub(crate) mod region;
pub(crate) use extension_query::ExtensionQuery;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageExtension {
    pub(crate) rva: u64,
    pub(crate) bytes: Arc<[u8]>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImageRegion {
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) state: u32,
    pub(crate) protection: u32,
}
pub(crate) struct ImageTemplate {
    pub(crate) bytes: Arc<[u8]>,
    pub(crate) regions: Vec<ImageRegion>,
    pub(crate) preferred: u64,
    pub(crate) machine: u16,
    pub(crate) extensions: [Option<ImageExtension>; 2],
    pub(crate) extension_query: ExtensionQuery,
    reserved_tail: u64,
    rebased: Option<Arc<[u8]>>,
    pub(crate) large_pages: bool,
    nt_offset: usize,
    wide: bool,
    relocations: DataDirectory,
}
impl std::fmt::Debug for ImageTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageTemplate")
            .field("bytes", &self.bytes.len())
            .field("regions", &self.regions)
            .field("preferred", &self.preferred)
            .field("machine", &self.machine)
            .field("reserved_tail", &self.reserved_tail)
            .finish()
    }
}
impl ImageTemplate {
    /// O(B + R) validation/storage for B bytes and R contiguous region runs.
    /// The preferred base and relocation words are preserved from the kernel
    /// view; this operation does not apply a second relocation delta.
    pub(crate) fn selected(bytes: Vec<u8>, regions: Vec<ImageRegion>) -> io::Result<Arc<Self>> {
        Self::selected_extended(bytes, regions, [None, None])
    }
    pub(crate) fn selected_extended(
        bytes: Vec<u8>,
        regions: Vec<ImageRegion>,
        extensions: [Option<ImageExtension>; 2],
    ) -> io::Result<Arc<Self>> {
        let size = bytes.len() as u64;
        if !(4096..=MAX_IMAGE_BYTES).contains(&size)
            || size % 4096 != 0
            || regions.is_empty()
            || regions.len() > 256
            || bytes.get(..2) != Some(b"MZ")
        {
            return Err(invalid(
                "selected kernel image extent/signature exceeds bounds",
            ));
        }
        let u16_at = |at: usize| {
            bytes
                .get(at..at.checked_add(2)?)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
        };
        let u32_at = |at: usize| {
            bytes
                .get(at..at.checked_add(4)?)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        };
        let at = u32_at(0x3C).ok_or_else(|| invalid("selected kernel DOS header"))? as usize;
        if at < 64
            || at > bytes.len().saturating_sub(264)
            || bytes.get(at..at + 4) != Some(b"PE\0\0")
        {
            return Err(invalid("selected kernel PE header is outside the image"));
        }
        let machine = u16_at(at + 4).unwrap();
        let wide = u16_at(at + 24).unwrap() == 0x20B;
        let preferred = match u16_at(at + 24).unwrap() {
            0x10B => u64::from(u32_at(at + 52).unwrap()),
            0x20B => u64::from_le_bytes(bytes[at + 48..at + 56].try_into().unwrap()),
            _ => return Err(invalid("selected kernel optional-header format")),
        };
        if u64::from(u32_at(at + 80).unwrap()) != size || preferred % 65536 != 0 {
            return Err(invalid(
                "selected kernel image extent/preferred-base mismatch",
            ));
        }
        let directory = at + 24 + if wide { 112 } else { 96 } + 5 * 8;
        let relocations = DataDirectory {
            rva: u32_at(directory).unwrap(),
            size: u32_at(directory + 4).unwrap(),
        };
        if relocations.size > (1 << 20)
            || u64::from(relocations.rva) + u64::from(relocations.size) > size
        {
            return Err(invalid(
                "selected kernel relocation directory exceeds the image",
            ));
        }
        let mut end = 0u64;
        for region in &regions {
            if region.offset != end
                || region.size == 0
                || region.size % 4096 != 0
                || !matches!(region.state, mem::COMMIT | mem::RESERVE)
                || region.state == mem::COMMIT && !valid_protection(region.protection)
                || region.state == mem::RESERVE && region.protection != 0
            {
                return Err(invalid("selected kernel image region contract"));
            }
            end = end
                .checked_add(region.size)
                .filter(|&n| n <= size)
                .ok_or_else(|| invalid("selected kernel image region extent"))?;
        }
        if end != size {
            return Err(invalid(
                "selected kernel image regions do not cover its extent",
            ));
        }
        let mut previous = size;
        for extension in extensions.iter().flatten() {
            let len = extension.bytes.len() as u64;
            if extension.rva < previous
                || extension.rva % 4096 != 0
                || len == 0
                || len % 4096 != 0
                || len > MAX_EXTENSION_BYTES
            {
                return Err(invalid("selected image extension geometry"));
            }
            previous = extension
                .rva
                .checked_add(len)
                .filter(|&end| end <= size + 2 * MAX_EXTENSION_BYTES)
                .ok_or_else(|| invalid("selected image extension extent"))?;
        }
        Ok(Arc::new(Self {
            bytes: bytes.into(),
            regions,
            preferred,
            machine,
            extensions,
            extension_query: ExtensionQuery::Both,
            reserved_tail: 0,
            rebased: None,
            large_pages: true,
            nt_offset: at,
            wide,
            relocations,
        }))
    }
    pub(crate) fn with_extension_query(
        mut image: Arc<Self>,
        query: ExtensionQuery,
    ) -> io::Result<Arc<Self>> {
        if query == ExtensionQuery::Unavailable && image.extensions.iter().any(Option::is_some)
            || query == ExtensionQuery::NativeOnly && image.extensions[1].is_some()
        {
            return Err(invalid("unavailable image extension has captured payload"));
        }
        Arc::get_mut(&mut image)
            .ok_or_else(|| invalid("image query policy already shared"))?
            .extension_query = query;
        Ok(image)
    }
    /// The compatibility syscall transport accepts LARGE_PAGES but maps
    /// ordinary image pages; combined-flag validation is still unchanged.
    pub(crate) fn without_large_pages(mut image: Arc<Self>) -> io::Result<Arc<Self>> {
        Arc::get_mut(&mut image)
            .ok_or_else(|| invalid("image policy already shared"))?
            .large_pages = false;
        Ok(image)
    }
    pub(crate) fn allocation_size(&self) -> u64 {
        self.extensions
            .iter()
            .flatten()
            .map(|e| e.rva + e.bytes.len() as u64)
            .max()
            .unwrap_or(self.bytes.len() as u64)
            + self.reserved_tail
    }
    /// Reserved host-owner padding follows the final image/code-extension page.
    /// Ordinary full views retain it; partial/large views omit it.
    pub(crate) fn with_reserved_tail(mut image: Arc<Self>, bytes: u64) -> io::Result<Arc<Self>> {
        if bytes % 4096 != 0 || bytes > MAX_IMAGE_TAIL_BYTES {
            return Err(invalid("selected image reserved tail geometry"));
        }
        Arc::get_mut(&mut image)
            .ok_or_else(|| invalid("image tail policy already shared"))?
            .reserved_tail = bytes;
        Ok(image)
    }
    /// Two independent native rebase views must normalize to identical bytes,
    /// page policy and extensions. Capture kernel guard adjustments as well as
    /// ordinary base relocations; never infer them from instruction patterns.
    pub(crate) fn with_rebase(
        mut original: Arc<Self>,
        first: &Self,
        second: &Self,
    ) -> io::Result<Arc<Self>> {
        if first.preferred == second.preferred
            || first.preferred == original.preferred
            || second.preferred == original.preferred
            || first.nt_offset != original.nt_offset
            || second.nt_offset != original.nt_offset
            || first.wide != original.wide
            || second.wide != original.wide
            || first.relocations.rva != original.relocations.rva
            || second.relocations.rva != original.relocations.rva
            || first.relocations.size != original.relocations.size
            || second.relocations.size != original.relocations.size
            || first.large_pages != original.large_pages
            || second.large_pages != original.large_pages
            || first.reserved_tail != original.reserved_tail
            || second.reserved_tail != original.reserved_tail
            || first.machine != original.machine
            || second.machine != original.machine
            || first.regions != original.regions
            || second.regions != original.regions
            || first.extensions != original.extensions
            || second.extensions != original.extensions
            || first.extension_query != original.extension_query
            || second.extension_query != original.extension_query
        {
            return Err(invalid("native rebase view policy changed"));
        }
        let one = first.view_bytes(original.preferred, true)?.into_owned();
        let two = second.view_bytes(original.preferred, true)?.into_owned();
        if one != two {
            return Err(invalid("native rebase views do not normalize identically"));
        }
        Arc::get_mut(&mut original)
            .ok_or_else(|| invalid("native rebase template already shared"))?
            .rebased = Some(one.into());
        Ok(original)
    }
    pub(crate) fn extension_region(extension: &ImageExtension) -> ImageRegion {
        ImageRegion {
            offset: extension.rva,
            size: extension.bytes.len() as u64,
            state: mem::COMMIT,
            protection: prot::EXECUTE_READ,
        }
    }
    /// MEM_DIFFERENT_IMAGE_BASE_OK performs this kernel rebase before slicing a
    /// partial view. Other allocation flags leave source-relative bytes intact.
    pub(crate) fn view_bytes(&self, image_base: u64, relocate: bool) -> io::Result<Cow<'_, [u8]>> {
        if !relocate || image_base == self.preferred {
            return Ok(Cow::Borrowed(&self.bytes));
        }
        if !self.wide && image_base > u64::from(u32::MAX) {
            return Err(invalid("selected PE32 rebase exceeds its pointer width"));
        }
        let mut bytes = self.rebased.as_deref().unwrap_or(&self.bytes).to_vec();
        relocs::apply(
            &mut bytes,
            self.relocations,
            image_base.wrapping_sub(self.preferred),
        )
        .map_err(|error| invalid(&format!("selected kernel image rebase: {error}")))?;
        let at = self.nt_offset + if self.wide { 48 } else { 52 };
        let width = if self.wide { 8 } else { 4 };
        bytes[at..at + width].copy_from_slice(&image_base.to_le_bytes()[..width]);
        Ok(Cow::Owned(bytes))
    }
}
