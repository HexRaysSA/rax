//! Private guest frames for immutable pinned kernel image sections.
use super::*;
use crate::user::image::pe::hybrid::{CodeKind, HybridMetadata};
use crate::user::windows::object_namespace::{ImageExtension, ImageSection, ImageTemplate};

#[derive(Debug)]
pub(crate) struct SectionView {
    pub(crate) section: Arc<ImageSection>,
    pub(crate) image_base: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) extensions: [Option<ImageExtension>; 2],
    machine: u16,
    native_machine: Option<u16>,
    hybrid: Option<Arc<HybridMetadata>>,
    // ImageExtensionPresent also covers reserved-only native owner tails.
    extended: bool,
}
impl SectionView {
    pub(super) fn code_kind(&self, address: u64) -> Option<CodeKind> {
        if self.section.no_execute {
            return None;
        }
        let within = address.checked_sub(self.image_base)?;
        if within >= self.size {
            let extension = self.extensions.iter().flatten().any(|extension| {
                within >= extension.rva && within - extension.rva < extension.bytes.len() as u64
            });
            return if extension {
                match self.native_machine {
                    Some(0xAA64) => Some(CodeKind::Arm64),
                    Some(0x8664) => Some(CodeKind::Amd64),
                    _ => None,
                }
            } else {
                None
            };
        }
        let rva = u32::try_from(self.offset.checked_add(within)?).ok()?;
        match &self.hybrid {
            Some(metadata) => metadata.code_kind(rva),
            None => match self.machine {
                0x8664 => Some(CodeKind::Amd64),
                0xAA64 => Some(CodeKind::Arm64),
                _ => None,
            },
        }
    }
}

#[derive(Debug)]
pub(super) struct LowPlacement {
    // Retain identity so an address key cannot be reused by a different Section.
    _section: Arc<ImageSection>,
    base: u64,
}
impl VirtualMemory {
    pub(crate) fn section_low_placement(&self, section: &Arc<ImageSection>) -> Option<u64> {
        self.section_low_placements
            .get(&(Arc::as_ptr(section) as usize))
            .map(|p| p.base)
            .or(self.default_low_image_placement)
    }
    pub(crate) fn record_section_low_placement(&mut self, section: Arc<ImageSection>, base: u64) {
        self.default_low_image_placement.get_or_insert(base);
        self.section_low_placements
            .entry(Arc::as_ptr(&section) as usize)
            .or_insert(LowPlacement {
                _section: section,
                base,
            });
    }
    /// Maps the caller's already validated image plan. No import binding,
    /// module registration, or PEB publication occurs here. A requested kernel
    /// rebase is applied before slicing the logical view.
    /// O(B + C + R log P) time for B copied bytes/C hybrid records/R region runs/P page-state runs,
    /// plus address-space mapping cost; O(R) per-view policy, shared O(C) metadata and B guest frames.
    pub(crate) fn map_section_image(
        &mut self,
        section: Arc<ImageSection>,
        image: &ImageTemplate,
        allocation_base: u64,
        image_base: u64,
        allocation_size: u64,
        offset: u64,
        size: u64,
        large: bool,
        relocate: bool,
    ) -> Result<(), VmError> {
        if allocation_base % ALLOCATION_GRANULARITY != 0
            || image_base < allocation_base
            || image_base % PAGE_SIZE != 0
            || size == 0
            || size % PAGE_SIZE != 0
            || offset % PAGE_SIZE != 0
            || offset
                .checked_add(size)
                .is_none_or(|end| end > image.bytes.len() as u64)
            || image_base
                .checked_sub(allocation_base)
                .and_then(|prefix| prefix.checked_add(size))
                .is_none_or(|end| end > allocation_size)
            || allocation_size % PAGE_SIZE != 0
            || section.image_size != image.bytes.len() as u64
        {
            return Err(VmError::InvalidParameter);
        }
        let hybrid = if section.no_execute {
            None
        } else {
            image.hybrid_metadata().map_err(|_| VmError::NotSupported)?
        };
        let full_image = !large && offset == 0 && size == image.bytes.len() as u64;
        let code_bitmap = if section.no_execute {
            None
        } else {
            image
                .arm64ec_code_bitmap()
                .map_err(|_| VmError::NotSupported)?
                .map(|mut plan| {
                    // A partial SEC_IMAGE view keeps the original RVA slicing.
                    // The bitmap describes its actual guest virtual pages.
                    plan.ranges = plan
                        .ranges
                        .into_iter()
                        .filter_map(|(start, end)| {
                            let start = u64::from(start).max(offset);
                            let end = u64::from(end).min(offset + size);
                            if start < end {
                                Some(((start - offset) as u32, (end - offset) as u32))
                            } else {
                                None
                            }
                        })
                        .collect();
                    plan
                })
        };
        let extensions = if full_image {
            image.extensions.clone()
        } else {
            [None, None]
        };
        let extent = if full_image {
            image.allocation_size()
        } else {
            size
        };
        if image_base
            .checked_sub(allocation_base)
            .and_then(|prefix| prefix.checked_add(extent))
            .is_none_or(|end| end > allocation_size)
        {
            return Err(VmError::InvalidParameter);
        }
        let data = image
            .view_bytes(
                image_base
                    .checked_sub(offset)
                    .ok_or(VmError::InvalidParameter)?,
                relocate,
            )
            .map_err(|_| VmError::NotSupported)?;
        let name: Arc<str> = String::from_utf16_lossy(&section.path).into();
        let base = self.reserve(
            Some(allocation_base),
            allocation_size,
            if section.no_execute {
                prot::READONLY
            } else {
                prot::EXECUTE_WRITECOPY
            },
            AllocKind::Image,
            false,
            Some(name),
        )?;
        let result = (|| {
            if large {
                self.commit(base, allocation_size, prot::EXECUTE_WRITECOPY)?;
                self.poke(image_base, &data[offset as usize..(offset + size) as usize])
                    .map_err(|_| VmError::NoMemory)?;
                self.space
                    .track_private_copies(base, allocation_size)
                    .map_err(mm)?;
            } else {
                for region in &image.regions {
                    let begin = region.offset.max(offset);
                    let end = (region.offset + region.size).min(offset + size);
                    if begin >= end || region.state != mem::COMMIT {
                        continue;
                    }
                    let address = image_base + begin - offset;
                    self.commit(address, end - begin, prot::READWRITE)?;
                    self.poke(address, &data[begin as usize..end as usize])
                        .map_err(|_| VmError::NoMemory)?;
                    self.protect_image_initial(address, end - begin, region.protection)?;
                    // Initial READWRITE/EXECUTE_READWRITE image runs are shared
                    // PE sections. An explicit later protect can make the page
                    // copy-capable, even when the requested protection matches.
                    if !matches!(
                        region.protection & 0xFF,
                        prot::READWRITE | prot::EXECUTE_READWRITE
                    ) {
                        self.space
                            .track_private_copies(address, end - begin)
                            .map_err(mm)?;
                    }
                }
            }
            for extension in extensions.iter().flatten() {
                let address = image_base + extension.rva;
                let length = extension.bytes.len() as u64;
                if !large {
                    self.commit(address, length, prot::READWRITE)?;
                }
                self.poke(address, &extension.bytes)
                    .map_err(|_| VmError::NoMemory)?;
                self.protect_image_initial(address, length, prot::EXECUTE_READ)?;
                self.space
                    .track_private_copies(address, length)
                    .map_err(mm)?;
            }
            if let Some(plan) = &code_bitmap {
                self.publish_ec_image(plan, image_base, size)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = self.release(base);
            return Err(error);
        }
        self.section_views.insert(
            base,
            SectionView {
                section,
                image_base,
                offset,
                size,
                extensions,
                machine: image.machine,
                native_machine: image.native_machine,
                hybrid,
                extended: full_image && image.allocation_size() > image.bytes.len() as u64,
            },
        );
        Ok(())
    }
    pub(crate) fn section_view(&self, address: u64) -> Option<&SectionView> {
        self.allocation(address)
            .and_then(|allocation| self.section_views.get(&allocation.base))
    }
    /// The metadata belongs to the exact mapped projection. A retained Section
    /// can also own a different native-machine projection.
    pub(crate) fn section_hybrid(&self, address: u64) -> Option<(u64, u64, &HybridMetadata)> {
        let view = self.section_view(address)?;
        view.code_kind(address)?;
        view.hybrid
            .as_deref()
            .map(|metadata| (view.image_base, view.offset, metadata))
    }

    pub(crate) fn section_image_information(&self, address: u64) -> Option<(u64, u64, u32)> {
        let view = self.section_view(address)?;
        let partial = view.offset != 0 || view.size != view.section.image_size;
        Some((
            view.image_base,
            view.section.image_size,
            u32::from(partial)
                | if view.section.no_execute { 0x02 } else { 0 }
                | if view.extended { 0x40 } else { 0 },
        ))
    }
    pub(crate) fn section_image_extension(&self, address: u64, kind: u32) -> Option<(u64, u64)> {
        let view = self.section_view(address)?;
        let extension = view.extensions.get(kind as usize)?.as_ref()?;
        Some((extension.rva, extension.bytes.len() as u64))
    }
    pub(crate) fn intersects_image_extension(&self, first: u64, end: u64) -> bool {
        self.section_view(first).is_some_and(|view| {
            view.extensions.iter().flatten().any(|e| {
                let start = view.image_base + e.rva;
                first < start + e.bytes.len() as u64 && end > start
            })
        })
    }
}
