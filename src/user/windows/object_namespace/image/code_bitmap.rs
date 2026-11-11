//! ARM64EC code classification advertised by an immutable selected image.
//! The kernel's complete bitmap-reader instruction sequence identifies its
//! embedded data address. Instructions and host bitmap contents stay unchanged.
use super::*;
use crate::user::image::pe::hybrid::{CodeKind, HybridMetadata};
use crate::user::image::pe::loadcfg::LoadConfig;
use crate::user::image::pe::{DataDirectory, PeKind, RvaSource};

pub(crate) const BITMAP_BYTES: u64 = 1 << 32;

pub(crate) struct CodeBitmapPlan {
    pub(crate) base: Option<u64>,
    /// Half-open image-relative byte ranges containing ARM64EC code.
    pub(crate) ranges: Vec<(u32, u32)>,
}

fn reader_base(bytes: &[u8]) -> io::Result<Option<u64>> {
    let mut base = None;
    for offset in (0..bytes.len().saturating_sub(39)).step_by(4) {
        let words: [u32; 10] = std::array::from_fn(|n| {
            let at = offset + n * 4;
            u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
        });
        if words[0] & 0xffe0_001f != 0xd280_0010
            || words[1] & 0xffe0_001f != 0xf2a0_0010
            || words[2] & 0xffe0_001f != 0xf2c0_0010
            || words[3] & 0xffe0_001f != 0xf2e0_0010
            || words[4..]
                != [
                    0xaa10_03ec,
                    0xd34f_fd71,
                    0x3871_6a11,
                    0xd34c_3970,
                    0x9ad0_2630,
                    0xf240_021f,
                ]
        {
            continue;
        }
        let value = (0..4).fold(0u64, |value, n| {
            value | (u64::from((words[n] >> 5) & 0xffff) << (16 * n))
        });
        if value == 0
            || value % 65536 != 0
            || value
                .checked_add(BITMAP_BYTES)
                .is_none_or(|end| end > 1 << 47)
            || base.is_some_and(|previous| previous != value)
        {
            return Err(invalid(
                "selected ARM64EC bitmap reader has inconsistent geometry",
            ));
        }
        base = Some(value);
    }
    Ok(base)
}

impl ImageTemplate {
    /// Parse bounded CHPE records once for this immutable projection. Repeated
    /// mappings share O(C) metadata storage instead of copying it per view.
    pub(crate) fn hybrid_metadata(&self) -> io::Result<Option<Arc<HybridMetadata>>> {
        self.hybrid
            .get_or_init(|| {
                self.decode_hybrid_metadata()
                    .map(|metadata| metadata.map(Arc::new))
                    .map_err(|error| error.to_string())
            })
            .clone()
            .map_err(|error| invalid(&error))
    }

    fn decode_hybrid_metadata(&self) -> io::Result<Option<HybridMetadata>> {
        if !self.wide || !matches!(self.machine, 0x8664 | 0xa641) {
            return Ok(None);
        }
        let source = self.bytes.as_ref();
        let directory = self.nt_offset as u64 + 24 + 112 + 10 * 8;
        let range = DataDirectory {
            rva: source
                .u32_at(directory)
                .map_err(|_| invalid("ARM64EC load-config RVA"))?,
            size: source
                .u32_at(directory + 4)
                .map_err(|_| invalid("ARM64EC load-config size"))?,
        };
        let metadata = LoadConfig::read(source, PeKind::Pe32Plus, range)
            .map_err(|_| invalid("ARM64EC load configuration is inaccessible"))?
            .and_then(|config| config.chpe_metadata_pointer)
            .filter(|&pointer| pointer != 0);
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        HybridMetadata::read(source, metadata, self.preferred, source.len() as u32)
            .map(Some)
            .map_err(|_| invalid("ARM64EC code-map metadata is invalid"))
    }

    /// O(E + C) work for extension bytes E and CHPE records C.
    /// One byte tags eight 4 KiB pages, so 2^47 guest bytes use 2^32 bitmap bytes.
    pub(crate) fn arm64ec_code_bitmap(&self) -> io::Result<Option<CodeBitmapPlan>> {
        let Some(metadata) = self.hybrid_metadata()? else {
            return Ok(None);
        };
        let base = self.extensions[0]
            .as_ref()
            .map(|extension| reader_base(&extension.bytes))
            .transpose()?
            .flatten();
        let ranges = metadata
            .code
            .iter()
            .filter(|range| range.kind == CodeKind::Arm64Ec)
            .map(|range| (range.start, range.end))
            .collect();
        Ok(Some(CodeBitmapPlan { base, ranges }))
    }
}

#[cfg(test)]
mod tests;
