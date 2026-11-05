//! Decode ISA ranges from the exact view used for module metadata and bytes.
use super::*;
use crate::user::image::pe::PeKind;
use crate::user::image::pe::hybrid::CodeKind;

#[cfg(test)]
#[path = "hybrid_tests.rs"]
mod tests;

pub(super) fn decode(pe: &PeImage) -> Result<Option<Arc<HybridMetadata>>, LoadError> {
    let h = pe.headers();
    let directory = h.directory(dir::LOAD_CONFIG);
    if h.kind != PeKind::Pe32Plus || !directory.is_present() {
        return Ok(None);
    }
    let config = LoadConfig::read(pe, h.kind, directory).map_err(|fault| {
        LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            format!("hybrid load configuration at RVA {:#x}", fault.rva),
        )
    })?;
    let Some(pointer) = config
        .and_then(|config| config.chpe_metadata_pointer)
        .filter(|&p| p != 0)
    else {
        return Ok(None);
    };
    HybridMetadata::read(pe, pointer, h.image_base, h.size_of_image)
        .map(|metadata| Some(Arc::new(metadata)))
        .map_err(|error| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, error.to_string()))
}

impl Modules {
    pub(crate) fn has_hybrid_code(&self) -> bool {
        self.list
            .iter()
            .enumerate()
            .any(|(index, module)| self.is_live(index) && module.hybrid.is_some())
    }

    /// AMD64 compatibility execution needs a transition before ARM64 code.
    /// Native ARM64 still decodes ARM64 instructions normally: an ARM64EC ABI
    /// tag does not change their instruction set or hardware permissions.
    /// O(M + log C) for AMD64; other architectures return without a lookup.
    pub(crate) fn check_instruction(&self, arch: WinArch, pc: u64) -> Result<(), String> {
        if arch != WinArch::X64 {
            return Ok(());
        }
        let Some((_, module)) = self.by_address(pc) else {
            return Ok(());
        };
        let Some(metadata) = &module.hybrid else {
            return Ok(());
        };
        let rva = u32::try_from(pc - module.base)
            .map_err(|_| "hybrid instruction RVA exceeds 32 bits".to_owned())?;
        let kind = metadata.code_kind(rva);
        if kind == Some(CodeKind::Amd64) {
            return Ok(());
        }
        Err(format!(
            "hybrid instruction requires an ISA/ABI transition: {}+{rva:#x} at {pc:#x}, code={kind:?}, current={arch}",
            module.name,
        ))
    }
}
