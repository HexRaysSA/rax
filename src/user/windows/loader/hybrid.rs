//! Decode ISA ranges from the exact view used for module metadata and bytes.
use super::*;
use crate::user::image::pe::PeKind;
use crate::user::image::pe::hybrid::CodeKind;
use crate::user::windows::arch::InstructionRoute;
use crate::user::windows::memory::Mem;

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

pub(super) fn bind_helpers(
    p: &mut Proc,
    metadata: Option<&HybridMetadata>,
    base: u64,
) -> Result<(), LoadError> {
    if p.arch != WinArch::X64 || p.native.is_none() {
        return Ok(());
    }
    let Some(metadata) = metadata else {
        return Ok(());
    };
    let mut writes = Vec::with_capacity(8);
    for (index, rva) in metadata.dispatch_slots.iter().copied().enumerate() {
        if rva == 0 {
            continue;
        }
        let target = p.traps.arm64ec_helper(index);
        if target == 0 {
            return Err(LoadError::new(
                STATUS_INVALID_IMAGE_FORMAT,
                "ARM64EC helper frontier is unavailable",
            ));
        }
        let address = base.checked_add(u64::from(rva)).ok_or_else(|| {
            LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "ARM64EC helper slot overflow")
        })?;
        p.space.u64(address).map_err(|_| {
            LoadError::new(
                STATUS_INVALID_IMAGE_FORMAT,
                "ARM64EC helper slot is unreadable",
            )
        })?;
        writes.push((address, target));
    }
    // These are private guest pages. Native pointers are never called or
    // copied into host execution; every slot enters a registered NX trap.
    for (address, target) in writes {
        p.vm.poke(address, &target.to_le_bytes()).map_err(|_| {
            LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "ARM64EC helper binding failed")
        })?;
    }
    Ok(())
}

impl Modules {
    pub(crate) fn code_kind(&self, pc: u64) -> Option<CodeKind> {
        let (_, module) = self.by_address(pc)?;
        match &module.hybrid {
            Some(metadata) => metadata.code_kind(u32::try_from(pc - module.base).ok()?),
            None => Some(CodeKind::Amd64),
        }
    }

    pub(crate) fn instruction_route(
        &self,
        mem: &impl Mem,
        pc: u64,
        active: WinArch,
        context_resume: bool,
    ) -> Result<InstructionRoute, String> {
        let Some((_, module)) = self.by_address(pc) else {
            // Private kernel/frontier slots retain the active decoder until
            // its checked instruction-fetch fault enters the trap registry.
            return Ok(InstructionRoute::Stay);
        };
        let kind = self.code_kind(pc);
        if context_resume {
            return match kind {
                Some(CodeKind::Amd64) => Ok(InstructionRoute::ResumeX64),
                Some(CodeKind::Arm64Ec | CodeKind::Arm64) => Ok(InstructionRoute::ResumeArm64),
                _ => Err(format!(
                    "mixed context resumes outside admitted code at {pc:#x}"
                )),
            };
        }
        match (active, kind) {
            (WinArch::X64, Some(CodeKind::Amd64))
            | (WinArch::Arm64, Some(CodeKind::Arm64Ec | CodeKind::Arm64)) => {
                Ok(InstructionRoute::Stay)
            }
            (WinArch::X64, Some(CodeKind::Arm64Ec)) => {
                let prefix = pc.checked_sub(4).ok_or("ARM64EC entry prefix underflow")?;
                let word = mem
                    .u32(prefix)
                    .map_err(|_| "ARM64EC entry prefix is unreadable")?;
                if word == 0xd63f_0200 {
                    // An x64 callee returned after the exit thunk's BLR X16.
                    return Ok(InstructionRoute::ResumeArm64);
                }
                let displacement = (word & !3) as i32;
                let thunk = pc
                    .checked_add_signed(i64::from(displacement))
                    .filter(|target| *target != pc && module.contains(*target))
                    .ok_or("ARM64EC entry thunk extent is invalid")?;
                if self.code_kind(thunk) != Some(CodeKind::Arm64Ec) {
                    return Err("ARM64EC entry thunk is outside emulation-compatible code".into());
                }
                Ok(InstructionRoute::Enter { target: pc, thunk })
            }
            _ => Err(format!(
                "mixed instruction requires an unadmitted transition at {pc:#x}: active={active}, code={kind:?}"
            )),
        }
    }

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
