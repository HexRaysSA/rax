//! A saved private producer selects a machine family before CPU construction.
use super::*;
use crate::vm::snapshot::{BackendContexts, GSC_CONTEXT, RISCV_CONTEXT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MachineFamily {
    Generic,
    Gsc,
    S5l8900,
}
impl MachineFamily {
    pub(super) fn from_env(arch: ArchKind) -> Self {
        match (arch, std::env::var("RAX_MACHINE").as_deref()) {
            (ArchKind::Riscv64, Ok("gsc")) => Self::Gsc,
            (ArchKind::Armv7a, Ok("s5l8900")) => Self::S5l8900,
            _ => Self::Generic,
        }
    }
}

pub(super) fn family(
    arch: ArchKind,
    contexts: Option<&BackendContexts>,
) -> Result<Option<MachineFamily>> {
    let Some(contexts) = contexts else {
        return Ok(None);
    };
    classify(arch, contexts.entries())
}

fn classify(
    arch: ArchKind,
    entries: &[Option<crate::vm::snapshot::BackendContext>],
) -> Result<Option<MachineFamily>> {
    let gsc = entries.iter().flatten().any(|c| c.kind == GSC_CONTEXT);
    if gsc {
        if arch != ArchKind::Riscv64 {
            return Err(Error::InvalidConfig(
                "GSC checkpoint requires RISC-V machine architecture".into(),
            ));
        }
        if entries.iter().any(Option::is_none) {
            return Err(Error::InvalidConfig(
                "checkpoint missing private context for GSC machine".into(),
            ));
        }
        if entries.iter().flatten().any(|c| c.kind != GSC_CONTEXT) {
            return Err(Error::InvalidConfig(
                "checkpoint GSC machine has conflicting CPU producers".into(),
            ));
        }
        return Ok(Some(MachineFamily::Gsc));
    }
    if arch == ArchKind::Riscv64 {
        if entries.iter().flatten().any(|c| c.kind != RISCV_CONTEXT) {
            return Err(Error::InvalidConfig(
                "checkpoint RISC-V machine has a foreign CPU producer".into(),
            ));
        }
        return Ok(Some(MachineFamily::Generic));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::snapshot::BackendContext;
    fn row(kind: u32) -> Option<BackendContext> {
        Some(BackendContext {
            kind,
            data: vec![1],
        })
    }
    #[test]
    fn gsc_family_requires_every_cpu_and_the_riscv_architecture() {
        for count in [1, 2, 4] {
            let mut rows = vec![row(GSC_CONTEXT); count];
            assert_eq!(
                classify(ArchKind::Riscv64, &rows).unwrap(),
                Some(MachineFamily::Gsc)
            );
            assert!(classify(ArchKind::X86_64, &rows).is_err());
            *rows.last_mut().unwrap() = None;
            if count > 1 {
                assert!(classify(ArchKind::Riscv64, &rows).is_err());
            }
        }
    }
    #[test]
    fn mixed_and_foreign_riscv_producers_reject_before_construction() {
        assert!(classify(ArchKind::Riscv64, &[row(GSC_CONTEXT), row(RISCV_CONTEXT)]).is_err());
        assert!(
            classify(
                ArchKind::Riscv64,
                &[row(crate::vm::snapshot::HEXAGON_CONTEXT)]
            )
            .is_err()
        );
    }
    #[test]
    fn generic_riscv_private_tables_select_the_generic_family() {
        assert_eq!(
            classify(ArchKind::Riscv64, &[row(RISCV_CONTEXT)]).unwrap(),
            Some(MachineFamily::Generic)
        );
        assert_eq!(
            classify(ArchKind::Riscv64, &[row(RISCV_CONTEXT), None]).unwrap(),
            Some(MachineFamily::Generic)
        );
    }
    #[test]
    fn absent_and_other_architecture_tables_retain_existing_selection() {
        assert_eq!(family(ArchKind::Riscv64, None).unwrap(), None);
        assert_eq!(
            classify(
                ArchKind::Aarch64,
                &[row(crate::vm::snapshot::AARCH64_CONTEXT)]
            )
            .unwrap(),
            None
        );
    }
}
