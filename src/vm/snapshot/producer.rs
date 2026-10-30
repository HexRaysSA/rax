//! Admission of public CPU projections with their complete native producer graph.

use super::{BackendContext, BackendContexts, CpuSnapshots, EmulatorState, Snapshot};
use crate::backend::arm64_hvf_context::{Context, GlobalContext};
use crate::config::{ArchKind, BackendKind, CheckpointConfig};
use crate::error::{Error, Result};

pub(super) fn is_native(config: &CheckpointConfig) -> bool {
    config.backend == BackendKind::Hvf && config.arch == ArchKind::Aarch64
}

fn invalid(message: &str) -> Error {
    Error::Emulator(format!("checkpoint producer graph: {message}"))
}

pub(super) fn validate(
    base: &Snapshot,
    cpus: Option<&CpuSnapshots>,
    contexts: Option<&BackendContexts>,
    shared: Option<&BackendContext>,
) -> Result<()> {
    if !is_native(&base.config) {
        if shared.is_some()
            || contexts.is_some_and(|set| {
                set.entries()
                    .iter()
                    .flatten()
                    .any(|record| record.kind == super::HVF_AARCH64_CONTEXT)
            })
        {
            return Err(invalid("native records require their native configuration"));
        }
        base.validate_for_restore()?;
        if let Some(cpus) = cpus {
            cpus.validate(base)?;
        }
        return Ok(());
    }

    base.validate_envelope()?;
    let cpus = cpus.ok_or_else(|| invalid("native producer requires the complete CPU set"))?;
    cpus.validate_structure(base)?;
    let contexts = contexts.ok_or_else(|| invalid("missing native CPU contexts"))?;
    contexts.validate(base.config.vcpus)?;
    let shared = shared.ok_or_else(|| invalid("missing shared native VM context"))?;
    super::vm_context::validate(shared)?;
    if shared.kind != super::HVF_AARCH64_CONTEXT {
        return Err(invalid("shared context belongs to a different producer"));
    }
    let shared = GlobalContext::decode(&shared.data)?;
    if shared.cpus != base.config.vcpus
        || shared.ram_size != base.memory_size
        || shared.ram_base != crate::machine::arm_virt::AARCH64_RAM_BASE
        || shared.distributor_base != crate::machine::arm_virt::AARCH64_GICD_BASE
        || shared.redistributor_base != crate::machine::arm_virt::AARCH64_GICR_BASE
    {
        return Err(invalid("shared native topology differs from the machine"));
    }
    let encode_emulator = |state: &EmulatorState| {
        crate::codec::serialize_limited(state, 4096)
            .map_err(|error| Error::Emulator(format!("native emulator projection: {error}")))
    };
    let default_emulator = encode_emulator(&EmulatorState::default())?;
    let mut profile = None;
    for (id, (cpu, context)) in cpus.entries().iter().zip(contexts.entries()).enumerate() {
        let context = context
            .as_ref()
            .filter(|record| record.kind == super::HVF_AARCH64_CONTEXT)
            .ok_or_else(|| invalid("missing or mismatched native CPU producer"))?;
        let context = Context::decode(&context.data)?;
        context.admit(id as u32, &context.profile, &cpu.state)?;
        if context.shutdown != shared.power.shutdown {
            return Err(invalid(
                "native CPU terminal state differs from the VM power graph",
            ));
        }
        if profile
            .as_ref()
            .is_some_and(|saved| saved != &context.profile)
        {
            return Err(invalid("native CPU profiles differ within one VM"));
        }
        profile = Some(context.profile);
        if encode_emulator(&cpu.emulator)? != default_emulator {
            return Err(invalid(
                "native CPU contains foreign emulator-private state",
            ));
        }
    }
    // ID_AA64MMFR0_EL1.BigEnd[11:8]: only 1 denotes BE support. A
    // checkpoint must not manufacture an entry mode absent from its profile.
    if shared
        .power
        .pending
        .iter()
        .any(|pending| pending.big_endian)
        && !profile
            .as_ref()
            .and_then(|profile| profile.feature_values.iter().find(|r| r.id == 0xc038))
            .is_some_and(|r| (r.value >> 8) & 15 == 1)
    {
        return Err(invalid(
            "pending big-endian startup requires native BigEnd capability",
        ));
    }
    // SDK compatibility and the opaque GIC image are admitted independently by
    // the actual destination backend before it performs any restore writes.
    Ok(())
}
