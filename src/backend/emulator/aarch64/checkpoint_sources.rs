//! Framed owned-GIC source records and complete VM timer-input admission.
use super::*;

pub(super) const TAG: &[u8; 8] = b"RAXA6405";

use crate::isa::arm::aarch64::gic::checkpoint::LegacyGicCheckpoint;

fn upgrade_legacy(old: Context<LegacyGicCheckpoint>) -> Result<Context> {
    let Context {
        counter_clock,
        id,
        core,
        observed_instructions,
        trace_reg_last,
        heartbeat_age,
        shutdown,
        fault_exits,
        powered_off,
        clustered,
        uart_bound,
        recording,
        observations,
        user,
        reservation,
        owned_gic,
    } = old;
    Ok(Context {
        counter_clock,
        id,
        core,
        observed_instructions,
        trace_reg_last,
        heartbeat_age,
        shutdown,
        fault_exits,
        powered_off,
        clustered,
        uart_bound,
        recording,
        observations,
        user,
        reservation,
        owned_gic: owned_gic.map(LegacyGicCheckpoint::upgrade).transpose()?,
    })
}

pub(super) fn decode(raw: &[u8]) -> Result<Context> {
    if raw.len() > MAX_PAYLOAD + 8 {
        return Err(invalid("record exceeds budget"));
    }
    let owned_sources = raw.starts_with(TAG) || raw.starts_with(counter_clock::OWNED_TAG);
    let (payload, clock) = if counter_clock::is_tag(raw) {
        let header = raw
            .get(8..8 + counter_clock::SIZE)
            .ok_or_else(|| invalid("truncated system counter header"))?;
        (
            &raw[8 + counter_clock::SIZE..],
            Some(counter_clock::decode(header)?),
        )
    } else {
        let payload = raw
            .strip_prefix(TAG)
            .or_else(|| raw.strip_prefix(super::TAG))
            .or_else(|| raw.strip_prefix(PREVIOUS_TAG))
            .or_else(|| raw.strip_prefix(LEGACY_TAG))
            .ok_or_else(|| invalid("invalid tag"))?;
        (payload, None)
    };
    let mut state: Context = if owned_sources {
        crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?
    } else {
        upgrade_legacy(
            crate::codec::deserialize_limited::<Context<LegacyGicCheckpoint>, MAX_PAYLOAD>(payload)
                .map_err(invalid)?,
        )?
    };
    state.counter_clock = clock;
    if owned_sources && state.owned_gic.is_none() {
        return Err(invalid("owned-GIC source record has no controller"));
    }
    validate_owned(&state)?;
    Ok(state)
}

pub(super) fn validate_owned(state: &Context) -> Result<()> {
    if state.core.owns_gic() != state.owned_gic.is_some() {
        return Err(invalid("invalid owned GIC source binding"));
    }
    if let Some((false, cpu, levels)) = state.core.gic_timer_frontier() {
        state
            .owned_gic
            .as_ref()
            .ok_or_else(|| invalid("missing owned GIC"))?
            .validate_timer_inputs(cpu, levels)?;
    }
    Ok(())
}

pub(super) fn validate_set(bundle: &crate::vm::snapshot::SnapshotBundle) -> Result<()> {
    let cluster = bundle
        .execution()
        .and_then(|execution| execution.arm_cluster.as_ref());
    let Some(records) = bundle.backend_contexts() else {
        return if cluster.is_some() {
            Err(invalid(
                "shared GIC is missing its private CPU source frontiers",
            ))
        } else {
            Ok(())
        };
    };
    let count = usize::from(bundle.base().config.vcpus);
    let mut shared = 0;
    for (id, record) in records.entries().iter().enumerate() {
        let Some(record) = record else {
            continue;
        };
        if record.kind != AARCH64_CONTEXT {
            continue;
        }
        let state = decode(&record.data)?;
        if state.id as usize != id {
            return Err(invalid(
                "GIC source CPU identity differs from record position",
            ));
        }
        if let Some((true, cpu, levels)) = state.core.gic_timer_frontier() {
            if cpu != id {
                return Err(invalid("GIC timer source is bound to another CPU"));
            }
            cluster
                .ok_or_else(|| invalid("missing shared GIC source state"))?
                .validate_timer_inputs(cpu, levels)?;
            shared += 1;
        }
    }
    if cluster.is_some() && (shared != count || records.entries().len() != count) {
        return Err(invalid(
            "shared GIC is missing a required private CPU source frontier",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn legacy_payload_for_test(state: &Context) -> Vec<u8> {
    let old: Context<LegacyGicCheckpoint> =
        serde_json::from_value(serde_json::to_value(state).unwrap()).unwrap();
    crate::codec::serialize(&old).unwrap()
}
