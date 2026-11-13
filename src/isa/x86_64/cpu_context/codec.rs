//! Explicit migration of private context versions; base positional layout stays fixed.
use super::*;

impl Context {
    pub(super) fn decode(raw: &[u8], target: &X86_64Vcpu) -> Result<Self> {
        if raw.len() > TAG.len() + MAX_PAYLOAD {
            return Err(invalid("invalid tag or length"));
        }
        let ioapic_mmio = raw.starts_with(IOAPIC_TAG) || raw.starts_with(IOAPIC_SHADOW_TAG);
        let (mut context, status, apic_base, shadow) = if let Some(payload) = raw
            .strip_prefix(IOAPIC_SHADOW_TAG)
            .or_else(|| raw.strip_prefix(SHADOW_TAG))
        {
            let version = crate::codec::deserialize_limited::<Version5<Self>, MAX_PAYLOAD>(payload)
                .map_err(invalid)?;
            (
                version.base.base.base,
                Some(version.base.base.user_debug_status),
                Some(version.base.apic_base),
                version.instruction_debug_inhibit,
            )
        } else if let Some(payload) = raw
            .strip_prefix(IOAPIC_TAG)
            .or_else(|| raw.strip_prefix(TAG))
        {
            let version = crate::codec::deserialize_limited::<Version3<Self>, MAX_PAYLOAD>(payload)
                .map_err(invalid)?;
            (
                version.base.base,
                Some(version.base.user_debug_status),
                Some(version.apic_base),
                false,
            )
        } else if let Some(payload) = raw.strip_prefix(VERSION2_TAG) {
            let version = crate::codec::deserialize_limited::<Version2<Self>, MAX_PAYLOAD>(payload)
                .map_err(invalid)?;
            (version.base, Some(version.user_debug_status), None, false)
        } else if let Some(payload) = raw.strip_prefix(LEGACY_TAG) {
            (
                crate::codec::deserialize_limited::<Self, MAX_PAYLOAD>(payload).map_err(invalid)?,
                None,
                None,
                false,
            )
        } else {
            return Err(invalid("invalid tag or length"));
        };
        if let Some(status) = status {
            if context.user.is_some() != status.is_some() {
                return Err(invalid("user debug status binding differs"));
            }
            if let (Some(user), Some(value)) = (&mut context.user, status) {
                user.last_debug_status = value;
            }
        }
        if shadow {
            let Some(user) = &mut context.user else {
                return Err(invalid("instruction debug shadow requires a user binding"));
            };
            user.instruction_debug_inhibit = true;
        }
        context.apic_base = apic_base
            .unwrap_or_else(|| crate::isa::x86_64::identity::initial_apic_base(context.id));
        context.mmu.ioapic_mmio = ioapic_mmio;
        context.validate(target)?;
        Ok(context)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let version = Version3 {
            base: Version2 {
                base: self,
                user_debug_status: self.user.as_ref().map(|user| user.last_debug_status),
            },
            apic_base: self.apic_base,
        };
        let shadow = self
            .user
            .as_ref()
            .is_some_and(|user| user.instruction_debug_inhibit);
        let payload = if shadow {
            crate::codec::serialize_limited(
                &Version5 {
                    base: version,
                    instruction_debug_inhibit: true,
                },
                MAX_PAYLOAD,
            )
        } else {
            crate::codec::serialize_limited(&version, MAX_PAYLOAD)
        }
        .map_err(invalid)?;
        let mut raw = Vec::with_capacity(TAG.len() + payload.len());
        raw.extend_from_slice(match (shadow, self.mmu.ioapic_mmio) {
            (true, true) => IOAPIC_SHADOW_TAG,
            (true, false) => SHADOW_TAG,
            (false, true) => IOAPIC_TAG,
            (false, false) => TAG,
        });
        raw.extend_from_slice(&payload);
        Ok(raw)
    }
}
