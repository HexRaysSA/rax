//! Explicit migration of private context versions; base positional layout stays fixed.
use super::*;

impl Context {
    fn bind_pending_input_port(&mut self, saved_port: Option<u16>) -> Result<()> {
        let queued = match self.pending_exit.as_ref() {
            Some(ExitContext::IoIn { port, size }) => Some((*port, *size, 1)),
            Some(ExitContext::IoInString { port, size, count }) => Some((*port, *size, *count)),
            _ => None,
        };
        let Some(input) = &mut self.io_pending else {
            if saved_port.is_some() || queued.is_some() {
                return Err(invalid("pending port input has no destination"));
            }
            return Ok(());
        };
        if let Some((port, size, count)) = queued {
            if input.size != size
                || input.count != count
                || saved_port.is_some_and(|saved| saved != port)
            {
                return Err(invalid("pending port input disagrees with queued exit"));
            }
            // Older records can recover the port if a JIT exit was still queued.
            input.port = Some(port);
        } else {
            input.port = saved_port;
        }
        Ok(())
    }

    pub(super) fn decode(raw: &[u8], target: &X86_64Vcpu) -> Result<Self> {
        if raw.len() > TAG.len() + MAX_PAYLOAD {
            return Err(invalid("invalid tag or length"));
        }
        let (version5, nmi_blocked, port, reply) = if let Some(payload) = raw
            .strip_prefix(PORT_REPLY_TAG)
            .or_else(|| raw.strip_prefix(IOAPIC_PORT_REPLY_TAG))
        {
            let version =
                crate::codec::deserialize_limited::<PortReplyVersion<Self>, MAX_PAYLOAD>(payload)
                    .map_err(invalid)?;
            (
                Some(version.base),
                version.nmi_blocked,
                version.port,
                Some(version.reply),
            )
        } else if let Some(payload) = raw
            .strip_prefix(PORT_INPUT_TAG)
            .or_else(|| raw.strip_prefix(IOAPIC_PORT_INPUT_TAG))
        {
            let version =
                crate::codec::deserialize_limited::<PortInputVersion<Self>, MAX_PAYLOAD>(payload)
                    .map_err(invalid)?;
            (
                Some(version.base),
                version.nmi_blocked,
                Some(version.port),
                None,
            )
        } else if let Some(payload) = raw
            .strip_prefix(IOAPIC_SHADOW_TAG)
            .or_else(|| raw.strip_prefix(SHADOW_TAG))
            .or_else(|| raw.strip_prefix(NMI_BLOCKED_TAG))
            .or_else(|| raw.strip_prefix(IOAPIC_NMI_BLOCKED_TAG))
        {
            let version = crate::codec::deserialize_limited::<Version5<Self>, MAX_PAYLOAD>(payload)
                .map_err(invalid)?;
            let nmi_blocked =
                raw.starts_with(NMI_BLOCKED_TAG) || raw.starts_with(IOAPIC_NMI_BLOCKED_TAG);
            (Some(version), nmi_blocked, None, None)
        } else {
            (None, false, None, None)
        };
        let (mut context, status, apic_base, shadow) = if let Some(version) = version5 {
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
        context.nmi_blocked = nmi_blocked;
        context.mmu.ioapic_mmio = X86_64Vcpu::context_requires_ioapic(raw);
        context.bind_pending_input_port(port)?;
        if let Some(reply) = reply {
            context
                .io_pending
                .as_mut()
                .ok_or_else(|| invalid("received port reply has no destination"))?
                .reply = Some(reply);
        }
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
        let version = Version5 {
            base: version,
            instruction_debug_inhibit: shadow,
        };
        let port = self.io_pending.as_ref().and_then(|input| input.port);
        let reply = self
            .io_pending
            .as_ref()
            .and_then(|input| input.reply.as_ref());
        let payload = if let Some(reply) = reply {
            crate::codec::serialize_limited(
                &PortReplyVersion {
                    base: version,
                    nmi_blocked: self.nmi_blocked,
                    port,
                    reply: reply.clone(),
                },
                MAX_PAYLOAD,
            )
        } else if let Some(port) = port {
            crate::codec::serialize_limited(
                &PortInputVersion {
                    base: version,
                    nmi_blocked: self.nmi_blocked,
                    port,
                },
                MAX_PAYLOAD,
            )
        } else if shadow || self.nmi_blocked {
            crate::codec::serialize_limited(&version, MAX_PAYLOAD)
        } else {
            crate::codec::serialize_limited(&version.base, MAX_PAYLOAD)
        }
        .map_err(invalid)?;
        let mut raw = Vec::with_capacity(TAG.len() + payload.len());
        raw.extend_from_slice(
            match (
                reply.is_some(),
                port.is_some(),
                self.nmi_blocked,
                shadow,
                self.mmu.ioapic_mmio,
            ) {
                (true, _, _, _, true) => IOAPIC_PORT_REPLY_TAG,
                (true, _, _, _, false) => PORT_REPLY_TAG,
                (false, true, _, _, true) => IOAPIC_PORT_INPUT_TAG,
                (false, true, _, _, false) => PORT_INPUT_TAG,
                (false, false, true, _, true) => IOAPIC_NMI_BLOCKED_TAG,
                (false, false, true, _, false) => NMI_BLOCKED_TAG,
                (false, false, false, true, true) => IOAPIC_SHADOW_TAG,
                (false, false, false, true, false) => SHADOW_TAG,
                (false, false, false, false, true) => IOAPIC_TAG,
                (false, false, false, false, false) => TAG,
            },
        );
        raw.extend_from_slice(&payload);
        Ok(raw)
    }
}
