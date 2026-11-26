//! A routed xAPIC message owns its unacknowledged destinations outside the LAPIC FIFO.
//! Canonical wrapper order is IPI -> deadline -> EOI -> base.
use super::*;
use crate::devices::lapic::IpiTarget;

pub(super) const TAG: &[u8; 8] = b"RAXEXE12";
const HEADER_LENGTH: usize = 12;
const MAX_IPI_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingIpiDelivery {
    pub(crate) source: u8,
    pub(crate) request: IpiRequest,
    // None means a read failed before destination selection. Once selected,
    // INIT can change the logical LAPIC registers used by that selection.
    pub(crate) remaining: Option<VecDeque<u8>>,
}

impl PendingIpiDelivery {
    pub(super) fn validate(&self, count: usize) -> Result<()> {
        if usize::from(self.source) >= count {
            return Err(invalid("pending IPI source outside topology"));
        }
        if let Some(targets) = self.remaining.as_ref() {
            let mut previous = None;
            if targets.is_empty()
                || matches!(self.request, IpiRequest::Smi { .. })
                || (matches!(self.request, IpiRequest::LowestPriority { .. }) && targets.len() != 1)
                || targets.iter().copied().any(|target| {
                    let ordered = previous.replace(target).is_none_or(|last| last < target);
                    !ordered
                        || usize::from(target) >= count
                        || match self.request.target() {
                            IpiTarget::ToSelf => target != self.source,
                            IpiTarget::AllExcludingSelf => target == self.source,
                            _ => false,
                        }
                })
            {
                return Err(invalid("invalid remaining IPI destinations"));
            }
        }
        Ok(())
    }
}

impl ExecutionSnapshot {
    pub(super) fn encode_pending_ipi(&self, base: Vec<u8>) -> Result<Vec<u8>> {
        let Some(delivery) = self.pending_ipi.as_ref() else {
            return Ok(base);
        };
        delivery.validate(self.online.len())?;
        let request = encode(&delivery.request)?;
        if request.is_empty() || request.len() > MAX_IPI_BYTES {
            return Err(invalid("pending IPI request exceeds format limit"));
        }
        let count = delivery.remaining.as_ref().map_or(0, VecDeque::len);
        let length = HEADER_LENGTH + 3 + base.len() + request.len() + count;
        if length as u64 > MAX_SECTION {
            return Err(invalid("pending IPI section exceeds format limit"));
        }
        let mut raw = Vec::new();
        raw.try_reserve_exact(length).map_err(invalid)?;
        raw.extend_from_slice(TAG);
        raw.extend_from_slice(&(base.len() as u32).to_le_bytes());
        raw.extend_from_slice(&base);
        raw.extend_from_slice(&[delivery.source, request.len() as u8, count as u8]);
        raw.extend_from_slice(&request);
        if let Some(targets) = delivery.remaining.as_ref() {
            raw.extend(targets.iter().copied());
        }
        Ok(raw)
    }

    pub(super) fn decode_pending_ipi(raw: &[u8], expected_count: u8) -> Result<Option<Self>> {
        if !raw.starts_with(TAG) {
            return Ok(None);
        }
        let length = raw
            .get(TAG.len()..HEADER_LENGTH)
            .map(|length| u32::from_le_bytes(length.try_into().unwrap()) as usize)
            .ok_or_else(|| invalid("truncated pending IPI frame"))?;
        let (base, extension) = raw[HEADER_LENGTH..]
            .split_at_checked(length)
            .ok_or_else(|| invalid("truncated pending IPI inner frame"))?;
        if base.starts_with(TAG) {
            return Err(invalid("nested pending IPI frame"));
        }
        let [source, request_len, target_count, payload @ ..] = extension else {
            return Err(invalid("truncated pending IPI delivery"));
        };
        let request_len = usize::from(*request_len);
        if request_len == 0
            || request_len > MAX_IPI_BYTES
            || payload.len() != request_len + usize::from(*target_count)
        {
            return Err(invalid("invalid pending IPI record length"));
        }
        let (request, targets) = payload.split_at(request_len);
        let delivery = PendingIpiDelivery {
            source: *source,
            request: decode(request)?,
            remaining: (!targets.is_empty()).then(|| VecDeque::from_iter(targets.iter().copied())),
        };
        delivery.validate(usize::from(expected_count))?;
        let mut state = Self::decode(base, expected_count)?;
        state.pending_ipi = Some(delivery);
        Ok(Some(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ExecutionSnapshot {
        ExecutionSnapshot {
            cursor: 3,
            retired: 53,
            last_snapshot_insn: None,
            online: vec![true, false, true, true],
            local_apics: (0..4)
                .map(|id| LocalApic::new(id).checkpoint_at(crate::host::time::Instant::now()))
                .collect(),
            pending_ipi: None,
            pc: None,
            pl011: None,
            riscv_platform: None,
            arm_cluster: None,
        }
    }

    fn delivery(remaining: Option<VecDeque<u8>>) -> PendingIpiDelivery {
        PendingIpiDelivery {
            source: 0,
            request: IpiRequest::Init {
                target: IpiTarget::AllExcludingSelf,
            },
            remaining,
        }
    }

    #[test]
    fn pending_ipi_wraps_the_unchanged_controller_frame() {
        let mut state = fixture();
        state.last_snapshot_insn = Some(17);
        let apic = &mut state.local_apics[0];
        apic.queued.push_back(IpiRequest::Sipi {
            vector: 9,
            target: IpiTarget::AllExcludingSelf,
        });
        apic.eois.push_back(0x51);
        apic.registers.write_register(0x320, 0x40051);
        apic.registers.deadline_handle().write(42);
        let before = state.encoded().unwrap();
        assert!(before.starts_with(super::super::deadline::TAG));
        for remaining in [None, Some(VecDeque::from([2, 3]))] {
            state.pending_ipi = Some(delivery(remaining));
            let raw = state.encoded().unwrap();
            assert!(raw.starts_with(TAG));
            assert_eq!(&raw[HEADER_LENGTH..HEADER_LENGTH + before.len()], before);
            let restored = ExecutionSnapshot::decode(&raw, 4).unwrap();
            assert_eq!(restored.pending_ipi, state.pending_ipi);
            assert_eq!(restored.last_snapshot_insn, Some(17));
            assert_eq!(restored.encoded().unwrap(), raw);
        }
        let legacy = ExecutionSnapshot::decode(&before, 4).unwrap();
        assert_eq!(legacy.pending_ipi, None);
        assert_eq!(legacy.encoded().unwrap(), before);
    }

    #[test]
    fn malformed_pending_ipi_lengths_topology_and_nesting_are_rejected() {
        let mut state = fixture();
        state.pending_ipi = Some(delivery(Some(VecDeque::from([2, 3]))));
        let raw = state.encoded().unwrap();
        for length in 0..raw.len() {
            assert!(
                ExecutionSnapshot::decode(&raw[..length], 4).is_err(),
                "prefix {length}"
            );
        }
        let record = HEADER_LENGTH + state.encoded_base().unwrap().len();
        for corruption in 0..9 {
            let mut bad = raw.clone();
            let length = bad.len();
            match corruption {
                0 => bad.push(0),
                1 => bad[record] = 4,
                2 => bad[record + 1] = 33,
                3 => bad[record + 2] = 3,
                4 => bad[length - 1] = 2,
                5 => bad[length - 2] = 0,
                6 => bad[length - 1] = 4,
                7 => bad[HEADER_LENGTH..HEADER_LENGTH + TAG.len()].copy_from_slice(TAG),
                _ => bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes()),
            }
            assert!(
                ExecutionSnapshot::decode(&bad, 4).is_err(),
                "corruption {corruption}"
            );
        }
        let mut inverted = super::super::deadline::TAG.to_vec();
        inverted.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        inverted.extend_from_slice(&raw);
        assert!(ExecutionSnapshot::decode(&inverted, 4).is_err());
    }
}
