//! Modeled controller image; publication never replays register-write effects.
use super::{
    IOAPIC_NUM_RTE, IoApic, PendingIrq, RTE_DELIVERY_MODE_SHIFT, RTE_DELIVERY_STATUS,
    RTE_DEST_SHIFT, RTE_MASK, RTE_REMOTE_IRR, RTE_TRIGGER_MODE,
};
use crate::error::{Error, Result};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_PENDING: usize = IOAPIC_NUM_RTE;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Delivery {
    gsi: u8,
    vector: u8,
    destination: u8,
    level_triggered: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct IoApicCheckpoint {
    ioregsel: u8,
    id: u32,
    redirection_table: [u64; IOAPIC_NUM_RTE],
    line_asserted: [bool; IOAPIC_NUM_RTE],
    #[serde(deserialize_with = "deliveries")]
    pending: Vec<Delivery>,
}

fn deliveries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Delivery>, D::Error> {
    struct Messages;
    impl<'de> Visitor<'de> for Messages {
        type Value = Vec<Delivery>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most 24 I/O APIC messages")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let count = sequence.size_hint().unwrap_or(0);
            if count > MAX_PENDING {
                return Err(A::Error::custom("I/O APIC pending message bound"));
            }
            let mut messages = Vec::with_capacity(count);
            while let Some(message) = sequence.next_element()? {
                if messages.len() == MAX_PENDING {
                    return Err(A::Error::custom("I/O APIC pending message bound"));
                }
                messages.push(message);
            }
            Ok(messages)
        }
    }
    deserializer.deserialize_seq(Messages)
}

pub(crate) struct PreparedIoApicCheckpoint {
    ioregsel: u8,
    id: u32,
    redirection_table: [u64; IOAPIC_NUM_RTE],
    line_asserted: [bool; IOAPIC_NUM_RTE],
    pending: Vec<PendingIrq>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("I/O APIC checkpoint: {message}"))
}

impl IoApic {
    pub(crate) fn checkpoint_state(&self) -> Result<IoApicCheckpoint> {
        if self.pending.len() > MAX_PENDING {
            return Err(invalid("pending delivery limit exceeded"));
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(self.pending.len())
            .map_err(invalid)?;
        pending.extend(self.pending.iter().map(|entry| Delivery {
            gsi: entry.gsi,
            vector: entry.vector,
            destination: entry.destination,
            level_triggered: entry.level_triggered,
        }));
        let image = IoApicCheckpoint {
            ioregsel: self.ioregsel,
            id: self.id,
            redirection_table: self.redirection_table,
            line_asserted: self.line_asserted,
            pending,
        };
        image.prepare()?;
        Ok(image)
    }
}

impl IoApicCheckpoint {
    pub(crate) fn prepare(&self) -> Result<PreparedIoApicCheckpoint> {
        if self.id & !0x0f00_0000 != 0
            || self.pending.len() > MAX_PENDING
            || self
                .pending
                .iter()
                .any(|entry| usize::from(entry.gsi) >= IOAPIC_NUM_RTE)
        {
            return Err(invalid("invalid identity, queue length or source pin"));
        }
        let mut queued = [false; IOAPIC_NUM_RTE];
        for request in &self.pending {
            let pin = usize::from(request.gsi);
            let rte = self.redirection_table[pin];
            if std::mem::replace(&mut queued[pin], true)
                || rte & RTE_MASK != 0
                || rte & RTE_REMOTE_IRR != 0
                || request.vector != rte as u8
                || request.destination != (rte >> RTE_DEST_SHIFT) as u8
                || request.level_triggered != (rte & RTE_TRIGGER_MODE != 0)
                || (request.level_triggered && !self.line_asserted[pin])
            {
                return Err(invalid("ambiguous or inconsistent pending message"));
            }
        }
        for (pin, &rte) in self.redirection_table.iter().enumerate() {
            let mode = (rte >> RTE_DELIVERY_MODE_SHIFT) & 7;
            if (rte & RTE_DELIVERY_STATUS != 0) != queued[pin]
                || (rte & RTE_REMOTE_IRR != 0 && (rte & RTE_TRIGGER_MODE == 0 || mode > 1))
                || (mode <= 1
                    && rte & RTE_TRIGGER_MODE != 0
                    && rte & RTE_MASK == 0
                    && self.line_asserted[pin]
                    && rte & RTE_REMOTE_IRR == 0
                    && !queued[pin])
            {
                return Err(invalid(
                    "controller delivery status differs from its owned phase",
                ));
            }
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(self.pending.len())
            .map_err(invalid)?;
        pending.extend(self.pending.iter().map(|entry| PendingIrq {
            gsi: entry.gsi,
            vector: entry.vector,
            destination: entry.destination,
            level_triggered: entry.level_triggered,
        }));
        Ok(PreparedIoApicCheckpoint {
            ioregsel: self.ioregsel,
            id: self.id,
            redirection_table: self.redirection_table,
            line_asserted: self.line_asserted,
            pending,
        })
    }
}

impl PreparedIoApicCheckpoint {
    pub(crate) fn commit(self, target: &mut IoApic) {
        target.ioregsel = self.ioregsel;
        target.id = self.id;
        target.redirection_table = self.redirection_table;
        target.line_asserted = self.line_asserted;
        // Calling write_indexed here could enqueue asserted lines a second time.
        target.pending = self.pending;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::MmioDevice;

    #[test]
    fn all_registers_levels_and_delivery_order_survive_without_reassertion() {
        let mut source = IoApic::new();
        source.write_indexed(0, 0x0900_0000);
        for pin in 0..IOAPIC_NUM_RTE {
            let low =
                0x40 + pin as u32 | (((pin & 1) as u32) << 15) | (u32::from(pin % 3 == 0) << 16);
            source.write_indexed(0x10 + 2 * pin as u32, low);
            source.write_indexed(0x11 + 2 * pin as u32, ((pin * 7) as u32) << 24 | 0xabcdef);
            source.set_irq(pin as u8, true);
        }
        source.ioregsel = 0xff;
        let image = source.checkpoint_state().unwrap();
        let bytes = crate::codec::serialize(&image).unwrap();
        assert_eq!(bytes.len(), 229 + 4 * source.pending.len());
        let decoded: IoApicCheckpoint = crate::codec::deserialize_strict(&bytes).unwrap();
        let mut target = IoApic::new();
        decoded.prepare().unwrap().commit(&mut target);
        assert_eq!(target.ioregsel, source.ioregsel);
        assert_eq!(target.id, source.id);
        assert_eq!(target.redirection_table, source.redirection_table);
        assert_eq!(target.line_asserted, source.line_asserted);
        assert_eq!(target.pending(), source.pending());
        assert_eq!(target.take_pending().len(), 16);
        assert_eq!(source.take_pending().len(), 16);
    }

    #[test]
    fn an_asserted_line_with_a_consumed_delivery_stays_consumed_on_import() {
        let mut source = IoApic::new();
        source.write_indexed(0x10, 0x8041);
        source.set_irq(0, true);
        assert_eq!(source.take_pending().len(), 1);
        let image = source.checkpoint_state().unwrap();
        let mut target = IoApic::new();
        image.prepare().unwrap().commit(&mut target);
        assert!(target.pending().is_empty());
        assert!(target.line_asserted[0]);
        target.set_irq(0, false);
        target.set_irq(0, true);
        assert!(
            target.pending().is_empty(),
            "accepted level still awaits EOI"
        );
        target.end_of_interrupt(0x41);
        assert_eq!(target.take_pending().len(), 1);
    }

    #[test]
    fn malformed_final_delivery_and_identity_reject_before_publication() {
        let source = IoApic::new().checkpoint_state().unwrap();
        for gsi in [24, 255] {
            let mut bad = source.clone();
            bad.pending.push(Delivery {
                gsi,
                vector: 0x41,
                destination: 0,
                level_triggered: false,
            });
            assert!(bad.prepare().is_err());
        }
        for id in [1, 0x1000_0000, u32::MAX] {
            let mut bad = source.clone();
            bad.id = id;
            assert!(bad.prepare().is_err());
        }
    }

    #[test]
    fn unknown_selection_and_modeled_raw_rte_bits_round_trip() {
        let mut source = IoApic::new();
        source.write_indexed(0x10, u32::MAX);
        source.write_indexed(0x11, u32::MAX);
        source.ioregsel = 255;
        let mut target = IoApic::new();
        source
            .checkpoint_state()
            .unwrap()
            .prepare()
            .unwrap()
            .commit(&mut target);
        assert_eq!(target.redirection_table, source.redirection_table);
        let mut bytes = [0; 4];
        target.read(super::super::IOAPIC_BASE + 0x10, &mut bytes);
        assert_eq!(bytes, [0; 4]);
    }

    #[test]
    fn record_truncation_trailer_and_invalid_line_boolean_reject() {
        let bytes = crate::codec::serialize(&IoApic::new().checkpoint_state().unwrap()).unwrap();
        assert_eq!(bytes.len(), 229);
        for length in 0..bytes.len() {
            assert!(
                crate::codec::deserialize_strict::<IoApicCheckpoint>(&bytes[..length]).is_err()
            );
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(crate::codec::deserialize_strict::<IoApicCheckpoint>(&extra).is_err());
        let mut invalid = bytes;
        invalid[197] = 2;
        assert!(crate::codec::deserialize_strict::<IoApicCheckpoint>(&invalid).is_err());
    }

    #[test]
    fn pending_and_accepted_level_phases_survive_source_free_codec_roundtrips() {
        for accepted in [false, true] {
            let mut source = IoApic::new();
            source.write_indexed(0x38, 0x8051);
            source.set_irq(20, true);
            if accepted {
                assert_eq!(source.take_pending().len(), 1);
            }
            let image = source.checkpoint_state().unwrap();
            let json = serde_json::to_vec(&image).unwrap();
            let binary = crate::codec::serialize(&image).unwrap();
            drop(image);
            drop(source);
            for restored in [
                serde_json::from_slice::<IoApicCheckpoint>(&json).unwrap(),
                crate::codec::deserialize_strict::<IoApicCheckpoint>(&binary).unwrap(),
            ] {
                let mut target = IoApic::new();
                restored.prepare().unwrap().commit(&mut target);
                assert_eq!(target.pending().len(), usize::from(!accepted));
                assert_eq!(target.redirection_table[20] & RTE_REMOTE_IRR != 0, accepted);
                if !accepted {
                    assert_eq!(target.take_pending().len(), 1);
                }
                target.set_irq(20, true);
                assert!(!target.has_pending());
                target.end_of_interrupt(0x51);
                assert_eq!(target.take_pending().len(), 1);
            }
        }
    }

    #[test]
    fn duplicate_stale_and_ambiguous_delivery_records_reject_before_publication() {
        let mut source = IoApic::new();
        source.write_indexed(0x38, 0x8051);
        source.set_irq(20, true);
        let image = source.checkpoint_state().unwrap();
        for corruption in 0..10 {
            let mut bad = image.clone();
            match corruption {
                0 => bad.pending.push(bad.pending[0].clone()),
                1 => bad.pending[0].vector ^= 1,
                2 => bad.pending[0].destination ^= 1,
                3 => bad.pending[0].level_triggered = false,
                4 => bad.redirection_table[20] |= RTE_REMOTE_IRR,
                5 => bad.redirection_table[20] |= RTE_MASK,
                6 => bad.line_asserted[20] = false,
                7 => bad.redirection_table[20] &= !RTE_DELIVERY_STATUS,
                8 => bad.pending.clear(),
                _ => {
                    // The old implementation could drop a consumed level
                    // without recording remote IRR. Its continuation cannot
                    // be reconstructed as a canonical new-controller phase.
                    bad.pending.clear();
                    bad.redirection_table[20] &= !RTE_DELIVERY_STATUS;
                }
            }
            assert!(bad.prepare().is_err(), "corruption {corruption}");
        }
        let mut impossible = IoApic::new().checkpoint_state().unwrap();
        impossible.redirection_table[20] |= RTE_REMOTE_IRR;
        assert!(impossible.prepare().is_err());
    }

    #[test]
    fn oversized_delivery_count_rejects_before_reserving_a_vector() {
        let empty = crate::codec::serialize(&IoApic::new().checkpoint_state().unwrap()).unwrap();
        for count in [25u64, 1_048_576, u64::MAX] {
            let mut bad = empty.clone();
            let offset = bad.len() - 8;
            bad[offset..].copy_from_slice(&count.to_le_bytes());
            assert!(crate::codec::deserialize_strict::<IoApicCheckpoint>(&bad).is_err());
        }
    }
}
