//! Modeled controller image; publication never replays register-write effects.
use super::{IOAPIC_NUM_RTE, IoApic, PendingIrq};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

const MAX_PENDING: usize = 1_048_576;

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
    pending: Vec<Delivery>,
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
        Ok(IoApicCheckpoint {
            ioregsel: self.ioregsel,
            id: self.id,
            redirection_table: self.redirection_table,
            line_asserted: self.line_asserted,
            pending,
        })
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
}
