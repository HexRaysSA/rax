//! Pure modeled RTC state; target runtime ownership remains outside this image.
use super::{
    OSCILLATOR_PHASE_MODULUS, REG_A, REG_A_UIP, REG_B, REG_C, REG_C_IRQF, REG_D, REG_D_VRT, RtcStub,
};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RtcCheckpoint {
    #[serde(with = "cmos_bytes")]
    cmos: [u8; 128],
    index: u8,
    nmi_disabled: bool,
}

pub(crate) struct PreparedRtcCheckpoint(RtcCheckpoint);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RtcTimingCheckpoint {
    periodic_phase: u64,
    last_polled_nanos: u64,
    last_calendar_second: u64,
}

impl RtcTimingCheckpoint {
    pub(crate) const WIRE_SIZE: usize = 24;

    pub(crate) fn validate(&self) -> Result<()> {
        if self.periodic_phase >= OSCILLATOR_PHASE_MODULUS {
            return Err(Error::InvalidConfig("invalid RTC oscillator phase".into()));
        }
        Ok(())
    }
}

impl RtcStub {
    pub(crate) fn timing_checkpoint(&self) -> RtcTimingCheckpoint {
        RtcTimingCheckpoint {
            periodic_phase: self.periodic_phase,
            last_polled_nanos: self.last_polled_nanos,
            last_calendar_second: self.last_calendar_second,
        }
    }

    pub(crate) fn restore_timing(&mut self, timing: Option<RtcTimingCheckpoint>) {
        if let Some(timing) = timing {
            self.periodic_phase = timing.periodic_phase;
            self.last_polled_nanos = timing.last_polled_nanos;
            self.published_irq = self.has_pending_interrupt();
            self.last_calendar_second = if self.uses_retired_calendar() {
                timing.last_calendar_second
            } else {
                self.calendar.timestamp().as_secs()
            };
        } else {
            // Old producers didn't advance or publish IRQ8 from the VMM.
            self.periodic_phase = 0;
            self.last_polled_nanos = crate::vm::timing::elapsed_nanos();
            self.last_calendar_second = self.calendar.timestamp().as_secs();
            self.published_irq = false;
        }
    }

    pub(crate) fn checkpoint_state(&self) -> RtcCheckpoint {
        RtcCheckpoint {
            cmos: self.cmos,
            index: self.index,
            nmi_disabled: self.nmi_disabled,
        }
    }
}

impl RtcCheckpoint {
    pub(crate) fn validate_irq_summary(&self) -> Result<()> {
        let summary = self.cmos[REG_C as usize];
        if (summary & REG_C_IRQF != 0) != (summary & self.cmos[REG_B as usize] & 0x70 != 0) {
            return Err(Error::InvalidConfig("invalid RTC IRQ summary".into()));
        }
        Ok(())
    }

    pub(crate) fn prepare(&self) -> Result<PreparedRtcCheckpoint> {
        if self.index >= 128
            || self.cmos[REG_A as usize] & REG_A_UIP != 0
            || self.cmos[REG_C as usize] & 0x0f != 0
            || self.cmos[REG_D as usize] != REG_D_VRT
        {
            return Err(Error::InvalidConfig("invalid RTC checkpoint state".into()));
        }
        Ok(PreparedRtcCheckpoint(self.clone()))
    }
}

impl PreparedRtcCheckpoint {
    pub(crate) fn irq_asserted(&self) -> bool {
        self.0.cmos[REG_C as usize] & REG_C_IRQF != 0
    }

    pub(crate) fn commit(self, target: &mut RtcStub) {
        target.cmos = self.0.cmos;
        target.index = self.0.index;
        target.nmi_disabled = self.0.nmi_disabled;
    }
}

// A tuple has exactly128 bytes, without a caller-controlled vector length.
mod cmos_bytes {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 128],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(128)?;
        for byte in bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 128], D::Error> {
        struct Cmos;
        impl<'de> Visitor<'de> for Cmos {
            type Value = [u8; 128];

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("exactly128 CMOS bytes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = [0; 128];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(index, &self))?;
                }
                Ok(bytes)
            }
        }
        deserializer.deserialize_tuple(128, Cmos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::IoDevice;

    #[test]
    fn all_writable_cmos_bytes_index_and_nmi_survive_prepared_publication() {
        let mut source = RtcStub::new();
        for index in 0x0e..=0x7f {
            source.write(0x70, index);
            source.write(0x71, index.wrapping_mul(37));
        }
        source.write(0x70, 0xb8);
        let image = source.checkpoint_state();
        let encoded = crate::codec::serialize(&image).unwrap();
        assert_eq!(encoded.len(), 130);
        let decoded: RtcCheckpoint = crate::codec::deserialize_strict(&encoded).unwrap();
        let mut target = RtcStub::new();
        decoded.prepare().unwrap().commit(&mut target);
        assert_eq!(target.cmos, source.cmos);
        assert_eq!(target.read(0x70), 0xb8);
        assert_eq!(target.nmi_disabled(), source.nmi_disabled());
        assert_eq!(target.read(0x71), source.read(0x71));
    }

    #[test]
    fn malformed_index_and_read_only_registers_reject_before_publication() {
        let source = RtcStub::new().checkpoint_state();
        for index in [128, 129, 255] {
            let mut bad = source.clone();
            bad.index = index;
            assert!(bad.prepare().is_err());
        }
        for (register, value) in [(REG_A, 0x80), (REG_C, 1), (REG_D, 0), (REG_D, 0xff)] {
            let mut bad = source.clone();
            bad.cmos[register as usize] = value;
            assert!(bad.prepare().is_err());
        }
    }

    #[test]
    fn control_and_latch_states_are_copied_without_read_side_effects() {
        let mut source = RtcStub::new();
        source.write(0x70, REG_C);
        source.cmos[REG_C as usize] = 0xf0;
        let image = source.checkpoint_state();
        assert_eq!(source.cmos[REG_C as usize], 0xf0);
        let mut target = RtcStub::new();
        image.prepare().unwrap().commit(&mut target);
        assert_eq!(target.read(0x71), 0xf0);
        assert_eq!(target.read(0x71), 0);
        assert_eq!(source.cmos[REG_C as usize], 0xf0);
    }

    #[test]
    fn fixed_wire_rejects_every_truncation_trailer_and_invalid_boolean() {
        let bytes = crate::codec::serialize(&RtcStub::new().checkpoint_state()).unwrap();
        for length in 0..bytes.len() {
            assert!(crate::codec::deserialize_strict::<RtcCheckpoint>(&bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(crate::codec::deserialize_strict::<RtcCheckpoint>(&extra).is_err());
        let mut invalid = bytes;
        invalid[129] = 2;
        assert!(crate::codec::deserialize_strict::<RtcCheckpoint>(&invalid).is_err());
    }
}
