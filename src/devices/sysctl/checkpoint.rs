//! System-control latches are copied without issuing reset or refresh actions.
use super::SystemControl;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SystemControlCheckpoint {
    a20_enabled: bool,
    reset_requested: bool,
    full_reset_requested: bool,
    rcr: u8,
    ch2_gate: bool,
    speaker_enabled: bool,
    refresh_toggle: bool,
    ch2_out: bool,
    post_scratch: u8,
}

pub(crate) struct PreparedSystemControlCheckpoint(SystemControlCheckpoint);

impl SystemControl {
    pub(crate) fn checkpoint_state(&self) -> SystemControlCheckpoint {
        SystemControlCheckpoint {
            a20_enabled: self.a20_enabled,
            reset_requested: self.reset_requested,
            full_reset_requested: self.full_reset_requested,
            rcr: self.rcr,
            ch2_gate: self.ch2_gate,
            speaker_enabled: self.speaker_enabled,
            refresh_toggle: self.refresh_toggle,
            ch2_out: self.ch2_out,
            post_scratch: self.post_scratch,
        }
    }
}

impl SystemControlCheckpoint {
    pub(crate) fn prepare(&self) -> Result<PreparedSystemControlCheckpoint> {
        if self.full_reset_requested && !self.reset_requested {
            return Err(Error::InvalidConfig(
                "cold reset requires a pending reset request".into(),
            ));
        }
        Ok(PreparedSystemControlCheckpoint(*self))
    }
}

impl PreparedSystemControlCheckpoint {
    pub(crate) fn commit(self, target: &mut SystemControl) {
        target.a20_enabled = self.0.a20_enabled;
        target.reset_requested = self.0.reset_requested;
        target.full_reset_requested = self.0.full_reset_requested;
        target.rcr = self.0.rcr;
        target.ch2_gate = self.0.ch2_gate;
        target.speaker_enabled = self.0.speaker_enabled;
        target.refresh_toggle = self.0.refresh_toggle;
        target.ch2_out = self.0.ch2_out;
        target.post_scratch = self.0.post_scratch;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::IoDevice;

    #[test]
    fn copied_state_preserves_refresh_phase_gate_and_output() {
        let mut source = SystemControl::new();
        source.write(0x92, 0);
        source.write(0x61, 3);
        source.set_pit_ch2_out(true);
        source.write(0x80, 0xa5);
        source.read(0x61);
        let before = source.checkpoint_state();
        assert!(before.refresh_toggle);
        let bytes = crate::codec::serialize(&before).unwrap();
        assert_eq!(bytes.len(), 9);
        let decoded: SystemControlCheckpoint = crate::codec::deserialize_strict(&bytes).unwrap();
        let mut target = SystemControl::new();
        decoded.prepare().unwrap().commit(&mut target);
        assert_eq!(target.checkpoint_state(), before);
        assert_eq!(
            source.checkpoint_state(),
            before,
            "capture does not read0x61"
        );
        assert_eq!(target.read(0x61), source.read(0x61));
        assert_eq!(target.read(0x92), 0);
        assert_eq!(target.read(0x8f), 0xa5);
    }

    #[test]
    fn consumed_reset_does_not_reappear_from_the_retained_rcr_value() {
        let mut source = SystemControl::new();
        source.write(0xcf9, 0x0e);
        assert!(source.reset_requested() && source.full_reset_requested());
        source.clear_reset();
        let image = source.checkpoint_state();
        let mut target = SystemControl::new();
        target.write(0xcf9, 0x0e);
        image.prepare().unwrap().commit(&mut target);
        assert_eq!(target.read(0xcf9), 0x0e);
        assert!(!target.reset_requested() && !target.full_reset_requested());
    }

    #[test]
    fn all_scalar_latch_combinations_preserve_their_wire_values() {
        let initial = SystemControl::new().checkpoint_state();
        let mut checked = 0;
        for bits in 0u8..128 {
            let state = SystemControlCheckpoint {
                a20_enabled: bits & 1 != 0,
                reset_requested: bits & 2 != 0,
                full_reset_requested: bits & 4 != 0,
                ch2_gate: bits & 8 != 0,
                speaker_enabled: bits & 16 != 0,
                refresh_toggle: bits & 32 != 0,
                ch2_out: bits & 64 != 0,
                ..initial
            };
            if state.full_reset_requested && !state.reset_requested {
                assert!(state.prepare().is_err());
                continue;
            }
            for rcr in [0, 0x06, 0x0e, 0xff] {
                let state = SystemControlCheckpoint {
                    rcr,
                    post_scratch: !rcr,
                    ..state
                };
                let mut target = SystemControl::new();
                state.prepare().unwrap().commit(&mut target);
                assert_eq!(target.checkpoint_state(), state);
                let bytes = crate::codec::serialize(&state).unwrap();
                let decoded: SystemControlCheckpoint =
                    crate::codec::deserialize_strict(&bytes).unwrap();
                assert_eq!(decoded, state);
                checked += 1;
            }
        }
        assert_eq!(checked, 384);
    }

    #[test]
    fn malformed_wire_and_impossible_cold_reset_reject() {
        let bytes = crate::codec::serialize(&SystemControl::new().checkpoint_state()).unwrap();
        for length in 0..bytes.len() {
            assert!(
                crate::codec::deserialize_strict::<SystemControlCheckpoint>(&bytes[..length])
                    .is_err()
            );
        }
        for index in [0, 1, 2, 4, 5, 6, 7] {
            let mut bad = bytes.clone();
            bad[index] = 2;
            assert!(crate::codec::deserialize_strict::<SystemControlCheckpoint>(&bad).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(crate::codec::deserialize_strict::<SystemControlCheckpoint>(&extra).is_err());
        let mut cold = bytes;
        cold[1] = 0;
        cold[2] = 1;
        let decoded: SystemControlCheckpoint = crate::codec::deserialize_strict(&cold).unwrap();
        assert!(decoded.prepare().is_err());
    }
}
