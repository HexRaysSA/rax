//! Acknowledgement of the Intel interrupt-window execution control.
//!
//! Intel SDM Vol.3C26.6.2/Table26-6 and AppendixC: bit2 requests a window
//! exit before an instruction when IF and interruptibility admit it. Clearing
//! this request consumes no caller-owned event and does not advance guest RIP.
const WINDOW: u64 = 1 << 2;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ControlError<E> {
    Host(E),
    Readback { expected: u64, observed: u64 },
}

pub(crate) trait Access {
    type Error;
    fn read_controls(&mut self) -> Result<u64, Self::Error>;
    fn write_controls(&mut self, value: u64) -> Result<(), Self::Error>;
}

/// O(1) work/storage. Caller retains IRQ ownership and fences any error.
pub(crate) fn acknowledge<T: Access>(host: &mut T) -> Result<(), ControlError<T::Error>> {
    let original = host.read_controls().map_err(ControlError::Host)?;
    if original & WINDOW == 0 {
        return Ok(());
    }
    let expected = original & !WINDOW;
    host.write_controls(expected).map_err(ControlError::Host)?;
    let observed = host.read_controls().map_err(ControlError::Host)?;
    if observed != expected {
        return Err(ControlError::Readback { expected, observed });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Access, ControlError, WINDOW, acknowledge};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Failure {
        ReadBefore,
        WriteBefore,
        WriteAfter,
        ReadAfter,
        IgnoreWrite,
        ChangeOtherBit,
    }

    struct Host {
        controls: u64,
        reads: usize,
        writes: Vec<u64>,
        failure: Option<Failure>,
    }

    impl Host {
        fn new(controls: u64, failure: Option<Failure>) -> Self {
            Self {
                controls,
                reads: 0,
                writes: Vec::new(),
                failure,
            }
        }
    }

    impl Access for Host {
        type Error = &'static str;
        fn read_controls(&mut self) -> Result<u64, Self::Error> {
            self.reads += 1;
            if (self.failure == Some(Failure::ReadBefore) && self.reads == 1)
                || (self.failure == Some(Failure::ReadAfter) && self.reads == 2)
            {
                return Err("read");
            }
            Ok(self.controls)
        }

        fn write_controls(&mut self, value: u64) -> Result<(), Self::Error> {
            self.writes.push(value);
            if self.failure == Some(Failure::WriteBefore) {
                return Err("write");
            }
            if self.failure == Some(Failure::IgnoreWrite) {
                return Ok(());
            }
            self.controls = value;
            if self.failure == Some(Failure::ChangeOtherBit) {
                self.controls ^= 1 << 27;
            }
            if self.failure == Some(Failure::WriteAfter) {
                return Err("write");
            }
            Ok(())
        }
    }

    #[test]
    fn clear_only_window_preserving_each_opaque_bit_and_monitor_trap() {
        for original in (0..64).map(|bit| (1u64 << bit) | WINDOW).chain([
            u64::MAX,
            0xaaaa_aaaa_aaaa_aaaa | WINDOW,
            0x5555_5555_5555_5555 | WINDOW,
        ]) {
            let mut host = Host::new(original, None);
            assert_eq!(acknowledge(&mut host), Ok(()));
            assert_eq!(host.controls & WINDOW, 0);
            assert_eq!(host.controls & !WINDOW, original & !WINDOW);
            assert_eq!((host.reads, host.writes.len()), (2, 1));
        }
    }

    #[test]
    fn already_acknowledged_window_avoids_a_redundant_control_write() {
        for original in [0, 1 << 27, u64::MAX & !WINDOW] {
            let mut host = Host::new(original, None);
            assert_eq!(acknowledge(&mut host), Ok(()));
            assert_eq!(host.controls, original);
            assert_eq!(host.reads, 1);
            assert!(host.writes.is_empty());
        }
    }

    #[test]
    fn failed_first_read_has_no_write_or_control_effect() {
        let mut host = Host::new(0x1234, Some(Failure::ReadBefore));
        assert_eq!(acknowledge(&mut host), Err(ControlError::Host("read")));
        assert_eq!(host.controls, 0x1234);
        assert!(host.writes.is_empty());
    }

    #[test]
    fn write_errors_propagate_both_before_and_after_mutation_without_retry() {
        for failure in [Failure::WriteBefore, Failure::WriteAfter] {
            let mut host = Host::new(0x1234, Some(failure));
            assert_eq!(acknowledge(&mut host), Err(ControlError::Host("write")));
            assert_eq!((host.reads, host.writes.len()), (1, 1));
            assert_eq!(
                host.controls,
                if failure == Failure::WriteBefore {
                    0x1234
                } else {
                    0x1230
                }
            );
        }
    }

    #[test]
    fn failed_readback_propagates_after_one_successful_control_write() {
        let mut host = Host::new(0x1234, Some(Failure::ReadAfter));
        assert_eq!(acknowledge(&mut host), Err(ControlError::Host("read")));
        assert_eq!(host.controls, 0x1230);
        assert_eq!((host.reads, host.writes.len()), (2, 1));
    }

    #[test]
    fn ignored_write_or_other_control_mutation_is_never_reported_successful() {
        for failure in [Failure::IgnoreWrite, Failure::ChangeOtherBit] {
            let mut host = Host::new(0x1234, Some(failure));
            let error = acknowledge(&mut host).unwrap_err();
            assert_eq!(
                error,
                ControlError::Readback {
                    expected: 0x1230,
                    observed: host.controls
                }
            );
            assert_eq!((host.reads, host.writes.len()), (2, 1));
        }
    }
}
