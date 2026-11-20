//! Acknowledgement of Intel maskable and NMI window execution controls.
//!
//! Intel SDM Vol. 3C §27.2 specifies both windows. Bit 2 requests an exit
//! when IF and interruptibility admit a maskable interrupt. Bit 22 requests
//! an exit when virtual NMI blocking and the instruction shadow allow an NMI.
//! Acknowledging a window leaves the caller's event and guest RIP intact.
pub(crate) const MASKABLE: u64 = 1 << 2;
pub(crate) const NMI: u64 = 1 << 22;

/// The SDK must permit both arming and releasing this optional control.
pub(crate) fn can_toggle(capability: u64, control: u64) -> bool {
    capability & control == 0 && (capability >> 32) & control == control
}

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

/// O(1) work and storage. Return whether this call changed the control.
/// The caller retains event ownership and fences any error.
pub(crate) fn set_enabled<T: Access>(
    host: &mut T,
    controls: u64,
    enabled: bool,
) -> Result<bool, ControlError<T::Error>> {
    let original = host.read_controls().map_err(ControlError::Host)?;
    let expected = if enabled {
        original | controls
    } else {
        original & !controls
    };
    if original == expected {
        return Ok(false);
    }
    host.write_controls(expected).map_err(ControlError::Host)?;
    let observed = host.read_controls().map_err(ControlError::Host)?;
    if observed != expected {
        return Err(ControlError::Readback { expected, observed });
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{Access, ControlError, MASKABLE as WINDOW, NMI};

    fn set_enabled(host: &mut Host, enabled: bool) -> Result<bool, ControlError<&'static str>> {
        super::set_enabled(host, WINDOW, enabled)
    }

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
            assert_eq!(set_enabled(&mut host, false), Ok(true));
            assert_eq!(host.controls & WINDOW, 0);
            assert_eq!(host.controls & !WINDOW, original & !WINDOW);
            assert_eq!((host.reads, host.writes.len()), (2, 1));
        }
    }

    #[test]
    fn already_acknowledged_window_avoids_a_redundant_control_write() {
        for original in [0, 1 << 27, u64::MAX & !WINDOW] {
            let mut host = Host::new(original, None);
            assert_eq!(set_enabled(&mut host, false), Ok(false));
            assert_eq!(host.controls, original);
            assert_eq!(host.reads, 1);
            assert!(host.writes.is_empty());
        }
    }

    #[test]
    fn failed_first_read_has_no_write_or_control_effect() {
        let mut host = Host::new(0x1234, Some(Failure::ReadBefore));
        assert_eq!(
            set_enabled(&mut host, false),
            Err(ControlError::Host("read"))
        );
        assert_eq!(host.controls, 0x1234);
        assert!(host.writes.is_empty());
    }

    #[test]
    fn write_errors_propagate_both_before_and_after_mutation_without_retry() {
        for failure in [Failure::WriteBefore, Failure::WriteAfter] {
            let mut host = Host::new(0x1234, Some(failure));
            assert_eq!(
                set_enabled(&mut host, false),
                Err(ControlError::Host("write"))
            );
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
        assert_eq!(
            set_enabled(&mut host, false),
            Err(ControlError::Host("read"))
        );
        assert_eq!(host.controls, 0x1230);
        assert_eq!((host.reads, host.writes.len()), (2, 1));
    }

    #[test]
    fn ignored_write_or_other_control_mutation_is_never_reported_successful() {
        for failure in [Failure::IgnoreWrite, Failure::ChangeOtherBit] {
            let mut host = Host::new(0x1234, Some(failure));
            let error = set_enabled(&mut host, false).unwrap_err();
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

    #[test]
    fn arming_preserves_other_controls_and_reports_ownership_of_the_change() {
        let original = (1 << 27) | 0x1230;
        let mut host = Host::new(original, None);
        assert_eq!(set_enabled(&mut host, true), Ok(true));
        assert_eq!(set_enabled(&mut host, true), Ok(false));
        assert_eq!(host.writes, [original | WINDOW]);
        assert_eq!(set_enabled(&mut host, false), Ok(true));
        assert_eq!(host.controls, original);
    }

    #[test]
    fn only_a_control_that_can_be_set_and_cleared_supports_a_slice_owned_watch() {
        for control in [WINDOW, NMI] {
            assert!(!super::can_toggle(0, control));
            assert!(!super::can_toggle(control, control));
            assert!(super::can_toggle(control << 32, control));
            assert!(!super::can_toggle((control << 32) | control, control));
        }
    }

    #[test]
    fn nmi_and_irq_controls_can_be_released_independently() {
        let monitor = 1 << 27;
        let mut host = Host::new(monitor, None);
        assert_eq!(super::set_enabled(&mut host, WINDOW | NMI, true), Ok(true));
        assert_eq!(host.controls, monitor | WINDOW | NMI);
        assert_eq!(super::set_enabled(&mut host, NMI, false), Ok(true));
        assert_eq!(host.controls, monitor | WINDOW);
        assert_eq!(super::set_enabled(&mut host, WINDOW, false), Ok(true));
        assert_eq!(host.controls, monitor);
    }
}
