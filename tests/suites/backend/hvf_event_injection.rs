//! Primary-contract VM-entry event arbitration and host-failure partitions.
#[path = "../../../src/backend/hvf/event_injection.rs"]
mod event_injection;
#[path = "../../../src/backend/hvf/interrupt_shadow.rs"]
mod interrupt_shadow;
#[path = "../../../src/backend/hvf/interrupt_window.rs"]
mod interrupt_window;
#[path = "../../../src/backend/hvf/retirement.rs"]
mod retirement;
use event_injection::{Access, Event, available, inject};

#[derive(Default)]
struct Host {
    info: u64,
    flags: u64,
    blocking: u64,
    pending: u64,
    fail: Option<&'static str>,
    calls: Vec<&'static str>,
    writes: Vec<u64>,
}
impl Host {
    fn call(&mut self, name: &'static str) -> Result<(), &'static str> {
        self.calls.push(name);
        if self.fail == Some(name) {
            Err(name)
        } else {
            Ok(())
        }
    }
}
impl Access for Host {
    type Error = &'static str;
    fn entry_information(&mut self) -> Result<u64, Self::Error> {
        self.call("entry")?;
        Ok(self.info)
    }
    fn rflags(&mut self) -> Result<u64, Self::Error> {
        self.call("flags")?;
        Ok(self.flags)
    }
    fn interruptibility(&mut self) -> Result<u64, Self::Error> {
        self.call("blocking")?;
        Ok(self.blocking)
    }
    fn pending_debug(&mut self) -> Result<u64, Self::Error> {
        self.call("pending")?;
        Ok(self.pending)
    }
    fn write_entry_information(&mut self, information: u64) -> Result<(), Self::Error> {
        self.call("write")?;
        self.info = information;
        self.writes.push(information);
        Ok(())
    }
}

#[test]
fn irq_matrix_preserves_existing_event_and_ignores_nmi_blocking() {
    // Orthogonal primary partitions: IF, event-slot occupancy, STI/MOVSS,
    // SMI/NMI/enclave state, every external vector, unrelated high bits.
    for vector in 0..=255 {
        for enabled in [false, true] {
            for occupied in [false, true] {
                for blocking in 0..32 {
                    for high in [0, 0x1234_5678_0000_0000] {
                        let prior = high | if occupied { 0x8000_0b0d } else { 0x306 };
                        let mut h = Host {
                            info: prior,
                            flags: if enabled { 0x202 } else { 2 },
                            blocking,
                            ..Host::default()
                        };
                        let expected = enabled
                            && !occupied
                            && matches!(blocking, 0 | 4 | 8 | 12 | 16 | 20 | 24 | 28);
                        assert_eq!(
                            inject(&mut h, Event::Interrupt(vector)),
                            Ok(expected),
                            "{vector}/{enabled}/{occupied}/{blocking}"
                        );
                        if expected {
                            assert_eq!(h.info, 0x8000_0000 | u64::from(vector));
                            assert_eq!(h.writes.len(), 1);
                        } else {
                            assert_eq!(h.info, prior);
                            assert!(h.writes.is_empty());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn nmi_matrix_ignores_if_and_preserves_nmi_and_ss_sti_blocking() {
    for flags in [2, 0x202, u64::MAX] {
        for occupied in [false, true] {
            for blocking in 0..32 {
                let prior = if occupied { 0x8000_0306 } else { 0 };
                let mut h = Host {
                    info: prior,
                    flags,
                    blocking,
                    ..Host::default()
                };
                let expected = !occupied && matches!(blocking, 0 | 4 | 16 | 20);
                assert_eq!(inject(&mut h, Event::Nmi), Ok(expected));
                assert_eq!(h.info, if expected { 0x8000_0202 } else { prior });
                assert!(!h.calls.contains(&"flags"));
            }
        }
    }
}

#[test]
fn every_occupied_event_type_and_vector_has_priority() {
    for kind in 0..8 {
        for vector in 0..=255 {
            for event in [Event::Interrupt(0x31), Event::Nmi] {
                let original = 0x8000_0000 | (kind << 8) | vector;
                let mut h = Host {
                    info: original,
                    flags: 0x202,
                    ..Host::default()
                };
                assert_eq!(inject(&mut h, event), Ok(false));
                assert_eq!(h.info, original);
                assert_eq!(h.calls, ["entry"]);
            }
        }
    }
}

#[test]
fn host_read_and_write_errors_propagate_without_accepting_request() {
    for event in [Event::Interrupt(0x41), Event::Nmi] {
        for fail in ["entry", "flags", "blocking", "pending", "write"] {
            if event == Event::Nmi && fail == "flags" {
                continue;
            }
            let mut h = Host {
                flags: 0x202,
                fail: Some(fail),
                ..Host::default()
            };
            assert_eq!(inject(&mut h, event), Err(fail));
            assert_eq!(h.calls.last(), Some(&fail));
            assert_eq!(h.info, 0);
            assert!(h.writes.is_empty());
            // Retrying the same caller-owned event succeeds exactly once.
            h.fail = None;
            assert_eq!(inject(&mut h, event), Ok(true));
            assert_eq!(inject(&mut h, event), Ok(false));
            assert_eq!(h.writes.len(), 1);
        }
    }
}

#[test]
fn blocked_then_retried_request_does_not_enqueue_or_duplicate() {
    let mut h = Host::default();
    assert_eq!(inject(&mut h, Event::Interrupt(0x40)), Ok(false));
    assert!(h.writes.is_empty());
    h.flags = 0x202;
    assert_eq!(inject(&mut h, Event::Interrupt(0x41)), Ok(true));
    assert_eq!(h.writes, [0x8000_0041]);
    assert_eq!(inject(&mut h, Event::Interrupt(0x40)), Ok(false));
    // Hardware clears valid on an actual VM exit (SDM26.8.3/29.2).
    h.info = 0;
    assert_eq!(available(&mut h, Event::Interrupt(0x40)), Ok(true));
    assert_eq!(inject(&mut h, Event::Interrupt(0x40)), Ok(true));
    assert_eq!(h.writes, [0x8000_0041, 0x8000_0040]);
}

#[test]
fn eligibility_query_never_mutates_the_event_slot() {
    for event in [Event::Interrupt(0), Event::Nmi] {
        for info in [0, 0x8000_0306] {
            for blocking in 0..32 {
                let mut h = Host {
                    info,
                    flags: 0x202,
                    blocking,
                    ..Host::default()
                };
                let _ = available(&mut h, event).unwrap();
                assert_eq!(h.info, info);
                assert!(h.writes.is_empty());
            }
        }
    }
}

#[test]
fn previous_instruction_debug_traps_defer_irq_and_nmi_without_consuming_either() {
    for pending in [1 << 12, 1 << 14, 0x500f] {
        for event in [Event::Interrupt(0x51), Event::Nmi] {
            let mut host = Host {
                flags: 0x202,
                pending,
                ..Host::default()
            };
            for _ in 0..3 {
                assert_eq!(available(&mut host, event), Ok(false));
                assert_eq!(inject(&mut host, event), Ok(false));
                assert_eq!(host.pending, pending);
                assert_eq!(host.info, 0);
                assert!(host.writes.is_empty());
            }
            // Actual guest delivery consumes the debug trap. The same
            // caller-owned event can then be injected once, without a queue.
            host.pending = 0;
            assert_eq!(inject(&mut host, event), Ok(true));
            assert_eq!(inject(&mut host, event), Ok(false));
            assert_eq!(host.writes.len(), 1);
        }
    }
}

#[test]
fn disabled_breakpoint_causes_do_not_defer_asynchronous_events() {
    for pending in 0..16 {
        for event in [Event::Interrupt(0x51), Event::Nmi] {
            let mut host = Host {
                flags: 0x202,
                pending,
                ..Host::default()
            };
            assert_eq!(inject(&mut host, event), Ok(true));
            assert_eq!(host.pending, pending);
        }
    }
}

#[test]
fn debug_causes_shadow_and_event_occupancy_partition_all_eligibility_cases() {
    for status in 0..16 {
        for enabled in [0, 1 << 12] {
            for bs in [0, 1 << 14] {
                for shadow in 0..32 {
                    for occupied in [false, true] {
                        for event in [Event::Interrupt(0x51), Event::Nmi] {
                            let pending = status | enabled | bs;
                            let info = if occupied { 0x8000_030d } else { 0 };
                            let mut host = Host {
                                flags: 0x202,
                                pending,
                                blocking: shadow,
                                info,
                                ..Host::default()
                            };
                            let expected = !occupied
                                && enabled == 0
                                && bs == 0
                                && shadow & if event == Event::Nmi { 11 } else { 3 } == 0;
                            assert_eq!(available(&mut host, event), Ok(expected));
                            assert_eq!(inject(&mut host, event), Ok(expected));
                            assert_eq!(host.pending, pending);
                            if !expected {
                                assert_eq!(host.info, info);
                                assert!(host.writes.is_empty());
                            }
                        }
                    }
                }
            }
        }
    }
}
