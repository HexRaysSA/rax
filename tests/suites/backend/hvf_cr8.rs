//! Execute the actual CR8 transfer boundary without native VMX calls.
#[path = "../../../src/backend/hvf/cr8.rs"]
mod cr8;
#[path = "hvf_cr8/priority.rs"]
mod priority_tests;
use cr8::{Cr8Access, handle};

#[derive(Debug, PartialEq, Eq)]
enum Event {
    ReadGpr(u8),
    WriteGpr(u8, u64),
    ReadTpr,
    WriteTpr(u64),
    Gp,
    Advance,
}
struct Host {
    gpr: [u64; 16],
    tpr: u64,
    rip: u64,
    events: Vec<Event>,
    fail: Option<usize>,
}
impl Host {
    fn new() -> Self {
        Self {
            gpr: std::array::from_fn(|i| 0x1122_3344_5566_7700 + i as u64),
            tpr: 0xa7,
            rip: 0x1000,
            events: vec![],
            fail: None,
        }
    }
    fn event(&mut self, event: Event) -> Result<(), &'static str> {
        self.events.push(event);
        if self.fail == Some(self.events.len()) {
            Err("host failure")
        } else {
            Ok(())
        }
    }
}
impl Cr8Access for Host {
    type Error = &'static str;
    fn read_gpr(&mut self, index: u8) -> Result<u64, Self::Error> {
        self.event(Event::ReadGpr(index))?;
        Ok(self.gpr[usize::from(index)])
    }
    fn write_gpr(&mut self, index: u8, value: u64) -> Result<(), Self::Error> {
        self.event(Event::WriteGpr(index, value))?;
        self.gpr[usize::from(index)] = value;
        Ok(())
    }
    fn read_tpr(&mut self) -> Result<u64, Self::Error> {
        self.event(Event::ReadTpr)?;
        Ok(self.tpr)
    }
    fn write_tpr(&mut self, value: u64) -> Result<(), Self::Error> {
        self.event(Event::WriteTpr(value))?;
        self.tpr = value;
        Ok(())
    }
    fn inject_gp(&mut self) -> Result<(), Self::Error> {
        self.event(Event::Gp)
    }
    fn advance_rip(&mut self) -> Result<(), Self::Error> {
        self.event(Event::Advance)?;
        self.rip += 4;
        Ok(())
    }
}

#[test]
fn all_gprs_and_valid_cr8_values_write_tpr_and_clear_its_subclass() {
    for reg in 0..16 {
        for value in 0..16 {
            let mut host = Host::new();
            host.gpr[reg] = value;
            let before = host.gpr;
            assert_eq!(handle(&mut host, 8 | ((reg as u64) << 8)), Ok(true));
            assert_eq!(host.gpr, before);
            assert_eq!(host.tpr, value << 4);
            assert_eq!(host.rip, 0x1004);
            assert_eq!(
                host.events,
                [
                    Event::ReadGpr(reg as u8),
                    Event::WriteTpr(value << 4),
                    Event::Advance
                ]
            );
        }
    }
}

#[test]
fn all_tpr_bytes_read_the_selected_gpr_with_full_zero_extension() {
    for reg in 0..16 {
        for tpr in 0..256 {
            let mut host = Host::new();
            host.tpr = tpr;
            let mut before = host.gpr;
            before[reg] = tpr >> 4;
            assert_eq!(handle(&mut host, 0x18 | ((reg as u64) << 8)), Ok(true));
            assert_eq!(host.gpr, before);
            assert_eq!(host.tpr, tpr);
            assert_eq!(host.rip, 0x1004);
            assert_eq!(
                host.events,
                [
                    Event::ReadTpr,
                    Event::WriteGpr(reg as u8, tpr >> 4),
                    Event::Advance
                ]
            );
        }
    }
}

#[test]
fn every_reserved_cr8_bit_faults_before_state_or_retirement() {
    for reg in 0..16 {
        for bit in 4..64 {
            let mut host = Host::new();
            host.gpr[reg] = 3 | (1u64 << bit);
            let before = host.gpr;
            assert_eq!(handle(&mut host, 8 | ((reg as u64) << 8)), Ok(true));
            assert_eq!(host.gpr, before);
            assert_eq!((host.tpr, host.rip), (0xa7, 0x1000));
            assert_eq!(host.events, [Event::ReadGpr(reg as u8), Event::Gp]);
        }
    }
}

#[test]
fn unrepresented_control_forms_make_no_host_calls() {
    for cr in 0..16 {
        for access in 0..4 {
            for reg in 0..16 {
                if cr == 8 && access < 2 {
                    continue;
                }
                let mut host = Host::new();
                let before = host.gpr;
                assert_eq!(
                    handle(&mut host, cr | (access << 4) | (reg << 8)),
                    Ok(false)
                );
                assert_eq!(host.gpr, before);
                assert_eq!((host.tpr, host.rip), (0xa7, 0x1000));
                assert!(host.events.is_empty());
            }
        }
    }
    for bit in (0..64).filter(|bit| (1u64 << bit) & 0x0f1f == 0) {
        assert_eq!(handle(&mut Host::new(), 8 | (1 << bit)), Ok(false));
    }
}

#[test]
fn host_errors_stop_before_any_later_call_or_fabricated_advance() {
    for read in [false, true] {
        for fail in 1..=3 {
            let mut host = Host::new();
            host.gpr[0] = 7;
            host.fail = Some(fail);
            assert_eq!(
                handle(&mut host, if read { 0x18 } else { 8 }),
                Err("host failure")
            );
            assert_eq!(host.events.len(), fail);
            assert_eq!(host.rip, 0x1000);
            if fail <= 2 {
                assert_eq!(host.tpr, 0xa7);
                assert_eq!(host.gpr[0], 7);
            }
        }
    }
    let mut host = Host::new();
    host.fail = Some(2);
    let before = host.gpr;
    assert_eq!(handle(&mut host, 8), Err("host failure"));
    assert_eq!(host.gpr, before);
    assert_eq!((host.tpr, host.rip), (0xa7, 0x1000));
}

#[test]
fn cr8_state_injection_validation_rejects_all_reserved_bits() {
    for value in 0..16 {
        assert_eq!(cr8::tpr_value(value), Some(value << 4));
    }
    for bit in 4..64 {
        assert_eq!(cr8::tpr_value(1 << bit), None);
    }
    assert_eq!(cr8::tpr_value(u64::MAX), None);
}
