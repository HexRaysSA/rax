use super::*;
use crate::vm::timing::ClockMode;

fn fixture(count: u8) -> (Arc<TimingContext>, Platform) {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let platform = Platform::new(count, 0x8000000, clock.clone()).unwrap();
    (clock, platform)
}
fn read(platform: &Platform, offset: u64, size: usize) -> u64 {
    let mut raw = [0; 8];
    platform.read(BASE + offset, &mut raw[..size]).unwrap();
    u64::from_le_bytes(raw)
}
fn write(platform: &Platform, offset: u64, value: u64, size: usize) {
    platform
        .write(BASE + offset, &value.to_le_bytes()[..size])
        .unwrap();
}
#[test]
fn msip_is_banked_low_bit_level_and_hart_identity_is_bounded() {
    let (_, platform) = fixture(4);
    for id in 0..4u32 {
        assert_eq!(platform.signals(id).unwrap(), Some((0, false, false)));
        write(&platform, u64::from(id) * 4, u64::MAX, 4);
        for other in 0..4u32 {
            assert_eq!(platform.signals(other).unwrap().unwrap().1, other <= id);
        }
        assert_eq!(read(&platform, u64::from(id) * 4, 4), 1);
    }
    for id in 0..4u32 {
        write(&platform, u64::from(id) * 4, 0xffff_fffe, 4);
        assert!(!platform.signals(id).unwrap().unwrap().1);
    }
    assert!(platform.signals(4).is_err());
    assert!(Platform::new(0, 0, Arc::new(TimingContext::new())).is_err());
}
#[test]
fn owned_clock_ticks_and_timer_threshold_are_independent_of_ambient_clock() {
    let (clock, platform) = fixture(2);
    let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _foreign = foreign.enter();
    write(&platform, COMPARE + 8, 10, 8);
    clock.advance_retired(2999).unwrap();
    assert_eq!(platform.signals(1).unwrap(), Some((9, false, false)));
    clock.advance_retired(1).unwrap();
    assert_eq!(platform.signals(1).unwrap(), Some((10, false, true)));
    assert!(!platform.signals(0).unwrap().unwrap().2);
    write(&platform, COMPARE + 8, 11, 8);
    assert!(!platform.signals(1).unwrap().unwrap().2);
    assert_eq!(read(&platform, TIME, 8), 10);
}
#[test]
fn timer_halves_and_writable_time_preserve_other_bits_and_wrap() {
    let (clock, platform) = fixture(1);
    write(&platform, COMPARE, 0x1122334455667788, 8);
    write(&platform, COMPARE + 4, 0xaabbccdd, 4);
    assert_eq!(read(&platform, COMPARE, 8), 0xaabbccdd55667788);
    write(&platform, COMPARE, 0x12345678, 4);
    assert_eq!(read(&platform, COMPARE, 8), 0xaabbccdd12345678);
    write(&platform, TIME, 0x1122334455667788, 8);
    write(&platform, TIME + 4, 0xaabbccdd, 4);
    assert_eq!(read(&platform, TIME, 8), 0xaabbccdd55667788);
    assert_eq!(read(&platform, TIME + 4, 4), 0xaabbccdd);
    write(&platform, TIME, u64::MAX, 8);
    assert!(platform.signals(0).unwrap().unwrap().2);
    clock.advance_retired(300).unwrap();
    assert_eq!(read(&platform, TIME, 8), 0);
    assert!(!platform.signals(0).unwrap().unwrap().2);
}
#[test]
fn unsupported_widths_crossings_and_alignment_reject_before_any_effect() {
    let (_, platform) = fixture(2);
    let before = platform.checkpoint().unwrap();
    for (address, size) in [
        (BASE, 1),
        (BASE, 2),
        (BASE, 8),
        (BASE + 2, 4),
        (BASE - 4, 8),
        (BASE + LEN - 4, 8),
        (BASE + TIME + 4, 8),
        (u64::MAX, 8),
    ] {
        let mut buffer = vec![0xa5; size];
        assert!(platform.read(address, &mut buffer).is_err());
        assert_eq!(buffer, vec![0xa5; size]);
        assert!(platform.write(address, &buffer).is_err());
        assert!(platform.probe(address, size).is_err());
        assert_eq!(platform.checkpoint().unwrap(), before);
    }
    assert!(overlaps(BASE - 4, 8));
    assert!(overlaps(BASE + LEN - 1, 8));
    assert!(!overlaps(BASE + LEN, 8));
    assert!(!overlaps(u64::MAX, 8));
    assert!(!overlaps(BASE, 0));
}
#[test]
fn unimplemented_slots_are_reserved_and_never_touch_live_harts() {
    let (_, platform) = fixture(1);
    let before = platform.checkpoint().unwrap();
    for (offset, size) in [
        (4, 4),
        (0x3ffc, 4),
        (COMPARE + 8, 8),
        (0xbff0, 8),
        (0xc000, 8),
        (LEN - 8, 8),
    ] {
        write(&platform, offset, u64::MAX, size);
        assert_eq!(read(&platform, offset, size), 0);
    }
    assert_eq!(platform.checkpoint().unwrap(), before);
}
#[test]
fn failed_publication_and_invalid_topology_leave_platform_intact() {
    let (_, platform) = fixture(2);
    write(&platform, 4, 1, 4);
    let before = platform.checkpoint().unwrap();
    assert!(
        platform
            .restore_with(None, || Err::<(), _>(invalid("injected rejection")))
            .is_err()
    );
    assert!(platform.enabled());
    assert_eq!(platform.checkpoint().unwrap(), before);
    let mut malformed = before.clone().unwrap();
    malformed.compare.pop();
    assert!(
        platform
            .restore_with(Some(malformed), || -> Result<()> {
                panic!("invalid state must not publish")
            })
            .is_err()
    );
    assert_eq!(platform.checkpoint().unwrap(), before);
    platform.restore_with(None, || Ok(())).unwrap();
    assert!(!platform.enabled());
    assert_eq!(platform.signals(1).unwrap(), None);
    assert_eq!(platform.checkpoint().unwrap(), None);
    assert!(!platform.claims(BASE, 4));
    platform.restore_with(before.clone(), || Ok(())).unwrap();
    assert_eq!(platform.checkpoint().unwrap(), before);
}
#[test]
fn poisoned_state_rejects_access_capture_and_restore_without_running_commit() {
    let (_, platform) = fixture(1);
    let platform = Arc::new(platform);
    let other = platform.clone();
    assert!(
        std::thread::spawn(move || {
            let _held = other.state.lock().unwrap();
            panic!("owned poison fixture");
        })
        .join()
        .is_err()
    );
    assert!(platform.read(BASE, &mut [0; 4]).is_err());
    assert!(platform.write(BASE, &[1; 4]).is_err());
    assert!(platform.signals(0).is_err());
    assert!(platform.checkpoint().is_err());
    assert!(
        platform
            .restore_with(None, || -> Result<()> { panic!("poison must not publish") })
            .is_err()
    );
}
