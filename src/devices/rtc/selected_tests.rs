//! Behavioral parent-engine selected-calendar regressions.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use std::sync::Arc;
#[test]
fn retired_rtc_calendar_and_uip_follow_the_owned_vm_clock() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut rtc = RtcStub::new();
    let mut read = |index| {
        rtc.write(0x70, index);
        rtc.read(0x71)
    };
    assert_eq!(
        [
            read(REG_SECONDS),
            read(REG_MINUTES),
            read(REG_HOURS),
            read(REG_DAY_OF_MONTH),
            read(REG_MONTH),
            read(REG_YEAR),
            read(REG_CENTURY)
        ],
        [0, 0, 0, 1, 1, 0, 0x20]
    );
    clock.advance_retired(3_000_000_000).unwrap();
    assert_eq!(read(REG_SECONDS), 1);
}

fn read(rtc: &mut RtcStub, index: u8) -> u8 {
    rtc.write(0x70, index);
    rtc.read(0x71)
}
#[test]
fn retired_cmos_uip_set_alarm_and_modes_use_the_same_retained_calendar() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut rtc = RtcStub::new();
    let other = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    other.advance_retired(3_000_000_000).unwrap();
    let _foreign = other.enter();
    assert_eq!(read(&mut rtc, REG_SECONDS), 0);
    let mut state = clock.checkpoint_state();
    state.elapsed_nanos = 999_755_999;
    state.subnanosecond_quanta = 2;
    clock.restore_checkpoint_state(&state).unwrap();
    assert_eq!(read(&mut rtc, REG_A) & REG_A_UIP, 0);
    clock.advance_retired(1).unwrap();
    assert_ne!(read(&mut rtc, REG_A) & REG_A_UIP, 0);
    rtc.write(0x70, REG_B);
    rtc.write(0x71, REG_B_SET | REG_B_24H);
    assert_eq!(read(&mut rtc, REG_A) & REG_A_UIP, 0);
    rtc.write(0x70, REG_B);
    rtc.write(0x71, REG_B_24H | REG_B_AIE);
    for index in [REG_SECONDS_ALARM, REG_MINUTES_ALARM, REG_HOURS_ALARM] {
        rtc.write(0x70, index);
        rtc.write(0x71, 0xc0);
    }
    assert!(rtc.tick(0));
    assert_ne!(read(&mut rtc, REG_C) & REG_C_AF, 0);
    state.elapsed_nanos = (13 * 3600 + 42 * 60 + 17) * 1_000_000_000;
    state.subnanosecond_quanta = 0;
    clock.restore_checkpoint_state(&state).unwrap();
    rtc.write(0x70, REG_B);
    rtc.write(0x71, 0);
    assert_eq!(read(&mut rtc, REG_HOURS), 0x81);
    assert_eq!(read(&mut rtc, REG_MINUTES), 0x42);
    rtc.write(0x70, REG_B);
    rtc.write(0x71, REG_B_DM | REG_B_24H);
    assert_eq!(read(&mut rtc, REG_HOURS), 13);
    assert_eq!(read(&mut rtc, REG_MINUTES), 42);
    assert_eq!(read(&mut rtc, REG_SECONDS), 17);
}
