//! Execute the actual PIC source, including its complete existing unit suite.
pub use rax::devices::bus;
#[path = "../../../src/devices/pic.rs"]
mod pic;
use bus::IoDevice;
use pic::{DualPic, MasterPicDevice, SlavePicDevice};
use std::sync::{Arc, Mutex};

fn configured(auto_eoi: bool, rotate: bool) -> DualPic {
    let shared = Arc::new(Mutex::new(DualPic::new()));
    let mut master = MasterPicDevice::new(shared.clone());
    let mut slave = SlavePicDevice::new(shared.clone());
    for (device, command, data, base, cascade) in [
        (&mut master as &mut dyn IoDevice, 0x20, 0x21, 0x20, 4),
        (&mut slave as &mut dyn IoDevice, 0xa0, 0xa1, 0x28, 2),
    ] {
        device.write(command, 0x11);
        device.write(data, base);
        device.write(data, cascade);
        device.write(data, if auto_eoi { 3 } else { 1 });
        device.write(data, 0);
        if rotate {
            device.write(command, 0x80);
        }
    }
    let copy = shared.lock().unwrap().clone();
    copy
}
fn snapshot(pic: &DualPic) -> Vec<u8> {
    bincode::serialize(pic).unwrap()
}

#[test]
fn blocked_and_failed_injections_preserve_every_pic_register_before_acceptance() {
    for auto_eoi in [false, true] {
        for rotate in [false, true] {
            for irq in 0..16 {
                let mut p = configured(auto_eoi, rotate);
                p.pulse_irq(irq);
                let before = snapshot(&p);
                let expected = if irq == 2 { 0x2f } else { 0x20 + irq };
                let mut offered = Vec::new();
                assert_eq!(
                    p.try_deliver_pending(|vector| {
                        offered.push(vector);
                        Ok::<_, &str>(false)
                    }),
                    Ok(false)
                );
                assert_eq!(snapshot(&p), before);
                assert_eq!(
                    p.try_deliver_pending(|vector| {
                        offered.push(vector);
                        Err("injection failure")
                    }),
                    Err("injection failure")
                );
                assert_eq!(snapshot(&p), before);
                assert_eq!(
                    p.try_deliver_pending(|vector| {
                        offered.push(vector);
                        Ok::<_, &str>(true)
                    }),
                    Ok(true)
                );
                assert_eq!(offered, [expected, expected, expected]);
                let (irr, _, isr, slave_irr, _, slave_isr) = p.debug_info();
                assert_eq!(irr, 0);
                assert_eq!(slave_irr, 0);
                assert_eq!(
                    isr,
                    if auto_eoi {
                        0
                    } else if irq >= 8 || irq == 2 {
                        4
                    } else {
                        1 << irq
                    }
                );
                assert_eq!(
                    slave_isr,
                    if auto_eoi || irq < 8 {
                        0
                    } else {
                        1 << (irq - 8)
                    }
                );
            }
        }
    }
}

#[test]
fn masked_or_absent_requests_do_not_call_the_cpu() {
    let mut p = DualPic::new();
    assert_eq!(
        p.try_deliver_pending(|_| -> Result<bool, ()> { panic!("no request") }),
        Ok(false)
    );
    p.pulse_irq(4);
    let before = snapshot(&p);
    assert_eq!(
        p.try_deliver_pending(|_| -> Result<bool, ()> { panic!("masked request") }),
        Ok(false)
    );
    assert_eq!(snapshot(&p), before);
}

#[test]
fn a_repeated_blocked_request_keeps_its_vector_and_does_not_enter_service() {
    let mut p = configured(false, false);
    p.pulse_irq(4);
    let before = snapshot(&p);
    for _ in 0..64 {
        assert_eq!(
            p.try_deliver_pending(|v| {
                assert_eq!(v, 0x24);
                Ok::<_, ()>(false)
            }),
            Ok(false)
        );
        assert_eq!(snapshot(&p), before);
    }
    assert_eq!(
        p.try_deliver_pending(|v| {
            assert_eq!(v, 0x24);
            Ok::<_, ()>(true)
        }),
        Ok(true)
    );
    assert_eq!(p.debug_info().2, 1 << 4);
    assert_eq!(
        p.try_deliver_pending(|_| -> Result<bool, ()> { panic!("already acknowledged") }),
        Ok(false)
    );
}

#[test]
fn priority_changes_only_after_a_successful_acknowledgement() {
    let mut p = configured(true, true);
    p.pulse_irq(0);
    p.pulse_irq(4);
    let before = snapshot(&p);
    assert_eq!(
        p.try_deliver_pending(|v| {
            assert_eq!(v, 0x20);
            Err::<bool, _>("host")
        }),
        Err("host")
    );
    assert_eq!(snapshot(&p), before);
    assert_eq!(
        p.try_deliver_pending(|v| {
            assert_eq!(v, 0x20);
            Ok::<_, ()>(true)
        }),
        Ok(true)
    );
    assert_eq!(
        p.try_deliver_pending(|v| {
            assert_eq!(v, 0x24);
            Ok::<_, ()>(true)
        }),
        Ok(true)
    );
}

#[test]
fn an_in_service_higher_priority_irq_keeps_lower_requests_pending() {
    let mut p = configured(false, false);
    p.pulse_irq(0);
    p.pulse_irq(4);
    assert_eq!(
        p.try_deliver_pending(|v| {
            assert_eq!(v, 0x20);
            Ok::<_, ()>(true)
        }),
        Ok(true)
    );
    let before = snapshot(&p);
    assert_eq!(
        p.try_deliver_pending(|_| -> Result<bool, ()> { panic!("priority blocked") }),
        Ok(false)
    );
    assert_eq!(snapshot(&p), before);
    assert_ne!(p.debug_info().0 & (1 << 4), 0);
}

#[test]
fn legacy_inta_entry_still_acknowledges_the_same_master_and_slave_vectors() {
    for irq in 0..16 {
        let mut p = configured(false, false);
        p.pulse_irq(irq);
        assert_eq!(
            p.get_pending_vector(),
            Some(if irq == 2 { 0x2f } else { 0x20 + irq })
        );
        assert_eq!(p.get_pending_vector(), None);
    }
}
