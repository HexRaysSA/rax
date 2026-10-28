//! AArch64 load completion policy: complete data, width and sign handling.
#[path = "../../../src/backend/hvf/arm64_mmio.rs"]
mod policy;
use policy::PendingMmioRead;

pub fn configurations() -> [(u8, bool, bool); 9] {
    [
        (1, false, false),
        (1, true, false),
        (1, true, true),
        (2, false, false),
        (2, true, false),
        (2, true, true),
        (4, false, false),
        (4, true, true),
        (8, false, true),
    ]
}
fn request(size: u8, sign_extend: bool, sixty_four: bool, rt: u32) -> PendingMmioRead {
    PendingMmioRead {
        addr: 0x09000000,
        rt,
        size,
        sign_extend,
        sixty_four,
    }
}
pub fn observations() -> Vec<u64> {
    let mut rows = Vec::new();
    for (case, (size, signed, wide)) in configurations().into_iter().enumerate() {
        let mask = if size == 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        };
        let sign = 1u64 << (size * 8 - 1);
        for rt in [0, 31] {
            let plan = request(size, signed, wide, rt);
            for (pattern, value) in [0, 1, mask, sign, sign - 1, 0x8877665544332211 & mask]
                .into_iter()
                .enumerate()
            {
                let mut data = value.to_le_bytes()[..usize::from(size)].to_vec();
                data.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
                for length in (0..=usize::from(size)).chain(std::iter::once(usize::from(size) + 3))
                {
                    let got = plan.value(&data[..length]);
                    rows.extend([
                        case as u64,
                        u64::from(rt),
                        pattern as u64,
                        length as u64,
                        u64::from(size),
                        u64::from(signed),
                        u64::from(wide),
                        u64::from(got.is_some()),
                        got.unwrap_or(u64::MAX),
                    ]);
                }
            }
        }
    }
    rows
}
#[test]
fn every_short_reply_keeps_all_scalar_loads_incomplete() {
    for (size, signed, wide) in configurations() {
        for rt in [0, 31] {
            let p = request(size, signed, wide, rt);
            for length in 0..size {
                assert_eq!(p.value(&vec![0xff; usize::from(length)]), None);
            }
        }
    }
}
#[test]
fn full_replies_apply_architectural_sign_and_destination_width() {
    for (size, signed, wide, data, want) in [
        (1, false, false, vec![0x80], 0x80u64),
        (1, true, false, vec![0x80], 0xffff_ff80),
        (1, true, true, vec![0x80], 0xffff_ffff_ffff_ff80),
        (2, true, false, vec![1, 0x80], 0xffff_8001),
        (2, true, true, vec![1, 0x80], 0xffff_ffff_ffff_8001),
        (4, false, false, vec![1, 0, 0, 0x80], 0x8000_0001),
        (4, true, true, vec![1, 0, 0, 0x80], 0xffff_ffff_8000_0001),
        (
            8,
            false,
            true,
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            0x8877_6655_4433_2211,
        ),
    ] {
        assert_eq!(request(size, signed, wide, 0).value(&data), Some(want));
    }
}
#[test]
fn trailing_reply_bytes_do_not_change_the_load_value() {
    for (size, signed, wide) in configurations() {
        let p = request(size, signed, wide, 0);
        let mut data = vec![0x80; usize::from(size)];
        let want = p.value(&data);
        data.extend_from_slice(&[0x11, 0x22, 0x33]);
        assert_eq!(p.value(&data), want);
    }
}
#[test]
fn invalid_internal_widths_fail_before_any_shift_or_slice() {
    for size in [0, 3, 5, 7, 9, 255] {
        assert_eq!(request(size, true, true, 0).value(&[0x80; 256]), None);
    }
}

#[test]
fn incomplete_replies_never_invoke_the_destination_writer() {
    for (size, signed, wide) in configurations() {
        for rt in [0, 31] {
            let pending = request(size, signed, wide, rt);
            for length in 0..usize::from(size) {
                let completed: Result<bool, ()> = pending.complete(&vec![0xff; length], |_, _| {
                    panic!("incomplete reply invoked destination writer")
                });
                assert_eq!(completed, Ok(false));
            }
        }
    }
}

#[test]
fn destination_write_failure_does_not_accept_a_complete_reply() {
    let pending = request(2, true, true, 9);
    let mut attempts = 0;
    let rejected = pending.complete(&[0, 0x80], |rt, value| {
        attempts += 1;
        assert_eq!(rt, 9);
        assert_eq!(value, 0xffff_ffff_ffff_8000);
        Err("injected destination write failure")
    });
    assert_eq!(rejected, Err("injected destination write failure"));
    let retried: Result<bool, ()> = pending.complete(&[1, 0x80], |rt, value| {
        attempts += 1;
        assert_eq!((rt, value), (9, 0xffff_ffff_ffff_8001));
        Ok(())
    });
    assert_eq!(retried, Ok(true));
    assert_eq!(attempts, 2);
}

#[test]
fn zero_register_load_requires_full_data_and_does_not_write_a_register() {
    let pending = request(8, false, true, 31);
    let completed: Result<bool, ()> = pending.complete(&[0x80; 8], |_, _| {
        panic!("zero-register load invoked destination writer")
    });
    assert_eq!(completed, Ok(true));
    assert_eq!(
        pending.complete(&[0x80; 7], |_, _| Ok::<(), ()>(())),
        Ok(false)
    );
}
