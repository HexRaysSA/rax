//! Native cleanup observations distinguish handles from retained objects.
use super::replay::*;
use super::*;

#[test]
fn native_notify_key_replays_duplicate_independent_and_last_handle_lifetimes_all_abis() {
    let data = corpus();
    let mut count = 0;
    for report in data["reports"].as_array().unwrap() {
        let arch = architecture(report);
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        profile(p, &data, report);
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        for row in rows(&data, report, "lifetime") {
            let key = body(p);
            let style = number(row, "style");
            let duplicate =
                (style & 1 != 0).then(|| u64::from(p.objects.duplicate(key, false).unwrap()));
            let independent = (style & 2 != 0).then(|| body(p));
            let event = event(p);
            p.space
                .wr(base, &vec![0xcc; arch.ptr_size() as usize * 2])
                .unwrap();
            p.space.w64(base + PAGE_SIZE * 3, 0).unwrap();
            assert_eq!(
                u64::from(call(
                    p,
                    &mut t,
                    "NtWaitForSingleObject",
                    &[key, 0, base + PAGE_SIZE * 3]
                )),
                number(row, "wait_before")
            );
            assert_eq!(
                u64::from(call(
                    p,
                    &mut t,
                    "NtNotifyChangeKey",
                    &[
                        key,
                        if number(row, "event_supplied") == 0 {
                            0
                        } else {
                            event
                        },
                        0,
                        0,
                        base,
                        number(row, "filter"),
                        0,
                        0,
                        0,
                        1
                    ]
                )),
                number(row, "status")
            );
            assert_eq!(signal(p, event), number(row, "event_armed"));
            assert_eq!(
                p.space.bytes(base, arch.ptr_size() as usize * 2).unwrap(),
                bytes(row["iosb_armed"].as_str().unwrap())
            );
            assert_eq!(
                u64::from(call(
                    p,
                    &mut t,
                    "NtWaitForSingleObject",
                    &[key, 0, base + PAGE_SIZE * 3]
                )),
                number(row, "wait_armed")
            );
            if let Some(handle) = independent {
                assert_eq!(call(p, &mut t, "NtClose", &[handle]), 0);
            }
            assert_eq!(
                signal(p, event),
                number(row, "event_after_independent_close")
            );
            assert_eq!(call(p, &mut t, "NtClose", &[key]), 0);
            assert_eq!(signal(p, event), number(row, "event_after_original_close"));
            assert_eq!(
                p.space.bytes(base, arch.ptr_size() as usize * 2).unwrap(),
                bytes(row["iosb_after_original_close"].as_str().unwrap())
            );
            if let Some(handle) = duplicate {
                assert_eq!(call(p, &mut t, "NtClose", &[handle]), 0);
            }
            assert_eq!(signal(p, event), number(row, "event_final"));
            assert_eq!(
                p.space.bytes(base, arch.ptr_size() as usize * 2).unwrap(),
                bytes(row["iosb_final"].as_str().unwrap())
            );
            assert_eq!(call(p, &mut t, "NtClose", &[event]), 0);
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.objects.iter().count(), objects);
            count += 1;
        }
    }
    assert_eq!(count, data["reports"].as_array().unwrap().len() * 32);
}

#[test]
fn native_notify_key_replays_late_store_faults_and_retained_event_identity_all_abis() {
    let data = corpus();
    let mut count = 0;
    for report in data["reports"].as_array().unwrap() {
        let arch = architecture(report);
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        profile(p, &data, report);
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        for kind in ["completion", "completion_stores"] {
            for row in rows(&data, report, kind) {
                p.vm.protect(base, PAGE_SIZE * 2, prot::READWRITE).unwrap();
                let io = if kind == "completion" {
                    base
                } else {
                    base + PAGE_SIZE - arch.ptr_size()
                };
                p.space
                    .wr(io, &vec![0xcc; arch.ptr_size() as usize * 2])
                    .unwrap();
                let key = body(p);
                let original = event(p);
                let original_id = p.objects.id(original).unwrap();
                let alias = u64::from(p.objects.duplicate(original, false).unwrap());
                assert_eq!(
                    u64::from(call(
                        p,
                        &mut t,
                        "NtNotifyChangeKey",
                        &[key, original, 0, 0, io, number(row, "filter"), 0, 0, 0, 1]
                    )),
                    number(row, "status")
                );
                assert_eq!(
                    p.space.bytes(io, arch.ptr_size() as usize * 2).unwrap(),
                    bytes(row["iosb_armed"].as_str().unwrap())
                );
                if kind == "completion_stores" {
                    p.space
                        .wr(io, &vec![0xa5; arch.ptr_size() as usize * 2])
                        .unwrap();
                }
                let retirement = number(row, "retirement");
                let replacement = if retirement == 0 {
                    None
                } else {
                    assert_eq!(call(p, &mut t, "NtClose", &[original]), 0);
                    if retirement == 2 {
                        assert_eq!(call(p, &mut t, "NtClose", &[alias]), 0);
                    }
                    let handle = event(p);
                    if let Some(Object::Event { signaled, .. }) = p.objects.get_mut(handle) {
                        *signaled = 0;
                    }
                    assert_ne!(p.objects.id(handle), Some(original_id));
                    Some(handle)
                };
                let protection = match number(row, "protection") {
                    0 => prot::READWRITE,
                    1 => prot::READONLY,
                    2 => prot::NOACCESS,
                    3 => prot::READWRITE | prot::GUARD,
                    _ => panic!("protection"),
                };
                let page = if kind == "completion" {
                    base
                } else {
                    base + PAGE_SIZE
                };
                p.vm.protect(page, PAGE_SIZE, protection).unwrap();
                assert_eq!(
                    u64::from(call(p, &mut t, "NtClose", &[key])),
                    number(row, "close_status")
                );
                assert_eq!(number(row, "exception"), 0);
                assert_eq!(
                    u64::from(p.vm.query(page).unwrap().protect),
                    number(row, "observed_protection")
                );
                if retirement != 2 {
                    assert_eq!(signal(p, alias), number(row, "original_signal"));
                } else {
                    assert!(p.objects.obj(original_id).is_none());
                }
                if let Some(handle) = replacement {
                    assert_eq!(signal(p, handle), number(row, "replacement_signal"));
                }
                p.vm.protect(base, PAGE_SIZE * 2, prot::READWRITE).unwrap();
                assert_eq!(
                    p.space.bytes(io, arch.ptr_size() as usize * 2).unwrap(),
                    bytes(row["iosb_final"].as_str().unwrap()),
                    "{arch:?} {kind} {row}"
                );
                if retirement == 0 {
                    assert_eq!(call(p, &mut t, "NtClose", &[original]), 0);
                }
                if retirement != 2 {
                    assert_eq!(call(p, &mut t, "NtClose", &[alias]), 0);
                }
                if let Some(handle) = replacement {
                    assert_eq!(call(p, &mut t, "NtClose", &[handle]), 0);
                }
                assert_eq!(p.objects.handle_count(), handles);
                assert_eq!(p.objects.iter().count(), objects);
                count += 1;
            }
        }
    }
    assert_eq!(count, data["reports"].as_array().unwrap().len() * 48);
}
