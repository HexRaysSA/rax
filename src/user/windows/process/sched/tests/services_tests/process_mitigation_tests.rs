use super::*;

#[test]
fn native_process_mitigation_preserves_selector_return_length_and_padding_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        for policy in [2, 11] {
            for returned in [0, scratch + 64, scratch + 65, scratch, scratch + 4] {
                p.space.wr(scratch, &[0xA5; 128]).unwrap();
                p.space.w32(scratch, policy).unwrap();
                let before = (p.rng, p.objects.handle_count(), p.objects.iter().count());
                arguments(p, &mut t, arch.ptr(u64::MAX), 52, scratch, 8, returned);
                assert_eq!(
                    dispatch(p, &mut t),
                    Outcome::Continue,
                    "{arch}/{returned:X}"
                );
                assert_eq!(t.cpu.gpr(0), 0);
                assert_eq!(p.space.u32(scratch).unwrap(), policy);
                assert_eq!(p.space.u32(scratch + 4).unwrap(), 0);
                assert_eq!(p.space.bytes(scratch + 8, 120).unwrap(), [0xA5; 120]);
                assert_eq!(
                    (p.rng, p.objects.handle_count(), p.objects.iter().count()),
                    before
                );
                assert!(t.frames.is_empty());
            }
        }
    }
}

#[path = "process_mitigation_tests/replay.rs"]
mod replay;

#[test]
fn native_process_mitigation_filter_exact_length_and_unimplemented_selectors_preserve_memory() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        for length in [0, 1, 4, 7, 9, 16, u32::MAX] {
            p.space.wr(scratch, &[0xA5; 128]).unwrap();
            p.space.w32(scratch, 11).unwrap();
            t.cpu.set_sp(sp);
            arguments(
                p,
                &mut t,
                arch.ptr(u64::MAX),
                52,
                scratch,
                length,
                scratch + 64,
            );
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INFO_LENGTH_MISMATCH));
            assert_eq!(p.space.u32(scratch).unwrap(), 11);
            assert_eq!(p.space.bytes(scratch + 4, 124).unwrap(), [0xA5; 124]);
        }
        for policy in [0, 1, 5, 15, 20, 31, u32::MAX] {
            p.space.wr(scratch, &[0xA5; 128]).unwrap();
            p.space.w32(scratch, policy).unwrap();
            t.cpu.set_sp(sp);
            arguments(p, &mut t, arch.ptr(u64::MAX), 52, scratch, 8, scratch + 64);
            assert!(
                matches!(dispatch(p,&mut t),Outcome::Fail(reason) if reason.contains(&format!("ProcessMitigationPolicy selector {policy}")))
            );
            assert_eq!(p.space.u32(scratch).unwrap(), policy);
            assert_eq!(p.space.bytes(scratch + 4, 124).unwrap(), [0xA5; 124]);
        }
    }
}

#[test]
fn native_process_mitigation_filter_unmodeled_peer_and_other_object_handles_fail_without_publication()
 {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        for access in [0x400, 0x1000, 0x1400] {
            let object = p.objects.create(Object::Process {
                pid: p.pid + 4,
                exit_code: None,
            });
            let h = p.objects.open_access(object, false, access).unwrap();
            p.space.w32(scratch, 11).unwrap();
            t.cpu.set_sp(sp);
            arguments(p, &mut t, u64::from(h), 52, scratch, 8, scratch + 64);
            assert!(
                matches!(dispatch(p,&mut t),Outcome::Fail(reason) if reason.contains("unmodeled peer process"))
            );
            assert_eq!(p.space.bytes(scratch + 4, 124).unwrap(), [0xA5; 124]);
        }
        for object in [
            Object::Thread {
                tid: t.tid,
                exit_code: None,
            },
            Object::Event {
                manual: false,
                signaled: 0,
            },
        ] {
            let id = p.objects.create(object);
            let h = p.objects.open_access(id, false, u32::MAX).unwrap();
            t.cpu.set_sp(sp);
            arguments(p, &mut t, u64::from(h | 1), 52, scratch, 8, scratch + 64);
            assert_eq!(dispatch(p, &mut t), Outcome::Continue);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(crate::user::windows::nt::status::STATUS_OBJECT_TYPE_MISMATCH)
            );
            assert_eq!(p.space.bytes(scratch + 4, 124).unwrap(), [0xA5; 124]);
        }
    }
}
