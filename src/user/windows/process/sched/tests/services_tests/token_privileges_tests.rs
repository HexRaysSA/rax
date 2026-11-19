//! TokenPrivileges layout, caller probes, and selected subject ownership.
use super::*;
use crate::user::windows::security::Privilege;
use crate::user::windows::wnf::Catalog;
use std::sync::Arc;

const UNTOUCHED: u32 = 0xa5a5_a5a5;
const RECORD: [u8; 28] = [
    2, 0, 0, 0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x03, 0, 0, 0, 0x08, 0x07, 0x06,
    0x05, 0x04, 0x03, 0x02, 0x01, 0x04, 0, 0, 0x80,
];

fn query(p: &mut Proc, thread: &mut Thread, token: u64, out: u64, len: u32, ret: u64) -> u32 {
    let sp = thread.cpu.sp();
    assert_eq!(
        invoke(p, thread, &[token, 3, out, u64::from(len), ret]),
        Outcome::Continue
    );
    thread.cpu.set_sp(sp);
    thread.cpu.gpr(0) as u32
}

#[test]
fn token_privileges_preserve_order_flags_and_native_probes_in_all_guest_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
        subject.privileges = vec![
            Privilege {
                luid: 0xfedc_ba98_7654_3210,
                attributes: 3,
            },
            Privilege {
                luid: 0x0102_0304_0506_0708,
                attributes: 0x80000004,
            },
        ];
        p.objects
            .select_wnf_catalog(Catalog::selected(vec![], subject.clone()).unwrap());

        for (length, role, kind, expected, changed) in [
            (0, 1, "primary", STATUS_BUFFER_TOO_SMALL, true),
            (27, 0, "real", STATUS_BUFFER_TOO_SMALL, true),
            (28, 0, "effective", STATUS_SUCCESS, true),
            (28, 25, "real", STATUS_SUCCESS, true),
            (44, 0, "real", STATUS_SUCCESS, true),
            (28, 1, "real", STATUS_ACCESS_VIOLATION, false),
            (28, 2, "null", STATUS_DATATYPE_MISALIGNMENT, false),
            (28, 5, "null", STATUS_ACCESS_VIOLATION, false),
            (28, 0, "no-access", STATUS_ACCESS_DENIED, false),
            (28, 0, "process", STATUS_OBJECT_TYPE_MISMATCH, false),
            (28, 0, "thread-token", STATUS_NO_TOKEN, false),
        ] {
            // The native oracle accepts a DWORD-aligned output at base+4.
            let (mut out, ret) = destinations(p, base, if role == 25 { 0 } else { role });
            if role == 25 {
                out += 4;
            }
            let token = handle(p, kind, handles);
            assert_eq!(
                query(p, &mut thread, token, out, length, ret),
                expected,
                "{arch:?} {kind}/{role}"
            );
            if ret != 0 {
                assert_eq!(
                    p.space.u32(ret).unwrap(),
                    if changed { 28 } else { UNTOUCHED }
                );
            }
            if expected == STATUS_SUCCESS {
                assert_eq!(p.space.bytes(out, 28).unwrap(), RECORD);
                assert_eq!(p.space.u32(out + 28).unwrap(), UNTOUCHED);
            } else if out != 0 {
                assert_eq!(p.space.u32(out).unwrap(), UNTOUCHED);
            }
        }

        let (out, ret) = destinations(p, base, 18);
        assert_eq!(
            query(p, &mut thread, handles[1], out, 28, ret),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.bytes(out, 28).unwrap(), RECORD);

        subject.privileges.clear();
        let id = p.objects.create(Object::GuestImpersonationToken {
            subject: Arc::new(subject),
            level: 2,
        });
        let token = u64::from(p.objects.open_access(id, false, 8).unwrap());
        p.objects.select_wnf_catalog(Catalog::default());
        for (length, status) in [
            (4, STATUS_BUFFER_TOO_SMALL),
            (15, STATUS_BUFFER_TOO_SMALL),
            (16, STATUS_SUCCESS),
            (32, STATUS_SUCCESS),
        ] {
            let (out, ret) = destinations(p, base, 0);
            assert_eq!(query(p, &mut thread, token, out, length, ret), status);
            assert_eq!(p.space.u32(ret).unwrap(), 16);
            assert_eq!(
                p.space.u32(out).unwrap(),
                if status == STATUS_SUCCESS {
                    0
                } else {
                    UNTOUCHED
                }
            );
            assert_eq!(p.space.bytes(out + 4, 28).unwrap(), [0xa5; 28]);
        }
    }
}
