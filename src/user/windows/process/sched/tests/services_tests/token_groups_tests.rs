//! Native class 2 layouts, probe ordering, and WoW64 copyback boundaries.
use super::*;
use crate::user::windows::security::Group;
use crate::user::windows::wnf::Catalog;
use std::sync::Arc;

const UNTOUCHED: u32 = 0xa5a5_a5a5;
const FIRST_SID: [u8; 28] = [
    1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 11, 0, 0, 0, 22, 0, 0, 0, 33, 0, 0, 0, 44, 0, 0, 0,
];
const SECOND_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];

fn select_subject(p: &mut Proc) -> [Group; 2] {
    let groups = [
        Group {
            sid: FIRST_SID.to_vec(),
            attributes: 0x10,
        },
        Group {
            sid: SECOND_SID.to_vec(),
            attributes: 0x60,
        },
    ];
    let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
    subject.groups = groups.to_vec();
    subject.restricted = vec![groups[0].clone()];
    p.objects
        .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
    groups
}

fn query(p: &mut Proc, thread: &mut Thread, token: u64, out: u64, len: u32, ret: u64) -> u32 {
    let sp = thread.cpu.sp();
    assert_eq!(
        invoke(p, thread, &[token, 2, out, u64::from(len), ret]),
        Outcome::Continue
    );
    thread.cpu.set_sp(sp);
    thread.cpu.gpr(0) as u32
}

fn check_records(p: &Proc, out: u64, groups: &[Group], required: u32) {
    let width = p.arch.ptr_size();
    assert_eq!(p.space.u32(out).unwrap(), groups.len() as u32);
    let mut sid = out + width * (1 + 2 * groups.len() as u64);
    for (index, group) in groups.iter().enumerate() {
        let record = out + width * (1 + 2 * index as u64);
        assert_eq!(p.space.ptr(record, width).unwrap(), sid);
        assert_eq!(p.space.u32(record + width).unwrap(), group.attributes);
        if width == 8 {
            assert_eq!(p.space.u32(record + 12).unwrap(), UNTOUCHED);
        }
        assert_eq!(p.space.bytes(sid, group.sid.len()).unwrap(), group.sid);
        sid += group.sid.len() as u64;
    }
    assert_eq!(sid, out + u64::from(required));
    assert_eq!(p.space.u32(sid).unwrap(), UNTOUCHED);
}

#[test]
fn token_groups_preserves_order_attributes_and_destination_precedence() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        let groups = select_subject(p);
        let required = if arch == WinArch::X86 { 60 } else { 80 };
        let wow = arch == WinArch::X86;
        for (length, role, kind, expected, changed) in [
            (0, 1, "primary", STATUS_BUFFER_TOO_SMALL, true),
            (required - 1, 0, "real", STATUS_BUFFER_TOO_SMALL, true),
            (required, 0, "effective", STATUS_SUCCESS, true),
            (required + 16, 0, "real", STATUS_SUCCESS, true),
            (required, 1, "real", STATUS_ACCESS_VIOLATION, wow),
            (
                required,
                2,
                "real",
                if wow {
                    STATUS_SUCCESS
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                },
                wow,
            ),
            (required, 5, "real", STATUS_ACCESS_VIOLATION, false),
            (
                required,
                5,
                "null",
                if wow {
                    STATUS_INVALID_HANDLE
                } else {
                    STATUS_ACCESS_VIOLATION
                },
                false,
            ),
            (required, 0, "no-access", STATUS_ACCESS_DENIED, false),
            (required, 0, "process", STATUS_OBJECT_TYPE_MISMATCH, false),
            (required, 0, "thread-token", STATUS_NO_TOKEN, false),
        ] {
            let (out, ret) = destinations(p, base, role);
            let token = handle(p, kind, handles);
            assert_eq!(
                query(p, &mut thread, token, out, length, ret),
                expected,
                "{arch:?}, {role}, {kind}"
            );
            if ret != 0 {
                assert_eq!(
                    p.space.u32(ret).unwrap(),
                    if changed { required } else { UNTOUCHED }
                );
            }
            if expected == STATUS_SUCCESS {
                check_records(p, out, &groups, required);
            } else if out != 0 {
                assert_eq!(p.space.u32(out).unwrap(), UNTOUCHED);
            }
        }

        let (out, ret) = destinations(p, base, 18);
        assert_eq!(
            query(p, &mut thread, handles[1], out, required, ret),
            STATUS_SUCCESS
        );
        check_records(p, out, &groups, required);
        if !wow {
            assert_eq!(p.space.u32(out + 4).unwrap(), 0xa5a5_a500);
        }

        let mut impersonation = (*p.objects.primary_token_subject().unwrap()).clone();
        impersonation.groups.reverse();
        let id = p.objects.create(Object::GuestImpersonationToken {
            subject: Arc::new(impersonation),
            level: 2,
        });
        let token = u64::from(p.objects.open_access(id, false, 8).unwrap());
        p.objects.select_wnf_catalog(Catalog::default());
        let (out, ret) = destinations(p, base, 0);
        assert_eq!(
            query(p, &mut thread, token, out, required, ret),
            STATUS_SUCCESS
        );
        check_records(p, out, &[groups[1].clone(), groups[0].clone()], required);
        assert!(matches!(
            invoke(p, &mut thread, &[handles[1], 2, out, u64::from(required), ret]),
            Outcome::Fail(reason) if reason.contains("token groups are not captured")
        ));
    }
}

#[test]
fn wow64_token_groups_retires_count_and_reached_sid_store_before_fault() {
    let (mut process, mut thread, base, handles) = setup(WinArch::X86, false);
    let p = process.state_mut();
    select_subject(p);
    let boundary = base + PAGE_SIZE * 2;
    for (protection, expected, guard_after) in [
        (prot::NOACCESS, STATUS_ACCESS_VIOLATION, prot::NOACCESS),
        (
            prot::READWRITE | prot::GUARD,
            STATUS_GUARD_PAGE_VIOLATION,
            prot::READWRITE,
        ),
        (
            prot::READONLY | prot::GUARD,
            STATUS_ACCESS_VIOLATION,
            prot::READONLY | prot::GUARD,
        ),
    ] {
        for (available, copied) in [(12, 0), (35, 0), (36, 16), (47, 16), (48, 28)] {
            let (_, ret) = destinations(p, base, 0);
            let out = boundary - available;
            p.vm.protect(boundary, PAGE_SIZE, protection).unwrap();
            assert_eq!(query(p, &mut thread, handles[1], out, 76, ret), expected);
            assert_eq!(p.vm.query(boundary).unwrap().protect, guard_after);
            assert_eq!(p.space.u32(ret).unwrap(), 60);
            assert_eq!(p.space.u32(out).unwrap(), 2);
            if available < 48 {
                assert_eq!(p.space.u32(out + 4).unwrap(), UNTOUCHED);
                assert_eq!(p.space.u32(out + 8).unwrap(), UNTOUCHED);
            } else {
                assert_eq!(p.space.u32(out + 4).unwrap(), (out + 20) as u32);
                assert_eq!(p.space.u32(out + 8).unwrap(), 0x10);
            }
            if copied != 0 {
                assert_eq!(
                    p.space.bytes(out + 20, copied as usize).unwrap(),
                    FIRST_SID[..copied as usize]
                );
            }
        }
    }
}
