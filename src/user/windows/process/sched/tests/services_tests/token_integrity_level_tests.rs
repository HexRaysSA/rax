//! NtQueryInformationToken class 25 against the Windows 11 build 29708 oracle.

use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::security::Group;
use std::sync::Arc;

const LABEL: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];
const ATTRIBUTES: u32 = 0x60;
const UNTOUCHED: u32 = 0xA5A5_A5A5;

fn query(p: &mut Proc, thread: &mut Thread, token: u64, out: u64, len: u32, ret: u64) -> u32 {
    let sp = thread.cpu.sp();
    assert_eq!(
        invoke(p, thread, &[token, 25, out, u64::from(len), ret]),
        Outcome::Continue
    );
    thread.cpu.set_sp(sp);
    thread.cpu.gpr(0) as u32
}

fn select_subject(p: &mut Proc) {
    let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
    subject.groups.retain(|group| group.attributes & 0x20 == 0);
    subject.groups.push(Group {
        sid: LABEL.to_vec(),
        attributes: ATTRIBUTES,
    });
    p.objects
        .select_wnf_catalog(crate::user::windows::wnf::Catalog::selected(vec![], subject).unwrap());
}

#[test]
fn native_token_integrity_level_replays_layout_and_probe_order() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        select_subject(p);
        let wow = arch == WinArch::X86;
        let width = arch.ptr_size();
        let header = width * 2;
        let required = header as u32 + LABEL.len() as u32;
        let handle = handles[1];
        let failure_length = if wow { u32::MAX - 7 } else { UNTOUCHED };
        for (length, role, status, returned) in [
            (0, 1, STATUS_BUFFER_TOO_SMALL, required),
            (required - 1, 0, STATUS_BUFFER_TOO_SMALL, required),
            (required, 0, STATUS_SUCCESS, required),
            (64, 0, STATUS_SUCCESS, required),
            (64, 1, STATUS_ACCESS_VIOLATION, failure_length),
            (
                64,
                2,
                if wow {
                    STATUS_SUCCESS
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                },
                if wow { required } else { UNTOUCHED },
            ),
            (
                64,
                5,
                if wow {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_VIOLATION
                },
                UNTOUCHED,
            ),
        ] {
            let (out, ret) = destinations(p, base, role);
            assert_eq!(
                query(p, &mut thread, handle, out, length, ret),
                status,
                "{arch:?}, role {role}"
            );
            if ret != 0 {
                assert_eq!(p.space.u32(ret).unwrap(), returned);
            }
            if status == STATUS_SUCCESS {
                let mut actual = [0; LABEL.len()];
                p.space.rd(out + header, &mut actual).unwrap();
                assert_eq!(actual, LABEL);
                assert_eq!(p.space.u32(out + width).unwrap(), ATTRIBUTES);
                let pointer = if wow {
                    u64::from(p.space.u32(out).unwrap())
                } else {
                    assert_eq!(p.space.u32(out + width + 4).unwrap(), UNTOUCHED);
                    p.space.u64(out).unwrap()
                };
                assert_eq!(pointer, out + header);
                assert_eq!(p.space.u8(out + u64::from(required)).unwrap(), 0xA5);
            } else if out != 0 {
                assert_eq!(p.space.u8(out).unwrap(), 0xA5);
            }
        }
        for (kind, status) in [
            ("null", STATUS_INVALID_HANDLE),
            ("no-access", STATUS_ACCESS_DENIED),
            ("thread-token", STATUS_NO_TOKEN),
            ("event", STATUS_OBJECT_TYPE_MISMATCH),
            ("primary", STATUS_SUCCESS),
            ("effective", STATUS_SUCCESS),
        ] {
            let (out, ret) = destinations(p, base, 0);
            let token = super::handle(p, kind, handles);
            assert_eq!(query(p, &mut thread, token, out, 64, ret), status);
            assert_eq!(
                p.space.u32(ret).unwrap(),
                if status == STATUS_SUCCESS {
                    required
                } else {
                    failure_length
                }
            );
        }
        let (out, _) = destinations(p, base, 0);
        let attributes = out + width;
        assert_eq!(
            query(p, &mut thread, handle, out, 64, attributes),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.space.u32(attributes).unwrap(),
            if wow { required } else { ATTRIBUTES }
        );
    }
}

#[test]
fn native_token_integrity_level_uses_the_queried_subject() {
    let (mut process, mut thread, base, handles) = setup(WinArch::Arm64, false);
    let p = process.state_mut();
    select_subject(p);
    let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
    let label = subject.groups.last_mut().unwrap();
    label.sid[9] = 0x10;
    let lower_rid = u32::from_le_bytes(label.sid[8..12].try_into().unwrap());
    let token = p.objects.create(Object::GuestImpersonationToken {
        subject: Arc::new(subject),
        level: 2,
    });
    let handle = u64::from(p.objects.open_access(token, false, 8).unwrap());
    let (out, ret) = destinations(p, base, 0);
    assert_eq!(query(p, &mut thread, handle, out, 28, ret), STATUS_SUCCESS);
    assert_eq!(p.space.u32(out + 24).unwrap(), lower_rid);
    assert_eq!(
        query(p, &mut thread, handles[1], out, 28, ret),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.u32(out + 24).unwrap(), 0x2000);
}
