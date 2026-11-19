//! Native empty claim layouts, buffer ordering, and WoW64 partial clearing.
use super::*;
use crate::user::windows::security::token::claims::{
    EmptyClaims, TOKEN_DEVICE_CLAIMS, TOKEN_USER_CLAIMS,
};
use crate::user::windows::wnf::Catalog;
use std::sync::Arc;

const UNTOUCHED: u32 = 0xa5a5_a5a5;
const EMPTY: [u8; 16] = 1_u128.to_le_bytes();

fn select(p: &mut Proc, user: bool, device: bool) {
    let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
    subject.empty_claims = EmptyClaims { user, device };
    p.objects
        .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
}

fn query(
    p: &mut Proc,
    thread: &mut Thread,
    token: u64,
    class: u32,
    out: u64,
    len: u32,
    ret: u64,
) -> u32 {
    let sp = thread.cpu.sp();
    assert_eq!(
        invoke(
            p,
            thread,
            &[token, u64::from(class), out, u64::from(len), ret]
        ),
        Outcome::Continue
    );
    thread.cpu.set_sp(sp);
    thread.cpu.gpr(0) as u32
}

#[test]
fn token_claims_preserve_empty_headers_length_and_probe_precedence() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        select(p, true, true);
        let wow = arch == WinArch::X86;
        for class in [TOKEN_USER_CLAIMS, TOKEN_DEVICE_CLAIMS] {
            for (length, role, kind, expected, changed) in [
                (0, 1, "primary", STATUS_BUFFER_TOO_SMALL, true),
                (15, 0, "real", STATUS_BUFFER_TOO_SMALL, true),
                (16, 0, "effective", STATUS_SUCCESS, true),
                (127, 0, "real", STATUS_SUCCESS, true),
                (16, 1, "real", STATUS_ACCESS_VIOLATION, wow),
                (
                    72,
                    2,
                    "real",
                    if wow {
                        STATUS_SUCCESS
                    } else {
                        STATUS_DATATYPE_MISALIGNMENT
                    },
                    wow,
                ),
                (16, 5, "real", STATUS_ACCESS_VIOLATION, false),
                (
                    16,
                    5,
                    "null",
                    if wow {
                        STATUS_INVALID_HANDLE
                    } else {
                        STATUS_ACCESS_VIOLATION
                    },
                    false,
                ),
                (16, 0, "no-access", STATUS_ACCESS_DENIED, false),
                (16, 0, "thread-token", STATUS_NO_TOKEN, false),
            ] {
                let (out, ret) = destinations(p, base, role);
                let token = handle(p, kind, handles);
                assert_eq!(
                    query(p, &mut thread, token, class, out, length, ret),
                    expected,
                    "{arch:?} class {class} role {role} {kind}"
                );
                if ret != 0 {
                    assert_eq!(
                        p.space.u32(ret).unwrap(),
                        if changed { 16 } else { UNTOUCHED }
                    );
                }
                if expected == STATUS_SUCCESS {
                    assert_eq!(p.space.bytes(out, 16).unwrap(), EMPTY);
                    let end = if wow { u64::from(length) } else { 16 };
                    assert_eq!(
                        p.space.bytes(out + 16, (end - 16) as usize).unwrap(),
                        vec![0; (end - 16) as usize]
                    );
                    assert_eq!(p.space.u32(out + end).unwrap(), UNTOUCHED);
                } else if out != 0 {
                    assert_eq!(p.space.u32(out).unwrap(), UNTOUCHED);
                }
            }

            let (out, ret) = destinations(p, base, 18);
            assert_eq!(
                query(p, &mut thread, handles[1], class, out, 128, ret),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.bytes(out, 16).unwrap(), EMPTY);
        }
    }
}

#[test]
fn token_claims_distinguish_user_device_and_explicit_subjects() {
    let (mut process, mut thread, base, handles) = setup(WinArch::Arm64, false);
    let p = process.state_mut();
    select(p, true, false);
    let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
    subject.empty_claims = EmptyClaims {
        user: false,
        device: true,
    };
    let id = p.objects.create(Object::GuestImpersonationToken {
        subject: Arc::new(subject),
        level: 2,
    });
    let impersonation = u64::from(p.objects.open_access(id, false, 8).unwrap());
    for (token, available, unavailable) in [
        (handles[1], TOKEN_USER_CLAIMS, TOKEN_DEVICE_CLAIMS),
        (impersonation, TOKEN_DEVICE_CLAIMS, TOKEN_USER_CLAIMS),
    ] {
        let (out, ret) = destinations(p, base, 0);
        assert_eq!(
            query(p, &mut thread, token, available, out, 16, ret),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.bytes(out, 16).unwrap(), EMPTY);

        let (out, ret) = destinations(p, base, 0);
        assert!(matches!(
            invoke(p, &mut thread, &[token, u64::from(unavailable), out, 16, ret]),
            Outcome::Fail(reason) if reason.contains("claims lack a supported empty capture")
        ));
        assert_eq!(p.space.u32(out).unwrap(), UNTOUCHED);
        assert_eq!(p.space.u32(ret).unwrap(), UNTOUCHED);
    }
}

#[test]
fn wow64_token_claims_preserve_native_vector_store_order_on_guard_faults() {
    let (mut process, mut thread, base, handles) = setup(WinArch::X86, false);
    let p = process.state_mut();
    select(p, true, true);
    let boundary = base + PAGE_SIZE * 2;
    // length, accessible prefix, first bytes cleared by native memset.
    for (length, available, cleared) in [
        (16, 15, 0),
        (23, 20, 16),
        (32, 24, 16),
        (64, 63, 48),
        (129, 127, 113),
        (1024, 127, 127),
        (32768, 127, 127),
    ] {
        let (_, ret) = destinations(p, base, 0);
        let out = boundary - available;
        p.vm.protect(boundary, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        assert_eq!(
            query(
                p,
                &mut thread,
                handles[1],
                TOKEN_USER_CLAIMS,
                out,
                length,
                ret
            ),
            STATUS_GUARD_PAGE_VIOLATION
        );
        assert_eq!(p.space.u32(ret).unwrap(), 16);
        assert_eq!(p.space.bytes(out, cleared).unwrap(), vec![0; cleared]);
        assert_eq!(
            p.space
                .bytes(out + cleared as u64, available as usize - cleared)
                .unwrap(),
            vec![0xa5; available as usize - cleared]
        );
        assert_eq!(p.vm.query(boundary).unwrap().protect, prot::READWRITE);
    }
}
