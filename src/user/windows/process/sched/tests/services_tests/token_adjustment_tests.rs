//! Native privilege adjustment and the lifetime of the selected guest subject.

use super::*;
use crate::user::windows::security::{Privilege, token::statistics::Statistics};
use crate::user::windows::wnf::Catalog;

const POISON: u32 = 0xa5a5_a5a5;

fn adjust(
    p: &mut Proc,
    t: &mut Thread,
    token: u64,
    disable_all: bool,
    [input, capacity, output, length]: [u64; 4],
) -> u32 {
    let ntdll = p.modules.by_name("ntdll.dll").unwrap();
    let table = p
        .modules
        .nt_services
        .replace((ntdll, super::table(p.arch, "NtAdjustPrivilegesToken", 0x21)));
    let sp = t.cpu.sp();
    let result = invoke(
        p,
        t,
        &[
            token,
            u64::from(disable_all),
            input,
            capacity,
            output,
            length,
        ],
    );
    t.cpu.set_sp(sp);
    p.modules.nt_services = table;
    assert_eq!(result, Outcome::Continue);
    t.cpu.gpr(0) as u32
}

fn request(p: &Proc, where_at: u64, entries: &[(u64, u32)]) {
    p.space.w32(where_at, entries.len() as u32).unwrap();
    for (index, &(luid, attributes)) in entries.iter().enumerate() {
        let position = where_at + 4 + index as u64 * 12;
        p.space.w64(position, luid).unwrap();
        p.space.w32(position + 8, attributes).unwrap();
    }
}

#[test]
fn native_adjust_privileges_orders_results_and_updates_the_live_token() {
    assert_eq!(
        crate::user::windows::nt::status_to_error(STATUS_NOT_ALL_ASSIGNED),
        1300
    );
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
        subject.privileges = vec![
            Privilege {
                luid: 23,
                attributes: 3,
            },
            Privilege {
                luid: 8,
                attributes: 1,
            },
        ];
        let mut stats = [0; 56];
        stats[24..28].copy_from_slice(&1u32.to_le_bytes());
        stats[44..48].copy_from_slice(&2u32.to_le_bytes());
        let captured = Statistics::selected(stats).unwrap();
        subject.statistics = Some(captured);
        p.objects
            .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
        let token = u64::from(p.objects.open_primary_token(0x28, false).unwrap());
        let query_only = u64::from(p.objects.open_primary_token(8, false).unwrap());
        let duplicate_id = p.objects.create(Object::GuestImpersonationToken {
            subject: p.objects.primary_token_subject().unwrap(),
            level: 2,
        });
        let duplicate = u64::from(p.objects.open_access(duplicate_id, false, 0x28).unwrap());
        let input = base + 1;
        let out = base + 101;
        let length = base + 201;
        p.space.wr(out, &[0xa5; 128]).unwrap();
        p.space.w32(length, POISON).unwrap();
        request(p, input, &[(23, 0), (23, 2)]);
        assert_eq!(
            adjust(p, &mut thread, query_only, false, [input, 128, out, length]),
            STATUS_ACCESS_DENIED
        );
        let pseudo_primary = p.arch.ptr(u64::MAX - 3);
        assert_eq!(
            adjust(
                p,
                &mut thread,
                pseudo_primary,
                false,
                [input, 128, out, length]
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(p.space.u32(length).unwrap(), POISON);
        assert_eq!(
            adjust(p, &mut thread, handles[0], false, [0, 128, out, length]),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            adjust(p, &mut thread, token, false, [input, 128, out, 0]),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            p.objects.primary_token_subject().unwrap().statistics,
            Some(captured)
        );
        assert_eq!(
            adjust(p, &mut thread, token, false, [input, 15, out, length]),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(p.space.u32(out).unwrap(), POISON);
        assert_eq!(
            adjust(p, &mut thread, token, false, [input, 128, out, length]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(length).unwrap(), 16);
        assert_eq!(p.space.u32(out).unwrap(), 2);
        assert_eq!(p.space.u32(out + 16).unwrap(), 23);
        assert_eq!(p.space.u32(out + 24).unwrap(), 1);
        assert_ne!(
            p.objects.primary_token_subject().unwrap().statistics,
            Some(captured)
        );

        request(p, input, &[(0x7fff_fffe, 2), (23, 6)]);
        assert_eq!(
            adjust(p, &mut thread, token, false, [input, 0, 0, length]),
            STATUS_NOT_ALL_ASSIGNED
        );
        assert_eq!(p.space.u32(length).unwrap(), 16);
        assert_eq!(
            p.objects.primary_token_subject().unwrap().privileges.len(),
            1
        );
        let subject = p.objects.primary_token_subject().unwrap();
        let stats = subject.statistics.unwrap();
        assert_eq!(
            u32::from_le_bytes(stats.bytes()[44..48].try_into().unwrap()),
            1
        );
        p.objects.close(token).unwrap();
        p.objects.close(query_only).unwrap();
        assert_eq!(
            p.objects.primary_token_subject().unwrap().privileges[0].luid,
            8
        );
        let Some(Object::GuestImpersonationToken { subject, .. }) = p.objects.get(duplicate) else {
            panic!("expected independent duplicate");
        };
        assert_eq!(subject.privileges[0].attributes, 3);
        let guard = base + PAGE_SIZE * 4;
        p.vm.protect(guard, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        request(p, input, &[(23, 0)]);
        assert_eq!(
            adjust(
                p,
                &mut thread,
                duplicate,
                false,
                [input, 128, guard, length]
            ),
            STATUS_GUARD_PAGE_VIOLATION
        );
        let Some(Object::GuestImpersonationToken { subject, .. }) = p.objects.get(duplicate) else {
            unreachable!()
        };
        assert_eq!(subject.privileges[0].attributes, 3);
        assert_ne!(subject.statistics, Some(captured));
        assert_eq!(
            adjust(p, &mut thread, duplicate, true, [0, 128, out, out]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(out).unwrap(), 1);
        let Some(Object::GuestImpersonationToken { subject, .. }) = p.objects.get(duplicate) else {
            unreachable!()
        };
        assert_eq!(subject.privileges[0].attributes, 1);
    }
}
