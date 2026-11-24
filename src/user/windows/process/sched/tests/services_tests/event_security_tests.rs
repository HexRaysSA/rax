use super::{Outcome, attrs, call, handle, setup, status};
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::security::Subject;
use crate::user::windows::security::token::pointer_records::Class;
use crate::user::windows::wnf::Catalog;

const OWNER: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const GROUP: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const CREATOR_ACE: [u8; 20] = [
    0, 0, 20, 0, 0, 0, 0, 0x10, 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
];
const USERS_ACE: [u8; 20] = [0, 0, 20, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];

fn subject() -> Subject {
    let mut subject = Subject {
        statistics: None,
        user_attributes: 0,
        token_pointer_records: Default::default(),
        empty_claims: Default::default(),
        user: OWNER.to_vec(),
        groups: vec![],
        restricted: vec![],
        app_container: false,
        privileges: vec![],
        attributes: None,
    };
    subject
        .token_pointer_records
        .insert(Class::Owner, Box::new(OWNER));
    subject
        .token_pointer_records
        .insert(Class::PrimaryGroup, Box::new(GROUP));
    subject
}

fn input(creator: bool) -> Vec<u8> {
    let mut input = vec![
        1,
        0,
        4,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        20,
        0,
        0,
        0,
        2,
        0,
        48,
        0,
        if creator { 2 } else { 1 },
        0,
        0,
        0,
    ];
    if creator {
        input.extend_from_slice(&CREATOR_ACE);
    }
    input.extend_from_slice(&USERS_ACE);
    input.resize(68, 0xcc);
    input
}

#[test]
fn unnamed_event_retains_security_across_aliases_and_projects_measured_fields() {
    for arch in WinArch::ALL {
        for creator in [true, false] {
            let (mut process, mut thread, output) = setup(arch);
            let p = process.state_mut();
            p.objects
                .select_wnf_catalog(Catalog::selected(vec![], subject()).unwrap());
            let attributes = output + 64;
            let descriptor = output + 128;
            let returned = output + 256;
            let size = if arch.is64() { 48 } else { 24 };
            let width = arch.ptr_size();
            attrs(p, attributes, size, 0, 0);
            p.space
                .wptr(attributes + 4 * width, width, descriptor)
                .unwrap();
            let mut input = input(creator);
            p.space.wr(descriptor, &input).unwrap();
            let before = p.objects.handle_count();
            assert_eq!(
                status(
                    p,
                    &mut thread,
                    "NtCreateEvent",
                    &[output, 0x0200_0000, attributes, 0, 0]
                ),
                STATUS_SUCCESS
            );
            let original = handle(p, output);
            assert_eq!(p.objects.access(original), Some(0x001f_0003));
            let id = p.objects.id(original).unwrap();
            let reader = u64::from(p.objects.open_access(id, false, 0x0002_0000).unwrap());
            let modifier = u64::from(p.objects.open_access(id, false, 2).unwrap());
            p.objects.close(original).unwrap();
            p.space.wr(descriptor, &[0xA5; 68]).unwrap();

            assert_eq!(
                status(
                    p,
                    &mut thread,
                    "NtQuerySecurityObject",
                    &[modifier, 7, 0, 0, returned]
                ),
                STATUS_ACCESS_DENIED
            );
            assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
            assert_eq!(
                status(
                    p,
                    &mut thread,
                    "NtQuerySecurityObject",
                    &[reader, 8, 0, 0, returned]
                ),
                STATUS_ACCESS_DENIED
            );
            if creator {
                input[32..36].copy_from_slice(&0x001f_0003u32.to_le_bytes());
            } else {
                input.truncate(48);
                input[22] = 28;
            }
            for (mask, owner, group, dacl) in [
                (0, 0, 0, 0),
                (1, 20, 0, 0),
                (2, 0, 20, 0),
                (3, 20, 36, 0),
                (4, 0, 0, 20),
                (5, 20, 0, 36),
                (6, 0, 20, 32),
                (7, 20, 36, 48),
                (16, 0, 0, 0),
                (23, 20, 36, 48),
            ] {
                let mut expected = vec![0; 20];
                expected[0] = 1;
                expected[2] = if dacl == 0 { 0 } else { 4 };
                expected[3] = 0x80;
                expected[4] = owner;
                expected[8] = group;
                expected[16] = dacl;
                if owner != 0 {
                    expected.extend_from_slice(&OWNER);
                }
                if group != 0 {
                    expected.extend_from_slice(&GROUP);
                }
                if dacl != 0 {
                    expected.extend_from_slice(&input[20..]);
                }
                let required = expected.len() as u64;
                p.space.wr(output, &[0xA5; 100]).unwrap();
                assert_eq!(
                    status(
                        p,
                        &mut thread,
                        "NtQuerySecurityObject",
                        &[reader, mask, output, required - 1, returned]
                    ),
                    STATUS_BUFFER_TOO_SMALL
                );
                assert_eq!(p.space.u32(returned).unwrap(), required as u32);
                assert_eq!(p.space.u32(output).unwrap(), 0xA5A5_A5A5);
                assert_eq!(
                    status(
                        p,
                        &mut thread,
                        "NtQuerySecurityObject",
                        &[reader, mask, output, 100, returned]
                    ),
                    STATUS_SUCCESS
                );
                assert_eq!(p.space.u32(returned).unwrap(), required as u32);
                assert_eq!(p.space.bytes(output, required as usize).unwrap(), expected);
                assert_eq!(p.space.u8(output + required).unwrap(), 0xA5);
            }
            p.objects.close(reader).unwrap();
            p.objects.close(modifier).unwrap();
            assert_eq!(p.objects.handle_count(), before);
            assert!(p.objects.obj(id).is_none());
        }
    }
}

#[test]
fn unnamed_event_rejects_unselected_acl_without_publishing() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, output) = setup(arch);
        let p = process.state_mut();
        p.objects
            .select_wnf_catalog(Catalog::selected(vec![], subject()).unwrap());
        let attributes = output + 64;
        let descriptor = output + 128;
        let width = arch.ptr_size();
        attrs(p, attributes, if arch.is64() { 48 } else { 24 }, 0, 0);
        p.space
            .wptr(attributes + 4 * width, width, descriptor)
            .unwrap();
        let mut input = input(true);
        input[28] = 1; // Deny ACE.
        p.space.wr(descriptor, &input).unwrap();
        let before = p.objects.handle_count();
        let kept = p.space.bytes(output, width as usize).unwrap();
        let result = call(
            p,
            &mut thread,
            "NtCreateEvent",
            &[output, 0x001f_0003, attributes, 0, 0],
        );
        assert!(format!("{result:?}").contains("NT event security descriptor"));
        assert!(matches!(result, Outcome::Fail(_)));
        assert_eq!(p.objects.handle_count(), before);
        assert_eq!(p.space.bytes(output, width as usize).unwrap(), kept);
    }
}
