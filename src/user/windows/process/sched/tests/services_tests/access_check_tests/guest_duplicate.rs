use super::*;
use serde::Deserialize;
use std::collections::BTreeMap;

const CAPTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-access-check/guest-duplicate-29708-arm64.json"
));
const USER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 0xa8, 0x52, 0, 0];
const WORLD: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

#[derive(Deserialize)]
struct Capture {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    level: u32,
    tracking: u8,
    grant: u32,
    dacl: String,
    desired: u32,
    capacity: u32,
    status: u32,
    returned: u32,
    granted: u32,
    decision: u32,
    privileges: String,
}

// A relative descriptor with an ordinary synthetic caller SID and one
// allow/deny ACE. The native probe used its own SID for the same roles.
fn descriptor(role: &str) -> Vec<u8> {
    let mut bytes = vec![1, 0, 4, 0x80];
    for offset in [20u32, 32, 0, if role == "null" { 0 } else { 44 }] {
        bytes.extend(offset.to_le_bytes());
    }
    bytes.extend(USER);
    bytes.extend(USER);
    if role != "null" {
        if role == "empty" {
            bytes.extend([2, 0, 8, 0, 0, 0, 0, 0]);
        } else {
            let (ace, sid) = match role {
                "self" => (0, USER),
                "everyone" => (0, WORLD),
                "deny" => (1, WORLD),
                _ => panic!("unknown DACL role {role}"),
            };
            bytes.extend([2, 0, 28, 0, 1, 0, 0, 0, ace, 0, 20, 0, 1, 0, 0, 0]);
            bytes.extend(sid);
        }
    }
    bytes
}

#[test]
fn guest_duplicate_replays_native_access_check_grants_and_impersonation_levels() {
    let capture: Capture = serde_json::from_str(CAPTURE).unwrap();
    assert_eq!(capture.cases.len(), 480);
    let (mut process, mut thread, base, _) = setup(WinArch::Arm64, false, false);
    let p = process.state_mut();
    let subject = Arc::new(Subject {
        statistics: None,
        user_attributes: 0,
        token_defaults: Default::default(),
        empty_claims: Default::default(),
        user: USER.to_vec(),
        groups: vec![Group {
            sid: WORLD.to_vec(),
            attributes: 4,
        }],
        restricted: Vec::new(),
        app_container: false,
        privileges: Vec::new(),
        attributes: None,
    });
    let mut handles = BTreeMap::new();
    for level in 0..4 {
        let object = p.objects.create(Object::GuestImpersonationToken {
            subject: subject.clone(),
            level,
        });
        for grant in [4, 12] {
            handles.insert(
                (level, grant),
                p.objects.open_access(object, false, grant).unwrap(),
            );
        }
    }
    for case in capture.cases {
        assert!(case.tracking <= 1);
        let f = logical_input(p, base, "empty-dacl", case.capacity);
        p.space.wr(f[0], &descriptor(&case.dacl)).unwrap();
        p.space.w32(f[4], 0x5a5a_5a5a).unwrap();
        p.space.w32(f[5], 0x5a5a_5a5a).unwrap();
        let token = u64::from(handles[&(case.level, case.grant)]);
        assert_eq!(
            invoke(p, &mut thread, &arguments(token, case.desired, f)),
            case.status,
            "{case:?}"
        );
        assert_eq!(p.space.u32(f[3]).unwrap(), case.returned, "{case:?}");
        assert_eq!(p.space.u32(f[4]).unwrap(), case.granted, "{case:?}");
        assert_eq!(p.space.u32(f[5]).unwrap(), case.decision, "{case:?}");
        assert_eq!(
            p.space.bytes(f[2], 20).unwrap(),
            hex(&case.privileges),
            "{case:?}"
        );
    }
}
