use super::*;
use crate::user::windows::loader::services::tests::table;
use serde::Deserialize;
use std::collections::HashMap;

const CAPTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-token-duplicate/query-kind-29708-arm64.json"
));
const SERVICE: u32 = 0x21;

#[derive(Deserialize)]
struct Capture {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    role: String,
    kind: u32,
    length: u32,
    #[serde(rename = "where")]
    output_address: String,
    return_length: String,
    status: u32,
    output: String,
    returned: String,
}

fn address(form: &str, base: u64) -> u64 {
    match form {
        "null" => 0,
        "aligned" => base,
        "misaligned" => base + 1,
        _ => panic!("unknown caller pointer role {form}"),
    }
}

#[test]
fn native_token_kind_replays_primary_and_guest_impersonation_query_order() {
    use super::super::native_profile::kernel_profile;
    let capture: Capture = serde_json::from_str(CAPTURE).unwrap();
    assert_eq!(capture.cases.len(), 528);
    let (mut process, mut thread, module) = super::super::terminal_fixture(WinArch::Arm64);
    let p = process.state_mut();
    kernel_profile(p, 29708, 0xaa64);
    p.modules.nt_services = Some((
        module,
        table(WinArch::Arm64, "NtQueryInformationToken", SERVICE),
    ));
    captured(p);
    let base = scratch(p);
    let output = base + 16;
    let returned = base + 64;
    let subject = p.objects.primary_token_subject().unwrap();
    let token = p
        .objects
        .try_create(Object::GuestImpersonationToken { subject, level: 2 })
        .unwrap();
    let event = p.objects.insert(Object::Event {
        manual: false,
        signaled: 0,
    });
    let roles = HashMap::from([
        (
            "primary",
            p.objects.open_primary_token(10, false).unwrap().into(),
        ),
        (
            "primary-no-query",
            p.objects.open_primary_token(2, false).unwrap().into(),
        ),
        (
            "duplicate",
            p.objects.open_access(token, false, 12).unwrap().into(),
        ),
        ("primary-pseudo", u64::MAX - 3),
        ("thread-token-pseudo", u64::MAX - 4),
        ("effective-pseudo", u64::MAX - 5),
        ("process-pseudo", u64::MAX),
        ("thread-pseudo", u64::MAX - 1),
        ("event", event.into()),
        ("invalid", 0x1234),
        ("null", 0),
    ]);
    for case in capture.cases {
        p.space.wr(output, &[0xa5; 24]).unwrap();
        p.space.wr(returned, &[0x5a; 12]).unwrap();
        let args = [
            roles[case.role.as_str()],
            case.kind.into(),
            address(&case.output_address, output),
            case.length.into(),
            address(&case.return_length, returned),
        ];
        thread.cpu.set_pc(0x1234_0004);
        for (reg, value) in args.into_iter().enumerate() {
            thread.cpu.set_gpr(reg, value);
        }
        assert_eq!(
            handle_stop(p, &mut thread, stop(WinArch::Arm64, SERVICE)),
            Outcome::Continue,
            "{case:?}"
        );
        assert_eq!(thread.cpu.gpr(0), u64::from(case.status), "{case:?}");
        assert_eq!(
            p.space.bytes(output, 24).unwrap(),
            crate::user::windows::wnf::tests::hex(&case.output),
            "{case:?}"
        );
        assert_eq!(
            p.space.bytes(returned, 12).unwrap(),
            crate::user::windows::wnf::tests::hex(&case.returned),
            "{case:?}"
        );
    }
}
