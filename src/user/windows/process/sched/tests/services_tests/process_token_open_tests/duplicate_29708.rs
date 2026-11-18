use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::loader::services::tests::named_table;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};

const NAME: &str = "NtDuplicateToken";
const NUMBER: u32 = 0x42;
const CAPTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-token-duplicate/duplicate-29708-arm64.json"
));

#[derive(Deserialize)]
struct Capture {
    cases: BTreeMap<String, Vec<Case>>,
    guards: Vec<GuardCase>,
}

#[derive(Debug, Deserialize)]
struct GuardCase {
    role: String,
    protection: u32,
    fitting: u64,
    attributes: u32,
    status: u32,
    observed_protection: u32,
    flags: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Case {
    role: String,
    desired: u32,
    kind: u32,
    flags: u32,
    effective: u32,
    level: u32,
    tracking: u8,
    inner_effective: u8,
    output: bool,
    attributes: bool,
    quality: bool,
    oa_length: u32,
    qos_length: u32,
    status: u32,
    changed: bool,
    grant: Option<u32>,
    handle_flags: Option<u32>,
    impersonation_level: Option<u32>,
}

#[test]
fn native_duplicate_token_replays_arm64_local_primary_to_impersonation() {
    use super::super::native_profile::kernel_profile;
    let groups = serde_json::from_str::<Capture>(CAPTURE).unwrap().cases;
    assert_eq!(groups.values().map(Vec::len).sum::<usize>(), 257);
    let (mut process, mut thread, module) = super::super::terminal_fixture(WinArch::Arm64);
    let p = process.state_mut();
    kernel_profile(p, 29708, 0xaa64);
    p.modules.nt_services = Some((module, named_table(WinArch::Arm64, NAME, NUMBER)));
    captured(p);
    let memory = scratch(p);
    let output = memory + 0x100;
    let qos = memory + 0x80;
    let event = p.objects.insert(Object::Event {
        manual: false,
        signaled: 0,
    });
    let handles = HashMap::from([
        (
            "caller-duplicate-query",
            p.objects.open_primary_token(10, false).unwrap().into(),
        ),
        (
            "caller-query",
            p.objects.open_primary_token(8, false).unwrap().into(),
        ),
        (
            "caller-duplicate",
            p.objects.open_primary_token(2, false).unwrap().into(),
        ),
        ("invalid", 0x1234),
        ("current-process", u64::MAX),
        ("current-thread", u64::MAX - 1),
        ("event", u64::from(event)),
    ]);
    let baseline = p.objects.handle_count();
    let source_id = p.objects.id(handles["caller-duplicate-query"]).unwrap();
    let mut created = HashSet::new();
    let mut supported = 0;
    for case in groups.into_values().flatten() {
        p.space.wr(memory, &[0; 0x110]).unwrap();
        p.space.w32(memory, case.oa_length).unwrap();
        p.space.w32(memory + 24, case.flags).unwrap();
        p.space
            .w64(memory + 40, if case.quality { qos } else { 0 })
            .unwrap();
        p.space.w32(qos, case.qos_length).unwrap();
        p.space.w32(qos + 4, case.level).unwrap();
        p.space.w8(qos + 8, case.tracking).unwrap();
        p.space.w8(qos + 9, case.inner_effective).unwrap();
        p.space.wr(output, &[0xa5; 16]).unwrap();
        let registers = [
            handles[case.role.as_str()],
            case.desired.into(),
            if case.attributes { memory } else { 0 },
            case.effective.into(),
            case.kind.into(),
            if case.output { output } else { 0 },
        ];
        let actual = duplicate(p, &mut thread, registers);
        let out_of_scope = case.flags == 0x10
            || case.status == 0
                && (case.kind != 2 || case.effective != 0 || case.inner_effective != 0);
        if out_of_scope {
            assert!(matches!(actual, Outcome::Fail(_)), "{case:?}");
            assert_eq!(p.space.bytes(output, 16).unwrap(), [0xa5; 16]);
        } else {
            supported += 1;
            assert_eq!(actual, Outcome::Continue, "{case:?}");
            assert_eq!(thread.cpu.gpr(0), u64::from(case.status), "{case:?}");
            if let Some(grant) = case.grant {
                assert!(case.changed);
                let token = p.space.u64(output).unwrap();
                let id = p.objects.id(token).unwrap();
                assert_ne!(id, source_id);
                assert!(created.insert(id));
                let Some(Object::GuestImpersonationToken { level, .. }) = p.objects.get(token)
                else {
                    panic!("{case:?}")
                };
                if let Some(expected) = case.impersonation_level {
                    assert_eq!(*level, expected);
                }
                assert_eq!(p.objects.access(token), Some(grant));
                assert_eq!(p.objects.flags(token), case.handle_flags);
                assert_eq!(p.objects.get(token).unwrap().type_name(), "Token");
                p.objects.close(token).unwrap();
                assert!(p.objects.obj(id).is_none());
            } else {
                assert_eq!(p.space.bytes(output, 16).unwrap(), [0xa5; 16]);
            }
            assert_eq!(p.space.bytes(output + 8, 8).unwrap(), [0xa5; 8]);
        }
        assert_eq!(p.objects.handle_count(), baseline);
    }
    assert_eq!(supported, 231);
}

fn duplicate(p: &mut Proc, thread: &mut Thread, registers: [u64; 6]) -> Outcome {
    thread.cpu.set_pc(0x1234_0004);
    for (reg, value) in registers.into_iter().enumerate() {
        thread.cpu.set_gpr(reg, value);
    }
    handle_stop(p, thread, stop(WinArch::Arm64, NUMBER))
}

#[test]
fn native_duplicate_token_replays_arm64_output_guard_order() {
    use super::super::native_profile::kernel_profile;
    let cases = serde_json::from_str::<Capture>(CAPTURE).unwrap().guards;
    assert_eq!(cases.len(), 100);
    let (mut process, mut thread, module) = super::super::terminal_fixture(WinArch::Arm64);
    let p = process.state_mut();
    kernel_profile(p, 29708, 0xaa64);
    p.modules.nt_services = Some((module, named_table(WinArch::Arm64, NAME, NUMBER)));
    captured(p);
    let memory = scratch(p);
    let after = memory + PAGE_SIZE;
    let qos = memory + 0x80;
    p.space.w32(memory, 48).unwrap();
    p.space.w64(memory + 40, qos).unwrap();
    p.space.w32(qos, 12).unwrap();
    p.space.w32(qos + 4, 2).unwrap();
    p.space.w8(qos + 8, 1).unwrap();
    let valid = p.objects.open_primary_token(10, false).unwrap();
    let denied = p.objects.open_primary_token(8, false).unwrap();
    let baseline = p.objects.handle_count();
    for case in cases {
        let source = match case.role.as_str() {
            "valid" => valid,
            "query-only" => denied,
            _ => panic!("{case:?}"),
        };
        let output = after - case.fitting;
        let sentinel = 0xa5a5_a5a5_a5a5_a5a5;
        p.space.w64(output, sentinel).unwrap();
        p.space.w32(memory + 24, case.attributes).unwrap();
        p.vm.protect(after, PAGE_SIZE, case.protection).unwrap();
        assert_eq!(
            duplicate(p, &mut thread, [source.into(), 12, memory, 0, 2, output]),
            Outcome::Continue,
            "{case:?}"
        );
        assert_eq!(thread.cpu.gpr(0), u64::from(case.status), "{case:?}");
        assert_eq!(
            p.vm.query(after).unwrap().protect,
            case.observed_protection,
            "{case:?}"
        );
        p.vm.protect(after, PAGE_SIZE, prot::READWRITE).unwrap();
        let result = p.space.u64(output).unwrap();
        if let Some(flags) = case.flags {
            assert_eq!(p.objects.access(result), Some(12));
            assert_eq!(p.objects.flags(result), Some(flags));
            p.objects.close(result).unwrap();
        } else {
            assert_eq!(result, sentinel);
        }
        assert_eq!(p.objects.handle_count(), baseline);
    }
}

#[test]
fn native_duplicate_token_rejects_unmeasured_profiles_and_abis() {
    use super::super::native_profile::kernel_profile;
    use crate::user::windows::dll::nt_service;
    assert_eq!(
        crate::user::windows::nt::status_to_error(STATUS_BAD_IMPERSONATION_LEVEL),
        1346
    );
    assert!(nt_service(NAME, WinArch::X86).is_none());
    assert!(nt_service(NAME, WinArch::X64).is_none());
    for profile in [
        None,
        Some((29707, 0xaa64)),
        Some((29709, 0xaa64)),
        Some((29708, 0x8664)),
    ] {
        let (mut process, mut thread, module) = super::super::terminal_fixture(WinArch::Arm64);
        let p = process.state_mut();
        if let Some((build, machine)) = profile {
            kernel_profile(p, build, machine);
        }
        p.modules.nt_services = Some((module, named_table(WinArch::Arm64, NAME, NUMBER)));
        assert!(matches!(duplicate(p, &mut thread, [0; 6]),
            Outcome::Fail(reason) if reason.contains("NtDuplicateToken profile")));
    }
}
