use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::process::WindowsProcess;
use serde::Deserialize;
use std::collections::HashMap;

const NAME: &str = "NtOpenProcessTokenEx";
const NUMBER: u32 = 0x30;
const SENTINEL: [u8; 16] = [0xa5; 16];
const CAPTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-process-token-open/open-ex-29708-arm64.json"
));

#[derive(Deserialize)]
struct Corpus {
    cases: HashMap<String, Vec<Case>>,
    guards: Vec<GuardCase>,
}

#[derive(Debug, Deserialize)]
struct Case {
    desired: u32,
    attributes: u32,
    output: bool,
    status: u32,
    changed: bool,
    grant: Option<u32>,
    flags: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct GuardCase {
    protection: u32,
    fitting: u64,
    attributes: u32,
    status: u32,
    observed_protection: u32,
    flags: Option<u32>,
}

fn service_fixture() -> (WindowsProcess, Thread) {
    let (mut process, thread, module) = super::super::terminal_fixture(WinArch::Arm64);
    let p = process.state_mut();
    p.modules.nt_services = Some((module, named_table(WinArch::Arm64, NAME, NUMBER)));
    (process, thread)
}

fn call_ex(p: &mut Proc, t: &mut Thread, arguments: [u64; 4]) -> Outcome {
    t.cpu.set_pc(0x1234_0004);
    for (register, value) in arguments.into_iter().enumerate() {
        t.cpu.set_gpr(register, value);
    }
    handle_stop(p, t, stop(WinArch::Arm64, NUMBER))
}

#[test]
fn native_process_token_ex_replays_arm64_open_attributes_and_grants() {
    use super::super::native_profile::kernel_profile;

    let corpus: Corpus = serde_json::from_str(CAPTURE).unwrap();
    assert_eq!(corpus.cases.values().map(Vec::len).sum::<usize>(), 256);
    let (mut process, mut thread) = service_fixture();
    let p = process.state_mut();
    kernel_profile(p, 29708, 0xaa64);
    captured(p);
    let output = scratch(p);
    let process_object = p.objects.create(Object::Process {
        pid: p.pid,
        exit_code: None,
    });
    let event = p.objects.insert(Object::Event {
        manual: true,
        signaled: 0,
    });
    let mut handles = HashMap::from([
        ("current", u64::MAX),
        ("current_access", u64::MAX),
        ("current_attribute_bits", u64::MAX),
        ("current_thread", u64::MAX - 1),
        ("invalid", 0x1234),
        ("event", u64::from(event)),
    ]);
    for (role, grant) in [
        ("query_information", 0x400),
        ("limited_information", 0x1000),
        ("denied_query", 0x100000),
    ] {
        handles.insert(
            role,
            p.objects
                .open_access(process_object, false, grant)
                .unwrap()
                .into(),
        );
    }
    assert_eq!(handles.len(), corpus.cases.len());
    let original_count = p.objects.handle_count();
    let mut token_identity = None;
    for (role, cases) in corpus.cases {
        for case in cases {
            p.space.wr(output, &SENTINEL).unwrap();
            let destination = if case.output { output } else { 0 };
            let args = [
                handles[role.as_str()],
                u64::from(case.desired),
                u64::from(case.attributes),
                destination,
            ];
            assert_eq!(
                call_ex(p, &mut thread, args),
                Outcome::Continue,
                "{role} {case:?}"
            );
            assert_eq!(thread.cpu.gpr(0), u64::from(case.status), "{role} {case:?}");
            assert_eq!(p.space.bytes(output + 8, 8).unwrap(), SENTINEL[8..]);
            if let Some(grant) = case.grant {
                assert!(case.changed);
                assert_eq!(p.objects.handle_count(), original_count + 1);
                let token = p.space.u64(output).unwrap();
                assert!(matches!(p.objects.get(token), Some(Object::PrimaryToken)));
                assert_eq!(p.objects.access(token), Some(grant));
                assert_eq!(p.objects.flags(token), case.flags);
                let id = p.objects.id(token).unwrap();
                assert_eq!(*token_identity.get_or_insert(id), id);
                p.objects.close(token).unwrap();
            } else {
                assert!(!case.changed);
                assert_eq!(p.space.bytes(output, 16).unwrap(), SENTINEL);
            }
            assert_eq!(p.objects.handle_count(), original_count);
            assert!(thread.frames.is_empty());
            assert_eq!(thread.cpu.pc(), 0x1234_0004);
        }
    }
}

#[test]
fn native_process_token_ex_replays_arm64_output_guard_order() {
    use super::super::native_profile::kernel_profile;

    let corpus: Corpus = serde_json::from_str(CAPTURE).unwrap();
    assert_eq!(corpus.guards.len(), 100);
    let (mut process, mut thread) = service_fixture();
    let p = process.state_mut();
    kernel_profile(p, 29708, 0xaa64);
    captured(p);
    let base = scratch(p);
    let next = base + PAGE_SIZE;
    let handles = p.objects.handle_count();
    for case in corpus.guards {
        let output = next - case.fitting;
        p.space.w64(output, 0xa5a5_a5a5_a5a5_a5a5).unwrap();
        p.vm.protect(next, PAGE_SIZE, case.protection).unwrap();
        let arguments = [u64::MAX, 8, u64::from(case.attributes), output];
        assert_eq!(
            call_ex(p, &mut thread, arguments),
            Outcome::Continue,
            "{case:?}"
        );
        assert_eq!(thread.cpu.gpr(0), u64::from(case.status), "{case:?}");
        assert_eq!(
            p.vm.query(next).unwrap().protect,
            case.observed_protection,
            "{case:?}"
        );
        p.vm.protect(next, PAGE_SIZE, prot::READWRITE).unwrap();
        let result = p.space.u64(output).unwrap();
        if let Some(flags) = case.flags {
            assert_eq!(p.objects.handle_count(), handles + 1);
            assert_eq!(p.objects.flags(result), Some(flags));
            assert_eq!(p.objects.access(result), Some(8));
            p.objects.close(result).unwrap();
        } else {
            assert_eq!(result, 0xa5a5_a5a5_a5a5_a5a5);
        }
        assert_eq!(p.objects.handle_count(), handles);
    }
}

#[test]
fn native_process_token_ex_rejects_unmeasured_profiles_and_abis() {
    use super::super::native_profile::kernel_profile;
    use crate::user::windows::dll::nt_service;

    assert!(nt_service(NAME, WinArch::X86).is_none());
    assert!(nt_service(NAME, WinArch::X64).is_none());
    for profile in [
        None,
        Some((29707, 0xaa64)),
        Some((29709, 0xaa64)),
        Some((29708, 0x8664)),
    ] {
        let (mut process, mut thread) = service_fixture();
        let p = process.state_mut();
        if let Some((build, machine)) = profile {
            kernel_profile(p, build, machine);
        }
        assert!(matches!(call_ex(p, &mut thread, [u64::MAX, 8, 0, 0]),
            Outcome::Fail(reason) if reason.contains("NtOpenProcessTokenEx profile")));
    }
}
