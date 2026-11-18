use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::process::WindowsProcess;
use serde::Deserialize;

const NAME: &str = "NtOpenThreadTokenEx";
const SERVICE: u32 = 0x2f;

#[derive(Deserialize)]
struct Corpus {
    cases: HashMap<String, Vec<Case>>,
}

#[derive(Deserialize)]
struct Case {
    desired_access: u32,
    open_as_self: u32,
    attributes: u32,
    write_output: bool,
    status: u32,
    output: String,
}

fn fixture_ex() -> (WindowsProcess, Thread) {
    let (mut process, thread, module) = terminal_fixture(WinArch::Arm64);
    process.state_mut().modules.nt_services =
        Some((module, named_table(WinArch::Arm64, NAME, SERVICE)));
    (process, thread)
}

fn call_ex(p: &mut Proc, t: &mut Thread, arguments: [u64; 5]) -> Outcome {
    t.cpu.set_pc(0x1234_0004);
    for (register, value) in arguments.into_iter().enumerate() {
        t.cpu.set_gpr(register, value);
    }
    handle_stop(p, t, stop(WinArch::Arm64, SERVICE))
}

#[test]
fn native_thread_token_ex_reproduces_arm64_absent_token_corpus() {
    use super::super::native_profile::kernel_profile;

    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-thread-token-open/open-ex-29708-arm64.json"
    ));
    let corpus: Corpus = serde_json::from_str(source).unwrap();
    assert_eq!(corpus.cases.values().map(Vec::len).sum::<usize>(), 81);

    let (mut process, mut thread) = fixture_ex();
    let p = process.state_mut();
    kernel_profile(p, 29708, 0xaa64);
    let (output, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let wrong_object = p.objects.insert(Object::Event {
        manual: true,
        signaled: 0,
    });
    let grants = [
        ("grant_0x2", 2),
        ("grant_0x40", 0x40),
        ("grant_0x800", 0x800),
        ("grant_0x840", 0x840),
    ];
    let mut handles = HashMap::from([
        ("current", u64::MAX - 1),
        ("wrong_object", u64::from(wrong_object)),
        ("invalid", 0x1234),
    ]);
    for (role, grant) in grants {
        let handle = p.objects.open_access(thread.obj, false, grant).unwrap();
        handles.insert(role, handle.into());
    }
    assert_eq!(handles.len(), corpus.cases.len());
    let count = p.objects.handle_count();
    for (role, cases) in corpus.cases {
        for case in cases {
            p.space.wr(output, &[0xa5; 16]).unwrap();
            let pointer = if case.write_output { output } else { 0 };
            let args = [
                handles[role.as_str()],
                u64::from(case.desired_access),
                u64::from(case.open_as_self),
                u64::from(case.attributes),
                pointer,
            ];
            assert_eq!(call_ex(p, &mut thread, args), Outcome::Continue, "{role}");
            assert_eq!(thread.cpu.gpr(0), u64::from(case.status), "{role}");
            assert_eq!(
                p.space.bytes(output, 16).unwrap(),
                bytes(&case.output),
                "{role}"
            );
            assert_eq!(p.objects.handle_count(), count, "{role}");
            assert!(thread.frames.is_empty());
            assert_eq!(thread.cpu.pc(), 0x1234_0004);
        }
    }
}

#[test]
fn native_thread_token_ex_rejects_unmeasured_profiles_and_abis() {
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
        let (mut process, mut thread) = fixture_ex();
        let p = process.state_mut();
        if let Some((build, machine)) = profile {
            kernel_profile(p, build, machine);
        }
        assert!(
            matches!(call_ex(p, &mut thread, [u64::MAX - 1, 8, 0, 0, 0]),
            Outcome::Fail(reason) if reason.contains("NtOpenThreadTokenEx profile"))
        );
    }
}
