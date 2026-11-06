//! Native NT entry into the shared guest thread lifecycle.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop, table};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::process::thread;

const SERVICE: u32 = 0x1e0;

fn call(p: &mut Proc, t: &mut Thread, name: &str, handle: u64, output: u64) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, SERVICE)));
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::Arm64 => {
            t.cpu.set_gpr(0, handle);
            t.cpu.set_gpr(1, output);
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            t.cpu.set_gpr(10, handle);
            t.cpu.set_gpr(2, output);
        }
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            p.space.w32(sp + 8, handle as u32).unwrap();
            p.space.w32(sp + 12, output as u32).unwrap();
            t.cpu.set_gpr(0, SERVICE.into());
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(result, Outcome::Continue, "{}/{name}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_thread_resume_and_suspend_publish_previous_guest_counts_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut current) = fixture(arch, "NtResumeThread", SERVICE);
        let p = process.state_mut();
        let output =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        let object = p.threads[&tid].obj;
        let handle = u64::from(p.objects.open_access(object, false, 2).unwrap());
        p.threads.get_mut(&tid).unwrap().suspend = 2;
        for previous in [2, 1, 0] {
            p.space.w32(output, 0xa5a5_a5a5).unwrap();
            assert_eq!(call(p, &mut current, "NtResumeThread", handle, output), 0);
            assert_eq!(p.space.u32(output).unwrap(), previous);
            assert_eq!(p.threads[&tid].suspend, previous.saturating_sub(1));
        }
        for previous in [0, 1] {
            p.space.w32(output, 0xa5a5_a5a5).unwrap();
            assert_eq!(call(p, &mut current, "NtSuspendThread", handle, output), 0);
            assert_eq!(p.space.u32(output).unwrap(), previous);
            assert_eq!(p.threads[&tid].suspend, previous + 1);
        }
        assert_eq!(call(p, &mut current, "NtResumeThread", handle, 0), 0);
        assert_eq!(p.threads[&tid].suspend, 1);
        let own = arch.ptr(u64::MAX - 1);
        assert_eq!(call(p, &mut current, "NtResumeThread", own, output), 0);
        assert_eq!(p.space.u32(output).unwrap(), 0);
        assert_eq!(current.suspend, 0);
    }
}

#[test]
fn native_thread_lifecycle_exports_preserve_prior_ntdll_ordinals_and_traps() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|export| export.name == "NtSuspendThread"))
        .unwrap();
    assert_eq!(
        current.exports[family]
            .iter()
            .map(|export| export.name)
            .collect::<Vec<_>>(),
        ["NtSuspendThread", "NtResumeThread"]
    );
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let checkpoint = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..=family],
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(&checkpoint, arch, 0, &[]);
        let latest = builtin::build(current, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(after.symbols.len(), before.symbols.len() + 2);
        assert_eq!(&after.symbols[..before.symbols.len()], before.symbols);
        assert_eq!(
            &latest.symbols[..after.symbols.len()],
            after.symbols.as_slice()
        );
        for name in ["NtSuspendThread", "NtResumeThread"] {
            assert!(dll::nt_service(name, arch).is_some());
        }
    }
}

#[test]
fn native_thread_control_replays_all_322_independent_windows_observations() {
    use crate::user::windows::objects::Object;
    use std::collections::BTreeMap;
    let capture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-nt-thread-lifecycle/observations-arm64-v1.json"
    ))
    .unwrap();
    let mut replayed = 0;
    for arch in WinArch::ALL {
        for run in capture["runs"].as_array().unwrap() {
            let (mut process, mut current) = fixture(arch, "NtResumeThread", SERVICE);
            let p = process.state_mut();
            let output =
                p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            // Creation is a separate API surface: seed the observed initial
            // state through the existing guest factory for this control replay.
            let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
            let object = p.threads[&tid].obj;
            p.threads.get_mut(&tid).unwrap().suspend = run["create_flags"].as_u64().unwrap() as u32;
            let handle = u64::from(p.objects.open_access(object, false, 0x1fffff).unwrap());
            let event = p.objects.create(Object::Event {
                manual: true,
                signaled: 0,
            });
            let event = u64::from(p.objects.open_access(event, false, 0x1fffff).unwrap());
            let mut aliases = BTreeMap::new();
            for row in run["observations"].as_array().unwrap() {
                let label = row["label"].as_str().unwrap();
                if label == "create" {
                    assert_eq!(row["status"], 0);
                    assert_eq!(row["thread_created"], true);
                    continue;
                }
                if label == "alias-grant" {
                    assert_eq!(row["query_status"], 0);
                    let requested = row["requested_access"].as_u64().unwrap() as u32;
                    let grant = row["granted_access"].as_u64().unwrap() as u32;
                    aliases.insert(
                        requested,
                        u64::from(p.objects.open_access(object, false, grant).unwrap()),
                    );
                    continue;
                }
                if label == "thread-terminal" {
                    assert_eq!(row["wait"], 0);
                    assert_eq!(row["exit_code"], 53);
                    let target = p.threads.remove(&tid).unwrap();
                    thread::destroy(p, target, 53);
                    continue;
                }
                let suspend = row["suspend"]
                    .as_bool()
                    .expect("every operation classified");
                let target = if label.starts_with("null-handle") {
                    0
                } else if label == "event-handle-resume" {
                    event
                } else if label == "current-thread-resume" {
                    arch.ptr(u64::MAX - 1)
                } else if label.starts_with("alias-resume-") || label.starts_with("alias-suspend-")
                {
                    let access: u32 = label.rsplit_once('-').unwrap().1.parse().unwrap();
                    aliases[&access]
                } else {
                    handle
                };
                let destination = if label == "resume-without-output" {
                    0
                } else if matches!(
                    label,
                    "null-handle-bad-output" | "thread-bad-output-suspend"
                ) {
                    1
                } else {
                    output
                };
                p.space.w32(output, 0xa5a5_a5a5).unwrap();
                let status = call(
                    p,
                    &mut current,
                    if suspend {
                        "NtSuspendThread"
                    } else {
                        "NtResumeThread"
                    },
                    target,
                    destination,
                );
                assert_eq!(
                    u64::from(status),
                    row["status"].as_u64().unwrap(),
                    "{arch}/{label}"
                );
                if let Some(previous) = row["previous"].as_u64() {
                    assert_eq!(
                        u64::from(p.space.u32(output).unwrap()),
                        previous,
                        "{arch}/{label}"
                    );
                }
                replayed += 1;
            }
        }
    }
    assert_eq!(
        replayed, 930,
        "155 control calls per run, two runs, three guest ABIs"
    );
}

#[test]
fn native_thread_control_replays_accessible_unaligned_output_stores() {
    let capture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-nt-thread-lifecycle/thread-alignment-observations-v1.json"
    ))
    .unwrap();
    for arch in WinArch::ALL {
        let run = capture["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| (run["pointer_bytes"] == 4) == (arch == WinArch::X86))
            .unwrap();
        let (mut process, mut current) = fixture(arch, "NtResumeThread", SERVICE);
        let p = process.state_mut();
        let output =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        let handle = u64::from(
            p.objects
                .open_access(p.threads[&tid].obj, false, 2)
                .unwrap(),
        );
        for row in run["observations"].as_array().unwrap() {
            let offset = row["offset"].as_u64().unwrap() as usize;
            for (name, status_key, previous_key, remaining) in [
                ("NtSuspendThread", "suspend_status", "suspend_previous", 1),
                ("NtResumeThread", "resume_status", "resume_previous", 0),
            ] {
                p.space.wr(output, &[0xa5; 16]).unwrap();
                assert_eq!(
                    u64::from(call(p, &mut current, name, handle, output + offset as u64)),
                    row[status_key].as_u64().unwrap()
                );
                let mut expected = [0xa5; 16];
                expected[offset..offset + 4]
                    .copy_from_slice(&(row[previous_key].as_u64().unwrap() as u32).to_le_bytes());
                assert_eq!(p.space.bytes(output, 16).unwrap(), expected);
                assert_eq!(p.threads[&tid].suspend, remaining);
            }
        }
    }
}
