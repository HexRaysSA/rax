use super::native_replay::select_native;
use super::*;
use crate::user::windows::objects::Object;
use crate::user::windows::process::thread::ThreadState;
use crate::user::windows::sync::Wait;

#[test]
fn native_thread_context_replays_stopped_state_and_current_thread_information_flags() {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-thread-context/context-information-states-v1.json"
    )))
    .unwrap();
    let mut count = 0;
    for profile in data["profiles"].as_array().unwrap() {
        for run in profile["runs"].as_array().unwrap() {
            let arch = match run["architecture"].as_str().unwrap() {
                "x86" => WinArch::X86,
                "x64" => WinArch::X64,
                "arm64" => WinArch::Arm64,
                _ => unreachable!(),
            };
            let (mut process, mut current, scratch) = setup(arch);
            let p = process.state_mut();
            let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
            select_native(p, tid);
            let object = p.threads[&tid].obj;
            let handle = u64::from(p.objects.open_access(object, false, 24).unwrap());
            match profile["state"].as_str().unwrap() {
                "startup" => p.threads.get_mut(&tid).unwrap().attached = false,
                "system-call wait" => {
                    let event = p.objects.create(Object::Event {
                        manual: true,
                        signaled: 0,
                    });
                    p.threads.get_mut(&tid).unwrap().state =
                        ThreadState::Waiting(Wait::NativeObjects {
                            objs: vec![event],
                            all: false,
                            deadline: None,
                            alertable: false,
                        });
                }
                "ordinary user code" | "current-thread" => {}
                _ => unreachable!(),
            }
            let target = if profile["state"] == "current-thread" {
                arch.ptr(u64::MAX - 1)
            } else {
                handle
            };
            for row in run["derived_rows"].as_array().unwrap() {
                p.space.wr(scratch, &vec![0xa5; 2048]).unwrap();
                let offset = if arch == WinArch::X64 { 48 } else { 0 };
                p.space
                    .w32(scratch + offset, row["requested"].as_u64().unwrap() as u32)
                    .unwrap();
                let error =
                    current.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
                p.space.w32(error, 0x7654_3210).unwrap();
                assert_eq!(
                    status(p, &mut current, "NtGetContextThread", &[target, scratch]),
                    row["status"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    p.space.u32(scratch + offset).unwrap(),
                    row["returned"].as_u64().unwrap() as u32,
                    "{arch}/{}/flags{}",
                    profile["state"],
                    row["requested"]
                );
                assert_eq!(p.space.u32(error).unwrap(), 0x7654_3210);
                count += 1;
            }
            p.objects.close(handle).unwrap();
        }
    }
    assert_eq!(count, 345, "all lifecycle profiles must contribute cases");
}
