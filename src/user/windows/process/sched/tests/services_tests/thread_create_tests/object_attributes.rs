//! Replay independent native unnamed-thread object-attribute observations.
use super::*;
use crate::user::windows::nt::status::STATUS_SUCCESS;
use crate::user::windows::process::thread;

fn rows(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-object-attributes/arm64-native-v1.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-object-attributes/x64-native-v1.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-object-attributes/x86-native-v1.txt"
        )),
    }
}

#[test]
fn native_thread_object_flags_replay_status_handle_visibility_and_inheritance_all_abis() {
    let mut count = 0;
    for arch in WinArch::ALL {
        let (mut process, mut caller) = fixture(arch, "NtCreateThreadEx", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let width = arch.ptr_size();
        for line in rows(arch).lines().skip(1) {
            let row: Vec<_> = line
                .split_whitespace()
                .skip(1)
                .map(|word| u64::from_str_radix(word, 16).unwrap())
                .collect();
            let flags = row[1] as u32;
            p.space.wr(base, &[0; 512]).unwrap();
            p.space.wptr(base, width, 0x5a5a_5a5a).unwrap();
            let attributes = base + 256;
            p.space.w32(attributes, 6 * width as u32).unwrap();
            p.space.w32(attributes + 3 * width, flags).unwrap();
            let threads = p.threads.len();
            let objects = p.objects.iter().count();
            let allocations = p.vm.allocations().count();
            assert_eq!(
                enter(
                    p,
                    &mut caller,
                    [
                        base,
                        0x1f_ffff,
                        attributes,
                        arch.ptr(u64::MAX),
                        0x1234_5000,
                        0,
                        1,
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                Outcome::Continue,
                "{arch}/{flags:#x}"
            );
            assert_eq!(caller.cpu.gpr(0) as u32, row[2] as u32, "{arch}/{flags:#x}");
            let handle = p.space.ptr(base, width).unwrap();
            if row[2] as u32 == STATUS_SUCCESS {
                assert!(p.objects.get(handle).is_some());
                assert_eq!(p.objects.access(handle), Some(0x1f_ffff));
                assert_eq!(p.objects.flags(handle), Some(row[5] as u32));
                assert_eq!(p.threads.len(), threads + 1);
                let Some(Object::Thread {
                    tid,
                    exit_code: None,
                }) = p.objects.get(handle)
                else {
                    panic!("published live guest thread");
                };
                let tid = *tid;
                assert_eq!(p.threads[&tid].suspend, 1);
                let created = p.threads.remove(&tid).unwrap();
                thread::destroy(p, created, 0);
                assert!(p.objects.close(handle).unwrap().is_some());
            } else {
                assert_eq!(handle, row[3], "{arch}/{flags:#x}/output");
            }
            assert_eq!(p.threads.len(), threads);
            assert_eq!(p.objects.iter().count(), objects);
            assert_eq!(p.vm.allocations().count(), allocations);
            count += 1;
        }
    }
    assert_eq!(count, 873);
}
