//! Initial kernel state captured before any owned native worker was resumed.
use super::*;
use crate::user::windows::process::thread;

fn rows(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-creation-flags/arm64-initial-v2.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-creation-flags/x64-initial-v2.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-thread-creation-flags/x86-initial-v2.txt"
        )),
    }
}

#[test]
fn native_thread_creation_flags_replay_suspended_teb_state_all_abis() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut caller) = fixture(arch, "NtCreateThreadEx", SERVICE);
        let p = process.state_mut();
        let memory =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        for line in rows(arch).lines().skip(1) {
            let words: Vec<_> = line.split_whitespace().skip(1).collect();
            let row: Vec<_> = words[..24]
                .iter()
                .map(|v| u64::from_str_radix(v, 16).unwrap())
                .collect();
            let flags = row[1];
            assert_eq!(row[2], 0, "independent native creation succeeded");
            assert_eq!(
                enter(
                    p,
                    &mut caller,
                    [
                        memory,
                        0x1fffff,
                        0,
                        arch.ptr(u64::MAX),
                        0x1234_5000,
                        0,
                        flags,
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                Outcome::Continue,
                "{arch}/{flags:#x}"
            );
            assert_eq!(caller.cpu.gpr(0), 0, "{arch}/{flags:#x}");
            let handle = p.space.ptr(memory, arch.ptr_size()).unwrap();
            let Some(Object::Thread { tid, .. }) = p.objects.get(handle) else {
                panic!("created guest worker")
            };
            let tid = *tid;
            let created = &p.threads[&tid];
            assert_eq!(created.suspend, 1);
            assert_eq!(p.objects.flags(handle), Some(row[15] as u32));
            let captured: Vec<_> = words[24]
                .as_bytes()
                .chunks_exact(2)
                .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
                .collect();
            let at = if arch == WinArch::X86 { 42 } else { 46 };
            let expected = u16::from_le_bytes(captured[at..at + 2].try_into().unwrap());
            let offset = if arch == WinArch::X86 { 0xfca } else { 0x17ee };
            assert_eq!(
                p.space.u16(created.teb + offset).unwrap() & 0x4008,
                expected & 0x4008,
                "{arch}/{flags:#x}"
            );
            let created = p.threads.remove(&tid).unwrap();
            thread::destroy(p, created, 0x37);
            p.objects.close(handle).unwrap();
            seen += 1;
        }
    }
    assert_eq!(seen, 24);
}
