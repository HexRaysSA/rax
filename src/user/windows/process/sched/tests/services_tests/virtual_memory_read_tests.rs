//! Current-process reads through the real kernel service dispatch seam.

use super::*;

fn setup_read(
    arch: WinArch,
) -> (
    super::super::super::super::super::WindowsProcess,
    Thread,
    u64,
) {
    let (mut process, thread) = fixture(arch, "NtReadVirtualMemory", 0x23);
    let p = process.state_mut();
    let base =
        p.vm.allocate(
            None,
            PAGE_SIZE * 3,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    (process, thread, base)
}

#[test]
fn native_read_virtual_memory_self_copies_bytes_and_pointer_width_count_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup_read(arch);
        let p = process.state_mut();
        let source = base + 32;
        let output = base + 64;
        let returned = base + 128;
        let bytes = [0x15, 0x26, 0x37, 0x48, 0x59, 0x6A, 0x7B, 0x8C];
        p.space.wr(source, &bytes).unwrap();
        p.space.wr(output, &[0xA5; 16]).unwrap();
        p.space.wr(returned, &[0xD3; 16]).unwrap();
        arguments(
            p,
            &mut thread,
            &[arch.ptr(u64::MAX), source, output, 8, returned],
        );
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue, "{arch}");
        assert_eq!(thread.cpu.gpr(0), 0, "{arch}");
        assert_eq!(
            p.space.bytes(output, 16).unwrap(),
            [&bytes[..], &[0xA5; 8]].concat()
        );
        assert_eq!(p.space.ptr(returned, arch.ptr_size()).unwrap(), 8);
        assert_eq!(p.space.u8(returned + arch.ptr_size()).unwrap(), 0xD3);
        assert!(thread.frames.is_empty());
    }
}

#[path = "virtual_memory_read_replay_tests.rs"]
mod replay;

#[test]
fn native_read_virtual_memory_uses_actual_protection_and_preserves_source_guards_all_abis() {
    for arch in WinArch::ALL {
        for actual in [prot::NOACCESS, prot::READWRITE | prot::GUARD, prot::EXECUTE] {
            let (mut process, mut thread, base) = setup_read(arch);
            let p = process.state_mut();
            let source = base + 32;
            let output = base + PAGE_SIZE + 64;
            let returned = base + PAGE_SIZE + 128;
            p.space.wr(source, &[0x6B; 8]).unwrap();
            p.space.wr(output, &[0xA5; 8]).unwrap();
            p.vm.protect(base, PAGE_SIZE, actual).unwrap();
            p.vm.set_reported(base, PAGE_SIZE, prot::READWRITE);
            arguments(
                p,
                &mut thread,
                &[arch.ptr(u64::MAX), source, output, 8, returned],
            );
            assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
            let accessible = actual == prot::EXECUTE;
            assert_eq!(thread.cpu.gpr(0), if accessible { 0 } else { 0x8000_000D });
            assert_eq!(
                p.space.bytes(output, 8).unwrap(),
                vec![if accessible { 0x6B } else { 0xA5 }; 8]
            );
            assert_eq!(
                p.space.ptr(returned, arch.ptr_size()).unwrap(),
                if accessible { 8 } else { 0 }
            );
            assert_eq!(p.vm.page_state(source).unwrap().protect, actual);
            assert_eq!(p.vm.query(source).unwrap().protect, prot::READWRITE);
        }
    }
}

#[test]
fn native_read_virtual_memory_foreign_frontier_preserves_caller_state_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup_read(arch);
        let p = process.state_mut();
        let process_id = p.objects.create(Object::Process {
            pid: p.pid + 1,
            exit_code: None,
        });
        let handle = p.objects.open_access(process_id, false, 0x10).unwrap();
        let returned = base + PAGE_SIZE;
        p.space.wr(base, &[0xA5; 64]).unwrap();
        p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        arguments(
            p,
            &mut thread,
            &[u64::from(handle), base, base + 32, 8, returned],
        );
        let result = dispatch(p, &mut thread);
        assert!(
            matches!(result,Outcome::Fail(ref message) if message.contains("NtReadVirtualMemory for another process")),
            "{result:?}"
        );
        assert_eq!(p.space.bytes(base, 64).unwrap(), vec![0xA5; 64]);
        assert_eq!(
            p.vm.page_state(returned).unwrap().protect,
            prot::READWRITE | prot::GUARD
        );
        assert!(!p.space.is_resident(returned));
        assert!(thread.frames.is_empty());
    }
}

#[test]
fn native_read_virtual_memory_source_fault_materializes_only_reached_guest_pages_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup_read(arch);
        let p = process.state_mut();
        let source = base + PAGE_SIZE - 4;
        p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let output = base + 2 * PAGE_SIZE + 32;
        assert!(!p.space.is_resident(base));
        assert!(!p.space.is_resident(output));
        arguments(p, &mut thread, &[arch.ptr(u64::MAX), source, output, 8, 0]);
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), 0x8000_000D);
        assert!(p.space.is_resident(base));
        assert!(!p.space.is_resident(base + PAGE_SIZE));
        assert!(!p.space.is_resident(output));
    }
}

#[cfg(windows)]
#[path = "virtual_memory_read_leaf_tests.rs"]
mod installed;

#[test]
fn native_read_virtual_memory_preserves_all_prior_ntdll_ordinals_and_trap_rvas_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let names = ["NtReadVirtualMemory"];
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == names[0]))
        .unwrap();
    assert_eq!(
        current.exports[family]
            .iter()
            .map(|e| e.name)
            .collect::<Vec<_>>(),
        names
    );
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(current, arch, 0, &[]);
        let added: Vec<_> = current.exports[family]
            .iter()
            .filter(|e| e.archs.has(arch))
            .map(|e| e.name)
            .collect();
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert!(after.symbols.len() >= before.symbols.len() + added.len());
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice(),
            "{arch}: prior ordinals or trap RVAs moved"
        );
        assert_eq!(
            after.symbols[before.symbols.len()..before.symbols.len() + added.len()]
                .iter()
                .map(|row| row.0)
                .collect::<Vec<_>>(),
            added
        );
    }
}

#[test]
fn native_read_virtual_memory_status_translation_matches_all_original_views() {
    macro_rules! captured {
        ($view:literal) => { include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-read-virtual-memory/native/native-read-virtual-memory-v5-four-views-",$view,".log")) };
    }
    for (view, text) in [
        ("arm64", captured!("arm64")),
        ("x64", captured!("x64")),
        ("x86", captured!("x86")),
        ("x86-laa", captured!("x86-laa")),
    ] {
        let mut count = 0;
        for line in text.lines().filter(|line| line.starts_with('{')) {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(row["id"].as_u64().unwrap(), count);
            assert_eq!(row["last-error"].as_u64().unwrap(), 0x12345678);
            let status = row["status"].as_u64().unwrap() as u32;
            let expected = row["dos-error"].as_u64().unwrap() as u32;
            assert_eq!(
                crate::user::windows::nt::status_to_error(status),
                expected,
                "{view} status={status:#x}"
            );
            count += 1;
        }
        assert_eq!(count, 7, "{view}");
    }
}
