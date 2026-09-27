//! Built-in completion is published only after data and LDR installation.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, mem};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn process(arch: WinArch) -> WindowsProcess {
    let image: &[u8] = match arch {
        WinArch::X86 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
        WinArch::X64 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
        WinArch::Arm64 => {
            include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut cfg = WindowsConfig::new("builtin-ready-test.exe", Vec::new());
    cfg.arena_bytes = 64 << 20;
    cfg.seed = Some(1);
    WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap()
}

#[test]
fn builtin_ready_order_follows_completion_and_repeated_load_is_not_duplicated_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let before = p.modules.ready_order();
        let legacy = load_dll(p, "msvcrt.dll").unwrap();
        let modern = load_dll(p, "ucrtbase.dll").unwrap();
        let mut expected = before;
        expected.extend([legacy, modern]);
        assert_eq!(p.modules.ready_order(), expected);
        assert!(p.modules.list[modern].initialized);
        assert!(p.traps.lookup(p.modules.list[modern].text).is_some());
        assert_eq!(load_dll(p, "UCRTBASE.DLL").unwrap(), modern);
        assert_eq!(p.modules.ready_order(), expected);
        detach_started(p, modern).unwrap();
        detach_completed(p, modern).unwrap();
        assert!(!p.modules.ready_order().contains(&modern));
        assert!(p.modules.is_live(modern));
        assert_eq!(p.modules.list[modern].load_count, u32::MAX);
        assert!(p.traps.lookup(p.modules.list[modern].text).is_some());
    }
}

#[test]
fn failed_builtin_publication_never_enters_ready_ledger_and_retry_commits_once_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        // Preserve loader heap commitment across the failed allocation/free.
        let block = p
            .heaps
            .alloc_checked(&mut p.vm, p.process_heap, 8 * PAGE_SIZE, true)
            .unwrap();
        p.heaps.free(p.process_heap, block).unwrap();
        let before_ready = p.modules.ready_order();
        let before_commit = p.vm.committed_bytes();
        let o = offsets(arch);
        let tail = p.modules.ldr_data + o.ldr_in_load_order + o.ptr;
        let saved = p.space.ptr(tail, o.ptr).unwrap();
        p.space.wptr(tail, o.ptr, 0).unwrap();
        let failed = p.modules.list.len();
        assert_eq!(
            load_dll(p, "ucrtbase.dll").unwrap_err().status,
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(p.modules.ready_order(), before_ready);
        assert!(!p.modules.dynamic.attached_order.contains(&failed));
        assert!(!p.modules.is_live(failed));
        assert!(!p.traps.contains(p.modules.list[failed].text));
        assert_eq!(
            p.vm.query(p.modules.list[failed].base).unwrap().state,
            mem::FREE
        );
        assert_eq!(p.vm.committed_bytes(), before_commit);
        assert!(p.failure.is_none());
        p.space.wptr(tail, o.ptr, saved).unwrap();
        let live = load_dll(p, "ucrtbase.dll").unwrap();
        assert!(live > failed);
        let mut expected = before_ready;
        expected.push(live);
        assert_eq!(p.modules.ready_order(), expected);
        assert!(p.failure.is_none());
    }
}
