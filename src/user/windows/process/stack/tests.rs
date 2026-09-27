use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::AllocKind;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn process(arch: WinArch) -> WindowsProcess {
    let bytes = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
                .as_slice()
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
                .as_slice()
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
                .as_slice()
        }
    };
    let mut config = WindowsConfig::new("stack-test.exe", Vec::new());
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap()
}

fn stack(p: &mut Proc, t: &mut Thread) {
    let base =
        p.vm.reserve(
            None,
            0x1_0000,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
    t.stack_alloc = base;
    t.stack_base = base + 0x1_0000;
    t.stack_limit = t.stack_base - PAGE_SIZE;
    p.vm.commit(t.stack_limit, PAGE_SIZE, prot::READWRITE)
        .unwrap();
    p.vm.commit(
        t.stack_limit - PAGE_SIZE,
        PAGE_SIZE,
        prot::READWRITE | prot::GUARD,
    )
    .unwrap();
    p.space
        .wptr(
            t.teb + offsets(p.arch).teb_stack_limit,
            p.arch.ptr_size(),
            t.stack_limit,
        )
        .unwrap();
}

#[test]
fn guard_growth_publishes_exact_frontier_and_preserves_hard_bottom_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        stack(p, &mut t);
        let mut count = 0;
        loop {
            let old = t.stack_limit;
            let guard = old - PAGE_SIZE;
            assert!(p.vm.take_guard(guard));
            match grow(p, &mut t, guard).unwrap() {
                Growth::Grown => {
                    count += 1;
                    assert_eq!(t.stack_limit, old - PAGE_SIZE);
                    assert_eq!(
                        p.space
                            .ptr(t.teb + offsets(arch).teb_stack_limit, arch.ptr_size())
                            .unwrap(),
                        t.stack_limit
                    );
                    assert_eq!(p.vm.query(t.stack_limit).unwrap().protect, prot::READWRITE);
                    assert_ne!(
                        p.vm.query(t.stack_limit - PAGE_SIZE).unwrap().protect & prot::GUARD,
                        0
                    );
                }
                Growth::Overflow => {
                    assert_eq!(t.stack_limit, guard);
                    assert_eq!(t.stack_limit, t.stack_alloc + PAGE_SIZE);
                    assert_eq!(
                        p.space
                            .ptr(t.teb + offsets(arch).teb_stack_limit, arch.ptr_size())
                            .unwrap(),
                        guard,
                    );
                    // The consumed page supports exception records without a
                    // second guard consumption; the reserved bottom stays denied.
                    prepare(p, &mut t, guard, PAGE_SIZE).unwrap();
                    let bottom = t.stack_alloc;
                    assert!(prepare(p, &mut t, bottom, PAGE_SIZE).is_err());
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(count, 13);
        assert_eq!(p.vm.query(t.stack_alloc).unwrap().state, mem::RESERVE);
    }
}

#[test]
fn checked_personality_stack_preparation_grows_before_writes_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        stack(p, &mut t);
        let address = t.stack_base - 4 * PAGE_SIZE;
        prepare(p, &mut t, address, 4 * PAGE_SIZE).unwrap();
        assert_eq!(t.stack_limit, address);
        assert!(
            p.space
                .write(address, &vec![0xA5; (4 * PAGE_SIZE) as usize])
                .is_ok()
        );
    }
}

#[test]
fn protected_teb_and_nonstack_guards_do_not_publish_growth_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        stack(p, &mut t);
        let original = t.stack_limit;
        let guard = original - PAGE_SIZE;
        let lower = p.vm.query(guard - PAGE_SIZE).unwrap();
        p.vm.protect(t.teb, PAGE_SIZE, prot::READONLY).unwrap();
        assert!(p.vm.take_guard(guard));
        assert!(grow(p, &mut t, guard).is_err());
        assert_eq!(t.stack_limit, original);
        assert_eq!(p.vm.query(guard - PAGE_SIZE).unwrap(), lower);
        assert_eq!(
            grow(p, &mut t, guard + 2 * PAGE_SIZE).unwrap(),
            Growth::NotStack
        );
    }
}
