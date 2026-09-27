//! Normal process exit retires peers while guest detach callbacks still use locks.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::process::{ThreadState, WindowsConfig, WindowsProcess, thread};
use std::time::Instant;

fn with_process(arch: WinArch, test: impl FnOnce(&mut Proc, u64, u32)) {
    let image: &[u8] = match arch {
        WinArch::X86 => include_bytes!("../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
        WinArch::X64 => include_bytes!("../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
        WinArch::Arm64 => {
            include_bytes!("../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut cfg = WindowsConfig::new("sync-normal-exit.exe", vec![]);
    cfg.seed = Some(1);
    cfg.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
    let p = process.state_mut();
    let caller = *p.threads.keys().next().unwrap();
    let (base, _) =
        p.vm.allocate(
            None,
            2 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap();
    test(p, base, caller);
}

fn peer(p: &mut Proc) -> u32 {
    thread::create(p, 0, 0, 0x10000, false).unwrap()
}

#[test]
fn normal_exit_keeps_initialized_critical_sections_and_dead_owner_all_abis() {
    for arch in WinArch::ALL {
        with_process(arch, |p, base, caller| {
            let free = base;
            let owned = base + 0x80;
            let peer = peer(p);
            cs_init(p, free, 0).unwrap();
            cs_init(p, owned, 0).unwrap();
            assert!(cs_try_enter(p, owned, peer).unwrap());
            let free_before = p.space.bytes(free, cs_size(p)).unwrap();
            let owned_before = p.space.bytes(owned, cs_size(p)).unwrap();

            on_normal_process_exit(p, caller).unwrap();
            assert_eq!(p.space.bytes(free, free_before.len()).unwrap(), free_before);
            assert_eq!(
                p.space.bytes(owned, owned_before.len()).unwrap(),
                owned_before
            );
            assert!(p.sync.initialized_cs.contains(&free));
            assert!(p.sync.initialized_cs.contains(&owned));
            assert!(cs_try_enter(p, free, caller).unwrap());
            assert!(cs_leave(p, free, caller).unwrap());
            cs_delete(p, free).unwrap();
            assert!(!cs_try_enter(p, owned, caller).unwrap());
            assert_eq!(cs_recursion(p, owned, peer).unwrap(), 1);
            assert!(!cs_leave(p, owned, caller).unwrap());
            assert!(matches!(cs_delete(p, owned), Err(SyncError::Invalid(_))));

            // The final teardown, unlike normal detach, discards lock state.
            on_process_exit(p);
            assert!(matches!(
                cs_try_enter(p, owned, caller),
                Err(SyncError::Invalid("uninitialized/deleted critical section"))
            ));
        });
    }
}

#[test]
fn normal_exit_releases_peer_object_pin_once_and_discards_address_waits_all_abis() {
    for arch in WinArch::ALL {
        with_process(arch, |p, base, caller| {
            let object_peer = peer(p);
            let address_peer = peer(p);
            let event = p.objects.create(Object::Event {
                manual: false,
                signaled: false,
            });
            let handle = p.objects.open(event, false);
            let objects = Wait::Objects {
                objs: vec![event],
                all: false,
                deadline: None,
                alertable: false,
            };
            on_block(p, object_peer, &objects).unwrap();
            p.threads.get_mut(&object_peer).unwrap().state = ThreadState::Waiting(objects.clone());
            p.objects.close(u64::from(handle)).unwrap();
            assert!(
                p.objects.obj(event).is_some(),
                "the wait holds the final reference"
            );
            let key = u128::from(base);
            let address = Wait::Address {
                key,
                deadline: None,
            };
            on_block(p, address_peer, &address).unwrap();
            p.threads.get_mut(&address_peer).unwrap().state = ThreadState::Waiting(address.clone());
            assert_eq!(p.sync.waiters[&key].len(), 1);

            on_normal_process_exit(p, caller).unwrap();
            assert!(p.objects.obj(event).is_none());
            assert!(!p.sync.parked.contains_key(&object_peer));
            assert!(!p.sync.parked.contains_key(&address_peer));
            assert!(!p.sync.waiters.contains_key(&key));
            on_cancel(p, object_peer, &objects).unwrap();
            on_cancel(p, address_peer, &address).unwrap();
            on_normal_process_exit(p, caller).unwrap();
            on_process_exit(p);
        });
    }
}

#[test]
fn normal_exit_retires_srw_writer_without_guest_write_and_reconciles_lazily_all_abis() {
    for arch in WinArch::ALL {
        with_process(arch, |p, base, caller| {
            let lock = base + 0x100;
            let dead_owner = base + 0x180;
            let writer = peer(p);
            let reader = peer(p);
            srw_init(p, lock).unwrap();
            assert!(srw_try(p, lock, reader, false).unwrap());
            let wait = Wait::Srw {
                addr: lock,
                exclusive: true,
            };
            on_block(p, writer, &wait).unwrap();
            p.threads.get_mut(&writer).unwrap().state = ThreadState::Waiting(wait.clone());
            assert_eq!(p.sync.srw[&lock].waiting_exclusive, 1);
            let before = p.space.ptr(lock, arch.ptr_size()).unwrap();
            assert_eq!(before, 0x13, "one shared owner and one exclusive waiter");

            srw_init(p, dead_owner).unwrap();
            assert!(srw_try(p, dead_owner, writer, true).unwrap());
            p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
            on_normal_process_exit(p, caller).unwrap();
            assert_eq!(p.space.ptr(lock, arch.ptr_size()).unwrap(), before);
            assert_eq!(p.sync.srw[&lock].waiting_exclusive, 0);
            assert!(!p.sync.parked.contains_key(&writer));
            assert_eq!(srw_held(p, lock, reader).unwrap(), Some(false));
            assert_eq!(srw_held(p, dead_owner, writer).unwrap(), Some(true));
            assert!(!srw_try(p, dead_owner, caller, false).unwrap());

            p.vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
            let tampered = before ^ 0x4;
            assert_ne!(tampered, before);
            assert_ne!(tampered, 0x11, "current word after waiter retirement");
            p.space.wptr(lock, arch.ptr_size(), tampered).unwrap();
            assert!(matches!(
                srw_held(p, lock, reader),
                Err(SyncError::Invalid("modified/uninitialized SRW lock word"))
            ));
            assert!(matches!(
                srw_try(p, lock, caller, false),
                Err(SyncError::Invalid("modified/uninitialized SRW lock word"))
            ));
            assert_eq!(p.space.ptr(lock, arch.ptr_size()).unwrap(), tampered);
            assert_eq!(p.sync.srw[&lock].waiting_exclusive, 0);
            p.space.wptr(lock, arch.ptr_size(), before).unwrap();
            assert_eq!(srw_held(p, lock, reader).unwrap(), Some(false));
            assert!(srw_try(p, lock, caller, false).unwrap());
            assert_eq!(p.space.ptr(lock, arch.ptr_size()).unwrap(), 0x21);
            assert_eq!(p.sync.srw[&lock].waiting_exclusive, 0);
            srw_release(p, lock, caller, false).unwrap();
            assert_eq!(p.space.ptr(lock, arch.ptr_size()).unwrap(), 0x11);
            on_cancel(p, writer, &wait).unwrap();
            on_process_exit(p);
        });
    }
}

#[test]
fn normal_exit_never_touches_unreadable_peer_lock_storage_all_abis() {
    for arch in WinArch::ALL {
        with_process(arch, |p, base, caller| {
            let owner = peer(p);
            let writer = peer(p);
            let critical = base;
            cs_init(p, critical, 0).unwrap();
            assert!(cs_try_enter(p, critical, caller).unwrap());
            let cs_wait = Wait::CritSec { addr: critical };
            on_block(p, owner, &cs_wait).unwrap();
            p.threads.get_mut(&owner).unwrap().state = ThreadState::Waiting(cs_wait.clone());
            let cs_before = p.space.bytes(critical, cs_size(p)).unwrap();
            p.vm.protect(base, PAGE_SIZE, prot::NOACCESS).unwrap();

            let (unmapped, _) =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap();
            srw_init(p, unmapped).unwrap();
            assert!(srw_try(p, unmapped, owner, true).unwrap());
            let srw_wait = Wait::Srw {
                addr: unmapped,
                exclusive: true,
            };
            on_block(p, writer, &srw_wait).unwrap();
            p.threads.get_mut(&writer).unwrap().state = ThreadState::Waiting(srw_wait.clone());
            p.vm.release(unmapped).unwrap();

            on_normal_process_exit(p, caller).unwrap();
            assert!(!p.sync.parked.contains_key(&owner));
            assert!(!p.sync.parked.contains_key(&writer));
            assert!(!p.sync.cs_waiters.contains_key(&critical));
            assert!(p.sync.initialized_cs.contains(&critical));
            assert_eq!(p.sync.srw[&unmapped].exclusive, Some(owner));
            assert_eq!(p.sync.srw[&unmapped].waiting_exclusive, 0);
            p.vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
            assert_eq!(p.space.bytes(critical, cs_before.len()).unwrap(), cs_before);
            let lock_field = critical + cs_fields(p).0;
            assert_eq!(p.space.u32(lock_field).unwrap(), (-6i32) as u32);
            assert_eq!(cs_spin(p, critical, 0).unwrap(), 0);
            assert_eq!(p.space.u32(lock_field).unwrap(), (-2i32) as u32);
            assert!(cs_leave(p, critical, caller).unwrap());
            cs_delete(p, critical).unwrap();
            on_cancel(p, owner, &cs_wait).unwrap();
            on_cancel(p, writer, &srw_wait).unwrap();
            on_process_exit(p);
        });
    }
}

#[test]
fn normal_exit_does_not_consume_completed_peer_waits_twice_all_abis() {
    for arch in WinArch::ALL {
        with_process(arch, |p, base, caller| {
            let now = Instant::now();
            let critical = base;
            let srw = base + 0x100;
            let cs_peer = peer(p);
            let srw_peer = peer(p);
            let object_peer = peer(p);

            cs_init(p, critical, 0).unwrap();
            assert!(cs_try_enter(p, critical, caller).unwrap());
            let cs_wait = Wait::CritSec { addr: critical };
            on_block(p, cs_peer, &cs_wait).unwrap();
            p.threads.get_mut(&cs_peer).unwrap().state = ThreadState::Waiting(cs_wait.clone());
            assert!(cs_leave(p, critical, caller).unwrap());
            assert_eq!(poll(p, cs_peer, &cs_wait, now, false).unwrap(), Some(0));
            assert!(p.sync.completed.contains(&cs_peer));
            assert!(!p.sync.cs_waiters.contains_key(&critical));
            assert_eq!(cs_recursion(p, critical, cs_peer).unwrap(), 1);

            srw_init(p, srw).unwrap();
            assert!(srw_try(p, srw, caller, false).unwrap());
            let srw_wait = Wait::Srw {
                addr: srw,
                exclusive: true,
            };
            on_block(p, srw_peer, &srw_wait).unwrap();
            p.threads.get_mut(&srw_peer).unwrap().state = ThreadState::Waiting(srw_wait.clone());
            srw_release(p, srw, caller, false).unwrap();
            assert_eq!(poll(p, srw_peer, &srw_wait, now, false).unwrap(), Some(0));
            assert!(p.sync.completed.contains(&srw_peer));
            assert_eq!(p.sync.srw[&srw].waiting_exclusive, 0);
            assert_eq!(srw_held(p, srw, srw_peer).unwrap(), Some(true));

            let event = p.objects.create(Object::Event {
                manual: false,
                signaled: false,
            });
            let handle = p.objects.open(event, false);
            let objects = Wait::Objects {
                objs: vec![event],
                all: false,
                deadline: None,
                alertable: false,
            };
            on_block(p, object_peer, &objects).unwrap();
            p.threads.get_mut(&object_peer).unwrap().state = ThreadState::Waiting(objects.clone());
            p.objects.close(u64::from(handle)).unwrap();
            let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(event) else {
                panic!("parked wait must pin its event");
            };
            *signaled = true;
            assert_eq!(poll(p, object_peer, &objects, now, false).unwrap(), Some(0));
            assert!(p.sync.completed.contains(&object_peer));
            assert!(p.objects.obj(event).is_some());

            on_normal_process_exit(p, caller).unwrap();
            assert!(p.sync.completed.is_empty());
            for tid in [cs_peer, srw_peer, object_peer] {
                assert!(!p.sync.parked.contains_key(&tid));
            }
            assert_eq!(cs_recursion(p, critical, cs_peer).unwrap(), 1);
            assert!(!cs_try_enter(p, critical, caller).unwrap());
            assert_eq!(srw_held(p, srw, srw_peer).unwrap(), Some(true));
            assert!(!srw_try(p, srw, caller, true).unwrap());
            assert!(p.objects.obj(event).is_none());
            on_cancel(p, cs_peer, &cs_wait).unwrap();
            on_cancel(p, srw_peer, &srw_wait).unwrap();
            on_cancel(p, object_peer, &objects).unwrap();
            on_normal_process_exit(p, caller).unwrap();
            on_process_exit(p);
        });
    }
}
