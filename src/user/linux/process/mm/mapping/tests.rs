use super::*;
use crate::user::mm::{EXTENT, HostFileSource, Perms, SpaceConfig, anonymous_file};
use std::io::Write;

const BASE: u64 = 0x2_0000;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn initial(abi: LinuxAbi) -> (AddressSpace, MmState, MmapPolicy) {
    let mut mm = crate::user::linux::process::mm::initial_state(abi);
    mm.def_lock = 0;
    mm.locked_vm = 0;
    mm.mmap_base = BASE + 32 * PAGE_SIZE;
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    (
        space,
        mm,
        MmapPolicy {
            lock: LockPolicy {
                abi,
                privileged: false,
                memlock_limit: 2 * PAGE_SIZE,
            },
            persona: 0,
        },
    )
}

fn args(address: u64, length: u64, flags: u32) -> MmapArgs {
    MmapArgs {
        address,
        length,
        protection: PROT_READ | PROT_WRITE,
        flags,
        offset: 0,
    }
}

fn plain() -> PreparedMmap {
    PreparedMmap {
        backing: Backing::Anonymous,
        name: None,
        flags: 0,
    }
}

#[test]
fn mmap_validation_area_search_and_fixed_collisions_preserve_order_for_every_abi() {
    for abi in ABIS {
        let (space, mut mm, policy) = initial(abi);
        let fixed = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        let basic = args(BASE, PAGE_SIZE, fixed);
        for (length, offset, flags, errno) in [
            (0, 1, 0, EINVAL),
            (0, 0, 0, EINVAL),
            (u64::MAX, 0, 0, ENOMEM),
            (PAGE_SIZE, u64::MAX & !PAGE_MASK, 0, EOVERFLOW),
            (PAGE_SIZE, 0, 0, EINVAL),
            (PAGE_SIZE, 0, MAP_SHARED_VALIDATE | MAP_SYNC, EOPNOTSUPP),
        ] {
            let invalid = MmapArgs {
                length,
                offset,
                flags,
                ..basic
            };
            assert_eq!(
                mm.map_prepared(&space, policy, invalid, plain()),
                Err(Errno(errno))
            );
            assert!(space.vma_at(BASE).is_none());
        }
        assert_eq!(
            mm.map_prepared(&space, policy, MmapArgs { length: 1, ..basic }, plain()),
            Ok(BASE)
        );
        space.write(BASE, &[17]).unwrap();
        for (address, flags, errno) in [
            (BASE + 1, fixed, EINVAL),
            (abi.task_size(), fixed, ENOMEM),
            (0, fixed, EPERM),
            (
                BASE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                EEXIST,
            ),
        ] {
            assert_eq!(
                mm.map_prepared(
                    &space,
                    policy,
                    MmapArgs {
                        address,
                        flags,
                        ..basic
                    },
                    plain()
                ),
                Err(Errno(errno))
            );
            let mut byte = [0];
            space.read(BASE, &mut byte).unwrap();
            assert_eq!(byte, [17]);
        }
        assert_eq!(
            mm.unmapped_area(&space, abi, BASE + PAGE_SIZE + 19, PAGE_SIZE, 0),
            Ok(BASE + PAGE_SIZE)
        );
        assert_eq!(
            mm.unmapped_area(&space, abi, 0, PAGE_SIZE, 0),
            Ok(mm.mmap_base - PAGE_SIZE)
        );
        assert_eq!(
            mm.unmapped_area(&space, abi, 0, abi.task_size() + 1, 0),
            Err(Errno(ENOMEM))
        );
        let low = mm
            .unmapped_area(&space, abi, BASE + 3 * PAGE_SIZE, PAGE_SIZE, MAP_32BIT)
            .unwrap();
        if abi == LinuxAbi::X86_64 {
            assert_eq!(low, 0x4000_0000);
        } else {
            assert_eq!(low, BASE + 3 * PAGE_SIZE);
        }
    }
}

#[test]
fn mmap_replacement_preserves_lock_admission_before_uncharging_and_seals() {
    for abi in ABIS {
        let (space, mut mm, mut policy) = initial(abi);
        let pinned = mm.pinned_vm.clone();
        let basic = args(
            BASE,
            2 * PAGE_SIZE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_LOCKED,
        );
        assert_eq!(mm.map_prepared(&space, policy, basic, plain()), Ok(BASE));
        assert_eq!(mm.locked_vm, 2);
        // Existing mmap checks the full new charge before uncharging its destination.
        assert_eq!(
            mm.map_prepared(&space, policy, basic, plain()),
            Err(Errno(EAGAIN))
        );
        policy.lock.privileged = true;
        assert_eq!(mm.map_prepared(&space, policy, basic, plain()), Ok(BASE));
        assert_eq!(mm.locked_vm, 2);
        assert_eq!(mm.seal_range(&space, BASE, 2 * PAGE_SIZE, 0), Ok(0));
        policy.lock.privileged = false;
        assert_eq!(
            mm.map_prepared(&space, policy, basic, plain()),
            Err(Errno(EAGAIN))
        );
        policy.lock.privileged = true;
        assert_eq!(
            mm.map_prepared(&space, policy, basic, plain()),
            Err(Errno(EPERM))
        );
        assert_eq!(mm.locked_vm, 2);
        let other = args(
            BASE + 4 * PAGE_SIZE,
            PAGE_SIZE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_LOCKED,
        );
        policy.lock.privileged = false;
        policy.lock.memlock_limit = 0;
        assert_eq!(
            mm.map_prepared(&space, policy, other, plain()),
            Err(Errno(EPERM))
        );
        policy.lock.memlock_limit = 1;
        assert_eq!(
            mm.map_prepared(&space, policy, other, plain()),
            Err(Errno(EAGAIN))
        );
        assert!(Arc::ptr_eq(&pinned, &mm.pinned_vm));
    }
}

#[test]
fn mmap_real_source_and_keep_survive_catalog_release_and_private_snapshot() {
    for abi in ABIS {
        let (space, mut mm, policy) = initial(abi);
        let mut file = anonymous_file().unwrap();
        let mut bytes = vec![5; 2 * PAGE_SIZE as usize];
        bytes[PAGE_SIZE as usize] = 31;
        file.write_all(&bytes).unwrap();
        let keep = Arc::new(());
        let retained = Arc::downgrade(&keep);
        let source = Arc::new(HostFileSource::keeping(file, Some(keep)).unwrap());
        let actual = source.clone();
        let prepared = PreparedMmap {
            backing: Backing::Source {
                source,
                offset: PAGE_SIZE,
            },
            name: Some("mapped-source".into()),
            flags: vma_flags::DENY_WRITE,
        };
        let a = args(BASE, PAGE_SIZE, MAP_PRIVATE | MAP_FIXED);
        assert_eq!(mm.map_prepared(&space, policy, a, prepared), Ok(BASE));
        {
            let vma = space.vma_at(BASE).unwrap();
            let Backing::Source { source, offset } = vma.backing else {
                panic!("source retained")
            };
            let erased: Arc<dyn crate::user::mm::PageSource> = actual.clone();
            assert!(Arc::ptr_eq(&source, &erased));
            assert_eq!(offset, PAGE_SIZE);
            assert_eq!(vma.name.as_deref(), Some("mapped-source"));
            assert_ne!(vma.flags & vma_flags::DENY_WRITE, 0);
        }
        drop(actual);
        assert!(retained.upgrade().is_some());
        assert!(!space.is_resident(BASE));
        let snapshot = space.process_snapshot().unwrap();
        assert_eq!(mm.unmap_range(&space, abi, BASE, PAGE_SIZE), Ok(0));
        assert!(
            retained.upgrade().is_some(),
            "unpopulated child mapping retains the actual source"
        );
        let mut byte = [0];
        snapshot.read(BASE, &mut byte).unwrap();
        assert_eq!(byte, [31]);
        snapshot.write(BASE, &[47]).unwrap();
        snapshot.discard(BASE, PAGE_SIZE).unwrap();
        snapshot.read(BASE, &mut byte).unwrap();
        assert_eq!(byte, [31]);
        snapshot.unmap(BASE, PAGE_SIZE).unwrap();
        assert!(retained.upgrade().is_none());
    }
}

#[test]
fn mmap_population_and_future_lock_flags_preserve_lazy_and_ignored_error_rules() {
    for abi in ABIS {
        let (space, mut mm, policy) = initial(abi);
        let a = args(
            BASE,
            PAGE_SIZE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE | MAP_NONBLOCK,
        );
        assert_eq!(mm.map_prepared(&space, policy, a, plain()), Ok(BASE));
        assert!(!space.is_resident(BASE));
        let a = MmapArgs {
            flags: a.flags & !MAP_NONBLOCK,
            protection: 0,
            ..a
        };
        assert_eq!(mm.map_prepared(&space, policy, a, plain()), Ok(BASE));
        assert!(!space.is_resident(BASE));
        mm.def_lock = vma_flags::LOCKED_MASK;
        let a = MmapArgs {
            protection: PROT_READ | PROT_WRITE,
            ..a
        };
        assert_eq!(mm.map_prepared(&space, policy, a, plain()), Ok(BASE));
        assert!(!space.is_resident(BASE));
        assert_eq!(mm.locked_vm, 1);
        assert_eq!(
            space.vma_at(BASE).unwrap().flags & vma_flags::LOCKED_MASK,
            vma_flags::LOCKED_MASK
        );
        mm.def_lock = 0;
        assert_eq!(mm.map_prepared(&space, policy, a, plain()), Ok(BASE));
        assert!(space.is_resident(BASE));
        assert_eq!(mm.locked_vm, 0);
        let shared = args(
            BASE + 2 * PAGE_SIZE,
            PAGE_SIZE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
        );
        let prepared = PreparedMmap::anonymous(shared).unwrap();
        assert_eq!(
            mm.map_prepared(&space, policy, shared, prepared),
            Ok(shared.address)
        );
        let snapshot = space.process_snapshot().unwrap();
        space.write(shared.address, &[73]).unwrap();
        let mut byte = [0];
        snapshot.read(shared.address, &mut byte).unwrap();
        assert_eq!(byte, [73]);
    }
}
