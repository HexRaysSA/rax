use super::*;
use crate::user::linux::process::mm::ProtectPolicy;
use crate::user::linux::syscall::mem::mman::PROT_READ;
use crate::user::mm::{EXTENT, Mapping, Perms, SpaceConfig};

const BASE: u64 = 0x2_0000;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn initial(abi: LinuxAbi) -> (AddressSpace, MmState, LockPolicy) {
    let mut mm = crate::user::linux::process::mm::initial_state(abi);
    mm.def_lock = 0;
    mm.locked_vm = 0;
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(P, P)],
    })
    .unwrap();
    (
        space,
        mm,
        LockPolicy {
            abi,
            privileged: false,
            memlock_limit: 3 * P,
        },
    )
}

fn flags(space: &AddressSpace, address: u64) -> u32 {
    space.vma_at(address).unwrap().flags & vma_flags::LOCKED_MASK
}

#[test]
fn lock_admission_rounding_and_privilege_preserve_existing_order_for_every_abi() {
    for abi in ABIS {
        let (space, mut mm, mut policy) = initial(abi);
        let pinned = mm.pinned_vm.clone();
        space
            .map(BASE, 4 * P, Mapping::anonymous(Perms::READ | Perms::WRITE))
            .unwrap();
        policy.memlock_limit = 0;
        assert_eq!(
            mm.lock_range(&space, policy, BASE, P, 2),
            Err(Errno(EINVAL))
        );
        assert_eq!(mm.lock_range(&space, policy, BASE, 0, 0), Err(Errno(EPERM)));
        assert_eq!(mm.lock_all(&space, policy, 0), Err(Errno(EINVAL)));
        assert_eq!(
            mm.lock_all(&space, policy, MCL_CURRENT as i32),
            Err(Errno(EPERM))
        );
        assert_eq!(mm.unlock_range(&space, BASE, 0), Ok(0));
        assert_eq!(mm.unlock_all(&space), Ok(0));
        // A nonzero byte limit grants admission, but fractions of a page
        // contribute no pages to RLIMIT_MEMLOCK.
        policy.memlock_limit = 1;
        assert_eq!(
            mm.lock_range(&space, policy, BASE, 1, 0),
            Err(Errno(ENOMEM))
        );
        assert_eq!(mm.lock_range(&space, policy, BASE, 0, 0), Ok(0));
        assert_eq!(mm.locked_vm, 0);
        policy.privileged = true;
        policy.memlock_limit = 0;
        assert_eq!(
            mm.lock_range(&space, policy, BASE, 4 * P, MLOCK_ONFAULT),
            Ok(0)
        );
        assert_eq!(mm.locked_vm, 4);
        assert!(!space.is_resident(BASE));
        assert_eq!(mm.unlock_range(&space, BASE + 1, P), Ok(0));
        assert_eq!(mm.locked_vm, 2);
        assert_eq!(flags(&space, BASE), 0);
        assert_eq!(flags(&space, BASE + P), 0);
        assert_eq!(flags(&space, BASE + 2 * P), vma_flags::LOCKED_MASK);
        assert_eq!(mm.lock_range(&space, policy, BASE, u64::MAX, 0), Ok(0));
        assert_eq!(
            mm.lock_range(&space, policy, u64::MAX & !(P - 1), 2 * P, 0),
            Err(Errno(EINVAL))
        );
        assert_eq!(mm.locked_vm, 2);
        assert!(std::sync::Arc::ptr_eq(&pinned, &mm.pinned_vm));
    }
}

#[test]
fn overlapping_locks_count_only_new_pages_and_leave_special_vmas_unlocked() {
    for abi in ABIS {
        let (space, mut mm, policy) = initial(abi);
        space
            .map(BASE, 4 * P, Mapping::anonymous(Perms::READ | Perms::WRITE))
            .unwrap();
        assert_eq!(
            mm.lock_range(&space, policy, BASE, 2 * P, MLOCK_ONFAULT),
            Ok(0)
        );
        assert_eq!(
            mm.lock_range(&space, policy, BASE + P, 2 * P, MLOCK_ONFAULT),
            Ok(0)
        );
        assert_eq!(mm.locked_vm, 3);
        assert_eq!(
            mm.lock_range(&space, policy, BASE, 3 * P, MLOCK_ONFAULT),
            Ok(0)
        );
        assert_eq!(mm.locked_vm, 3);
        assert_eq!(
            mm.lock_range(&space, policy, BASE + 3 * P, P, MLOCK_ONFAULT),
            Err(Errno(ENOMEM))
        );
        assert_eq!(flags(&space, BASE + 3 * P), 0);
        assert_eq!(mm.unlock_range(&space, BASE + P + 1, P), Ok(0));
        assert_eq!(mm.locked_vm, 1);
        let mut special = Mapping::anonymous(Perms::READ);
        special.flags = vma_flags::SPECIAL;
        space.map(BASE + 4 * P, P, special).unwrap();
        assert_eq!(
            mm.lock_range(&space, policy, BASE + 4 * P, P, MLOCK_ONFAULT),
            Ok(0)
        );
        assert_eq!(flags(&space, BASE + 4 * P), 0);
        assert_eq!(mm.locked_vm, 1);
    }
}

#[test]
fn lock_errors_preserve_earlier_flags_accounts_and_population_effects() {
    for abi in ABIS {
        let (space, mut mm, mut policy) = initial(abi);
        policy.privileged = true;
        policy.memlock_limit = 0;
        space
            .map(BASE, P, Mapping::anonymous(Perms::READ | Perms::WRITE))
            .unwrap();
        space
            .map(BASE + 2 * P, P, Mapping::anonymous(Perms::empty()))
            .unwrap();
        assert_eq!(
            mm.lock_range(&space, policy, BASE, 3 * P, MLOCK_ONFAULT),
            Err(Errno(ENOMEM))
        );
        assert_eq!(mm.locked_vm, 1);
        assert_eq!(flags(&space, BASE), vma_flags::LOCKED_MASK);
        assert_eq!(flags(&space, BASE + 2 * P), 0);
        assert!(!space.is_resident(BASE));
        assert_eq!(mm.unlock_range(&space, BASE, 3 * P), Err(Errno(ENOMEM)));
        assert_eq!(mm.locked_vm, 0);
        assert_eq!(flags(&space, BASE), 0);
        // A population error follows the successful flag/account update.
        assert_eq!(
            mm.lock_range(&space, policy, BASE + 2 * P, P, 0),
            Err(Errno(ENOMEM))
        );
        assert_eq!(mm.locked_vm, 1);
        assert_eq!(flags(&space, BASE + 2 * P), vma_flags::LOCKED);
        assert!(!space.is_resident(BASE + 2 * P));
        assert_eq!(
            mm.protect_range(
                &space,
                ProtectPolicy { abi, persona: 0 },
                BASE + 2 * P,
                P,
                PROT_READ
            ),
            Ok(0)
        );
        assert_eq!(mm.lock_range(&space, policy, BASE + 2 * P, P, 0), Ok(0));
        assert_eq!(mm.locked_vm, 1);
        assert!(space.is_resident(BASE + 2 * P));
    }
}

#[test]
fn lock_all_preserves_current_future_onfault_and_ignored_population_rules() {
    for abi in ABIS {
        let (space, mut mm, mut policy) = initial(abi);
        space
            .map(BASE, 2 * P, Mapping::anonymous(Perms::READ | Perms::WRITE))
            .unwrap();
        space
            .map(BASE + 3 * P, P, Mapping::anonymous(Perms::empty()))
            .unwrap();
        let mut special = Mapping::anonymous(Perms::READ);
        special.flags = vma_flags::SPECIAL;
        space.map(BASE + 4 * P, P, special).unwrap();
        assert_eq!(
            mm.lock_all(&space, policy, (MCL_CURRENT | MCL_ONFAULT) as i32),
            Err(Errno(ENOMEM))
        );
        assert_eq!(mm.locked_vm, 0);
        assert_eq!(mm.def_lock, 0);
        assert_eq!(
            mm.lock_all(&space, policy, (MCL_FUTURE | MCL_ONFAULT) as i32),
            Ok(0)
        );
        assert_eq!(mm.def_lock, vma_flags::LOCKED_MASK);
        for bad in [0, -1, MCL_ONFAULT as i32] {
            assert_eq!(mm.lock_all(&space, policy, bad), Err(Errno(EINVAL)));
            assert_eq!(mm.def_lock, vma_flags::LOCKED_MASK);
        }
        policy.memlock_limit = 4 * P;
        assert_eq!(
            mm.lock_all(&space, policy, (MCL_CURRENT | MCL_ONFAULT) as i32),
            Ok(0)
        );
        assert_eq!(mm.def_lock, 0);
        assert_eq!(mm.locked_vm, 3);
        assert!(!space.is_resident(BASE));
        assert_eq!(flags(&space, BASE + 4 * P), 0);
        policy.privileged = true;
        policy.memlock_limit = 0;
        assert_eq!(mm.lock_all(&space, policy, MCL_CURRENT as i32), Ok(0));
        assert_eq!(mm.locked_vm, 3);
        assert!(space.is_resident(BASE));
        assert!(space.is_resident(BASE + P));
        assert!(!space.is_resident(BASE + 3 * P));
        assert_eq!(mm.lock_all(&space, policy, MCL_FUTURE as i32), Ok(0));
        assert_eq!(mm.def_lock, vma_flags::LOCKED);
        assert_eq!(mm.locked_vm, 3);
        assert_eq!(mm.unlock_all(&space), Ok(0));
        assert_eq!(mm.def_lock, 0);
        assert_eq!(mm.locked_vm, 0);
        for address in [BASE, BASE + P, BASE + 3 * P, BASE + 4 * P] {
            assert_eq!(flags(&space, address), 0);
        }
    }
}
