use super::*;
use crate::user::linux::tests::harness::Harness;
use crate::user::mm::{EXTENT, SpaceConfig};

const BASE: u64 = 0x2_0000;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn initial(abi: LinuxAbi) -> (AddressSpace, MmState, BrkPolicy) {
    let harness = Harness::embedded(abi);
    let policy = BrkPolicy::from(&harness.proc.state);
    let mut mm = harness.proc.state.mm.clone();
    mm.start_brk = BASE;
    mm.brk = BASE;
    mm.def_lock = vma_flags::LOCKED_MASK;
    mm.locked_vm = 0;
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    (space, mm, policy)
}

#[test]
fn break_mapping_lock_account_and_seal_rules_stay_together_for_every_abi() {
    for abi in ABIS {
        let (space, mut mm, mut policy) = initial(abi);
        let pinned = mm.pinned_vm.clone();
        policy.privileged = false;
        policy.memlock_limit = 2 * PAGE_SIZE;
        policy.persona = READ_IMPLIES_EXEC;
        assert_eq!(mm.change_brk(&space, policy, BASE - 1), Ok(BASE));
        assert_eq!(mm.change_brk(&space, policy, u64::MAX), Ok(BASE));
        assert_eq!(mm.change_brk(&space, policy, abi.task_size()), Ok(BASE));
        assert!(space.vma_snapshot().is_empty());
        assert_eq!(mm.change_brk(&space, policy, BASE + 17), Ok(BASE + 17));
        assert_eq!(mm.locked_vm, 1);
        assert!(!space.is_resident(BASE), "LOCKONFAULT must not populate");
        let heap = space.vma_at(BASE).unwrap();
        assert_eq!(heap.flags, vma_flags::LOCKED_MASK);
        assert_eq!(heap.perms.contains(Perms::EXEC), abi != LinuxAbi::Riscv64);
        assert_eq!(heap.name.as_deref(), Some("[heap]"));
        assert_eq!(mm.change_brk(&space, policy, BASE + 19), Ok(BASE + 19));
        assert_eq!(mm.locked_vm, 1);
        assert_eq!(
            mm.change_brk(&space, policy, BASE + 3 * PAGE_SIZE),
            Ok(BASE + 19)
        );
        assert_eq!(mm.brk, BASE + 19);
        assert!(space.vma_at(BASE + PAGE_SIZE).is_none());
        assert_eq!(mm.locked_vm, 1);
        assert_eq!(
            mm.change_brk(&space, policy, BASE + 2 * PAGE_SIZE),
            Ok(BASE + 2 * PAGE_SIZE)
        );
        assert_eq!(mm.locked_vm, 2);
        space
            .set_flags(
                BASE + PAGE_SIZE,
                PAGE_SIZE,
                vma_flags::SEALED,
                vma_flags::SEALED,
            )
            .unwrap();
        assert_eq!(
            mm.change_brk(&space, policy, BASE + PAGE_SIZE),
            Ok(BASE + 2 * PAGE_SIZE)
        );
        assert_eq!(mm.locked_vm, 2);
        assert!(space.vma_at(BASE + PAGE_SIZE).is_some());
        // A byte-only shrink changes no mapping, even within a sealed page.
        assert_eq!(
            mm.change_brk(&space, policy, BASE + 2 * PAGE_SIZE - 1),
            Ok(BASE + 2 * PAGE_SIZE - 1)
        );
        assert_eq!(mm.locked_vm, 2);
        assert!(std::sync::Arc::ptr_eq(&pinned, &mm.pinned_vm));
    }
}

#[test]
fn guard_boundaries_privilege_population_and_shrink_preserve_existing_rules() {
    for abi in ABIS {
        let (space, mut mm, mut policy) = initial(abi);
        policy.privileged = true;
        policy.memlock_limit = 0;
        policy.persona = 0;
        mm.def_lock = vma_flags::LOCKED;
        let mut stack = Mapping::anonymous(Perms::READ | Perms::WRITE);
        stack.flags = vma_flags::GROWSDOWN;
        let boundary = BASE + 3 * PAGE_SIZE + STACK_GUARD_GAP;
        space
            .map(boundary - PAGE_SIZE, PAGE_SIZE, stack.clone())
            .unwrap();
        assert_eq!(
            mm.change_brk(&space, policy, BASE + 2 * PAGE_SIZE),
            Ok(BASE)
        );
        assert_eq!(mm.locked_vm, 0);
        space.unmap(boundary - PAGE_SIZE, PAGE_SIZE).unwrap();
        space.map(boundary, PAGE_SIZE, stack).unwrap();
        assert_eq!(
            mm.change_brk(&space, policy, BASE + 2 * PAGE_SIZE),
            Ok(BASE + 2 * PAGE_SIZE)
        );
        assert_eq!(mm.locked_vm, 2);
        assert!(space.is_resident(BASE));
        assert!(space.is_resident(BASE + PAGE_SIZE));
        assert!(!space.vma_at(BASE).unwrap().perms.contains(Perms::EXEC));
        assert_eq!(mm.change_brk(&space, policy, BASE), Ok(BASE));
        assert_eq!(mm.locked_vm, 0);
        assert!(space.vma_at(BASE).is_none());
        // A regular mapping in the required trailing page also refuses growth.
        space
            .map(
                BASE + 2 * PAGE_SIZE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ),
            )
            .unwrap();
        assert_eq!(
            mm.change_brk(&space, policy, BASE + 2 * PAGE_SIZE),
            Ok(BASE)
        );
        assert_eq!(mm.locked_vm, 0);
        assert!(space.vma_at(BASE).is_none());
    }
}
