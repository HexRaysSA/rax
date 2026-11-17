use super::*;
use crate::user::mm::{EXTENT, Mapping, Perms, SpaceConfig};

const BASE: u64 = 0x2_0000;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn initial(abi: LinuxAbi) -> (AddressSpace, MmState, ProtectPolicy) {
    let mut mm = crate::user::linux::process::mm::initial_state(abi);
    mm.locked_vm = 0;
    let space = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 8 * EXTENT,
        reserved_phys: vec![(PAGE_SIZE, PAGE_SIZE)],
    })
    .unwrap();
    (space, mm, ProtectPolicy { abi, persona: 0 })
}

#[test]
fn unmap_checks_seals_before_changing_mappings_or_lock_accounts_for_every_abi() {
    for abi in ABIS {
        let (space, mut mm, _) = initial(abi);
        let pinned = mm.pinned_vm.clone();
        let break_before = mm.brk;
        let mut mapping = Mapping::anonymous(Perms::READ | Perms::WRITE);
        mapping.flags = vma_flags::LOCKED_MASK;
        space.map(BASE, 3 * PAGE_SIZE, mapping).unwrap();
        mm.locked_vm = 3;
        assert_eq!(mm.seal_range(&space, BASE + 2 * PAGE_SIZE, 1, 0), Ok(0));
        for (address, length, error) in [
            (BASE + 1, PAGE_SIZE, EINVAL),
            (BASE, 0, EINVAL),
            (abi.task_size(), 1, EINVAL),
            (BASE, u64::MAX, EINVAL),
            (BASE, 2 * PAGE_SIZE + 1, EPERM),
        ] {
            assert_eq!(
                mm.unmap_range(&space, abi, address, length),
                Err(Errno(error))
            );
            assert_eq!(mm.locked_vm, 3);
            assert!(space.first_unmapped(BASE, 3 * PAGE_SIZE).is_none());
        }
        assert_eq!(mm.unmap_range(&space, abi, BASE, PAGE_SIZE + 1), Ok(0));
        assert_eq!(mm.locked_vm, 1);
        assert!(space.vma_at(BASE).is_none());
        assert!(space.vma_at(BASE + PAGE_SIZE).is_none());
        assert!(space.vma_at(BASE + 2 * PAGE_SIZE).is_some());
        // Unmapping an existing hole succeeds without uncharging it again.
        assert_eq!(mm.unmap_range(&space, abi, BASE, 2 * PAGE_SIZE), Ok(0));
        assert_eq!(mm.locked_vm, 1);
        assert_eq!(mm.brk, break_before);
        assert!(std::sync::Arc::ptr_eq(&pinned, &mm.pinned_vm));
    }
}

#[test]
fn protection_preserves_partial_hole_denied_write_and_seal_order_for_every_abi() {
    for abi in ABIS {
        let (space, mut mm, mut policy) = initial(abi);
        space
            .map(
                BASE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        let mut last = Mapping::anonymous(Perms::READ | Perms::WRITE);
        last.flags = vma_flags::DENY_WRITE | vma_flags::SEALED;
        space.map(BASE + 2 * PAGE_SIZE, PAGE_SIZE, last).unwrap();
        assert_eq!(
            mm.protect_range(&space, policy, BASE, 3 * PAGE_SIZE, PROT_READ),
            Err(Errno(ENOMEM))
        );
        let first = space.vma_at(BASE).unwrap();
        assert!(first.perms.contains(Perms::READ));
        assert!(!first.perms.intersects(Perms::WRITE | Perms::EXEC));
        assert!(
            space
                .vma_at(BASE + 2 * PAGE_SIZE)
                .unwrap()
                .perms
                .contains(Perms::WRITE)
        );
        space
            .map(BASE + PAGE_SIZE, PAGE_SIZE, Mapping::anonymous(Perms::READ))
            .unwrap();
        assert_eq!(
            mm.protect_range(&space, policy, BASE, 3 * PAGE_SIZE, PROT_WRITE),
            Err(Errno(EACCES))
        );
        assert!(space.vma_at(BASE).unwrap().perms.contains(Perms::WRITE));
        assert_ne!(space.vma_at(BASE).unwrap().flags & vma_flags::NO_READ, 0);
        // DENY_WRITE is checked before SEALED; read-only still reaches the seal.
        assert_eq!(
            mm.protect_range(&space, policy, BASE, 3 * PAGE_SIZE, PROT_READ),
            Err(Errno(EPERM))
        );
        assert!(!space.vma_at(BASE).unwrap().perms.contains(Perms::WRITE));
        assert_eq!(space.vma_at(BASE).unwrap().flags & vma_flags::NO_READ, 0);
        assert_eq!(
            mm.protect_range(&space, policy, BASE + 1, 0, 0),
            Err(Errno(EINVAL))
        );
        assert_eq!(
            mm.protect_range(
                &space,
                policy,
                BASE,
                0,
                u32::MAX & !(PROT_GROWSDOWN | PROT_GROWSUP)
            ),
            Ok(0)
        );
        assert_eq!(
            mm.protect_range(&space, policy, BASE, 0, PROT_GROWSDOWN | PROT_GROWSUP),
            Err(Errno(EINVAL))
        );
        assert_eq!(
            mm.protect_range(&space, policy, BASE, u64::MAX, PROT_READ),
            Err(Errno(ENOMEM))
        );
        policy.persona = READ_IMPLIES_EXEC;
        assert_eq!(
            mm.protect_range(&space, policy, BASE, PAGE_SIZE, PROT_READ),
            Ok(0)
        );
        assert!(space.vma_at(BASE).unwrap().perms.contains(Perms::EXEC));
    }
}

#[test]
fn sealing_validates_the_whole_range_before_publishing_any_seal_for_every_abi() {
    for abi in ABIS {
        let (space, mut mm, policy) = initial(abi);
        space
            .map(BASE, PAGE_SIZE, Mapping::anonymous(Perms::READ))
            .unwrap();
        space
            .map(
                BASE + 2 * PAGE_SIZE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ),
            )
            .unwrap();
        for (start, length, flags, error) in [
            (BASE, 0, 1, EINVAL),
            (BASE + 1, 0, 0, EINVAL),
            (BASE, u64::MAX, 0, EINVAL),
            (u64::MAX & !PAGE_MASK, PAGE_SIZE, 0, EINVAL),
            (BASE, 3 * PAGE_SIZE, 0, ENOMEM),
        ] {
            assert_eq!(
                mm.seal_range(&space, start, length, flags),
                Err(Errno(error))
            );
            assert_eq!(space.vma_at(BASE).unwrap().flags & vma_flags::SEALED, 0);
            assert_eq!(
                space.vma_at(BASE + 2 * PAGE_SIZE).unwrap().flags & vma_flags::SEALED,
                0
            );
        }
        assert_eq!(mm.seal_range(&space, BASE, 0, 0), Ok(0));
        space
            .map(BASE + PAGE_SIZE, PAGE_SIZE, Mapping::anonymous(Perms::READ))
            .unwrap();
        assert_eq!(mm.seal_range(&space, BASE, 2 * PAGE_SIZE + 1, 0), Ok(0));
        assert_eq!(mm.seal_range(&space, BASE, 3 * PAGE_SIZE, 0), Ok(0));
        for address in [BASE, BASE + PAGE_SIZE, BASE + 2 * PAGE_SIZE] {
            assert_ne!(space.vma_at(address).unwrap().flags & vma_flags::SEALED, 0);
        }
        assert_eq!(
            mm.protect_range(&space, policy, BASE, PAGE_SIZE, PROT_READ),
            Err(Errno(EPERM))
        );
        assert_eq!(
            mm.unmap_range(&space, abi, BASE, PAGE_SIZE),
            Err(Errno(EPERM))
        );
    }
}
