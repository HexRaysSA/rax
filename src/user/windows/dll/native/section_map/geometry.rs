//! Image-view geometry observed on native build29683 and its WoW64 wrappers.
use crate::user::windows::memory::{ALLOCATION_GRANULARITY, VirtualMemory, mem};
use crate::user::windows::nt::status::*;

pub(super) struct Plan {
    pub(super) allocation_base: u64,
    pub(super) image_base: u64,
    pub(super) allocation_size: u64,
    pub(super) size: u64,
    pub(super) offset: u64,
    pub(super) large: bool,
}
pub(super) fn ceiling(zero: u64, high: u64) -> Result<u64, u32> {
    if zero == 0 {
        return Ok(high);
    }
    if zero < 32 {
        if zero > 21 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        return Ok(high.min(1u64 << (32 - zero)));
    }
    let bits = 64 - zero.leading_zeros();
    if bits < 11 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(if bits == 64 {
        high
    } else {
        high.min(1u64 << bits)
    })
}
pub(super) fn plan(
    vm: &VirtualMemory,
    preferred: u64,
    full_size: u64,
    requested_base: u64,
    requested_size: u64,
    offset: u64,
    zero: u64,
    commit: u64,
    flags: u32,
    wow: bool,
) -> Result<Plan, u32> {
    with_low_placement(
        vm,
        preferred,
        full_size,
        requested_base,
        requested_size,
        offset,
        zero,
        commit,
        flags,
        wow,
        None,
    )
}
pub(super) fn with_low_placement(
    vm: &VirtualMemory,
    preferred: u64,
    full_size: u64,
    requested_base: u64,
    requested_size: u64,
    offset: u64,
    zero: u64,
    commit: u64,
    flags: u32,
    wow: bool,
    low_placement: Option<u64>,
) -> Result<Plan, u32> {
    with_extensions(
        vm,
        Some(preferred),
        full_size,
        requested_base,
        requested_size,
        offset,
        zero,
        commit,
        flags,
        wow,
        low_placement,
        0,
        true,
    )
}
pub(super) fn with_extensions(
    vm: &VirtualMemory,
    preferred: Option<u64>,
    full_size: u64,
    requested_base: u64,
    requested_size: u64,
    offset: u64,
    zero: u64,
    commit: u64,
    flags: u32,
    wow: bool,
    low_placement: Option<u64>,
    extension_size: u64,
    large_pages: bool,
) -> Result<Plan, u32> {
    let high = ceiling(zero, vm.high())?;
    let size_limit = if wow {
        if vm.high() > 0x7FFF_0000 {
            1u64 << 32
        } else {
            1u64 << 31
        }
    } else {
        vm.high()
    };
    if !wow && requested_base >= vm.high() || requested_size > size_limit {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if requested_base % ALLOCATION_GRANULARITY != 0 || offset % ALLOCATION_GRANULARITY != 0 {
        return Err(STATUS_MAPPED_ALIGNMENT);
    }
    if commit > full_size {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if offset >= full_size {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    let remaining = full_size - offset;
    if requested_size > remaining {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    let size = if requested_size == 0 {
        remaining
    } else {
        requested_size
            .checked_add(4095)
            .ok_or(STATUS_INVALID_PARAMETER)?
            & !4095
    };
    if size > remaining {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    let footprint = size
        .checked_add(
            if offset == 0
                && size == full_size
                && !(large_pages && flags & 0x2000_0000 != 0 && requested_base == 0)
            {
                extension_size
            } else {
                0
            },
        )
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if requested_base != 0
        && zero != 0
        && requested_base
            .checked_add(footprint)
            .is_none_or(|end| end > high)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let requested_large = flags & 0x2000_0000 != 0;
    if requested_large && flags & 0x0080_0000 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Native SEC_IMAGE large pages are opportunistic. Explicit placement and
    // nonzero offsets use the ordinary image page policy in the recorded calls.
    let top = flags & mem::TOP_DOWN != 0;
    if let Some(preferred) =
        preferred.filter(|_| large_pages && requested_large && requested_base == 0 && offset == 0)
    {
        let prefix = preferred % (2 << 20);
        let allocation_size = prefix
            .checked_add(footprint)
            .and_then(|n| n.checked_add((2 << 20) - 1))
            .ok_or(STATUS_INVALID_PARAMETER)?
            & !((2 << 20) - 1);
        let allocation_base = vm
            .find_free(allocation_size, 2 << 20, vm.low(), high, top)
            .ok_or(STATUS_NO_MEMORY)?;
        return Ok(Plan {
            allocation_base,
            image_base: allocation_base + prefix,
            allocation_size,
            size,
            offset,
            large: true,
        });
    }
    let preferred = preferred
        .map(|base| base.checked_add(offset).ok_or(STATUS_CONFLICTING_ADDRESSES))
        .transpose()?;
    let image_base = if requested_base != 0 {
        requested_base
    } else if let Some(preferred) = preferred.filter(|base| {
        base.checked_add(footprint).is_some_and(|end| end <= high) && vm.is_free(*base, footprint)
    }) {
        preferred
    } else if let Some(placement) = low_placement.filter(|_| high <= 1u64 << 32) {
        // The native randomized low image candidate is retained across unmap.
        // A stricter ZeroBits ceiling can reject it even with other free low
        // addresses. Explicit bases and a free preferred base bypass the hint.
        if placement
            .checked_add(footprint)
            .is_none_or(|end| end > high)
        {
            return Err(STATUS_NO_MEMORY);
        }
        vm.find_free(
            footprint,
            ALLOCATION_GRANULARITY,
            placement.max(vm.low()),
            high,
            top,
        )
        .ok_or(STATUS_NO_MEMORY)?
    } else {
        vm.find_free(footprint, ALLOCATION_GRANULARITY, vm.low(), high, top)
            .ok_or(STATUS_NO_MEMORY)?
    };
    if !vm.is_free(image_base, footprint) {
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }
    Ok(Plan {
        allocation_base: image_base,
        image_base,
        allocation_size: footprint,
        size,
        offset,
        large: false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, SpaceConfig};
    use crate::user::windows::memory::{AllocKind, prot};
    fn memory() -> VirtualMemory {
        VirtualMemory::new(
            AddressSpace::new(SpaceConfig {
                va_limit: 1 << 32,
                arena_bytes: 4 << 20,
                reserved_phys: vec![],
            })
            .unwrap(),
            65536,
            1 << 32,
        )
    }
    #[test]
    fn image_extension_compatibility_large_flag_keeps_ordinary_geometry_and_conflict_validation() {
        let vm = memory();
        let p = with_extensions(
            &vm,
            Some(0x70000000),
            0x3000,
            0,
            0,
            0,
            0,
            0,
            0x20000000,
            false,
            None,
            0x2000,
            false,
        )
        .unwrap();
        assert!(!p.large);
        assert_eq!(p.allocation_size, 0x5000);
        assert_eq!(
            with_extensions(
                &vm,
                Some(0x70000000),
                0x3000,
                0,
                0,
                0,
                0,
                0,
                0x20800000,
                false,
                None,
                0x2000,
                false
            )
            .err(),
            Some(STATUS_INVALID_PARAMETER)
        );
    }
    #[test]
    fn image_extension_owner_geometry_reserves_full_tail_and_omits_partial_or_large_tail() {
        let vm = memory();
        for (size, flags, allocation, large) in [
            (0, 0, 0x5000, false),
            (0x3000, 0, 0x5000, false),
            (0x1000, 0, 0x1000, false),
            (0, 0x20000000, 0x200000, true),
        ] {
            let p = with_extensions(
                &vm,
                Some(0x70000000),
                0x3000,
                0,
                size,
                0,
                0,
                0,
                flags,
                false,
                None,
                0x2000,
                true,
            )
            .unwrap();
            assert_eq!(p.allocation_size, allocation);
            assert_eq!(p.large, large);
        }
    }
    #[test]
    fn zero_bits_count_mask_and_full_width_limits_match_native_controls() {
        let high = 1 << 47;
        assert_eq!(ceiling(0, high), Ok(high));
        for n in 1..=21 {
            assert_eq!(ceiling(n, high), Ok(1u64 << (32 - n)));
        }
        for n in [22, 23, 30, 31, 32, 63, 511, 512, 1023] {
            assert_eq!(ceiling(n, high), Err(STATUS_INVALID_PARAMETER));
        }
        for (mask, limit) in [
            (1024, 2048),
            (2047, 2048),
            (2048, 4096),
            (4095, 4096),
            (0x1000FFFF, 1 << 29),
            (0x7FFFFFFF, 1 << 31),
            (0xFFFFFFFF, 1 << 32),
            (0x100000000, 1 << 33),
            (u64::MAX, high),
        ] {
            assert_eq!(ceiling(mask, high), Ok(limit));
        }
    }
    #[test]
    fn image_view_geometry_rounds_pages_and_falls_back_from_large_requests() {
        let mut vm = memory();
        let full = 0x171000;
        let preferred = 0x70600000;
        for n in [0, 1, 4095, 4096, 65535] {
            let p = plan(&vm, preferred, full, 0, n, 0, 0, 0, 0, false).unwrap();
            assert_eq!(p.image_base, preferred);
            assert_eq!(p.size, if n == 0 { full } else { (n + 4095) & !4095 });
        }
        let p = plan(&vm, preferred, full, 0, 0, 65536, 0, 0, 0, false).unwrap();
        assert_eq!(
            (p.image_base, p.size, p.offset),
            (preferred + 65536, full - 65536, 65536)
        );
        let p = plan(&vm, preferred, full, 0, 0, 0, 0, 0, 0x20000000, false).unwrap();
        assert!(p.large);
        assert_eq!(p.allocation_base % (2 << 20), 0);
        assert_eq!(p.image_base - p.allocation_base, preferred % (2 << 20));
        for (base, offset) in [(0x50010000, 0), (0, 65536)] {
            let p = plan(
                &vm, preferred, full, base, 4096, offset, 0, 0, 0x20000000, false,
            )
            .unwrap();
            assert!(!p.large);
            assert_eq!(p.allocation_size, 4096);
        }
        vm.reserve(
            Some(preferred),
            full,
            prot::READONLY,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
        let p = plan(&vm, preferred, full, 0, 0, 0, 0, 0, 0, false).unwrap();
        assert_ne!(p.image_base, preferred);
        assert_eq!(p.image_base % 65536, 0);
        assert_eq!(
            plan(&vm, preferred, full, preferred, 0, 0, 0, 0, 0, false).err(),
            Some(STATUS_CONFLICTING_ADDRESSES)
        );
    }
    #[test]
    fn invalid_view_inputs_preserve_status_partitions() {
        let vm = memory();
        for (base, size, offset, zero, commit, flags, status) in [
            (1, 0, 0, 0, 0, 0, STATUS_MAPPED_ALIGNMENT),
            (0, 0, 4096, 0, 0, 0, STATUS_MAPPED_ALIGNMENT),
            (0, 0, 0x180000, 0, 0, 0, STATUS_INVALID_VIEW_SIZE),
            (0, 0x180000, 0, 0, 0, 0, STATUS_INVALID_VIEW_SIZE),
            (0, 0, 0, 22, 0, 0, STATUS_INVALID_PARAMETER),
            (0, 0, 0, 0, 0x180000, 0, STATUS_INVALID_PARAMETER),
            (0, 0, 0, 0, 0, 0x20800000, STATUS_INVALID_PARAMETER),
            (u64::MAX, 0, 0, 0, 0, 0, STATUS_INVALID_PARAMETER),
        ] {
            assert_eq!(
                plan(
                    &vm, 0x70600000, 0x171000, base, size, offset, zero, commit, flags, false
                )
                .err(),
                Some(status)
            );
        }
        assert_eq!(
            plan(
                &vm,
                0x70600000,
                0x171000,
                u32::MAX.into(),
                0,
                0,
                0,
                0,
                0,
                true
            )
            .err(),
            Some(STATUS_MAPPED_ALIGNMENT)
        );
    }
    #[test]
    fn retained_randomized_low_candidate_can_fail_a_tighter_ceiling_with_free_space() {
        let vm = memory();
        assert!(vm.is_free(65536, 0x171000));
        assert_eq!(
            with_low_placement(
                &vm,
                0x7FF8DD860000,
                0x171000,
                0,
                0,
                0,
                8,
                0,
                0x800000,
                false,
                Some(0xEE0000)
            )
            .err(),
            Some(STATUS_NO_MEMORY)
        );
        let p = with_low_placement(
            &vm,
            0x7FF8DD860000,
            0x171000,
            0,
            0,
            0,
            8,
            0,
            0x800000,
            false,
            Some(0xA30000),
        )
        .unwrap();
        assert_eq!(p.image_base, 0xA30000);
        let p = with_low_placement(
            &vm,
            0x7FF8DD860000,
            0x171000,
            65536,
            0,
            0,
            8,
            0,
            0x800000,
            false,
            Some(0xEE0000),
        )
        .unwrap();
        assert_eq!(p.image_base, 65536);
        let mut vm = memory();
        vm.reserve(
            Some(0x550000),
            0x171000,
            prot::READONLY,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
        let second = with_low_placement(
            &vm,
            0x7FF8DD860000,
            0x171000,
            0,
            0,
            0,
            1,
            0,
            0x800000,
            false,
            Some(0x550000),
        )
        .unwrap();
        assert_eq!(second.image_base, 0x6D0000);
        vm.reserve(
            Some(second.image_base),
            second.size,
            prot::READONLY,
            AllocKind::Private,
            false,
            None,
        )
        .unwrap();
        let third = with_low_placement(
            &vm,
            0x7FF8DD860000,
            0x171000,
            0,
            0,
            0,
            8,
            0,
            0x800000,
            false,
            Some(0x550000),
        )
        .unwrap();
        assert_eq!(third.image_base, 0x850000);
        vm.release(0x550000).unwrap();
        vm.release(0x6D0000).unwrap();
        let reused = with_low_placement(
            &vm,
            0x7FF8DD860000,
            0x171000,
            0,
            0,
            0,
            1,
            0,
            0x800000,
            false,
            Some(0x550000),
        )
        .unwrap();
        assert_eq!(reused.image_base, 0x550000);
    }
}
