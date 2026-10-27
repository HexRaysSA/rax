//! Native ARM stack projection policy, independently executable on all hosts.
#[path = "../../../src/backend/hvf/arm64_stack.rs"]
mod stack;
#[test]
fn thread_modes_select_el0_stack() {
    for mode in [0, 4] {
        assert_eq!(stack::current_sp(mode, 11, 22), Some(11));
    }
}
#[test]
fn handler_mode_selects_el1_stack() {
    assert_eq!(stack::current_sp(5, 11, 22), Some(22));
}
#[test]
fn every_unrepresented_mode_rejects_before_a_stack_effect_is_prepared() {
    for mode in 0..32 {
        if [0, 4, 5].contains(&mode) {
            continue;
        }
        assert_eq!(stack::current_sp(mode, 11, 22), None);
        assert_eq!(stack::restored_banks(mode, 33, 11, 22), None);
    }
}
#[test]
fn current_thread_stack_overlays_only_el0_bank() {
    for mode in [0, 4] {
        assert_eq!(stack::restored_banks(mode, 33, 11, 22), Some([33, 22]));
    }
}
#[test]
fn current_handler_stack_overlays_only_el1_bank() {
    assert_eq!(stack::restored_banks(5, 33, 11, 22), Some([11, 33]));
}
#[test]
fn full_width_stack_values_are_not_aligned_masked_or_truncated() {
    for current in [0, 1, 0xffff_ffff, 0x1_0000_0001, u64::MAX] {
        for mode in [0, 4, 5] {
            let banks =
                stack::restored_banks(mode, current, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444)
                    .unwrap();
            assert_eq!(stack::current_sp(mode, banks[0], banks[1]), Some(current));
        }
    }
}
#[test]
fn mode_selection_preserves_all_other_pstate_bits() {
    for flags in [0, 0x3c0, 0xf000_0000, 1 << 21, 1 << 22, 1 << 24, 1 << 63] {
        for mode in [0, 4, 5] {
            assert_eq!(
                stack::restored_banks(flags | mode, 33, 11, 22),
                stack::restored_banks(mode, 33, 11, 22)
            );
        }
    }
}
#[test]
fn seeded_projection_roundtrip_preserves_the_inactive_bank() {
    let mut seed = 0x7261785f73746163u64;
    for i in 0..10000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mode = [0, 4, 5][i % 3];
        let inactive = seed.rotate_left(17);
        let old_current = !seed;
        let banks = stack::restored_banks(mode, seed, inactive, old_current).unwrap();
        assert_eq!(stack::current_sp(mode, banks[0], banks[1]), Some(seed));
        if mode == 5 {
            assert_eq!(banks[0], inactive);
        } else {
            assert_eq!(banks[1], old_current);
        }
    }
}
pub fn emit_reference(path: &std::path::Path) {
    let mut bytes = Vec::new();
    let mut seed = 0x7261785f73746163u64;
    for i in 0..10000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mode = (i % 32) as u64;
        let current = seed;
        let a = seed.rotate_left(17);
        let b = !seed;
        let prepared = stack::restored_banks(mode, current, a, b);
        let valid = u64::from(prepared.is_some());
        let banks = prepared.unwrap_or([a, b]);
        let read = stack::current_sp(mode, banks[0], banks[1]).unwrap_or(0);
        for word in [mode, current, a, b, valid, banks[0], banks[1], read] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    std::fs::write(path, bytes).unwrap();
}
