use super::*;
use crate::user::windows::memory::{Mem, mem};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn native_thread_stack_sizes_follow_observed_commit_and_reserve_partitions() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/specifications/windows/native-nt-thread-lifecycle/create-thread-sizing-observations-v2.json"
    )).unwrap();
    let mut count = 0;
    let mut without_stack_observation = 0;
    for profile in corpus["profiles"].as_array().unwrap() {
        for row in profile["rows"].as_array().unwrap() {
            if row["status"].as_u64().unwrap() != 0 || row["zero_bits"].as_u64().unwrap() != 0 {
                continue;
            }
            if !row["attributes"].as_bool().unwrap() {
                assert!(row.get("committed_bytes").is_none());
                assert!(row.get("reserved_bytes").is_none());
                without_stack_observation += 1;
                continue;
            }
            let commit = row["commit"].as_u64().unwrap();
            let reserve = row["reserve"].as_u64().unwrap();
            let sizes = Sizes::select(
                reserve,
                commit,
                profile["image_defaults"]["stack_reserve"].as_u64().unwrap(),
                profile["image_defaults"]["stack_commit"].as_u64().unwrap(),
            )
            .unwrap();
            assert_eq!(
                sizes.commit,
                row["committed_bytes"].as_u64().unwrap(),
                "{commit:#x}/{reserve:#x}"
            );
            assert_eq!(
                sizes.reserve,
                row["reserved_bytes"].as_u64().unwrap(),
                "{commit:#x}/{reserve:#x}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 22);
    assert_eq!(without_stack_observation, 2);
}

#[test]
fn native_thread_stack_defaults_rounding_and_overflow_remain_checked() {
    assert_eq!(
        Sizes::select(0, 0, 0, 0),
        Ok(Sizes {
            reserve: 0x10_0000,
            commit: PAGE_SIZE,
        })
    );
    assert_eq!(
        Sizes::select(0x1_0001, 1, 0, 0),
        Ok(Sizes {
            reserve: 0x2_0000,
            commit: PAGE_SIZE,
        })
    );
    for (reserve, commit, image_reserve, image_commit) in [
        (u64::MAX, PAGE_SIZE, 0, 0),
        (0, u64::MAX, 0, 0),
        (0, 0, u64::MAX, PAGE_SIZE),
        (0, 0, 0, u64::MAX),
    ] {
        assert_eq!(
            Sizes::select(reserve, commit, image_reserve, image_commit),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}

fn process() -> WindowsProcess {
    let mut config = WindowsConfig::new("native-thread-stack.exe", Vec::new());
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(
        config,
        include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe").to_vec(),
    )
    .unwrap()
}

#[test]
fn native_thread_stack_mapping_keeps_exact_commit_guard_and_reserved_lower_pages() {
    let mut process = process();
    let state = process.state_mut();
    let sizes = Sizes::select(0x1_0000, 0x2000, 0, 0).unwrap();
    let allocated = sizes.allocate(&mut state.vm).unwrap();
    assert_eq!(allocated.base - allocated.address, 0x1_0000);
    assert_eq!(allocated.base - allocated.limit, 0x2000);
    let guard = state.vm.query(allocated.limit - PAGE_SIZE).unwrap();
    assert_eq!(guard.state, mem::COMMIT);
    assert_eq!(guard.protect, prot::READWRITE | prot::GUARD);
    assert_eq!(
        state.vm.query(allocated.address).unwrap().state,
        mem::RESERVE
    );
    state.space.w32(allocated.limit, 0x1234).unwrap();
    state.vm.release(allocated.address).unwrap();
    assert_eq!(state.vm.query(allocated.address).unwrap().state, mem::FREE);
}

#[test]
fn native_thread_full_commit_has_no_out_of_reservation_guard() {
    let mut process = process();
    let state = process.state_mut();
    let sizes = Sizes::select(0x10_0000, 0x20_0000, 0, 0).unwrap();
    let allocated = sizes.allocate(&mut state.vm).unwrap();
    assert_eq!(allocated.limit, allocated.address);
    assert_eq!(allocated.base - allocated.limit, 0x20_0000);
    assert_eq!(
        state.vm.query(allocated.limit).unwrap().protect,
        prot::READWRITE
    );
    state.vm.release(allocated.address).unwrap();
}

#[test]
fn native_thread_zero_bits_replays_independent_placement_boundaries() {
    use crate::user::mm::{AddressSpace, SpaceConfig};
    for zero_bits in 1..=21 {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 4 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let mut vm = VirtualMemory::new(space, RESERVE_GRANULARITY, 1 << 32);
        let sizes = Sizes::select(0, 0, 0x8_0000, 0x2000).unwrap();
        let result = sizes.allocate_with_zero_bits(&mut vm, zero_bits);
        if zero_bits <= 12 {
            let allocated = result.unwrap();
            assert_eq!(allocated.address, 0x1_0000);
            assert_eq!(allocated.base, 0x9_0000);
            vm.release(allocated.address).unwrap();
        } else {
            assert_eq!(
                result,
                Err(if zero_bits == 13 {
                    STATUS_CONFLICTING_ADDRESSES
                } else {
                    STATUS_INVALID_PARAMETER
                }),
                "ZeroBits={zero_bits}"
            );
            assert_eq!(vm.allocations().count(), 0);
        }
    }
}
