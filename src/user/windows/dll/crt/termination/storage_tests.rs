//! Internal global queues across x86/x64/ARM64, not exit-export acceptance.
//! SDK insertion/visited order is tested; private addresses, fault recovery and
//! ownership-safe nested-reset behavior are explicit personality profiles.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::dll::crt::{RuntimeKind, state, tests::run};
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::prot;

fn heap(c: &mut Ctx, kind: RuntimeKind) -> u64 {
    state::ensure_heap(c, kind).unwrap()
}
fn queue(state: &TerminationState, kind: Kind) -> Queue {
    state.0.borrow().queues[kind.index()]
}
fn fault<T>(result: Result<T, TerminationError>) -> MemFault {
    match result {
        Err(TerminationError::Fault(fault)) => fault,
        _ => panic!("expected checked guest memory fault"),
    }
}
fn fill(state: &TerminationState, c: &mut Ctx, h: u64, kind: Kind, count: u64) {
    for index in 0..count {
        state.register(c.p, h, kind, 0x1000 + index).unwrap();
    }
}
fn finish(state: &TerminationState, c: &mut Ctx, kind: Kind) -> Vec<u64> {
    let mut drain = state.begin(kind, c.t.tid).unwrap();
    let mut result = Vec::new();
    while let Some(target) = drain.next(c.p).unwrap() {
        result.push(target);
    }
    drain.finish(c.p).unwrap();
    result
}

#[test]
fn queues_are_runtime_and_kind_isolated_and_do_not_use_malloc_ledger() {
    run(|c| {
        let ordinary = TerminationState::default();
        let other = TerminationState::default();
        let a = heap(c, RuntimeKind::Msvcrt);
        let b = heap(c, RuntimeKind::Ucrt);
        ordinary.register(c.p, a, Kind::Ordinary, 0x1111).unwrap();
        ordinary.register(c.p, a, Kind::Quick, 0x2222).unwrap();
        other.register(c.p, b, Kind::Ordinary, 0x3333).unwrap();
        let block = queue(&ordinary, Kind::Ordinary).buffer.unwrap();
        assert_eq!(
            c.p.heaps.size(a, block.base).unwrap(),
            32 * c.arch().ptr_size()
        );
        assert!(!c.p.crt.runtimes[0].allocations.contains_key(&block.base));
        assert!(c.p.crt.atexit.is_empty());
        assert_eq!(finish(&ordinary, c, Kind::Ordinary), [0x1111]);
        assert_eq!(finish(&other, c, Kind::Ordinary), [0x3333]);
        assert_eq!(finish(&ordinary, c, Kind::Quick), [0x2222]);
        assert!(c.p.heaps.size(a, block.base).is_err());
        ordinary.discard_process(c.p).unwrap();
        other.discard_process(c.p).unwrap();
    });
}

#[test]
fn insertion_length_lifo_duplicate_callbacks_and_null_holes_match_sdk_scan() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        for target in [0x1111, 0, 0x2222, 0, 0x2222] {
            s.register(c.p, h, Kind::Ordinary, target).unwrap();
        }
        let before = queue(&s, Kind::Ordinary);
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0x2222));
        assert_eq!(queue(&s, Kind::Ordinary).length, 5);
        let block = before.buffer.unwrap();
        assert_eq!(
            c.mem()
                .ptr(block.base + 4 * c.arch().ptr_size(), c.arch().ptr_size())
                .unwrap(),
            0
        );
        assert_eq!(drain.next(c.p).unwrap(), Some(0x2222));
        assert_eq!(drain.next(c.p).unwrap(), Some(0x1111));
        assert_eq!(drain.next(c.p).unwrap(), None);
        drain.finish(c.p).unwrap();
        assert!(queue(&s, Kind::Ordinary).buffer.is_none());
        assert_eq!(queue(&s, Kind::Ordinary).length, 0);
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn callback_registration_restarts_at_latest_insertion_endpoint_without_replay() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        for target in [0x1111, 0x2222] {
            s.register(c.p, h, Kind::Ordinary, target).unwrap();
        }
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0x2222));
        s.register(c.p, h, Kind::Ordinary, 0x3333).unwrap();
        assert_eq!(queue(&s, Kind::Ordinary).length, 3);
        assert_eq!(drain.next(c.p).unwrap(), Some(0x3333));
        assert_eq!(drain.next(c.p).unwrap(), Some(0x1111));
        assert_eq!(drain.next(c.p).unwrap(), None);
        drain.finish(c.p).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn growth_during_callback_preserves_visited_holes_and_refreshes_buffer_identity() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        fill(&s, c, h, Kind::Ordinary, 32);
        let old = queue(&s, Kind::Ordinary).buffer.unwrap();
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0x101F));
        s.register(c.p, h, Kind::Ordinary, 0xABCD).unwrap();
        let new = queue(&s, Kind::Ordinary).buffer.unwrap();
        assert_ne!(old.generation, new.generation);
        assert!(c.p.heaps.size(h, old.base).is_err());
        assert_eq!(drain.next(c.p).unwrap(), Some(0xABCD));
        for index in (0..31).rev() {
            assert_eq!(drain.next(c.p).unwrap(), Some(0x1000 + index));
        }
        assert_eq!(drain.next(c.p).unwrap(), None);
        drain.finish(c.p).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn nested_drain_consumes_remaining_slots_once_and_outer_safely_observes_reset() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        fill(&s, c, h, Kind::Ordinary, 3);
        let mut outer = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert_eq!(outer.next(c.p).unwrap(), Some(0x1002));
        assert_eq!(finish(&s, c, Kind::Ordinary), [0x1001, 0x1000]);
        assert_eq!(outer.next(c.p).unwrap(), None);
        outer.finish(c.p).unwrap();
        assert!(s.0.borrow().active.is_empty());
        assert!(s.take_abandoned().unwrap().is_empty());
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn nested_reset_then_fresh_registration_uses_new_generation_even_if_base_reused() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        fill(&s, c, h, Kind::Ordinary, 2);
        let old = queue(&s, Kind::Ordinary).buffer.unwrap();
        let mut outer = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert_eq!(outer.next(c.p).unwrap(), Some(0x1001));
        assert_eq!(finish(&s, c, Kind::Ordinary), [0x1000]);
        s.register(c.p, h, Kind::Ordinary, 0xABCD).unwrap();
        let new = queue(&s, Kind::Ordinary).buffer.unwrap();
        assert_ne!(old.generation, new.generation);
        assert_eq!(outer.next(c.p).unwrap(), Some(0xABCD));
        assert_eq!(outer.next(c.p).unwrap(), None);
        outer.finish(c.p).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn ordinary_and_quick_nested_tickets_are_independent_without_storage_lock_policy() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        s.register(c.p, h, Kind::Ordinary, 0x1111).unwrap();
        s.register(c.p, h, Kind::Quick, 0x2222).unwrap();
        let mut ordinary = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert_eq!(ordinary.next(c.p).unwrap(), Some(0x1111));
        assert_eq!(finish(&s, c, Kind::Quick), [0x2222]);
        assert_eq!(ordinary.next(c.p).unwrap(), None);
        ordinary.finish(c.p).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn growth_uses_sdk_capped_increment_and_zeroes_unused_tail() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        fill(&s, c, h, Kind::Ordinary, 1024);
        assert_eq!(queue(&s, Kind::Ordinary).buffer.unwrap().capacity, 1024);
        s.register(c.p, h, Kind::Ordinary, 0xAAAA).unwrap();
        let block = queue(&s, Kind::Ordinary).buffer.unwrap();
        assert_eq!(block.capacity, 1536);
        let width = c.arch().ptr_size();
        assert_eq!(
            c.mem().ptr(block.base + 1024 * width, width).unwrap(),
            0xAAAA
        );
        assert_eq!(c.mem().ptr(block.base + 1025 * width, width).unwrap(), 0);
        assert_eq!(c.mem().ptr(block.base + 1535 * width, width).unwrap(), 0);
        assert_eq!(finish(&s, c, Kind::Ordinary).len(), 1025);
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn initial_allocation_uses_four_slot_fallback_when_thirty_two_slots_do_not_fit() {
    run(|c| {
        let s = TerminationState::default();
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, PAGE_SIZE).unwrap();
        let width = c.arch().ptr_size();
        let filler =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, h, PAGE_SIZE - 0x100 - 4 * width, false)
                .unwrap();
        s.register(c.p, h, Kind::Ordinary, 0x1234).unwrap();
        assert_eq!(queue(&s, Kind::Ordinary).buffer.unwrap().capacity, 4);
        assert_eq!(finish(&s, c, Kind::Ordinary), [0x1234]);
        c.p.heaps.free(h, filler).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn growth_fallback_and_total_oom_preserve_old_entries_and_live_blocks() {
    run(|c| {
        let s = TerminationState::default();
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, PAGE_SIZE).unwrap();
        fill(&s, c, h, Kind::Ordinary, 32);
        let width = c.arch().ptr_size();
        let filler =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, h, PAGE_SIZE - 0x100 - (32 + 36) * width, false)
                .unwrap();
        s.register(c.p, h, Kind::Ordinary, 0xABCD).unwrap();
        let block = queue(&s, Kind::Ordinary).buffer.unwrap();
        assert_eq!(block.capacity, 36);
        for target in [0xAAAA, 0xBBBB, 0xCCCC] {
            s.register(c.p, h, Kind::Ordinary, target).unwrap();
        }
        let before = queue(&s, Kind::Ordinary);
        let blocks = c.p.heaps.blocks(h);
        assert!(matches!(
            s.register(c.p, h, Kind::Ordinary, 0xDEAD),
            Err(TerminationError::NoMemory)
        ));
        assert_eq!(queue(&s, Kind::Ordinary), before);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        let result = finish(&s, c, Kind::Ordinary);
        assert_eq!(result.len(), 36);
        assert_eq!(&result[..4], [0xCCCC, 0xBBBB, 0xAAAA, 0xABCD]);
        c.p.heaps.free(h, filler).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn in_capacity_write_fault_has_no_publication_or_block_effects() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        s.register(c.p, h, Kind::Ordinary, 0x1111).unwrap();
        let before = queue(&s, Kind::Ordinary);
        let block = before.buffer.unwrap();
        let blocks = c.p.heaps.blocks(h);
        let page = block.base & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let f = fault(s.register(c.p, h, Kind::Ordinary, 0x2222));
        assert!(f.write);
        assert_eq!(f.addr, block.base + c.arch().ptr_size());
        assert_eq!(queue(&s, Kind::Ordinary), before);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        s.register(c.p, h, Kind::Ordinary, 0x2222).unwrap();
        assert_eq!(finish(&s, c, Kind::Ordinary), [0x2222, 0x1111]);
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn growth_source_fault_rolls_back_candidate_and_retry_preserves_old_callbacks() {
    run(|c| {
        let s = TerminationState::default();
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, 0).unwrap();
        fill(&s, c, h, Kind::Ordinary, 32);
        let old = queue(&s, Kind::Ordinary).buffer.unwrap();
        let width = c.arch().ptr_size();
        let filler =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, h, PAGE_SIZE - 0x100 - 32 * width, false)
                .unwrap();
        let before = queue(&s, Kind::Ordinary);
        let blocks = c.p.heaps.blocks(h);
        c.p.vm.protect(h, PAGE_SIZE, prot::NOACCESS).unwrap();
        let f = fault(s.register(c.p, h, Kind::Ordinary, 0xABCD));
        assert!(!f.write);
        assert_eq!(f.addr, old.base);
        assert_eq!(queue(&s, Kind::Ordinary), before);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        c.p.vm.protect(h, PAGE_SIZE, prot::READONLY).unwrap();
        s.register(c.p, h, Kind::Ordinary, 0xABCD).unwrap();
        c.p.vm.protect(h, PAGE_SIZE, prot::READWRITE).unwrap();
        let result = finish(&s, c, Kind::Ordinary);
        assert_eq!(result.len(), 33);
        assert_eq!(result[0], 0xABCD);
        c.p.heaps.free(h, filler).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn unread_slot_fault_keeps_cursor_and_future_guest_value_is_read_lazily() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        fill(&s, c, h, Kind::Ordinary, 2);
        let block = queue(&s, Kind::Ordinary).buffer.unwrap();
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0x1001));
        let page = block.base & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::NOACCESS).unwrap();
        let f = fault(drain.next(c.p));
        assert!(!f.write);
        assert_eq!(f.addr, block.base);
        assert_eq!(drain.cursor, 1);
        assert!(drain.pending.is_none());
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        // A private-byte mutation is an adversarial checked-memory probe,
        // not permission to manipulate the CRT's private representation.
        c.mem()
            .wptr(block.base, c.arch().ptr_size(), 0xABCD)
            .unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0xABCD));
        assert_eq!(drain.next(c.p).unwrap(), None);
        drain.finish(c.p).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn clearing_fault_preserves_selected_target_without_rereading_repaired_bytes() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        s.register(c.p, h, Kind::Ordinary, 0x1234).unwrap();
        let block = queue(&s, Kind::Ordinary).buffer.unwrap();
        let page = block.base & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        let f = fault(drain.next(c.p));
        assert!(f.write);
        assert_eq!(f.addr, block.base);
        assert_eq!(drain.pending.unwrap().target, 0x1234);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        c.mem()
            .wptr(block.base, c.arch().ptr_size(), 0xDEAD)
            .unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0x1234));
        assert_eq!(c.mem().ptr(block.base, c.arch().ptr_size()).unwrap(), 0);
        assert_eq!(drain.next(c.p).unwrap(), None);
        drain.finish(c.p).unwrap();
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn reentrant_registration_during_selected_slot_repair_rejects_stale_selection() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        s.register(c.p, h, Kind::Ordinary, 0x1111).unwrap();
        let block = queue(&s, Kind::Ordinary).buffer.unwrap();
        let page = block.base & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert!(fault(drain.next(c.p)).write);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        s.register(c.p, h, Kind::Ordinary, 0x2222).unwrap();
        assert!(matches!(
            drain.next(c.p),
            Err(TerminationError::Internal(_))
        ));
        assert_eq!(
            c.mem().ptr(block.base, c.arch().ptr_size()).unwrap(),
            0x1111
        );
        drop(drain);
        let receipt = s.take_abandoned().unwrap().pop().unwrap();
        cleanup_abandoned(c.p, receipt).unwrap();
        assert_eq!(finish(&s, c, Kind::Ordinary), [0x2222, 0x1111]);
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn selected_callback_is_a_value_and_nested_reset_cannot_retarget_or_replay_it() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        fill(&s, c, h, Kind::Ordinary, 2);
        let mut outer = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        let selected = outer.next(c.p).unwrap().unwrap();
        assert_eq!(selected, 0x1001);
        assert_eq!(finish(&s, c, Kind::Ordinary), [0x1000]);
        s.register(c.p, h, Kind::Ordinary, 0x3333).unwrap();
        assert_eq!(selected, 0x1001);
        assert_eq!(outer.next(c.p).unwrap(), Some(0x3333));
        assert_eq!(outer.next(c.p).unwrap(), None);
        outer.finish(c.p).unwrap();
        s.discard_process(c.p).unwrap();
        // The facade's CallChecked continuation owns this selected scalar
        // across callback-stack faults. This storage test does not claim HLE
        // stack or cross-thread fiber migration coverage by itself.
    });
}

#[test]
fn abandoned_receipt_preserves_remaining_global_callbacks_and_owner_identity() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        fill(&s, c, h, Kind::Ordinary, 2);
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        let generation = drain.ticket.generation;
        assert_eq!(drain.next(c.p).unwrap(), Some(0x1001));
        drop(drain);
        assert_eq!(Rc::strong_count(&s.0), 1);
        assert!(s.0.borrow().active.is_empty());
        let mut receipts = s.take_abandoned().unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = receipts.pop().unwrap();
        assert_eq!(
            (receipt.tid, receipt.kind, receipt.generation),
            (c.t.tid, Kind::Ordinary, generation)
        );
        cleanup_abandoned(c.p, receipt).unwrap();
        assert!(s.take_abandoned().unwrap().is_empty());
        assert_eq!(finish(&s, c, Kind::Ordinary), [0x1000]);
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn receipt_extraction_keeps_pre_reserved_drop_capacity_and_process_discard_is_host_only() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        s.register(c.p, h, Kind::Ordinary, 0x1111).unwrap();
        s.register(c.p, h, Kind::Quick, 0x2222).unwrap();
        let blocks = [
            queue(&s, Kind::Ordinary).buffer.unwrap(),
            queue(&s, Kind::Quick).buffer.unwrap(),
        ];
        let a = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        let b = s.begin(Kind::Quick, c.t.tid).unwrap();
        let capacity = s.0.borrow().abandoned.capacity();
        assert!(matches!(
            s.discard_process(c.p),
            Err(TerminationError::Internal(_))
        ));
        drop(a);
        let receipts = s.take_abandoned().unwrap();
        assert_eq!(s.0.borrow().abandoned.capacity(), capacity);
        drop(b);
        assert_eq!(s.0.borrow().abandoned.capacity(), capacity);
        for block in blocks {
            c.p.vm
                .protect(block.base & !(PAGE_SIZE - 1), PAGE_SIZE, prot::NOACCESS)
                .unwrap();
        }
        for receipt in receipts.into_iter().chain(s.take_abandoned().unwrap()) {
            cleanup_abandoned(c.p, receipt).unwrap();
        }
        s.discard_process(c.p).unwrap();
        for block in blocks {
            assert!(c.p.heaps.size(h, block.base).is_err());
        }
        s.discard_process(c.p).unwrap();
        assert!(matches!(
            s.begin(Kind::Ordinary, c.t.tid),
            Err(TerminationError::Internal(_))
        ));
        assert!(matches!(
            s.register(c.p, h, Kind::Quick, 0),
            Err(TerminationError::Internal(_))
        ));
    });
}

#[test]
fn generation_revision_and_guest_width_exhaustion_are_checked_before_effects() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        s.0.borrow_mut().next_buffer = u64::MAX;
        assert!(matches!(
            s.register(c.p, h, Kind::Ordinary, 1),
            Err(TerminationError::GenerationExhausted)
        ));
        assert!(queue(&s, Kind::Ordinary).buffer.is_none());
        s.0.borrow_mut().next_buffer = 0;
        s.register(c.p, h, Kind::Ordinary, 0x1111).unwrap();
        s.0.borrow_mut().queues[0].revision = u64::MAX;
        let before = queue(&s, Kind::Ordinary);
        assert!(matches!(
            s.register(c.p, h, Kind::Ordinary, 2),
            Err(TerminationError::GenerationExhausted)
        ));
        assert_eq!(queue(&s, Kind::Ordinary), before);
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        assert!(matches!(
            drain.next(c.p),
            Err(TerminationError::GenerationExhausted)
        ));
        assert_eq!(
            c.mem()
                .ptr(before.buffer.unwrap().base, c.arch().ptr_size())
                .unwrap(),
            0x1111
        );
        drop(drain);
        s.0.borrow_mut().next_ticket = u64::MAX;
        assert!(matches!(
            s.begin(Kind::Quick, c.t.tid),
            Err(TerminationError::GenerationExhausted)
        ));
        if !c.arch().is64() {
            assert!(matches!(
                s.register(c.p, h, Kind::Quick, 1 << 32),
                Err(TerminationError::Invalid)
            ));
        }
        assert!(matches!(
            bytes(c.p, u64::MAX),
            Err(TerminationError::NoMemory)
        ));
        let max = c.arch().ptr(u64::MAX);
        let f = fault(range(c.p, max - 1, 4, true));
        assert!(f.write);
        assert_eq!(f.addr, if c.arch().is64() { max } else { max + 1 });
        s.discard_process(c.p).unwrap();
    });
}

#[test]
fn non_aba_raw_free_or_destroy_is_detected_without_freeing_foreign_reuse() {
    run(|c| {
        let s = TerminationState::default();
        let h = heap(c, RuntimeKind::Ucrt);
        s.register(c.p, h, Kind::Ordinary, 0x1111).unwrap();
        let block = queue(&s, Kind::Ordinary).buffer.unwrap();
        let mut drain = s.begin(Kind::Ordinary, c.t.tid).unwrap();
        c.p.heaps.free(h, block.base).unwrap();
        let foreign = c.p.heaps.alloc_checked(&mut c.p.vm, h, 16, false).unwrap();
        assert_eq!(foreign, block.base);
        assert!(matches!(
            drain.next(c.p),
            Err(TerminationError::Internal(_))
        ));
        drop(drain);
        assert!(matches!(
            cleanup_abandoned(c.p, s.take_abandoned().unwrap().pop().unwrap()),
            Err(TerminationError::Internal(_))
        ));
        assert!(matches!(
            s.discard_process(c.p),
            Err(TerminationError::Internal(_))
        ));
        assert_eq!(c.p.heaps.size(h, foreign).unwrap(), 16);
        c.p.heaps.free(h, foreign).unwrap();
        let s = TerminationState::default();
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, 0).unwrap();
        s.register(c.p, h, Kind::Quick, 0x2222).unwrap();
        let mut drain = s.begin(Kind::Quick, c.t.tid).unwrap();
        assert!(c.p.heaps.destroy(&mut c.p.vm, h));
        assert!(matches!(
            drain.next(c.p),
            Err(TerminationError::Internal(_))
        ));
        drop(drain);
        assert!(matches!(
            s.discard_process(c.p),
            Err(TerminationError::Internal(_))
        ));
        // Exact address+requested-size ABA after illegal raw frees cannot be
        // detected by current heap metadata; no stronger guarantee is claimed.
    });
}
