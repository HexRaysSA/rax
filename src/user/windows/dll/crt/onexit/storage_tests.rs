//! Storage invariants, not an oracle for native UCRT's opaque representation.
//! Every test uses x86, x64 and ARM64 guest pointer widths via the CRT harness.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::dll::crt::{
    RuntimeKind, state,
    tests::{area, run},
};
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::{mem, prot};

fn heap(c: &mut Ctx) -> u64 {
    state::ensure_heap(c, RuntimeKind::Ucrt).unwrap()
}

fn fault<T>(result: Result<T, TableError>) -> MemFault {
    match result {
        Err(TableError::Fault(fault)) => fault,
        _ => panic!("expected a checked guest-memory fault"),
    }
}

fn current(tables: &OnExitState, table: u64) -> (u64, bool, Option<Buffer>, u64) {
    let entry = tables.0.borrow().tables[&table];
    (
        entry.generation,
        entry.initialized,
        entry.buffer,
        entry.length,
    )
}

fn fill(tables: &OnExitState, c: &mut Ctx, heap: u64, table: u64, count: u64) {
    for index in 0..count {
        tables.register(c.p, heap, table, 0x1000 + index).unwrap();
    }
}

#[test]
fn initialize_writes_exact_three_guest_pointers_and_requires_valid_alignment() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let width = c.arch().ptr_size();
        c.mem().wr(table, &[0xA5; 32]).unwrap();
        assert!(matches!(
            tables.initialize(c.p, 0),
            Err(TableError::Invalid)
        ));
        assert!(matches!(
            tables.initialize(c.p, table + 1),
            Err(TableError::Invalid)
        ));
        assert!(tables.0.borrow().tables.is_empty());
        tables.initialize(c.p, table).unwrap();
        assert_eq!(read_table(c.p, table).unwrap(), [0; 3]);
        assert_eq!(c.mem().u8(table + 3 * width).unwrap(), 0xA5);
        assert_eq!(current(&tables, table), (1, true, None, 0));
        tables.initialize(c.p, table).unwrap();
        assert_eq!(current(&tables, table), (2, true, None, 0));
        assert!(tables.0.borrow().owned.is_empty());
    });
}

#[test]
fn initialization_cross_page_fault_is_atomic_and_preserves_old_generation() {
    run(|c| {
        let tables = OnExitState::default();
        let mapping =
            c.p.vm
                .allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        let width = c.arch().ptr_size();
        let table = mapping + PAGE_SIZE - 2 * width;
        c.mem().wr(table, &[0x6D; 24]).unwrap();
        c.p.vm
            .protect(mapping + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
            .unwrap();
        let f = fault(tables.initialize(c.p, table));
        assert!(f.write);
        assert_eq!(f.addr, mapping + PAGE_SIZE);
        assert_eq!(
            c.mem().bytes(table, 3 * width as usize).unwrap(),
            vec![0x6D; 3 * width as usize]
        );
        assert!(tables.0.borrow().tables.is_empty());
        c.p.vm
            .protect(mapping + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        tables.initialize(c.p, table).unwrap();
        let h = heap(c);
        tables.register(c.p, h, table, 0x1234).unwrap();
        let before = current(&tables, table);
        let fields = read_table(c.p, table).unwrap();
        let blocks = c.p.heaps.blocks(h);
        c.p.vm
            .protect(mapping + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
            .unwrap();
        assert!(fault(tables.initialize(c.p, table)).write);
        assert_eq!(current(&tables, table), before);
        assert_eq!(read_table(c.p, table).unwrap(), fields);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        c.p.vm
            .protect(mapping + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        tables.discard_process(c.p).unwrap();
    });
}

#[test]
fn execute_is_lifo_skips_null_and_invalidates_until_reinitialize() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        assert!(matches!(
            tables.register(c.p, h, table, 1),
            Err(TableError::Invalid)
        ));
        assert!(matches!(
            tables.begin_execute(c.p, table, c.t.tid),
            Err(TableError::Invalid)
        ));
        tables.initialize(c.p, table).unwrap();
        for target in [0x1111, 0, 0x2222, 0, 0x3333] {
            tables.register(c.p, h, table, target).unwrap();
        }
        let buffer = current(&tables, table).2.unwrap();
        assert_eq!(
            read_table(c.p, table).unwrap(),
            [
                buffer.base,
                buffer.base + 5 * c.arch().ptr_size(),
                buffer.base + INITIAL_CAPACITY * c.arch().ptr_size()
            ]
        );
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert_eq!(read_table(c.p, table).unwrap(), [0; 3]);
        assert!(matches!(
            tables.register(c.p, h, table, 1),
            Err(TableError::Invalid)
        ));
        assert!(matches!(
            tables.begin_execute(c.p, table, c.t.tid),
            Err(TableError::Invalid)
        ));
        for target in [0x3333, 0x2222, 0x1111] {
            assert_eq!(drain.next(c.p).unwrap(), Some(target));
        }
        assert_eq!(drain.next(c.p).unwrap(), None);
        drain.finish(c.p).unwrap();
        assert_eq!(tables.0.borrow().active, 0);
        assert!(tables.0.borrow().owned.is_empty());
        assert!(tables.take_abandoned().unwrap().is_empty());
        assert!(c.p.heaps.size(h, buffer.base).is_err());
        tables.initialize(c.p, table).unwrap();
        tables
            .begin_execute(c.p, table, c.t.tid)
            .unwrap()
            .finish(c.p)
            .unwrap();
    });
}

#[test]
fn growth_is_fresh_preserves_order_and_never_enters_malloc_ledger() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        let ledger = c.p.crt.runtimes[RuntimeKind::Ucrt.index()]
            .allocations
            .clone();
        let blocks = c.p.heaps.blocks(h);
        tables.initialize(c.p, table).unwrap();
        fill(&tables, c, h, table, INITIAL_CAPACITY);
        let old = current(&tables, table).2.unwrap();
        assert_eq!(old.capacity, INITIAL_CAPACITY);
        tables.register(c.p, h, table, 0xABCD).unwrap();
        let new = current(&tables, table).2.unwrap();
        assert_ne!(new.base, old.base);
        assert_eq!(new.capacity, 2 * INITIAL_CAPACITY);
        assert!(c.p.heaps.size(h, old.base).is_err());
        assert_eq!(
            c.p.heaps.size(h, new.base).unwrap(),
            2 * INITIAL_CAPACITY * c.arch().ptr_size()
        );
        assert_eq!(
            c.p.crt.runtimes[RuntimeKind::Ucrt.index()].allocations,
            ledger
        );
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0xABCD));
        for index in (0..INITIAL_CAPACITY).rev() {
            assert_eq!(drain.next(c.p).unwrap(), Some(0x1000 + index));
        }
        drain.finish(c.p).unwrap();
        assert_eq!(c.p.heaps.blocks(h), blocks);
    });
}

#[test]
fn readonly_header_fault_preserves_append_detach_and_owned_blocks() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        tables.initialize(c.p, table).unwrap();
        tables.register(c.p, h, table, 0x1234).unwrap();
        let before = current(&tables, table);
        let fields = read_table(c.p, table).unwrap();
        let blocks = c.p.heaps.blocks(h);
        c.p.vm.protect(table, PAGE_SIZE, prot::READONLY).unwrap();
        assert!(fault(tables.register(c.p, h, table, 0x5678)).write);
        assert!(fault(tables.begin_execute(c.p, table, c.t.tid)).write);
        assert_eq!(current(&tables, table), before);
        assert_eq!(read_table(c.p, table).unwrap(), fields);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        assert_eq!(tables.0.borrow().active, 0);
        let buffer = before.2.unwrap();
        assert_eq!(
            c.mem()
                .ptr(buffer.base + c.arch().ptr_size(), c.arch().ptr_size())
                .unwrap(),
            0
        );
        // Process cleanup does not need to write the caller's now-read-only table.
        tables.discard_process(c.p).unwrap();
        assert_eq!(read_table(c.p, table).unwrap(), fields);
    });
}

#[test]
fn corrupt_fields_never_free_arbitrary_memory_and_initialize_can_repair() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        let foreign = c.p.heaps.alloc_checked(&mut c.p.vm, h, 64, false).unwrap();
        tables.initialize(c.p, table).unwrap();
        tables.register(c.p, h, table, 0x1234).unwrap();
        let old = current(&tables, table).2.unwrap();
        let before = current(&tables, table);
        let blocks = c.p.heaps.blocks(h);
        write_table(
            c.p,
            table,
            [foreign, foreign + c.arch().ptr_size(), foreign + 64],
        )
        .unwrap();
        assert!(matches!(
            tables.register(c.p, h, table, 1),
            Err(TableError::Invalid)
        ));
        assert!(matches!(
            tables.begin_execute(c.p, table, c.t.tid),
            Err(TableError::Invalid)
        ));
        assert_eq!(current(&tables, table), before);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        tables.initialize(c.p, table).unwrap();
        assert_eq!(read_table(c.p, table).unwrap(), [0; 3]);
        assert!(c.p.heaps.size(h, old.base).is_err());
        assert_eq!(c.p.heaps.size(h, foreign).unwrap(), 64);
        c.p.heaps.free(h, foreign).unwrap();
    });
}

#[test]
fn overlapping_table_objects_and_internal_buffer_aliases_are_rejected_before_writes() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        let width = c.arch().ptr_size();
        tables.initialize(c.p, table).unwrap();
        assert!(matches!(
            tables.initialize(c.p, table + width),
            Err(TableError::Invalid)
        ));
        tables.register(c.p, h, table, 0x1234).unwrap();
        let old = current(&tables, table).2.unwrap();
        let bytes = c
            .mem()
            .bytes(old.base, 3 * c.arch().ptr_size() as usize)
            .unwrap();
        assert!(matches!(
            tables.initialize(c.p, old.base),
            Err(TableError::Invalid)
        ));
        assert_eq!(c.mem().bytes(old.base, bytes.len()).unwrap(), bytes);
        tables.discard_process(c.p).unwrap();
    });
}

#[test]
fn allocator_candidate_alias_does_not_zero_caller_table_or_publish_a_block() {
    run(|c| {
        let tables = OnExitState::default();
        // Caller storage in freed heap space is intentionally hostile. The
        // allocator must not zero it before checking candidate/table aliases.
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, PAGE_SIZE).unwrap();
        let table_bytes = 3 * c.arch().ptr_size();
        let table =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, h, table_bytes, false)
                .unwrap();
        c.p.heaps.free(h, table).unwrap();
        tables.initialize(c.p, table).unwrap();
        let before = current(&tables, table);
        assert!(matches!(
            tables.register(c.p, h, table, 0x1234),
            Err(TableError::Invalid)
        ));
        assert_eq!(read_table(c.p, table).unwrap(), [0; 3]);
        assert_eq!(current(&tables, table), before);
        assert!(c.p.heaps.blocks(h).is_empty());
        assert!(tables.0.borrow().owned.is_empty());
        tables.discard_process(c.p).unwrap();
    });
}

#[test]
fn growth_source_fault_rolls_back_candidate_and_retry_uses_old_generation() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, 0).unwrap();
        tables.initialize(c.p, table).unwrap();
        fill(&tables, c, h, table, INITIAL_CAPACITY);
        let old = current(&tables, table).2.unwrap();
        // Force the growth candidate onto the next page so old-read and
        // candidate-write permissions can be controlled independently.
        assert_eq!(old.base, h + 0x100, "the heap header is not block storage");
        let filler_bytes = h + PAGE_SIZE - (old.base + INITIAL_CAPACITY * c.arch().ptr_size());
        let filler =
            c.p.heaps
                .alloc_checked(&mut c.p.vm, h, filler_bytes, false)
                .unwrap();
        let before = current(&tables, table);
        let fields = read_table(c.p, table).unwrap();
        let blocks = c.p.heaps.blocks(h);
        c.p.vm.protect(h, PAGE_SIZE, prot::NOACCESS).unwrap();
        let f = fault(tables.register(c.p, h, table, 0xABCD));
        assert!(!f.write);
        assert_eq!(f.addr, old.base);
        assert_eq!(current(&tables, table), before);
        assert_eq!(read_table(c.p, table).unwrap(), fields);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        assert_eq!(tables.0.borrow().owned.len(), 1);
        c.p.vm.protect(h, PAGE_SIZE, prot::READONLY).unwrap();
        tables.register(c.p, h, table, 0xABCD).unwrap();
        assert!(c.p.heaps.size(h, old.base).is_err());
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0xABCD));
        while drain.next(c.p).unwrap().is_some() {}
        drain.finish(c.p).unwrap();
        c.p.heaps.free(h, filler).unwrap();
    });
}

#[test]
fn fixed_heap_growth_oom_preserves_full_old_table_and_block() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, 3 * PAGE_SIZE).unwrap();
        tables.initialize(c.p, table).unwrap();
        // A 4 KiB old generation plus its 8 KiB growth candidate cannot fit
        // the 12 KiB reservation minus its 0x100-byte heap header. Both
        // widths can reach the old generation without relying on fragments.
        let capacity = PAGE_SIZE / c.arch().ptr_size();
        fill(&tables, c, h, table, capacity);
        let before = current(&tables, table);
        assert_eq!(before.2.unwrap().capacity, capacity);
        let fields = read_table(c.p, table).unwrap();
        let blocks = c.p.heaps.blocks(h);
        assert!(matches!(
            tables.register(c.p, h, table, 0xABCD),
            Err(TableError::NoMemory)
        ));
        assert_eq!(current(&tables, table), before);
        assert_eq!(read_table(c.p, table).unwrap(), fields);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        for index in (0..capacity).rev() {
            assert_eq!(drain.next(c.p).unwrap(), Some(0x1000 + index));
        }
        drain.finish(c.p).unwrap();
        assert!(c.p.heaps.blocks(h).is_empty());
    });
}

#[test]
fn lazy_reads_observe_future_mutation_and_fault_does_not_pop_unread_slot() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        tables.initialize(c.p, table).unwrap();
        for target in [0x1111, 0x2222, 0x3333] {
            tables.register(c.p, h, table, target).unwrap();
        }
        let buffer = current(&tables, table).2.unwrap();
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0x3333));
        c.mem()
            .wptr(
                buffer.base + c.arch().ptr_size(),
                c.arch().ptr_size(),
                0xABCD,
            )
            .unwrap();
        let page = buffer.base & !(PAGE_SIZE - 1);
        c.p.vm
            .protect(page, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        let f = fault(drain.next(c.p));
        assert!(!f.write);
        assert_eq!(f.addr, buffer.base + c.arch().ptr_size());
        assert_eq!(drain.remaining, 2);
        assert_ne!(c.p.vm.query(page).unwrap().protect & prot::GUARD, 0);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0xABCD));
        assert_eq!(drain.next(c.p).unwrap(), Some(0x1111));
        assert_eq!(drain.next(c.p).unwrap(), None);
        // Detached completion requires neither caller-table nor buffer writes.
        c.p.vm.free(table, 0, mem::RELEASE).unwrap();
        drain.finish(c.p).unwrap();
        assert!(tables.0.borrow().owned.is_empty());
    });
}

#[test]
fn reinitialize_and_nested_execute_do_not_clobber_detached_generations() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        tables.initialize(c.p, table).unwrap();
        for target in [0x1111, 0x2222] {
            tables.register(c.p, h, table, target).unwrap();
        }
        let old = current(&tables, table).2.unwrap();
        let mut outer = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert_eq!(outer.next(c.p).unwrap(), Some(0x2222));
        tables.initialize(c.p, table).unwrap();
        for target in [0x3333, 0x4444] {
            tables.register(c.p, h, table, target).unwrap();
        }
        let middle = current(&tables, table).2.unwrap();
        assert_ne!(middle.base, old.base);
        let mut inner = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert_eq!(inner.next(c.p).unwrap(), Some(0x4444));
        assert_eq!(inner.next(c.p).unwrap(), Some(0x3333));
        inner.finish(c.p).unwrap();
        assert!(c.p.heaps.size(h, middle.base).is_err());
        tables.initialize(c.p, table).unwrap();
        tables.register(c.p, h, table, 0x5555).unwrap();
        let final_entry = current(&tables, table);
        let final_fields = read_table(c.p, table).unwrap();
        assert_eq!(outer.next(c.p).unwrap(), Some(0x1111));
        outer.finish(c.p).unwrap();
        assert_eq!(current(&tables, table), final_entry);
        assert_eq!(read_table(c.p, table).unwrap(), final_fields);
        assert!(c.p.heaps.size(h, old.base).is_err());
        assert_eq!(tables.0.borrow().active, 0);
        assert_eq!(tables.0.borrow().owned.len(), 1);
        tables.discard_process(c.p).unwrap();
    });
}

#[test]
fn abandoned_receipts_preserve_owner_and_free_only_their_generation() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        tables.initialize(c.p, table).unwrap();
        fill(&tables, c, h, table, 2);
        let old = current(&tables, table).2.unwrap();
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert_eq!(drain.next(c.p).unwrap(), Some(0x1001));
        tables.initialize(c.p, table).unwrap();
        tables.register(c.p, h, table, 0xABCD).unwrap();
        let next = current(&tables, table);
        let fields = read_table(c.p, table).unwrap();
        drop(drain);
        assert_eq!(tables.0.borrow().active, 0);
        assert_eq!(
            Rc::strong_count(&tables.0),
            1,
            "queue retains only a weak registry link"
        );
        let mut receipts = tables.take_abandoned().unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = receipts.pop().unwrap();
        assert_eq!(
            (receipt.tid, receipt.table, receipt.generation),
            (c.t.tid, table, 1)
        );
        c.p.vm.protect(table, PAGE_SIZE, prot::READONLY).unwrap();
        cleanup_abandoned(c.p, receipt).unwrap();
        assert!(c.p.heaps.size(h, old.base).is_err());
        assert_eq!(current(&tables, table), next);
        assert_eq!(read_table(c.p, table).unwrap(), fields);
        assert_eq!(tables.0.borrow().owned.len(), 1);
        assert!(tables.take_abandoned().unwrap().is_empty());
        tables.discard_process(c.p).unwrap();
    });
}

#[test]
fn receipt_extraction_preserves_pre_reserved_capacity_for_live_drops() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let other = table + 3 * c.arch().ptr_size();
        let h = heap(c);
        for address in [table, other] {
            tables.initialize(c.p, address).unwrap();
            tables.register(c.p, h, address, address).unwrap();
        }
        let first = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        let second = tables.begin_execute(c.p, other, c.t.tid + 1).unwrap();
        let capacity = tables.0.borrow().abandoned.capacity();
        drop(first);
        let receipts = tables.take_abandoned().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(tables.0.borrow().abandoned.capacity(), capacity);
        drop(second);
        assert_eq!(tables.0.borrow().abandoned.capacity(), capacity);
        for receipt in receipts.into_iter().chain(tables.take_abandoned().unwrap()) {
            cleanup_abandoned(c.p, receipt).unwrap();
        }
        assert!(tables.0.borrow().owned.is_empty());
        assert_eq!(tables.0.borrow().active, 0);
    });
}

#[test]
fn process_discard_reaps_all_host_blocks_without_guest_access_or_callbacks() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let other = table + 3 * c.arch().ptr_size();
        let h = heap(c);
        let blocks = c.p.heaps.blocks(h);
        for address in [table, other] {
            tables.initialize(c.p, address).unwrap();
            tables.register(c.p, h, address, 0x1234).unwrap();
        }
        let drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert!(matches!(
            tables.discard_process(c.p),
            Err(TableError::Internal(_))
        ));
        assert_eq!(tables.0.borrow().owned.len(), 2);
        drop(drain);
        let fields = read_table(c.p, other).unwrap();
        c.p.vm.protect(table, PAGE_SIZE, prot::NOACCESS).unwrap();
        tables.discard_process(c.p).unwrap();
        assert_eq!(c.p.heaps.blocks(h), blocks);
        assert!(tables.0.borrow().tables.is_empty());
        assert!(tables.0.borrow().owned.is_empty());
        assert!(tables.take_abandoned().unwrap().is_empty());
        c.p.vm.protect(table, PAGE_SIZE, prot::READONLY).unwrap();
        assert_eq!(read_table(c.p, other).unwrap(), fields);
    });
}

#[test]
fn generation_and_guest_address_exhaustion_fail_without_publication() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        tables.initialize(c.p, table).unwrap();
        tables.register(c.p, h, table, 0x1234).unwrap();
        tables
            .0
            .borrow_mut()
            .tables
            .get_mut(&table)
            .unwrap()
            .generation = u64::MAX;
        let before = current(&tables, table);
        let fields = read_table(c.p, table).unwrap();
        let blocks = c.p.heaps.blocks(h);
        assert!(matches!(
            tables.initialize(c.p, table),
            Err(TableError::GenerationExhausted)
        ));
        assert_eq!(current(&tables, table), before);
        assert_eq!(read_table(c.p, table).unwrap(), fields);
        assert_eq!(c.p.heaps.blocks(h), blocks);
        let max = c.arch().ptr(u64::MAX);
        let last_pointer = max & !(c.arch().ptr_size() - 1);
        assert!(fault(tables.initialize(c.p, last_pointer)).write);
        for write in [false, true] {
            let f = fault(range(c.p, max - 1, 4, write));
            assert_eq!(f.write, write);
            assert_eq!(f.addr, if c.arch().is64() { max } else { max + 1 });
        }
        if !c.arch().is64() {
            assert!(matches!(
                tables.register(c.p, h, table, max + 1),
                Err(TableError::Invalid)
            ));
        }
        tables.discard_process(c.p).unwrap();
    });
}

#[test]
fn externally_freed_opaque_block_and_nonmatching_reuse_are_rejected_not_freed() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = heap(c);
        tables.initialize(c.p, table).unwrap();
        tables.register(c.p, h, table, 0x1234).unwrap();
        let old = current(&tables, table).2.unwrap();
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        c.p.heaps.free(h, old.base).unwrap();
        assert!(matches!(drain.next(c.p), Err(TableError::Internal(_))));
        assert_eq!(drain.remaining, 1);
        let foreign = c.p.heaps.alloc_checked(&mut c.p.vm, h, 16, false).unwrap();
        assert_eq!(foreign, old.base, "force a different-size reuse");
        assert!(matches!(drain.next(c.p), Err(TableError::Internal(_))));
        drop(drain);
        let receipt = tables.take_abandoned().unwrap().pop().unwrap();
        assert!(matches!(
            cleanup_abandoned(c.p, receipt),
            Err(TableError::Internal(_))
        ));
        assert_eq!(c.p.heaps.size(h, foreign).unwrap(), 16);
        assert!(matches!(
            tables.discard_process(c.p),
            Err(TableError::Internal(_))
        ));
        assert_eq!(c.p.heaps.size(h, foreign).unwrap(), 16);
        c.p.heaps.free(h, foreign).unwrap();
        // Equal-address/equal-requested-size reuse is not detectable with the
        // current heap metadata. This test does not claim native behavior for
        // raw frees/reallocations of opaque CRT-owned storage.
    });
}

#[test]
fn destroyed_private_heap_is_an_explicit_internal_error_before_callback_reads() {
    run(|c| {
        let tables = OnExitState::default();
        let table = area(c);
        let h = c.p.heaps.create(&mut c.p.vm, 0, 0, 0).unwrap();
        tables.initialize(c.p, table).unwrap();
        tables.register(c.p, h, table, 0x1234).unwrap();
        let mut drain = tables.begin_execute(c.p, table, c.t.tid).unwrap();
        assert!(c.p.heaps.destroy(&mut c.p.vm, h));
        assert!(matches!(drain.next(c.p), Err(TableError::Internal(_))));
        assert_eq!(drain.remaining, 1);
        drop(drain);
        let receipt = tables.take_abandoned().unwrap().pop().unwrap();
        assert!(matches!(
            cleanup_abandoned(c.p, receipt),
            Err(TableError::Internal(_))
        ));
        assert!(matches!(
            tables.discard_process(c.p),
            Err(TableError::Internal(_))
        ));
        assert!(tables.0.borrow().owned.is_empty());
    });
}
