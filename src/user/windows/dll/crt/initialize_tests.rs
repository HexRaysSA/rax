//! Checked constructor traversal, independent of ordinary compiler startup.

use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::crt::{
    RuntimeKind,
    tests::{api, area, int, invoke, run, void},
};
use crate::user::windows::hle::{ApiErr, ApiResult, Cont, Conv, Ctx, Flow};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{Mem, MemFault, mem, prot};

fn put(c: &Ctx, at: u64, value: u64) {
    c.mem().wptr(at, c.psize(), value).unwrap();
}

fn callback(result: ApiResult, expected: u64) -> Cont {
    match result.unwrap() {
        Flow::Call { target, args, then } => {
            assert_eq!(target, expected);
            assert!(args.is_empty(), "constructors take no arguments");
            then
        }
        _ => panic!("expected a constructor continuation"),
    }
}

fn read_fault(result: ApiResult) -> MemFault {
    match result {
        Ok(Flow::RetryFault { fault, retry }) => {
            assert!(!fault.write);
            drop(retry);
            fault
        }
        Err(ApiErr::Fault(fault)) => {
            assert!(!fault.write);
            fault
        }
        _ => panic!("expected a checked constructor-table read fault"),
    }
}

fn retry_fault(result: ApiResult) -> (MemFault, Cont) {
    match result.unwrap() {
        Flow::RetryFault { fault, retry } => {
            assert!(!fault.write);
            (fault, retry)
        }
        _ => panic!("expected a retained constructor-table retry"),
    }
}

fn span(c: &mut Ctx, bytes: u64) -> u64 {
    c.p.vm
        .allocate(None, bytes, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

#[test]
fn initializer_signatures_and_empty_ranges_all_abis() {
    run(|c| {
        for name in ["_initterm", "_initterm_e"] {
            assert_eq!(api(name).conv, Conv::Cdecl);
            assert_eq!(api(name).args.len(), 2);
        }
        let max = c.arch().ptr(u64::MAX);
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            // Empty intervals require no pointer read, even at an unmapped VA.
            void(invoke(c, kind, "_initterm", &[max, max]));
        }
        assert_eq!(
            int(invoke(c, RuntimeKind::Ucrt, "_initterm_e", &[max, max])),
            0
        );
    });
}

#[test]
fn legacy_error_initializer_admission_matches_arch_inventory_all_abis() {
    run(|c| {
        let index = c.p.modules.by_name("msvcrt.dll").unwrap();
        let address =
            loader::lookup(c.p, index, &SymRef::Name(b"_initterm_e".to_vec(), None)).unwrap();
        assert_eq!(address.is_some(), c.arch() == WinArch::Arm64);
        if c.arch() == WinArch::Arm64 {
            let first = area(c);
            let end = first + c.psize();
            put(c, first, 0x1110);
            let then = callback(
                invoke(c, RuntimeKind::Msvcrt, "_initterm_e", &[first, end]),
                0x1110,
            );
            assert_eq!(int(then(c, 0xFFFF_FFFE)), 0xFFFF_FFFE);
        }
    });
}

#[test]
fn ascending_null_holes_and_exclusive_unmapped_end_all_abis() {
    run(|c| {
        let a = area(c);
        let width = c.psize();
        let first = a + PAGE_SIZE - 4 * width;
        let end = a + PAGE_SIZE;
        put(c, first, 0x1110);
        put(c, first + width, 0);
        put(c, first + 2 * width, 0x2220);
        put(c, first + 3 * width, 0);
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let then = callback(invoke(c, kind, "_initterm", &[first, end]), 0x1110);
            // _initterm ignores even a nonzero integer callback register.
            let then = callback(then(c, u64::MAX), 0x2220);
            void(then(c, 0x1234));
        }
        let then = callback(
            invoke(c, RuntimeKind::Ucrt, "_initterm_e", &[first, end]),
            0x1110,
        );
        let then = callback(then(c, 0), 0x2220);
        assert_eq!(int(then(c, 0)), 0);
        // The final NULL occupies a complete readable word. Nothing at end is
        // read; the next allocation page is not part of this table.
    });
}

#[test]
fn callback_mutations_are_read_lazily_with_captured_end_all_abis() {
    run(|c| {
        let first = area(c);
        let width = c.psize();
        let end = first + 3 * width;
        put(c, first, 0x1110);
        put(c, first + width, 0);
        put(c, first + 2 * width, 0x3330);
        put(c, end, 0xDEAD0);
        let then = callback(
            invoke(c, RuntimeKind::Ucrt, "_initterm", &[first, end]),
            0x1110,
        );
        // A callback may replace future elements, including a previous NULL.
        put(c, first + width, 0x2220);
        put(c, first + 2 * width, 0x4440);
        // Constructor calls clobber argument registers on 64-bit ABIs. This
        // unrelated call also rewrites the original x86 argument stack slots.
        let saved_api = c.api;
        let saved_pc = c.entry_pc;
        void(invoke(c, RuntimeKind::Ucrt, "_initterm", &[end, end]));
        c.api = saved_api;
        c.entry_pc = saved_pc;
        let then = callback(then(c, 0), 0x2220);
        let then = callback(then(c, 0), 0x4440);
        void(then(c, 0));
        assert_eq!(c.mem().ptr(end, width).unwrap(), 0xDEAD0);
    });
}

#[test]
fn error_initializer_uses_only_low_int_bits_and_stops_all_abis() {
    run(|c| {
        let first = area(c);
        let width = c.psize();
        put(c, first, 0x1110);
        put(c, first + width, 0x2220);
        put(c, first + 2 * width, 0x3330);
        let end = first + 3 * width;
        for result in [7u32, 0xFFFF_FFFE] {
            let then = callback(
                invoke(c, RuntimeKind::Ucrt, "_initterm_e", &[first, end]),
                0x1110,
            );
            // Only the 32-bit int return is defined. Nonzero upper register
            // bits do not stop traversal when the low 32 bits are zero.
            let then = callback(then(c, 0x1234_5678_0000_0000), 0x2220);
            assert_eq!(
                int(then(c, 0xABCD_EF01_0000_0000 | u64::from(result))),
                u64::from(result)
            );
        }
    });
}

#[test]
fn early_error_does_not_read_inaccessible_remaining_entries_all_abis() {
    run(|c| {
        let a = area(c);
        let first = a + PAGE_SIZE - c.psize();
        put(c, first, 0x1110);
        let then = callback(
            invoke(
                c,
                RuntimeKind::Ucrt,
                "_initterm_e",
                &[first, a + 2 * PAGE_SIZE],
            ),
            0x1110,
        );
        assert_eq!(int(then(c, 23)), 23);
    });
}

#[test]
fn independent_nested_initializer_continuations_all_abis() {
    run(|c| {
        let outer = area(c);
        let inner = area(c);
        let width = c.psize();
        put(c, outer, 0x1110);
        put(c, outer + width, 0x2220);
        put(c, inner, 0x3330);
        put(c, inner + width, 0x4440);
        let outer_then = callback(
            invoke(
                c,
                RuntimeKind::Ucrt,
                "_initterm",
                &[outer, outer + 2 * width],
            ),
            0x1110,
        );
        let outer_api = c.api;
        let outer_pc = c.entry_pc;
        let inner_then = callback(
            invoke(
                c,
                RuntimeKind::Ucrt,
                "_initterm_e",
                &[inner, inner + 2 * width],
            ),
            0x3330,
        );
        let inner_then = callback(inner_then(c, 0), 0x4440);
        assert_eq!(int(inner_then(c, 3)), 3);
        // dispatch::callback_return restores the owning frame's API frontier.
        c.api = outer_api;
        c.entry_pc = outer_pc;
        let outer_then = callback(outer_then(c, u64::MAX), 0x2220);
        void(outer_then(c, 0));
    });
}

#[test]
fn read_only_tables_are_not_modified_all_abis() {
    run(|c| {
        let first = area(c);
        let width = c.psize();
        put(c, first, 0);
        put(c, first + width, 0x1110);
        put(c, first + 2 * width, 0);
        c.p.vm.protect(first, PAGE_SIZE, prot::READONLY).unwrap();
        let then = callback(
            invoke(
                c,
                RuntimeKind::Ucrt,
                "_initterm",
                &[first, first + 3 * width],
            ),
            0x1110,
        );
        void(then(c, 0));
        assert_eq!(c.mem().ptr(first, width).unwrap(), 0);
        assert_eq!(c.mem().ptr(first + width, width).unwrap(), 0x1110);
        assert_eq!(c.mem().ptr(first + 2 * width, width).unwrap(), 0);
    });
}

#[test]
fn late_table_fault_preserves_completed_callback_frontier_all_abis() {
    run(|c| {
        let a = span(c, 2 * PAGE_SIZE);
        let next_page = a + PAGE_SIZE;
        let first = next_page - c.psize();
        let end = next_page + c.psize();
        put(c, first, 0x1110);
        c.p.vm
            .protect(next_page, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let then = callback(
            invoke(c, RuntimeKind::Ucrt, "_initterm", &[first, end]),
            0x1110,
        );
        // The first callback has already completed; its side effects cannot be
        // undone when lazy reading of the following table entry fails.
        c.mem().w32(a, 0x1234_5678).unwrap();
        assert_eq!(read_fault(then(c, 0)).addr, next_page);
        assert_eq!(c.mem().u32(a).unwrap(), 0x1234_5678);
    });
}

#[test]
fn repaired_read_retries_saved_cursor_and_end_not_callback_arguments_all_abis() {
    run(|c| {
        for (kind, name, fallible) in [
            (RuntimeKind::Msvcrt, "_initterm", false),
            (RuntimeKind::Ucrt, "_initterm", false),
            (RuntimeKind::Ucrt, "_initterm_e", true),
        ] {
            let a = span(c, 2 * PAGE_SIZE);
            let next_page = a + PAGE_SIZE;
            let first = next_page - c.psize();
            let end = next_page + c.psize();
            put(c, first, 0x1110);
            put(c, next_page, 0x2220);
            put(c, end, 0xDEAD0);
            c.p.vm
                .protect(next_page, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let then = callback(invoke(c, kind, name, &[first, end]), 0x1110);
            let saved_api = c.api;
            let saved_pc = c.entry_pc;
            c.mem().w32(a, 1).unwrap(); // Completed callback's observable effect.
            let (fault, retry) = retry_fault(then(c, 0));
            assert_eq!(fault.addr, next_page);

            // Both x86 argument slots and x64/ARM64 argument registers may be
            // overwritten by a callback or exception handler. The retry must
            // not restart at first or replace the captured exclusive endpoint.
            let changed_end = end + c.psize();
            void(invoke(
                c,
                RuntimeKind::Ucrt,
                "_initterm",
                &[changed_end, changed_end],
            ));
            c.api = saved_api;
            c.entry_pc = saved_pc;
            let (again, retry) = retry_fault(retry(c, u64::MAX));
            assert_eq!(again.addr, next_page);
            c.p.vm
                .protect(next_page, PAGE_SIZE, prot::READWRITE)
                .unwrap();
            let then = callback(retry(c, u64::MAX), 0x2220);
            if fallible {
                assert_eq!(int(then(c, 0)), 0);
            } else {
                void(then(c, 0));
            }
            assert_eq!(c.mem().u32(a).unwrap(), 1);
            assert_eq!(c.mem().ptr(end, c.psize()).unwrap(), 0xDEAD0);
        }
    });
}

#[test]
fn partial_null_word_at_page_boundary_is_a_read_fault_all_abis() {
    run(|c| {
        let a = span(c, 2 * PAGE_SIZE);
        let next_page = a + PAGE_SIZE;
        // Zero initialized bytes before the boundary are not a complete NULL
        // pointer. The other half must be checked before skipping this entry.
        let first = next_page - c.psize() / 2;
        let end = next_page + c.psize();
        c.p.vm
            .protect(next_page, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        assert_eq!(
            read_fault(invoke(c, RuntimeKind::Ucrt, "_initterm", &[first, end])).addr,
            next_page
        );
    });
}

#[test]
fn long_null_runs_have_no_snapshot_limit_or_host_recursion_all_abis() {
    run(|c| {
        let width = c.psize();
        let null_count = 65_537;
        let bytes = (null_count + 1) * width;
        let first = span(c, bytes);
        let final_entry = first + null_count * width;
        put(c, final_entry, 0x1110);
        let end = final_entry + width;
        let then = callback(
            invoke(c, RuntimeKind::Ucrt, "_initterm", &[first, end]),
            0x1110,
        );
        void(then(c, 0));
        let then = callback(
            invoke(c, RuntimeKind::Ucrt, "_initterm_e", &[first, end]),
            0x1110,
        );
        assert_eq!(int(then(c, 0)), 0);
    });
}

#[test]
fn discarded_continuation_has_no_global_progress_or_completion_all_abis() {
    run(|c| {
        let first = area(c);
        put(c, first, 0x1110);
        put(c, first + c.psize(), 0x2220);
        let end = first + 2 * c.psize();
        let then = callback(
            invoke(c, RuntimeKind::Ucrt, "_initterm", &[first, end]),
            0x1110,
        );
        // The HLE/fiber engine owns frame parking: same-thread switches retain
        // this closure, while cross-thread migration of such a frame rejects.
        // This helper-level test establishes only the dropped-closure contract.
        drop(then); // longjmp/unwind/terminal callback does not return the API.
        assert!(c.p.loader.is_idle());
        assert!(c.p.tls.fls_take_abandoned().is_empty());
        let then = callback(
            invoke(c, RuntimeKind::Ucrt, "_initterm", &[first, end]),
            0x1110,
        );
        let then = callback(then(c, 0), 0x2220);
        void(then(c, 0));
    });
}

#[test]
fn guest_width_overflow_rejects_without_wrap_all_abis() {
    run(|c| {
        let max = c.arch().ptr(u64::MAX);
        let width = c.psize();
        assert_eq!(super::advance(c, max - width).unwrap(), max);
        let overflow = max - width + 1;
        match super::advance(c, overflow) {
            Err(ApiErr::Fault(fault)) => {
                assert_eq!(fault.addr, overflow);
                assert!(!fault.write);
            }
            _ => panic!("pointer-width overflow must not wrap the cursor"),
        }
        read_fault(invoke(c, RuntimeKind::Ucrt, "_initterm", &[max - 1, max]));
        read_fault(invoke(c, RuntimeKind::Ucrt, "_initterm_e", &[max - 1, max]));
    });
}
