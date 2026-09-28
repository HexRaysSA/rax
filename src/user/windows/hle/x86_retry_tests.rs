//! PE32 callback-setup fault ownership at the synthetic exception dispatcher.

use std::cell::Cell;
use std::rc::Rc;

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{mem, prot};

const ORIGINAL_CODE: u32 = 0xE123_4567;

/// The x86 dispatcher layout with ESP at `page + 0x360` is:
/// CONTEXT `+0x94`, EXCEPTION_RECORD `+0x40`, EXCEPTION_POINTERS `+0x30`,
/// and callback cursor `+0x10`. A one-argument callback writes its argument at
/// `page` and its 4-byte return address at `page - 4`.
///
/// With ESP at `page + 0x370`, the pointers and cursor each move 16 bytes up.
/// Allocating the x86 frame handler's 4-byte DispatcherContext moves the cursor
/// to `+0x1c`; its four argument words occupy `page..page+0xf`, and its return
/// address again lands at `page - 4`.
fn stack_fixture(
    p: &mut Proc,
    t: &mut Thread,
    original_sp_offset: u64,
    lower_protection: u32,
) -> (u64, u64, u64) {
    let (stack, size) =
        p.vm.allocate(None, 0x1_0000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let page = stack + 0x8000;
    t.stack_alloc = stack;
    t.stack_limit = stack;
    t.stack_base = stack + size;
    let original_pc = p.modules.exe().base + 0x40;
    let original_sp = page + original_sp_offset;
    t.cpu.set_pc(original_pc);
    t.cpu.set_sp(original_sp);
    p.space.w32(original_sp, 0).unwrap();
    p.space
        .w32(
            t.teb + offsets(WinArch::X86).teb_exception_list,
            seh::x86::CHAIN_END as u32,
        )
        .unwrap();
    p.vm.protect(page - PAGE_SIZE, PAGE_SIZE, lower_protection)
        .unwrap();
    (page, original_pc, original_sp)
}

fn frame_handler(p: &mut Proc, t: &Thread, page: u64) -> (u64, u64) {
    let record = page + 0x800;
    let handler = p.modules.exe().base + 0x400;
    p.modules.list[0].no_seh = false;
    p.modules.list[0].safe_seh = None;
    p.space.w32(record, seh::x86::CHAIN_END as u32).unwrap();
    p.space.w32(record + 4, handler as u32).unwrap();
    p.space
        .w32(
            t.teb + offsets(WinArch::X86).teb_exception_list,
            record as u32,
        )
        .unwrap();
    (record, handler)
}

fn original_exception(p: &mut Proc, t: &mut Thread, pc: u64) -> Outcome {
    let context = RegContext::capture(&t.cpu);
    seh::raise(
        p,
        t,
        ExceptionRecord::new(ORIGINAL_CODE, pc, Vec::new()),
        context,
    )
}

/// `ret 4` for a one-argument WINAPI callback; `ret` for the four-argument
/// x86 frame handler (`__cdecl`). The callback-return trap owns the saved HLE
/// continuation, so it does not infer argument cleanup from this ESP.
fn return_callback(p: &mut Proc, t: &mut Thread, value: u64, callee_pop: u64) -> Outcome {
    t.cpu.set_gpr(0, value);
    t.cpu.set_sp(t.cpu.sp() + 4 + callee_pop);
    t.cpu.set_pc(p.traps.callback_return());
    callback_return(p, t)
}

fn callback_pointers(p: &Proc, t: &Thread) -> (u64, u64, u64) {
    let pointers = u64::from(p.space.u32(t.cpu.sp() + 4).unwrap());
    let record = u64::from(p.space.u32(pointers).unwrap());
    let context = u64::from(p.space.u32(pointers + 4).unwrap());
    (pointers, record, context)
}

#[test]
fn x86_dispatcher_context_guard_fault_retains_selected_frame_handler() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    // ESP = page + 0x350 puts the original EXCEPTION_RECORD at +0x30,
    // EXCEPTION_POINTERS at +0x20, and dispatcher cursor at the page edge.
    // The 4-byte DispatcherContext initialization therefore touches page - 4.
    let (page, original_pc, original_sp) =
        stack_fixture(p, &mut t, 0x350, prot::READWRITE | prot::GUARD);
    let (registration, handler) = frame_handler(p, &t, page);
    let original_record_at = page + 0x30;
    let original_context_at = page + 0x84;

    // There is no initial VEH: its own return slot would touch this guard.
    // The registration handler can handle the nested one-shot guard fault after
    // guard consumption, then must be selected again for the original record.
    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), handler, "nested frame handler must start");
    assert_eq!(t.frames[0].dispatcher_setup_retries, 1);
    assert!(t.frames[0].retry.is_some());
    assert_eq!(t.frames[0].entry_sp, page);
    let nested_sp = t.cpu.sp();
    let nested_record_at = u64::from(p.space.u32(nested_sp + 4).unwrap());
    let nested_context_at = u64::from(p.space.u32(nested_sp + 12).unwrap());
    assert_eq!(p.space.u32(nested_sp + 8).unwrap(), registration as u32);
    let nested = ExceptionRecord::read(&p.space, WinArch::X86, nested_record_at).unwrap();
    assert_eq!(nested.code, STATUS_GUARD_PAGE_VIOLATION);
    assert_eq!(nested.params, [1, page - 4]);
    assert_eq!(nested.address, p.traps.dispatcher_retry());
    let nested_context = RegContext::read(&p.space, WinArch::X86, nested_context_at).unwrap();
    assert_eq!(nested_context.pc(), p.traps.dispatcher_retry());
    assert_eq!(nested_context.sp(), page);
    assert_eq!(
        p.vm.query(page - PAGE_SIZE).unwrap().protect,
        prot::READWRITE
    );
    let original = ExceptionRecord::read(&p.space, WinArch::X86, original_record_at).unwrap();
    assert_eq!(original.code, ORIGINAL_CODE);
    let original_context = RegContext::read(&p.space, WinArch::X86, original_context_at).unwrap();
    assert_eq!(
        (original_context.pc(), original_context.sp()),
        (original_pc, original_sp)
    );

    // The original frame handler was selected before the metadata fault.
    // Mutating its TEB registration during nested dispatch must not retarget
    // the already-selected continuation when the metadata write is retried.
    let replacement_handler = p.modules.exe().base + 0x600;
    assert_ne!(handler, replacement_handler);
    p.space
        .w32(registration + 4, replacement_handler as u32)
        .unwrap();

    assert_eq!(
        return_callback(p, &mut t, seh::disposition::CONTINUE_EXECUTION.into(), 0),
        Outcome::Continue
    );
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (retry_pc, page));
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), handler, "original selected handler must start");
    let callback_sp = t.cpu.sp();
    assert_eq!(
        p.space.u32(callback_sp + 4).unwrap(),
        original_record_at as u32
    );
    assert_eq!(p.space.u32(callback_sp + 8).unwrap(), registration as u32);
    assert_eq!(
        p.space.u32(callback_sp + 12).unwrap(),
        original_context_at as u32
    );
    assert_eq!(p.space.u32(callback_sp + 16).unwrap(), (page - 4) as u32);
    assert_eq!(p.space.u32(page - 4).unwrap(), 0);
    assert!(t.frames[0].retry.is_none());
    assert!(t.frames[0].cont.is_some());

    assert_eq!(
        return_callback(p, &mut t, seh::disposition::CONTINUE_EXECUTION.into(), 0),
        Outcome::Continue
    );
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty());
}

#[test]
fn x86_dispatcher_context_exhausted_stack_guard_preserves_overflow_classification() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, original_sp) =
        stack_fixture(p, &mut t, 0x350, prot::READWRITE | prot::GUARD);
    let (registration, handler) = frame_handler(p, &t, page);
    // Unlike the non-stack guard case, this is the selected stack's current
    // guard. The fully committed lower reservation has no next reserved page.
    t.stack_limit = page;
    p.space
        .w32(t.teb + offsets(WinArch::X86).teb_stack_limit, page as u32)
        .unwrap();

    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), handler);
    assert_eq!(t.frames[0].dispatcher_setup_retries, 1);
    assert!(t.frames[0].retry.is_some());
    assert_eq!(t.frames[0].entry_sp, page);
    let nested_sp = t.cpu.sp();
    let nested_record_at = u64::from(p.space.u32(nested_sp + 4).unwrap());
    let nested_context_at = u64::from(p.space.u32(nested_sp + 12).unwrap());
    assert_eq!(p.space.u32(nested_sp + 8).unwrap(), registration as u32);
    let nested = ExceptionRecord::read(&p.space, WinArch::X86, nested_record_at).unwrap();
    assert_eq!(nested.code, STATUS_STACK_OVERFLOW);
    assert_eq!(nested.params, [1, page - PAGE_SIZE]);
    assert_eq!(nested.address, p.traps.dispatcher_retry());
    let nested_context = RegContext::read(&p.space, WinArch::X86, nested_context_at).unwrap();
    assert_eq!(
        (nested_context.pc(), nested_context.sp()),
        (p.traps.dispatcher_retry(), page)
    );
    assert_eq!(t.stack_limit, page - PAGE_SIZE);
    assert_eq!(
        u64::from(
            p.space
                .u32(t.teb + offsets(WinArch::X86).teb_stack_limit)
                .unwrap()
        ),
        page - PAGE_SIZE
    );
    assert_eq!(
        p.vm.query(page - PAGE_SIZE).unwrap().protect,
        prot::READWRITE
    );

    assert_eq!(
        return_callback(p, &mut t, seh::disposition::CONTINUE_EXECUTION.into(), 0),
        Outcome::Continue
    );
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (retry_pc, page));
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), handler);
    assert_eq!(p.space.u32(t.cpu.sp() + 16).unwrap(), (page - 4) as u32);
    assert_eq!(
        return_callback(p, &mut t, seh::disposition::CONTINUE_EXECUTION.into(), 0),
        Outcome::Continue
    );
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty());
}

#[test]
fn x86_selected_scope_dispatcher_context_guard_fault_retains_taken_handler() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, _) = stack_fixture(p, &mut t, 0x350, prot::READWRITE | prot::GUARD);
    let (registration, guest_handler) = frame_handler(p, &t, page);
    let selected_calls = Rc::new(Cell::new(0));
    let calls = selected_calls.clone();
    let scope_cursor = page + 0x400;
    t.frames.push(Frame {
        api: &super::tests::TEST_API,
        entry_pc: 0xAB00,
        entry_sp: page + 0x500,
        ret_addr: original_pc,
        cursor: scope_cursor,
        cont: Some(Box::new(|_, _| {
            panic!("protected operation is still pending")
        })),
        checked_call: true,
        callback_sp: None,
        exception_caller: None,
        retry: None,
        dispatcher_setup_retries: 0,
        exception: vec![super::super::exception::ExceptionBoundary::new(
            Some(ORIGINAL_CODE),
            scope_cursor,
            Box::new(move |c, code| {
                assert_eq!(code, u64::from(ORIGINAL_CODE));
                assert!(c.t.frames[0].cont.is_some());
                calls.set(calls.get() + 1);
                Ok(Flow::TerminateProcess(91))
            }),
        )],
    });

    // The scope is selected before the outer TEB registration, but its
    // DispatcherContext falls on the guarded lower page. The nested fault
    // must visit the TEB handler without re-offering the taken scope.
    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(selected_calls.get(), 0);
    assert_eq!(t.cpu.pc(), guest_handler);
    assert_eq!(t.frames[1].entry_sp, page);
    assert!(t.frames[1].retry.is_some());
    let nested_sp = t.cpu.sp();
    let nested_record_at = u64::from(p.space.u32(nested_sp + 4).unwrap());
    let nested_context_at = u64::from(p.space.u32(nested_sp + 12).unwrap());
    assert_eq!(p.space.u32(nested_sp + 8).unwrap(), registration as u32);
    let nested = ExceptionRecord::read(&p.space, WinArch::X86, nested_record_at).unwrap();
    assert_eq!(nested.code, STATUS_GUARD_PAGE_VIOLATION);
    assert_eq!(nested.params, [1, page - 4]);
    assert_eq!(nested.address, p.traps.dispatcher_retry());
    let nested_context = RegContext::read(&p.space, WinArch::X86, nested_context_at).unwrap();
    assert_eq!(
        (nested_context.pc(), nested_context.sp()),
        (p.traps.dispatcher_retry(), page)
    );

    assert_eq!(
        return_callback(p, &mut t, seh::disposition::CONTINUE_EXECUTION.into(), 0),
        Outcome::Continue
    );
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (retry_pc, page));
    assert_eq!(
        dispatcher_retry(p, &mut t, retry_pc),
        Outcome::ProcessTerminate(91)
    );
    assert_eq!(selected_calls.get(), 1);
    assert_eq!(t.frames.len(), 1, "protected owner remains pending");
    assert!(t.frames[0].cont.is_some());
}

#[test]
fn x86_frame_handler_guard_setup_fault_is_repaired_by_veh() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, original_sp) =
        stack_fixture(p, &mut t, 0x370, prot::READWRITE | prot::GUARD);
    let (registration, handler) = frame_handler(p, &t, page);
    let veh = p.modules.exe().base + 0x500;
    p.seh.veh.push((1, veh));

    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh);
    let (_, original_record, original_context) = callback_pointers(p, &t);
    let record_before = p
        .space
        .bytes(
            original_record,
            ExceptionRecord::size(WinArch::X86) as usize,
        )
        .unwrap();
    let context_before = p
        .space
        .bytes(original_context, RegContext::size(WinArch::X86))
        .unwrap();

    // The first VEH declines. Its four-argument frame handler is selected,
    // then the callback return-address write touches the non-stack guard.
    assert_eq!(return_callback(p, &mut t, 0, 4), Outcome::Continue);
    assert_eq!(t.cpu.pc(), veh, "repair VEH must see the setup fault");
    let (_, nested_record_at, nested_context_at) = callback_pointers(p, &t);
    let nested = ExceptionRecord::read(&p.space, WinArch::X86, nested_record_at).unwrap();
    assert_eq!(nested.code, STATUS_GUARD_PAGE_VIOLATION);
    assert_eq!(nested.params, [1, page - 4]);
    assert_eq!(nested.address, p.traps.dispatcher_retry());
    let nested_context = RegContext::read(&p.space, WinArch::X86, nested_context_at).unwrap();
    assert_eq!(nested_context.pc(), p.traps.dispatcher_retry());
    assert_eq!(nested_context.sp(), t.frames[0].entry_sp);
    assert!(t.frames[0].retry.is_some());
    assert_eq!(
        p.vm.query(page - PAGE_SIZE).unwrap().protect,
        prot::READWRITE
    );
    assert_eq!(
        p.space
            .bytes(
                original_record,
                ExceptionRecord::size(WinArch::X86) as usize
            )
            .unwrap(),
        record_before
    );
    assert_eq!(
        p.space
            .bytes(original_context, RegContext::size(WinArch::X86))
            .unwrap(),
        context_before
    );

    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (retry_pc, page + 0x1c));
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), handler);
    let callback_sp = t.cpu.sp();
    assert_eq!(
        p.space.u32(callback_sp + 4).unwrap(),
        original_record as u32
    );
    assert_eq!(p.space.u32(callback_sp + 8).unwrap(), registration as u32);
    assert_eq!(
        p.space.u32(callback_sp + 12).unwrap(),
        original_context as u32
    );
    assert_eq!(return_callback(p, &mut t, 0, 0), Outcome::Continue);
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty());
}

#[test]
fn x86_nested_setup_fault_continue_search_visits_teb_registration() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, original_sp) =
        stack_fixture(p, &mut t, 0x370, prot::READWRITE | prot::GUARD);
    let (registration, handler) = frame_handler(p, &t, page);
    let veh = p.modules.exe().base + 0x500;
    p.seh.veh.push((1, veh));
    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh);
    assert_eq!(return_callback(p, &mut t, 0, 4), Outcome::Continue);
    assert_eq!(t.cpu.pc(), veh);
    let (_, nested_record, nested_context) = callback_pointers(p, &t);
    assert_eq!(
        ExceptionRecord::read(&p.space, WinArch::X86, nested_record)
            .unwrap()
            .code,
        STATUS_GUARD_PAGE_VIOLATION
    );

    // The x86 search is TEB-chain based, not a table walk. Declining this
    // nested fault visits the registration while the original selected call
    // remains pending in the outer pseudo-dispatcher frame.
    assert_eq!(return_callback(p, &mut t, 0, 4), Outcome::Continue);
    assert_eq!(t.cpu.pc(), handler);
    let callback_sp = t.cpu.sp();
    assert_eq!(p.space.u32(callback_sp + 4).unwrap(), nested_record as u32);
    assert_eq!(p.space.u32(callback_sp + 8).unwrap(), registration as u32);
    assert_eq!(
        p.space.u32(callback_sp + 12).unwrap(),
        nested_context as u32
    );
    assert!(t.frames[0].retry.is_some());
    assert_eq!(return_callback(p, &mut t, 0, 0), Outcome::Continue);
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!(t.cpu.pc(), retry_pc);
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), handler);
    assert_eq!(return_callback(p, &mut t, 0, 0), Outcome::Continue);
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty());
}

#[test]
fn x86_veh_guard_setup_fault_retries_original_vectored_slot() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, original_sp) =
        stack_fixture(p, &mut t, 0x360, prot::READWRITE | prot::GUARD);
    let veh = p.modules.exe().base + 0x500;
    p.seh.veh.push((1, veh));

    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh, "nested VEH starts after guard consumption");
    let (_, nested_record_at, _) = callback_pointers(p, &t);
    let nested = ExceptionRecord::read(&p.space, WinArch::X86, nested_record_at).unwrap();
    assert_eq!(nested.code, STATUS_GUARD_PAGE_VIOLATION);
    assert_eq!(nested.params, [1, page - 4]);
    assert_eq!(t.frames[0].dispatcher_setup_retries, 1);
    assert!(t.frames[0].retry.is_some());
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!(t.cpu.pc(), retry_pc);
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), veh, "original VEH slot starts once after retry");
    let (_, original_record_at, _) = callback_pointers(p, &t);
    assert_eq!(
        ExceptionRecord::read(&p.space, WinArch::X86, original_record_at)
            .unwrap()
            .code,
        ORIGINAL_CODE
    );
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty());
}

#[test]
fn x86_vch_guard_setup_fault_retries_original_continue_slot() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, original_sp) = stack_fixture(p, &mut t, 0x360, prot::READWRITE);
    let veh = p.modules.exe().base + 0x500;
    let vch = p.modules.exe().base + 0x600;
    p.seh.veh.push((1, veh));
    p.seh.vch.push((2, vch));
    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), veh);
    p.vm.protect(page - PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
        .unwrap();

    // Original VEH requests continuation, but the first VCH call faults at
    // its return slot. Nested dispatch runs VEH then VCH before the retry.
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    assert_eq!(t.cpu.pc(), veh);
    let (_, nested_record_at, _) = callback_pointers(p, &t);
    assert_eq!(
        ExceptionRecord::read(&p.space, WinArch::X86, nested_record_at)
            .unwrap()
            .code,
        STATUS_GUARD_PAGE_VIOLATION
    );
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    assert_eq!(t.cpu.pc(), vch, "nested VCH");
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!(t.cpu.pc(), retry_pc);
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), vch, "original VCH starts after repair");
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty());
}

#[test]
fn x86_unhandled_filter_guard_setup_fault_retries_original_filter() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, original_sp) =
        stack_fixture(p, &mut t, 0x360, prot::READWRITE | prot::GUARD);
    let filter = p.modules.exe().base + 0x600;
    p.seh.unhandled_filter = filter;

    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), filter, "nested filter starts after guard fault");
    let (_, nested_record_at, _) = callback_pointers(p, &t);
    let nested = ExceptionRecord::read(&p.space, WinArch::X86, nested_record_at).unwrap();
    assert_eq!(nested.code, STATUS_GUARD_PAGE_VIOLATION);
    assert_eq!(nested.params, [1, page - 4]);
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!(t.cpu.pc(), retry_pc);
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), filter, "original filter starts after repair");
    let (_, original_record_at, _) = callback_pointers(p, &t);
    assert_eq!(
        ExceptionRecord::read(&p.space, WinArch::X86, original_record_at)
            .unwrap()
            .code,
        ORIGINAL_CODE
    );
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    assert_eq!((t.cpu.pc(), t.cpu.sp()), (original_pc, original_sp));
    assert!(t.frames.is_empty());
}

#[test]
fn x86_frame_handler_persistent_readonly_setup_fault_fails_closed() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, _) = stack_fixture(p, &mut t, 0x370, prot::READONLY);
    let (_, handler) = frame_handler(p, &t, page);
    let veh = p.modules.exe().base + 0x500;
    p.seh.veh.push((1, veh));
    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    let (_, original_record, _) = callback_pointers(p, &t);
    let before = p
        .space
        .bytes(
            original_record,
            ExceptionRecord::size(WinArch::X86) as usize,
        )
        .unwrap();
    assert_eq!(
        return_callback(p, &mut t, 0, 4),
        Outcome::ProcessTerminate(STATUS_BAD_STACK)
    );
    assert_ne!(t.cpu.pc(), handler);
    assert_eq!(
        p.vm.query(page - PAGE_SIZE).unwrap().protect,
        prot::READONLY
    );
    assert_eq!(
        p.space
            .bytes(
                original_record,
                ExceptionRecord::size(WinArch::X86) as usize
            )
            .unwrap(),
        before
    );
}

#[test]
fn x86_repaired_frame_handler_invalid_disposition_rejects_synthetic_resume_search() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let (page, original_pc, _) = stack_fixture(p, &mut t, 0x370, prot::READWRITE | prot::GUARD);
    let (_, handler) = frame_handler(p, &t, page);
    let veh = p.modules.exe().base + 0x500;
    p.seh.veh.push((1, veh));
    assert_eq!(
        original_exception(p, &mut t, original_pc),
        Outcome::Continue
    );
    let (_, original_record, _) = callback_pointers(p, &t);
    let before = p
        .space
        .bytes(
            original_record,
            ExceptionRecord::size(WinArch::X86) as usize,
        )
        .unwrap();
    assert_eq!(return_callback(p, &mut t, 0, 4), Outcome::Continue);
    assert_eq!(t.cpu.pc(), veh, "guard setup fault reaches repair VEH");
    assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
    let retry_pc = p.traps.dispatcher_retry();
    assert_eq!(t.cpu.pc(), retry_pc);
    assert_eq!(dispatcher_retry(p, &mut t, retry_pc), Outcome::Continue);
    assert_eq!(t.cpu.pc(), handler);

    // Invalid disposition requests another exception after the original
    // callback starts. The private retry slot has no guest `+8` resume half
    // or return frame, so the dispatcher must stop without searching scratch.
    let outcome = return_callback(p, &mut t, 0xBAD, 0);
    assert!(
        matches!(&outcome, Outcome::Fail(message)
            if message.contains("repaired dispatcher cannot raise")),
        "{outcome:?}"
    );
    assert!(
        t.frames
            .iter()
            .all(|frame| frame.cont.is_none() && frame.callback_sp.is_none())
    );
    assert_eq!(
        p.space
            .bytes(
                original_record,
                ExceptionRecord::size(WinArch::X86) as usize
            )
            .unwrap(),
        before
    );
}

#[test]
fn x86_changed_nested_context_abandons_selected_handler_retry() {
    for change_sp in [false, true] {
        let mut process = super::tests::process(WinArch::X86);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let (page, original_pc, original_sp) =
            stack_fixture(p, &mut t, 0x370, prot::READWRITE | prot::GUARD);
        let (_, handler) = frame_handler(p, &t, page);
        let veh = p.modules.exe().base + 0x500;
        p.seh.veh.push((1, veh));
        assert_eq!(
            original_exception(p, &mut t, original_pc),
            Outcome::Continue
        );
        assert_eq!(return_callback(p, &mut t, 0, 4), Outcome::Continue);
        assert_eq!(t.cpu.pc(), veh);
        let retry_sp = t.frames[0].entry_sp;
        let (_, _, nested_context_at) = callback_pointers(p, &t);
        let mut context = RegContext::read(&p.space, WinArch::X86, nested_context_at).unwrap();
        assert_eq!(context.pc(), p.traps.dispatcher_retry());
        context.set_pc(original_pc);
        context.set_sp(if change_sp { original_sp } else { retry_sp });
        context.write(&p.space, nested_context_at).unwrap();
        assert_eq!(return_callback(p, &mut t, u64::MAX, 4), Outcome::Continue);
        assert_eq!(t.cpu.pc(), original_pc);
        assert!(t.frames.is_empty());
        assert_ne!(t.cpu.pc(), handler);
        let retry_pc = p.traps.dispatcher_retry();
        assert!(matches!(
            dispatcher_retry(p, &mut t, retry_pc),
            Outcome::Fail(_)
        ));
    }
}

#[test]
fn x86_private_dispatcher_retry_rejects_fresh_and_resume_half() {
    let mut process = super::tests::process(WinArch::X86);
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let retry_pc = p.traps.dispatcher_retry();
    assert_ne!(retry_pc, 0);
    assert!(matches!(
        p.traps.lookup(retry_pc),
        Some(crate::user::windows::traps::Trap::DispatcherRetry)
    ));
    assert!(p.traps.lookup(retry_pc + 8).is_none());
    assert!(p.traps.address_of(&seh::DISPATCHER).is_none());
    for pc in [retry_pc, retry_pc + 8] {
        t.cpu.set_pc(pc);
        let before = RegContext::capture(&t.cpu);
        assert!(matches!(
            dispatcher_retry(p, &mut t, pc),
            Outcome::Fail(message) if message.contains("no matching checked callback")
        ));
        assert_eq!(RegContext::capture(&t.cpu), before);
        assert!(t.frames.is_empty());
    }
}
