//! Execution control: run, step, stop, exit reporting, and interrupt injection.
//!
//! The run loop drives the vCPU instruction-by-instruction when a stepping
//! backend and any per-instruction requirement (instruction count, an `until`
//! address, a timeout, or code/block hooks) are present, and otherwise runs to
//! the next exit. Crucially it never holds a Rust borrow of the engine across a
//! C callback, so hook callbacks may freely re-enter the API.

use std::os::raw::c_int;
use std::time::Instant;

use rax_engine::cpu::{MemAccess, MemRecord, VcpuExit};

use crate::engine::{Engine, engine_mut};
use crate::guard;
use crate::hook::{
    MemHook, RAX_HOOK_MEM_FETCH, RAX_HOOK_MEM_READ, RAX_HOOK_MEM_WRITE, RAX_MEM_FETCH,
    RAX_MEM_READ, RAX_MEM_WRITE, SimpleHook,
};
use crate::status::RaxStatus;

/// Dispatches buffered memory-access records to matching memory hooks. Called
/// from the run loop between steps, so no Rust borrow of the engine is held and
/// callbacks may freely re-enter the API.
fn fire_mem_hooks(eptr: *mut Engine, mem_hooks: &[MemHook], records: &[MemRecord]) {
    for rec in records {
        let (kind, bit) = match rec.access {
            MemAccess::Read => (RAX_MEM_READ, RAX_HOOK_MEM_READ),
            MemAccess::Write => (RAX_MEM_WRITE, RAX_HOOK_MEM_WRITE),
            MemAccess::Exec => (RAX_MEM_FETCH, RAX_HOOK_MEM_FETCH),
        };
        for h in mem_hooks {
            if (h.types & bit) != 0 && h.matches(rec.addr) {
                (h.cb)(eptr, kind, rec.addr, rec.size as u32, rec.value, h.user);
            }
        }
    }
}

// Stop reasons. Mirror `RAX_STOP_*` in `rax.h`.
pub const RAX_STOP_NONE: i32 = 0;
pub const RAX_STOP_COUNT: i32 = 1;
pub const RAX_STOP_UNTIL: i32 = 2;
pub const RAX_STOP_TIMEOUT: i32 = 3;
pub const RAX_STOP_STOPPED: i32 = 4;
pub const RAX_STOP_HLT: i32 = 5;
pub const RAX_STOP_IO_IN: i32 = 6;
pub const RAX_STOP_IO_OUT: i32 = 7;
pub const RAX_STOP_MMIO_READ: i32 = 8;
pub const RAX_STOP_MMIO_WRITE: i32 = 9;
pub const RAX_STOP_EXCEPTION: i32 = 10;
pub const RAX_STOP_INTERRUPT: i32 = 11;
pub const RAX_STOP_SHUTDOWN: i32 = 12;
pub const RAX_STOP_DEBUG: i32 = 13;
pub const RAX_STOP_ERROR: i32 = 14;

/// Sentinel `until` meaning "no until-address stop". Mirrors `RAX_NO_ADDR`.
pub const RAX_NO_ADDR: u64 = u64::MAX;

/// Description of why execution stopped. Mirrors `rax_exit` in `rax.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitInfo {
    pub reason: i32,
    pub status: i32,
    pub address: u64,
    pub value: u64,
    pub size: u32,
    pub port: u32,
    pub intno: u32,
    pub _reserved: u32,
}

impl ExitInfo {
    pub fn none() -> Self {
        ExitInfo {
            reason: RAX_STOP_NONE,
            status: 0,
            address: 0,
            value: 0,
            size: 0,
            port: 0,
            intno: 0,
            _reserved: 0,
        }
    }
    fn stop(reason: i32) -> Self {
        let mut e = ExitInfo::none();
        e.reason = reason;
        e
    }
}

enum Action {
    Continue,
    Stop(ExitInfo),
}

#[inline]
fn le_bytes(value: u64, size: usize) -> Vec<u8> {
    value.to_le_bytes()[..size.min(8)].to_vec()
}

/// Services a synchronous vCPU exit, dispatching the relevant hook if present.
/// Returns whether to continue execution or stop (with an exit descriptor).
///
/// SAFETY: `eptr` is a live engine pointer; this function holds no Rust borrow
/// across any callback invocation.
fn dispatch_exit(
    eptr: *mut Engine,
    exit: VcpuExit,
    io_in: &[SimpleHook<crate::hook::IoInCb>],
    io_out: &[SimpleHook<crate::hook::IoOutCb>],
    mmio_r: &[SimpleHook<crate::hook::MmioReadCb>],
    mmio_w: &[SimpleHook<crate::hook::MmioWriteCb>],
    intr: &[SimpleHook<crate::hook::IntrCb>],
) -> Action {
    match exit {
        VcpuExit::Hlt => Action::Stop(ExitInfo::stop(RAX_STOP_HLT)),
        VcpuExit::Shutdown | VcpuExit::SystemEvent { .. } => {
            Action::Stop(ExitInfo::stop(RAX_STOP_SHUTDOWN))
        }
        VcpuExit::IoIn { port, size } => {
            if let Some(h) = io_in.first() {
                let value = (h.cb)(eptr, port as u32, size as u32, h.user);
                let bytes = le_bytes(value, size as usize);
                unsafe {
                    (*eptr).vcpu.complete_io_in(&bytes);
                }
                Action::Continue
            } else {
                let mut e = ExitInfo::stop(RAX_STOP_IO_IN);
                e.port = port as u32;
                e.size = size as u32;
                Action::Stop(e)
            }
        }
        VcpuExit::IoInString { port, size, count } => {
            if let Some(h) = io_in.first() {
                let mut buf = Vec::with_capacity(count as usize * size as usize);
                for _ in 0..count {
                    let value = (h.cb)(eptr, port as u32, size as u32, h.user);
                    buf.extend_from_slice(&le_bytes(value, size as usize));
                }
                unsafe {
                    (*eptr).vcpu.complete_io_in(&buf);
                }
                Action::Continue
            } else {
                let mut e = ExitInfo::stop(RAX_STOP_IO_IN);
                e.port = port as u32;
                e.size = size as u32;
                e.value = count as u64;
                Action::Stop(e)
            }
        }
        VcpuExit::IoOut { port, data } => {
            let mut val = [0u8; 8];
            let n = data.len().min(8);
            val[..n].copy_from_slice(&data[..n]);
            let value = u64::from_le_bytes(val);
            if let Some(h) = io_out.first() {
                (h.cb)(eptr, port as u32, data.len() as u32, value, h.user);
                Action::Continue
            } else {
                let mut e = ExitInfo::stop(RAX_STOP_IO_OUT);
                e.port = port as u32;
                e.size = data.len() as u32;
                e.value = value;
                Action::Stop(e)
            }
        }
        VcpuExit::MmioRead { addr, size } => {
            if let Some(h) = mmio_r.first() {
                let value = (h.cb)(eptr, addr, size as u32, h.user);
                let bytes = le_bytes(value, size as usize);
                unsafe {
                    (*eptr).vcpu.complete_io_in(&bytes);
                }
                Action::Continue
            } else {
                let mut e = ExitInfo::stop(RAX_STOP_MMIO_READ);
                e.address = addr;
                e.size = size as u32;
                Action::Stop(e)
            }
        }
        VcpuExit::MmioWrite { addr, data } => {
            let mut val = [0u8; 8];
            let n = data.len().min(8);
            val[..n].copy_from_slice(&data[..n]);
            let value = u64::from_le_bytes(val);
            if let Some(h) = mmio_w.first() {
                (h.cb)(eptr, addr, data.len() as u32, value, h.user);
                Action::Continue
            } else {
                let mut e = ExitInfo::stop(RAX_STOP_MMIO_WRITE);
                e.address = addr;
                e.size = data.len() as u32;
                e.value = value;
                Action::Stop(e)
            }
        }
        VcpuExit::Exception(vector) => {
            if let Some(h) = intr.first() {
                (h.cb)(eptr, vector as u32, h.user);
                Action::Continue
            } else {
                let mut e = ExitInfo::stop(RAX_STOP_EXCEPTION);
                e.intno = vector as u32;
                Action::Stop(e)
            }
        }
        VcpuExit::Debug => Action::Stop(ExitInfo::stop(RAX_STOP_DEBUG)),
        VcpuExit::FailEntry { reason } => {
            let mut e = ExitInfo::stop(RAX_STOP_ERROR);
            e.status = RaxStatus::Fault as i32;
            e.value = reason;
            Action::Stop(e)
        }
        VcpuExit::InternalError => {
            let mut e = ExitInfo::stop(RAX_STOP_ERROR);
            e.status = RaxStatus::Fault as i32;
            Action::Stop(e)
        }
        VcpuExit::Unknown(_) => {
            let mut e = ExitInfo::stop(RAX_STOP_ERROR);
            e.status = RaxStatus::Fault as i32;
            Action::Stop(e)
        }
        // Debug-feature variants (GdbBreakpoint/GdbStep) and any future exits.
        #[allow(unreachable_patterns)]
        _ => Action::Stop(ExitInfo::stop(RAX_STOP_DEBUG)),
    }
}

/// Core run loop. `set_begin` (if `Some`) loads PC before running; `until`
/// stops just before executing that address when `has_until`; `count` (if
/// non-zero) caps instructions; `timeout_us` (if non-zero) caps wall-clock
/// time. The number of instructions executed is written to `executed_out`.
fn run_emulation(
    eptr: *mut Engine,
    set_begin: Option<u64>,
    until: u64,
    has_until: bool,
    count: u64,
    timeout_us: u64,
    executed_out: Option<&mut u64>,
) -> RaxStatus {
    // ---- setup (single transient borrow) ----
    let supports;
    let code_hooks;
    let block_hooks;
    let intr_hooks;
    let io_in_hooks;
    let io_out_hooks;
    let mmio_r_hooks;
    let mmio_w_hooks;
    let invalid_hooks;
    let mem_hooks;
    {
        let e = unsafe { &mut *eptr };
        e.clear_err();
        e.last_exit = ExitInfo::none();
        e.last_fault = crate::fault::RaxFaultInfo::default();
        e.stop_flag.set(false);
        e.running = true;
        if let Some(b) = set_begin {
            if let Err(err) = e.vcpu.set_current_pc(b) {
                e.running = false;
                return e.fail_engine(&err);
            }
        }
        supports = e.vcpu.supports_stepping();
        code_hooks = e.hooks.code.clone();
        block_hooks = e.hooks.block.clone();
        intr_hooks = e.hooks.intr.clone();
        io_in_hooks = e.hooks.io_in.clone();
        io_out_hooks = e.hooks.io_out.clone();
        mmio_r_hooks = e.hooks.mmio_read.clone();
        mmio_w_hooks = e.hooks.mmio_write.clone();
        invalid_hooks = e.hooks.invalid.clone();
        mem_hooks = e.hooks.mem.clone();
        // Arm per-access recording only while memory hooks are present.
        e.vcpu.set_mem_recording(!mem_hooks.is_empty());
    }

    let want_step = supports
        && (count != 0
            || has_until
            || timeout_us != 0
            || !code_hooks.is_empty()
            || !block_hooks.is_empty()
            || !mem_hooks.is_empty());
    let mut mem_records: Vec<MemRecord> = Vec::new();

    let start = Instant::now();
    let mut executed: u64 = 0;
    let mut block_pending = true;
    // Definitely assigned on every loop-exit path before the teardown reads it.
    let mut exit_info: ExitInfo;
    let mut ret = RaxStatus::Ok;

    let timed_out = |start: &Instant| -> bool {
        timeout_us != 0 && (start.elapsed().as_micros() as u64) >= timeout_us
    };
    let stopped = |eptr: *mut Engine| -> bool { unsafe { (*eptr).stop_flag.get() } };

    if want_step {
        'step: loop {
            let pc = unsafe { (*eptr).vcpu.current_pc() };

            if stopped(eptr) {
                exit_info = ExitInfo::stop(RAX_STOP_STOPPED);
                exit_info.address = pc;
                break;
            }
            if has_until && pc == until {
                exit_info = ExitInfo::stop(RAX_STOP_UNTIL);
                exit_info.address = pc;
                break;
            }
            if count != 0 && executed >= count {
                exit_info = ExitInfo::stop(RAX_STOP_COUNT);
                exit_info.address = pc;
                exit_info.value = executed;
                break;
            }
            if timed_out(&start) {
                exit_info = ExitInfo::stop(RAX_STOP_TIMEOUT);
                exit_info.address = pc;
                exit_info.value = executed;
                break;
            }

            // Block-entry hooks.
            if block_pending {
                for h in &block_hooks {
                    if h.matches(pc) {
                        (h.cb)(eptr, pc, 0, h.user);
                    }
                }
                block_pending = false;
                if stopped(eptr) {
                    exit_info = ExitInfo::stop(RAX_STOP_STOPPED);
                    exit_info.address = pc;
                    break;
                }
            }

            // Per-instruction code hooks.
            for h in &code_hooks {
                if h.matches(pc) {
                    (h.cb)(eptr, pc, 0, h.user);
                }
            }
            if stopped(eptr) {
                exit_info = ExitInfo::stop(RAX_STOP_STOPPED);
                exit_info.address = pc;
                break;
            }

            let before = unsafe { (*eptr).vcpu.instruction_count() };
            let res = unsafe { (*eptr).vcpu.step_insn() };
            let after = unsafe { (*eptr).vcpu.instruction_count() };
            executed = executed.saturating_add(after.wrapping_sub(before));

            // Surface the memory accesses this instruction made (re-entrancy is
            // safe: we hold no Rust borrow of the engine here).
            if !mem_hooks.is_empty() {
                mem_records.clear();
                unsafe {
                    (*eptr).vcpu.drain_mem_records(&mut mem_records);
                }
                fire_mem_hooks(eptr, &mem_hooks, &mem_records);
            }

            match res {
                Ok(None) => {}
                Ok(Some(exit)) => {
                    match dispatch_exit(
                        eptr,
                        exit,
                        &io_in_hooks,
                        &io_out_hooks,
                        &mmio_r_hooks,
                        &mmio_w_hooks,
                        &intr_hooks,
                    ) {
                        Action::Continue => {}
                        Action::Stop(mut info) => {
                            if info.address == 0 {
                                info.address = pc;
                            }
                            exit_info = info;
                            break 'step;
                        }
                    }
                }
                Err(err) => {
                    let s = crate::status::status_from_engine_error(&err);
                    let msg = err.to_string();
                    unsafe {
                        (*eptr).err_msg = msg;
                        (*eptr).last_fault = crate::fault::RaxFaultInfo::from_error(pc, &err);
                        (*eptr).last_fault.retired_instructions = executed;
                    }
                    if let Some(h) = invalid_hooks.first() {
                        let handled = (h.cb)(eptr, pc, h.user);
                        if handled != 0 {
                            unsafe {
                                (*eptr).last_fault = crate::fault::RaxFaultInfo::default();
                            }
                            continue 'step;
                        }
                    }
                    let mut info = ExitInfo::stop(RAX_STOP_ERROR);
                    info.address = pc;
                    info.status = s as i32;
                    exit_info = info;
                    ret = s;
                    break 'step;
                }
            }

            // Block-boundary detection for the next iteration: a non-sequential
            // PC change (backward, or beyond one max-length instruction ahead)
            // marks the next instruction as a block head.
            let new_pc = unsafe { (*eptr).vcpu.current_pc() };
            if new_pc < pc || new_pc > pc.wrapping_add(15) {
                block_pending = true;
            }
        }
    } else {
        // Run-to-exit mode (also the only mode for non-stepping backends).
        loop {
            if stopped(eptr) {
                exit_info = ExitInfo::stop(RAX_STOP_STOPPED);
                break;
            }
            if timed_out(&start) {
                exit_info = ExitInfo::stop(RAX_STOP_TIMEOUT);
                break;
            }
            let before = unsafe { (*eptr).vcpu.instruction_count() };
            let res = unsafe { (*eptr).vcpu.run() };
            let after = unsafe { (*eptr).vcpu.instruction_count() };
            executed = executed.saturating_add(after.wrapping_sub(before));
            let pc = unsafe { (*eptr).vcpu.current_pc() };
            match res {
                Ok(exit) => match dispatch_exit(
                    eptr,
                    exit,
                    &io_in_hooks,
                    &io_out_hooks,
                    &mmio_r_hooks,
                    &mmio_w_hooks,
                    &intr_hooks,
                ) {
                    Action::Continue => {}
                    Action::Stop(mut info) => {
                        if info.address == 0 {
                            info.address = pc;
                        }
                        exit_info = info;
                        break;
                    }
                },
                Err(err) => {
                    let s = crate::status::status_from_engine_error(&err);
                    let msg = err.to_string();
                    unsafe {
                        (*eptr).err_msg = msg;
                        (*eptr).last_fault = crate::fault::RaxFaultInfo::from_error(pc, &err);
                        (*eptr).last_fault.retired_instructions = executed;
                    }
                    if let Some(h) = invalid_hooks.first() {
                        let handled = (h.cb)(eptr, pc, h.user);
                        if handled != 0 {
                            unsafe {
                                (*eptr).last_fault = crate::fault::RaxFaultInfo::default();
                            }
                            continue;
                        }
                    }
                    let mut info = ExitInfo::stop(RAX_STOP_ERROR);
                    info.address = pc;
                    info.status = s as i32;
                    exit_info = info;
                    ret = s;
                    break;
                }
            }
        }
    }

    // ---- teardown (single transient borrow) ----
    // For non-I/O control stops, `value` is an unambiguous retired-step
    // count. I/O/MMIO exits retain their protocol-specific value.
    if matches!(
        exit_info.reason,
        RAX_STOP_COUNT
            | RAX_STOP_UNTIL
            | RAX_STOP_TIMEOUT
            | RAX_STOP_STOPPED
            | RAX_STOP_HLT
            | RAX_STOP_EXCEPTION
            | RAX_STOP_SHUTDOWN
            | RAX_STOP_DEBUG
            | RAX_STOP_ERROR
    ) {
        exit_info.value = executed;
    }
    {
        let e = unsafe { &mut *eptr };
        e.running = false;
        e.last_exit = exit_info;
        e.last_fault.retired_instructions = executed;
        if exit_info.reason == RAX_STOP_EXCEPTION && exit_info.intno == 6 {
            e.last_fault.kind = crate::fault::RAX_FAULT_INVALID_INSTRUCTION;
            e.last_fault.pc = exit_info.address;
        }
        if !mem_hooks.is_empty() {
            e.vcpu.set_mem_recording(false);
        }
        if let Some(out) = executed_out {
            *out = executed;
        }
    }
    ret
}

// ===========================================================================
// FFI: run control
// ===========================================================================

/// Runs from `begin` until one of the stop conditions is met:
///   * `count` instructions retired (0 = unlimited),
///   * PC reaches `until` (pass `RAX_NO_ADDR` for none),
///   * `timeout_us` microseconds elapse (0 = none),
///   * `rax_emu_stop` is called from a hook,
///   * the guest halts / an unhandled exit or fault occurs.
///
/// Returns `RAX_OK` for any clean stop (inspect `rax_emu_last_exit` for the
/// reason) and an error status for an unrecoverable guest/engine fault.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_start(
    engine: *mut Engine,
    begin: u64,
    until: u64,
    timeout_us: u64,
    count: u64,
) -> RaxStatus {
    guard(|| {
        let valid = unsafe { engine_mut(engine) }.is_some();
        if !valid {
            return RaxStatus::Handle;
        }
        if unsafe { (*engine).running } {
            return unsafe { (*engine).fail(RaxStatus::State, "engine is already running") };
        }
        let has_until = until != RAX_NO_ADDR;
        run_emulation(
            engine,
            Some(begin),
            until,
            has_until,
            count,
            timeout_us,
            None,
        )
    })
}

/// Steps `count` instructions from the current PC (no PC reload, no `until`),
/// writing the number actually executed to `*executed` if non-NULL. `count==0`
/// is treated as 1.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_step(engine: *mut Engine, count: u64, executed: *mut u64) -> RaxStatus {
    guard(|| {
        let valid = unsafe { engine_mut(engine) }.is_some();
        if !valid {
            return RaxStatus::Handle;
        }
        if unsafe { (*engine).running } {
            return unsafe { (*engine).fail(RaxStatus::State, "engine is already running") };
        }
        if !unsafe { (*engine).vcpu.supports_stepping() } {
            return unsafe {
                (*engine).fail(
                    RaxStatus::Unsupported,
                    "this backend does not support stepping",
                )
            };
        }
        let n = if count == 0 { 1 } else { count };
        let mut done: u64 = 0;
        let st = run_emulation(engine, None, RAX_NO_ADDR, false, n, 0, Some(&mut done));
        if !executed.is_null() {
            unsafe {
                *executed = done;
            }
        }
        st
    })
}

/// Requests that the running loop stop at the next safe point. Intended to be
/// called from within a hook callback.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_stop(engine: *mut Engine) -> RaxStatus {
    guard(|| match unsafe { engine_mut(engine) } {
        Some(e) => {
            e.stop_flag.set(true);
            RaxStatus::Ok
        }
        None => RaxStatus::Handle,
    })
}

/// Copies the most recent stop/exit descriptor into `*out`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_last_exit(engine: *const Engine, out: *mut ExitInfo) -> RaxStatus {
    guard(|| {
        let e = match unsafe { crate::engine::engine_ref(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        if out.is_null() {
            return RaxStatus::Arg;
        }
        unsafe {
            *out = e.last_exit;
        }
        RaxStatus::Ok
    })
}

/// Returns the total number of instructions retired by the vCPU, or 0.
#[unsafe(no_mangle)]
pub extern "C" fn rax_emu_icount(engine: *const Engine) -> u64 {
    crate::guard_val(0, || match unsafe { crate::engine::engine_ref(engine) } {
        Some(e) => e.icount_base.saturating_add(e.vcpu.instruction_count()),
        None => 0,
    })
}

// ===========================================================================
// FFI: interrupt injection
// ===========================================================================

/// Injects a maskable interrupt with `vector` into the guest. Returns
/// `RAX_OK` if delivered, `RAX_ERR_STATE` if interrupts are currently masked.
#[unsafe(no_mangle)]
pub extern "C" fn rax_interrupt(engine: *mut Engine, vector: u32) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        e.clear_err();
        match e.vcpu.inject_interrupt(vector as u8) {
            Ok(true) => RaxStatus::Ok,
            Ok(false) => e.fail(RaxStatus::State, "interrupts are masked"),
            Err(err) => e.fail_engine(&err),
        }
    })
}

/// Injects a non-maskable interrupt into the guest.
#[unsafe(no_mangle)]
pub extern "C" fn rax_nmi(engine: *mut Engine) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        e.clear_err();
        match e.vcpu.inject_nmi() {
            Ok(_) => RaxStatus::Ok,
            Err(err) => e.fail_engine(&err),
        }
    })
}

/// Returns non-zero if the guest can currently accept a maskable interrupt.
#[unsafe(no_mangle)]
pub extern "C" fn rax_can_interrupt(engine: *const Engine) -> c_int {
    crate::guard_val(0, || match unsafe { crate::engine::engine_ref(engine) } {
        Some(e) => e.vcpu.can_inject_interrupt() as c_int,
        None => 0,
    })
}
