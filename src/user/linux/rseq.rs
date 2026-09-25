//! Restartable sequences (`kernel/rseq.c`, `include/linux/rseq.h`,
//! `include/linux/rseq_entry.h`, Linux 6.19): a thread's registration and
//! what the return to user mode does with it.
//!
//! The model follows the generic IRQ entry all three architectures use:
//! a thread records whether it last left user mode through an interrupt
//! or exception (a preemption at the end of its slice, or a fault) or
//! through a system call. When it is switched out and in again with that
//! flag, or with its IDs to write (after registration), the return to
//! user mode writes the IDs and, for an interrupted thread, checks the
//! critical section `rseq_cs` names: an instruction pointer inside it
//! moves to the abort handler, whose preceding word must be the registered
//! signature; outside, `rseq_cs` is only cleared. Signal delivery to an
//! interrupted thread does the same check before the handler's frame
//! saves the instruction pointer. A failure (a fault, an abort handler
//! outside user space, a wrong signature) is `SIGSEGV`. The emulated CPU
//! is CPU 0 of node 0, and the thread's concurrency ID 0.

use super::abi::LinuxAbi;
use super::process::Thread;
use crate::user::mm::AddressSpace;

/// `ORIG_RSEQ_SIZE`: the original `struct rseq` with its padding.
pub const ORIG_SIZE: u32 = 32;
/// `offsetof(struct rseq, end)`: the fields this kernel knows
/// (`AT_RSEQ_FEATURE_SIZE`).
pub const FEATURE_SIZE: u32 = 28;
/// `__alignof__(struct rseq)` (`AT_RSEQ_ALIGN`).
pub const ALIGN: u64 = 32;
/// `RSEQ_CPU_ID_UNINITIALIZED`.
pub const CPU_ID_UNINITIALIZED: u32 = u32::MAX;

/// `struct rseq` field offsets.
mod field {
    pub const CPU_ID_START: u64 = 0;
    pub const CPU_ID: u64 = 4;
    pub const RSEQ_CS: u64 = 8;
    pub const NODE_ID: u64 = 20;
    pub const MM_CID: u64 = 24;
}

/// A thread's registration (`task_struct::rseq`) and pending events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rseq {
    /// The `struct rseq` area.
    pub addr: u64,
    /// Its registered length.
    pub len: u32,
    /// The signature abort handlers are preceded by.
    pub sig: u32,
    /// `rseq_event::user_irq`: the thread last left user mode through an
    /// interrupt or exception rather than a system call.
    pub user_irq: bool,
    /// `rseq_event::ids_changed`: the IDs are to be written.
    pub ids_changed: bool,
    /// `rseq_event::sched_switch`: work is due on the return to user mode.
    pub sched_switch: bool,
}

impl Rseq {
    /// A new registration, with its IDs due (`rseq_force_update`).
    pub fn new(addr: u64, len: u32, sig: u32) -> Self {
        Rseq {
            addr,
            len,
            sig,
            user_irq: false,
            ids_changed: true,
            sched_switch: true,
        }
    }
}

/// Writes the IDs (`rseq_set_ids_get_csaddr`): `cpu` to `cpu_id_start` and
/// `cpu_id`, then the node and concurrency IDs.
pub fn set_ids(space: &AddressSpace, addr: u64, cpu: u32, node: u32, cid: u32) -> bool {
    [
        (field::CPU_ID_START, cpu),
        (field::CPU_ID, cpu),
        (field::NODE_ID, node),
        (field::MM_CID, cid),
    ]
    .iter()
    .all(|&(off, v)| space.write(addr + off, &v.to_le_bytes()).is_ok())
}

fn read_u64(space: &AddressSpace, addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    space.read(addr, &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

/// `rseq_update_user_cs` for the critical section at `csaddr`: false for a
/// descriptor outside user space, a fault, an abort handler outside user
/// space, or a wrong signature.
fn update_user_cs(space: &AddressSpace, task_size: u64, t: &mut Thread, csaddr: u64) -> bool {
    let Some(r) = t.rseq.clone() else {
        return true;
    };
    if csaddr >= task_size {
        return false;
    }
    let ip = t.cpu.pc();
    let (Some(start), Some(offset), Some(abort)) = (
        read_u64(space, csaddr + 8),
        read_u64(space, csaddr + 16),
        read_u64(space, csaddr + 24),
    ) else {
        return false;
    };
    let clear = |space: &AddressSpace| space.write(r.addr + field::RSEQ_CS, &[0u8; 8]).is_ok();
    // Outside the section: clear it.
    if ip.wrapping_sub(start) >= offset {
        return clear(space);
    }
    if abort >= task_size || abort < 4 {
        return false;
    }
    let mut sig = [0u8; 4];
    if space.read(abort - 4, &mut sig).is_err() || u32::from_le_bytes(sig) != r.sig {
        return false;
    }
    if !clear(space) {
        return false;
    }
    t.cpu.set_pc(abort);
    true
}

/// `rseq_handle_cs`: the critical section `rseq_cs` names, if any.
fn handle_cs(space: &AddressSpace, task_size: u64, t: &mut Thread) -> bool {
    let Some(addr) = t.rseq.as_ref().map(|r| r.addr) else {
        return true;
    };
    match read_u64(space, addr + field::RSEQ_CS) {
        None => false,
        Some(0) => true,
        Some(cs) => update_user_cs(space, task_size, t, cs),
    }
}

/// The thread leaves user mode: through an interrupt or exception
/// (`irq`), or a system call.
pub fn left_user(t: &mut Thread, irq: bool) {
    if let Some(r) = &mut t.rseq {
        r.user_irq = irq;
    }
}

/// `rseq_sched_switch_event`: the thread was switched out; work is due if
/// it was interrupted or its IDs are to be written.
pub fn switched(t: &mut Thread) {
    if let Some(r) = &mut t.rseq
        && (r.user_irq || r.ids_changed)
    {
        r.sched_switch = true;
    }
}

/// `rseq_signal_deliver`, before a handler's frame is built: an
/// interrupted thread's critical section is checked (and aborted) first.
/// False when `SIGSEGV` must be forced.
pub fn signal_deliver(space: &AddressSpace, task_size: u64, t: &mut Thread) -> bool {
    match &t.rseq {
        Some(r) if r.user_irq => handle_cs(space, task_size, t),
        _ => true,
    }
}

/// The rseq work of the return to user mode (`__rseq_exit_to_user_mode_restart`,
/// and on arm64 `rseq_slowpath_update_usr`, which writes the IDs on every
/// switch): false when `SIGSEGV` must be forced. The events are consumed.
pub fn exit_to_user(space: &AddressSpace, abi: LinuxAbi, task_size: u64, t: &mut Thread) -> bool {
    let Some(r) = t.rseq.clone() else {
        return true;
    };
    let mut ok = true;
    if r.sched_switch {
        if r.ids_changed || abi == LinuxAbi::Aarch64 {
            ok = set_ids(space, r.addr, 0, 0, 0);
        }
        if ok && r.user_irq {
            ok = handle_cs(space, task_size, t);
        }
    }
    if let Some(r) = &mut t.rseq {
        r.user_irq = false;
        r.ids_changed = false;
        r.sched_switch = false;
    }
    ok
}
