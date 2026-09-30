//! Deferred memory reclamation (`osfmk/vm/vm_reclaim.c`): a task's ring of
//! freed regions, shared with the kernel, which libmalloc's xzone
//! allocator fills and the kernel empties when asked (`flush`, `resize`)
//! or when a sample of the ring's idle content finds memory worth trimming
//! (the accounting trap).
//!
//! The ring is guest memory: a 128-byte header and 16-byte entries.
//! Userspace writes the entries and `tail`; the kernel writes `head` and
//! `busy` (IDs below `head` are reclaimed, those below `busy` are being
//! reclaimed) and takes slots modulo its own copy of the ring's length.
//! A fault on the ring, an index userspace corrupted, or an entry with an
//! unknown action kills the task with a virtual-memory guard exception.
//! The emulated machine is never under memory pressure, so nothing else
//! reclaims.

use super::guard;
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::exception;
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::task::Ring;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Mapping, Perms};

/// `VM_MEMORY_VM_RECLAIM`.
const TAG: u32 = 22;
/// `VM_RECLAIM_MAX_BUFFER_SIZE`.
const MAX_BUFFER_SIZE: u64 = 128 << 20;
/// `kReclaimChunkSize`.
const CHUNK: u64 = 16;
/// `offsetof(struct mach_vm_reclaim_ring_s, entries)`.
const HEADER: u64 = 128;
/// `sizeof(struct mach_vm_reclaim_entry_s)`.
const ENTRY: u64 = 16;
/// The sampling period without memory pressure (macOS): 10 s.
const PERIOD_NS: u64 = 10_000_000_000;
/// The share of the task's peak footprint an idle minimum must exceed to
/// be trimmed without memory pressure (macOS), in percent.
const TRIM_PERCENT: u64 = 10;
/// Sampling periods after which a ring counts as abandoned.
const ABANDONED: u64 = 512;
/// `VMDR_WMA_UNIT`, and the moving average's weights.
const WMA_UNIT: u64 = 256;

/// Ring header fields.
mod off {
    pub const RECLAIMABLE_BYTES: u64 = 0x48;
    pub const RECLAIMABLE_BYTES_MIN: u64 = 0x50;
    pub const HEAD: u64 = 0x58;
    pub const BUSY: u64 = 0x60;
    pub const TAIL: u64 = 0x68;
}

/// `VM_RECLAIM_FREE`, `VM_RECLAIM_DEALLOCATE`.
const FREE: u8 = 1;
const DEALLOCATE: u8 = 2;

/// `VM_RECLAIM_RESOURCE_SHORTAGE` (`err_vm_reclaim(6)`).
pub const RESOURCE_SHORTAGE: KernReturn = 0x2000_4006;

/// `TASK_EXC_GUARD_VM_FATAL`.
const TASK_EXC_GUARD_VM_FATAL: u32 = 0x08;

/// `kGUARD_EXC_*` virtual-memory flavors of the kills.
mod flavor {
    pub const DEALLOC_GAP: u64 = 1;
    pub const RECLAIM_COPYIO_FAILURE: u64 = 2;
    pub const RECLAIM_INDEX_FAILURE: u64 = 4;
    pub const RECLAIM_DEALLOCATE_FAILURE: u64 = 8;
}

/// `EFAULT`, the subcode of a copy-in or copy-out failure.
const EFAULT: u64 = 14;

/// The sampling period in the guest's `mach_absolute_time` units.
fn period(abi: DarwinAbi) -> u64 {
    match abi {
        DarwinAbi::X86_64 => PERIOD_NS,
        DarwinAbi::Arm64 => {
            (u128::from(PERIOD_NS) * u128::from(crate::user::darwin::arch::ARM64_COUNTER_HZ)
                / 1_000_000_000) as u64
        }
    }
}

fn now(ctx: &Ctx<'_>) -> u64 {
    super::absolute_time(ctx.proc.abi)
}

/// `vmdr_round_len_to_size`: the mapping that holds `count` entries.
fn round_len_to_size(page: u64, count: u32) -> u64 {
    (HEADER + ENTRY * u64::from(count)).div_ceil(page) * page
}

/// Why a reclamation stopped short.
enum Stop {
    /// An error the caller reports.
    Err(KernReturn),
    /// The task was killed.
    Killed,
}

impl Stop {
    fn kr(self) -> KernReturn {
        match self {
            Stop::Err(k) => k,
            Stop::Killed => kr::KERN_FAILURE,
        }
    }
}

/// `reclaim_kill_with_reason`: an `EXC_GUARD` of type
/// `GUARD_TYPE_VIRT_MEMORY` goes to the thread's and task's handlers,
/// then the task dies of `SIGKILL` (`exit_with_fatal_exception_and_notify`;
/// both once the call returns, which it never does to user code).
fn kill(ctx: &mut Ctx<'_>, flavor: u64, subcode: u64) -> Stop {
    let code = guard::code(guard::GUARD_TYPE_VIRT_MEMORY, flavor as u32, 0);
    if ctx.proc.config.warn_unhandled() {
        eprintln!("rax-user: EXC_GUARD (virtual memory {code:#x}, subcode {subcode:#x}): fatal");
    }
    exception::post_guard(
        &mut ctx.proc.guard_ast,
        exception::GuardAst {
            code,
            subcode,
            sticky: true,
        },
    );
    Stop::Killed
}

/// A ring word, the task killed when it cannot be read.
fn load(ctx: &mut Ctx<'_>, addr: u64) -> Result<u64, Stop> {
    match ctx.read_u64(addr) {
        Ok(v) => Ok(v),
        Err(_) => Err(kill(ctx, flavor::RECLAIM_COPYIO_FAILURE, EFAULT)),
    }
}

/// Stores a ring word, the task killed when it cannot be written.
fn store(ctx: &mut Ctx<'_>, addr: u64, v: u64) -> Result<(), Stop> {
    ctx.write_u64(addr, v)
        .map_err(|_| kill(ctx, flavor::RECLAIM_COPYIO_FAILURE, EFAULT))
}

/// `reclaim_chunk`: reclaims up to `chunk` pending entries from the head
/// of `ring`, stopping once `target` bytes are reclaimed; the bytes and
/// the entries reclaimed. (Each guest process runs on one host thread,
/// so `tail` cannot move during the call and the kernel's retry loop
/// takes one pass; a `tail` below `head` is a cancellation in progress.)
fn reclaim_chunk(
    ctx: &mut Ctx<'_>,
    ring: Ring,
    target: u64,
    chunk: u64,
) -> Result<(u64, u64), Stop> {
    let base = ring.addr;
    let mut busy = load(ctx, base + off::BUSY)?;
    let mut head = load(ctx, base + off::HEAD)?;
    let tail = load(ctx, base + off::TAIL)?;
    if busy < head || busy - head > CHUNK {
        return Err(kill(ctx, flavor::RECLAIM_INDEX_FAILURE, busy));
    }
    if tail < head {
        return Err(Stop::Err(kr::KERN_ABORTED));
    }
    let n = (tail - head).min(chunk);
    if n > 0 {
        busy = head + n;
        store(ctx, base + off::BUSY, busy)?;
    }
    // The entries, from the head's slot, wrapping at the kernel's length.
    let len = u64::from(ring.len.max(1));
    let mut entries = Vec::with_capacity(n as usize);
    for i in 0..n {
        let slot = (head + i) % len;
        let at = base + HEADER + slot * ENTRY;
        let mut e = [0u8; 16];
        if ctx.read_into(at, &mut e).is_err() {
            return Err(kill(ctx, flavor::RECLAIM_COPYIO_FAILURE, EFAULT));
        }
        entries.push(e);
    }
    let page = ctx.proc.vm.page;
    let mut bytes = 0u64;
    let mut done = 0u64;
    for e in &entries {
        if bytes >= target {
            break;
        }
        let addr = u64::from_le_bytes(e[..8].try_into().expect("8 bytes"));
        let size = u64::from(u32::from_le_bytes(e[8..12].try_into().expect("4 bytes")));
        if addr != 0 && size != 0 {
            let start = addr & !(page - 1);
            let end = addr.saturating_add(size).div_ceil(page) * page;
            match e[12] {
                // VM_BEHAVIOR_REUSABLE: the mapping and its contents stay.
                FREE => {}
                DEALLOCATE => {
                    // Any hole fails the whole range, nothing removed.
                    if ctx.proc.space.first_unmapped(start, end - start).is_some() {
                        if ctx.proc.task.exc_guard & TASK_EXC_GUARD_VM_FATAL != 0 {
                            return Err(kill(ctx, flavor::DEALLOC_GAP, addr));
                        }
                        return Err(Stop::Err(kr::KERN_INVALID_VALUE));
                    }
                    let r = super::vm::deallocate(ctx, start, end - start);
                    if r != kr::KERN_SUCCESS {
                        return Err(kill(ctx, flavor::RECLAIM_DEALLOCATE_FAILURE, r as u64));
                    }
                }
                _ => return Err(kill(ctx, flavor::RECLAIM_DEALLOCATE_FAILURE, 0)),
            }
            bytes += size;
        }
        done += 1;
    }
    head += done;
    store(ctx, base + off::HEAD, head)?;
    if busy > head {
        store(ctx, base + off::BUSY, head)?;
    }
    Ok((bytes, done))
}

/// Reclaims until `num` entries (or, with `drain`, all of them) are gone
/// or a chunk reclaims nothing: the bytes reclaimed.
fn reclaim(ctx: &mut Ctx<'_>, ring: Ring, num: Option<u64>) -> Result<u64, Stop> {
    let mut bytes = 0u64;
    let mut total = 0u64;
    loop {
        let chunk = match num {
            Some(n) if total >= n => break,
            Some(n) => (n - total).min(CHUNK),
            None => CHUNK,
        };
        let (b, n) = reclaim_chunk(ctx, ring, u64::MAX, chunk)?;
        bytes += b;
        total += n;
        if n == 0 {
            break;
        }
    }
    Ok(bytes)
}

/// `mach_vm_deferred_reclamation_buffer_allocate(len, max_len)`: a ring
/// for `max_len` entries (`len` in use), zero-filled, read-write, tagged
/// `VM_MEMORY_VM_RECLAIM`; its address and the first sampling deadline.
/// A task has one ring: another request is refused
/// (`VM_RECLAIM_RESOURCE_SHORTAGE`), leaving the inaccessible region
/// XNU's failed mapping leaves.
pub fn allocate(ctx: &mut Ctx<'_>, len: u32, max_len: u32) -> Result<(u64, u64), KernReturn> {
    if len == 0 || max_len == 0 || max_len < len {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let vmx = ctx.proc.vm;
    let size = round_len_to_size(vmx.page, max_len);
    if size > MAX_BUFFER_SIZE {
        return Err(kr::KERN_NO_SPACE);
    }
    let at = ctx
        .proc
        .space
        .find_free_bottom_up(size, vmx.page, vmx.min, vmx.max)
        .ok_or(kr::KERN_NO_SPACE)?;
    let taken = ctx.proc.task.reclaim.is_some();
    let (perms, max) = if taken {
        (Perms::empty(), vm::VM_PROT_NONE)
    } else {
        (vm::perms(vm::VM_PROT_DEFAULT), vm::VM_PROT_DEFAULT)
    };
    let mapping = Mapping {
        flags: VmFlags::new(max, vm::VM_INHERIT_COPY, TAG).bits(),
        ..Mapping::anonymous(perms)
    };
    ctx.proc
        .space
        .map(at, size, mapping)
        .map_err(|_| kr::KERN_NO_SPACE)?;
    if taken {
        return Err(RESOURCE_SHORTAGE);
    }
    ctx.proc.task.reclaim = Some(Ring {
        addr: at,
        size,
        len,
        last_sample: 0,
        wma: 0,
        peak: 0,
    });
    Ok((at, now(ctx) + period(ctx.proc.abi)))
}

/// `mach_vm_deferred_reclamation_buffer_flush(num_entries)`: reclaims up
/// to `num_entries` pending entries; the bytes reclaimed and the next
/// sampling deadline.
pub fn flush(ctx: &mut Ctx<'_>, num: u32) -> Result<(u64, u64), KernReturn> {
    let ring = ctx.proc.task.reclaim.ok_or(kr::KERN_INVALID_ARGUMENT)?;
    let bytes = reclaim(ctx, ring, Some(u64::from(num))).map_err(Stop::kr)?;
    Ok((bytes, now(ctx) + period(ctx.proc.abi)))
}

/// `mach_vm_deferred_reclamation_buffer_resize(new_len)`: reclaims every
/// pending entry, then takes `new_len` as the ring's length (within its
/// mapping); the bytes reclaimed and the next sampling deadline.
pub fn resize(ctx: &mut Ctx<'_>, len: u32) -> Result<(u64, u64), KernReturn> {
    if len == 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let ring = ctx.proc.task.reclaim.ok_or(kr::KERN_INVALID_TASK)?;
    if round_len_to_size(ctx.proc.vm.page, len) > ring.size {
        return Err(kr::KERN_NO_SPACE);
    }
    let bytes = reclaim(ctx, ring, None).map_err(Stop::kr)?;
    if let Some(r) = ctx.proc.task.reclaim.as_mut() {
        r.len = len;
    }
    Ok((bytes, now(ctx) + period(ctx.proc.abi)))
}

/// `mach_vm_deferred_reclamation_buffer_query`: the ring's address and
/// size, or zeros.
pub fn query(ctx: &Ctx<'_>) -> (u64, u64) {
    ctx.proc.task.reclaim.map_or((0, 0), |r| (r.addr, r.size))
}

/// `vm_deferred_reclamation_update_accounting_internal`: within a
/// sampling period, nothing; otherwise a sample of the ring (its idle
/// minimum over the period becomes the start of the next, and feeds a
/// moving average of what the task did not need), and a trim from the
/// head of the minimum the average confirms when it is at least a page
/// and a tenth of the task's peak footprint. The bytes reclaimed and the
/// next deadline.
fn update_accounting(ctx: &mut Ctx<'_>) -> Result<(u64, u64), KernReturn> {
    let mut ring = ctx.proc.task.reclaim.ok_or(kr::KERN_NOT_FOUND)?;
    let p = period(ctx.proc.abi);
    let t = now(ctx);
    if ring.last_sample != 0 && t.saturating_sub(ring.last_sample) < p {
        return Ok((0, ring.last_sample + p));
    }
    let min = load(ctx, ring.addr + off::RECLAIMABLE_BYTES_MIN).map_err(Stop::kr)?;
    let cur = load(ctx, ring.addr + off::RECLAIMABLE_BYTES).map_err(Stop::kr)?;
    store(ctx, ring.addr + off::RECLAIMABLE_BYTES_MIN, cur).map_err(Stop::kr)?;
    // A ring never sampled counts as abandoned (a host's uptime is far
    // longer than the periods it would span).
    let periods = if ring.last_sample == 0 {
        u64::MAX
    } else {
        (t - ring.last_sample) / p
    };
    ring.wma = if periods > ABANDONED {
        cur.saturating_mul(WMA_UNIT) / 4
    } else {
        (ring.wma.saturating_mul(3) + min.saturating_mul(WMA_UNIT)) / 4
    };
    let unneeded = min.min(ring.wma / WMA_UNIT);
    let footprint = ctx.proc.space.resident_pages() * crate::user::mm::PAGE_SIZE;
    ring.peak = ring.peak.max(footprint);
    let page = ctx.proc.vm.page;
    let trim = if unneeded >= page && unneeded >= ring.peak * TRIM_PERCENT / 100 {
        unneeded.div_ceil(page) * page
    } else {
        0
    };
    ring.last_sample = now(ctx);
    ctx.proc.task.reclaim = Some(ring);
    let mut bytes = 0u64;
    while bytes < trim {
        match reclaim_chunk(ctx, ring, trim - bytes, CHUNK) {
            Ok((b, n)) => {
                bytes += b;
                if n == 0 {
                    break;
                }
            }
            // A cancellation in progress ends the trim.
            Err(Stop::Err(kr::KERN_ABORTED)) => break,
            Err(s) => return Err(s.kr()),
        }
    }
    Ok((bytes, ring.last_sample + p))
}

/// `mach_vm_reclaim_update_kernel_accounting_trap(task, bytes_out,
/// deadline_out)`: the outputs are written only on success, and faults
/// writing them are ignored.
pub fn update_accounting_trap(ctx: &mut Ctx<'_>, bytes_out: u64, deadline_out: u64) -> KernReturn {
    if bytes_out == 0 || deadline_out == 0 {
        return kr::KERN_INVALID_ARGUMENT;
    }
    match update_accounting(ctx) {
        Ok((bytes, deadline)) => {
            let _ = ctx.write_u64(bytes_out, bytes);
            let _ = ctx.write_u64(deadline_out, deadline);
            kr::KERN_SUCCESS
        }
        Err(k) => k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rings_are_sized_as_the_kernel_sizes_them() {
        assert_eq!(round_len_to_size(0x4000, 1016), 0x4000);
        assert_eq!(round_len_to_size(0x4000, 1017), 0x8000);
        assert_eq!(round_len_to_size(0x4000, 4_195_320), 0x400_4000);
        assert_eq!(round_len_to_size(0x4000, 8_388_600), MAX_BUFFER_SIZE);
        assert!(round_len_to_size(0x4000, 8_388_601) > MAX_BUFFER_SIZE);
        assert_eq!(round_len_to_size(0x1000, 248), 0x1000);
    }

    #[test]
    fn the_period_is_ten_seconds_of_the_guest_clock() {
        assert_eq!(period(DarwinAbi::Arm64), 240_000_000);
        assert_eq!(period(DarwinAbi::X86_64), 10_000_000_000);
    }
}
