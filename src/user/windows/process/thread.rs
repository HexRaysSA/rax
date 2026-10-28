//! Threads: creation and teardown of a thread's TEB, stack, static TLS
//! blocks, and CPU.
//!
//! Stack layout (one reservation, rounded up to 64 KiB):
//!
//! ```text
//! DeallocationStack  +0x0000  reserved (never committed)
//!                    +0x1000  guard page (PAGE_READWRITE | PAGE_GUARD)
//! StackLimit         +0x2000  committed read-write ...
//! StackBase          +size    (exclusive top)
//! ```
//!
//! Touching the guard page raises `STATUS_STACK_OVERFLOW`; the page's guard
//! is then consumed, leaving one usable page for the exception's dispatch.
//!
//! Built-in mode begins at the synthetic thread-start trap. Installed-library
//! mode enters LdrInitializeThunk with a saved native RtlUserThreadStart context.
//! That context carries the start address and parameter in the
//! registers that routine receives them in (x86: EAX, EBX; x64: RCX, RDX;
//! ARM64: X0, X1), and the Windows initial floating-point state: x87
//! control word 0x027F (all exceptions masked, 53-bit precision) and MXCSR
//! 0x1F80; FPCR 0 on ARM64.

use std::collections::VecDeque;
use std::sync::Arc;

use super::Proc;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::{WinArch, WinCpu};
use crate::user::windows::hle::Frame;
use crate::user::windows::layout::{self, offsets};
use crate::user::windows::memory::{AllocKind, Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{ObjId, Object};
use crate::user::windows::sync::Wait;

mod dynamic_tls;
pub(crate) mod teb;
pub(crate) use dynamic_tls::{install_dynamic_tls, remove_dynamic_tls};

/// A thread's scheduling state.
#[derive(Clone, Debug)]
pub enum ThreadState {
    /// Runnable.
    Ready,
    /// Parked.
    Waiting(Wait),
    /// Ended.
    Exited(u32),
}

/// A guest thread.
pub struct Thread {
    /// Thread id.
    pub tid: u32,
    /// The CPU.
    pub cpu: WinCpu,
    /// TEB address.
    pub teb: u64,
    pub(crate) teb_allocation: teb::Allocation,
    /// `StackBase`.
    pub stack_base: u64,
    /// `StackLimit`.
    pub stack_limit: u64,
    /// `DeallocationStack` (the reservation's base).
    pub stack_alloc: u64,
    /// Stack owned directly by this thread. Conversion transfers this ledger
    /// to a fiber; reconversion transfers its current stack back to the thread.
    pub thread_stack_alloc: u64,
    /// Currently selected fiber; None denotes an ordinary thread context.
    pub current_fiber: Option<u64>,
    /// Final normal-exit FLS callback drain has begun.
    pub fls_exiting: bool,
    /// Scheduling state.
    pub state: ThreadState,
    /// Built-in calls in progress.
    pub frames: Vec<Frame>,
    /// The thread's kernel object.
    pub obj: ObjId,
    /// Start routine.
    pub start: u64,
    /// Start parameter.
    pub param: u64,
    /// The process's first thread.
    pub main: bool,
    /// Suspend count.
    pub suspend: u32,
    /// Queued user APCs: (routine, argument).
    pub apcs: VecDeque<(u64, u64)>,
    /// Pending user-mode alert; a test consumes it before delivering APCs.
    /// This is guest-owned state, independent of the executing host thread.
    pub user_alerted: bool,
    /// The status of a completed wait, for the waiting continuation.
    pub wait_status: Option<u64>,
    /// `TerminateThread` requested with this exit code.
    pub terminate: Option<u32>,
    /// `ThreadLocalStoragePointer` array.
    pub tls_array: u64,
    /// Host-owned TLS blocks, including static templates and expansion arrays;
    /// freed at exit without trusting guest-writable TEB pointers.
    pub tls_blocks: Vec<u64>,
    /// `DLL_THREAD_ATTACH` notifications have been delivered.
    pub attached: bool,
}

/// Priority of an owned user-alert check. An existing alert is consumed before
/// queued APCs; the queue itself is not modified by this decision.
pub(crate) enum AlertCheck {
    Alerted,
    PendingApcs,
    Empty,
}

/// Default stack reservation when an image specifies none (1 MiB).
const DEFAULT_STACK: u64 = 0x10_0000;

/// Allocates the static TLS array and blocks for a thread whose TEB is
/// `teb`: one block per module with a TLS directory, copied from the
/// template and zero-filled.
fn alloc_static_tls(p: &mut Proc) -> Result<(u64, Vec<u64>), u32> {
    let count = p.modules.next_tls_index;
    if count == 0 {
        return Ok((0, Vec::new()));
    }
    let psize = p.arch.ptr_size();
    let heap = p.process_heap;
    let array = p
        .heaps
        .alloc(&mut p.vm, heap, psize * u64::from(count), true)
        .ok_or(STATUS_NO_MEMORY)?;
    let mut blocks = Vec::new();
    let tls: Vec<_> = p
        .modules
        .list
        .iter()
        .enumerate()
        .filter(|(idx, _)| p.modules.is_live(*idx))
        .filter_map(|(_, m)| m.tls)
        .collect();
    let result = (|| {
        for t in tls {
            if t.index >= count {
                return Err(STATUS_INVALID_IMAGE_FORMAT);
            }
            let size = t
                .raw_size
                .checked_add(t.zero_fill)
                .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let block = p
                .heaps
                .alloc(&mut p.vm, heap, size.max(1), true)
                .ok_or(STATUS_NO_MEMORY)?;
            blocks.push(block);
            if t.raw_size > 0 {
                let mut buf = vec![0u8; t.raw_size.min(0x10000) as usize];
                let mut offset = 0;
                while offset < t.raw_size {
                    let len = (t.raw_size - offset).min(buf.len() as u64) as usize;
                    let source = t
                        .template
                        .checked_add(offset)
                        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                    p.vm.peek(source, &mut buf[..len])
                        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
                    p.vm.poke(block + offset, &buf[..len])
                        .map_err(|_| STATUS_NO_MEMORY)?;
                    offset += len as u64;
                }
            }
            p.space
                .wptr(array + psize * u64::from(t.index), psize, block)
                .map_err(|_| STATUS_NO_MEMORY)?;
        }
        Ok(())
    })();
    if let Err(status) = result {
        for block in blocks {
            let _ = p.heaps.free(heap, block);
        }
        let _ = p.heaps.free(heap, array);
        return Err(status);
    }
    Ok((array, blocks))
}

/// Sets the Windows initial floating-point state on `cpu`.
fn init_fpu(cpu: &mut WinCpu) -> Result<(), u32> {
    match cpu {
        WinCpu::X86(x, _) => {
            let v = x.vcpu_mut();
            let mut fx = v.xsave_image(3).bytes;
            fx.truncate(512);
            fx[0..2].copy_from_slice(&0x027Fu16.to_le_bytes());
            fx[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
            v.fxrstor_image(&fx).map_err(|_| STATUS_INVALID_PARAMETER)?;
        }
        WinCpu::Arm64(a) => a.core_mut().set_fpcr_value(0),
    }
    Ok(())
}

/// Creates a thread that will run `start(param)` on a stack of
/// `stack_size` bytes (0: the executable's `SizeOfStackReserve`).
/// Returns its thread id.
pub fn create(
    p: &mut Proc,
    start: u64,
    param: u64,
    stack_size: u64,
    main: bool,
) -> Result<u32, u32> {
    let mut cleanup = ThreadAlloc::default();
    let result = create_inner(p, start, param, stack_size, main, &mut cleanup);
    if result.is_err() {
        for block in cleanup.tls_blocks {
            let _ = p.heaps.free(p.process_heap, block);
        }
        if cleanup.tls_array != 0 {
            let _ = p.heaps.free(p.process_heap, cleanup.tls_array);
        }
        if cleanup.stack != 0 {
            let _ = p.vm.release(cleanup.stack);
        }
        if let Some(teb) = cleanup.teb {
            teb.release(p);
        }
    }
    result
}

#[derive(Default)]
struct ThreadAlloc {
    teb: Option<teb::Allocation>,
    stack: u64,
    tls_array: u64,
    tls_blocks: Vec<u64>,
}

fn create_inner(
    p: &mut Proc,
    start: u64,
    param: u64,
    stack_size: u64,
    main: bool,
    cleanup: &mut ThreadAlloc,
) -> Result<u32, u32> {
    // The guest-visible CreateThread path must not overflow the host's ID
    // allocator or replace a previously published thread/object. Exhaustion
    // is a resource failure, not wraparound/reuse of an outstanding client ID.
    if p.next_tid == 0
        || p.next_tid & 3 != 0
        || p.next_tid.checked_add(4).is_none()
        || p.objects
            .iter()
            .any(|(_, object)| matches!(object, Object::Thread { tid, .. } if *tid == p.next_tid))
    {
        return Err(STATUS_NO_MEMORY);
    }
    let tid = p.alloc_tid();
    let o = *offsets(p.arch);
    let teb_allocation = teb::Allocation::allocate(p)?;
    cleanup.teb = Some(teb_allocation.clone());
    let teb = teb_allocation.teb;

    let reserve = if stack_size != 0 {
        stack_size
    } else {
        p.modules
            .list
            .first()
            .map(|_| p.exe_stack_reserve)
            .filter(|&s| s != 0)
            .unwrap_or(DEFAULT_STACK)
    };
    let reserve = reserve
        .max(0x1_0000)
        .checked_add(0xFFFF)
        .ok_or(STATUS_INVALID_PARAMETER)?
        & !0xFFFF;
    let label: Arc<str> = Arc::from("[stack]");
    let alloc =
        p.vm.reserve(
            None,
            reserve,
            prot::READWRITE,
            AllocKind::Private,
            false,
            Some(label),
        )
        .map_err(|e| e.status())?;
    cleanup.stack = alloc;
    let limit = alloc + 2 * PAGE_SIZE;
    let base = alloc + reserve;
    p.vm.commit(limit, base - limit, prot::READWRITE)
        .map_err(|e| e.status())?;
    p.vm.commit(alloc + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
        .map_err(|e| e.status())?;

    // Installed LdrInitializeThunk owns the native thread's static TLS vector.
    // HLE heap blocks are private bookkeeping, never native RTL allocations.
    let (tls_array, tls_blocks) = if p.native.is_some() {
        (0, Vec::new())
    } else {
        alloc_static_tls(p)?
    };
    cleanup.tls_array = tls_array;
    cleanup.tls_blocks = tls_blocks.clone();

    // TEB.
    let s = &p.space;
    let ptr = o.ptr;
    let end_of_chain = if p.arch == WinArch::X86 {
        0xFFFF_FFFF
    } else {
        0
    };
    s.wptr(teb + o.teb_exception_list, ptr, end_of_chain)
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_stack_base, ptr, base)
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_stack_limit, ptr, limit)
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_self, ptr, teb)
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_client_id, ptr, u64::from(p.pid))
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_client_id + ptr, ptr, u64::from(tid))
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_tls_pointer, ptr, tls_array)
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_peb, ptr, p.peb)
        .map_err(|_| STATUS_NO_MEMORY)?;
    if p.arch == WinArch::X86 && p.traps.wow64_transition() != 0 {
        s.w32(
            teb + layout::WOW64_TEB_TRANSITION,
            p.traps.wow64_transition() as u32,
        )
        .map_err(|_| STATUS_NO_MEMORY)?;
    }
    s.w32(teb + o.teb_current_locale, 0x409)
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_deallocation_stack, ptr, alloc)
        .map_err(|_| STATUS_NO_MEMORY)?;
    // TlsLinks: an empty list head.
    s.wptr(teb + o.teb_tls_links, ptr, teb + o.teb_tls_links)
        .map_err(|_| STATUS_NO_MEMORY)?;
    s.wptr(teb + o.teb_tls_links + ptr, ptr, teb + o.teb_tls_links)
        .map_err(|_| STATUS_NO_MEMORY)?;

    teb_allocation.initialize_companion(p, tid, base, limit, alloc)?;

    // CPU.
    let mut cpu = WinCpu::new(p.arch, &p.space);
    cpu.set_teb(teb);
    init_fpu(&mut cpu)?;
    let sp = (base - 0x40) & !0xF;
    cpu.set_sp(sp);
    cpu.set_pc(p.traps.thread_start());
    let (r0, r1) = match p.arch {
        WinArch::X86 => (0, 3),
        WinArch::X64 => (1, 2),
        WinArch::Arm64 => (0, 1),
    };
    cpu.set_gpr(r0, start);
    cpu.set_gpr(r1, param);
    if p.native.is_some() {
        super::native_start::prepare(p, &mut cpu, main)?;
    }

    let obj = p
        .objects
        .try_create(Object::Thread {
            tid,
            exit_code: None,
        })
        .ok_or(STATUS_NO_MEMORY)?;
    p.objects.retain(obj);

    let owned = p
        .modules
        .list
        .iter()
        .enumerate()
        .filter(|(idx, m)| p.modules.is_live(*idx) && m.tls.is_some())
        .map(|(idx, _)| idx)
        .zip(tls_blocks.iter().copied())
        .collect();
    p.modules.dynamic.tls_blocks.insert(tid, owned);

    p.threads.insert(
        tid,
        Thread {
            tid,
            cpu,
            teb,
            teb_allocation,
            stack_base: base,
            stack_limit: limit,
            stack_alloc: alloc,
            thread_stack_alloc: alloc,
            current_fiber: None,
            fls_exiting: false,
            state: ThreadState::Ready,
            frames: Vec::new(),
            obj,
            start,
            param,
            main,
            suspend: 0,
            apcs: VecDeque::new(),
            user_alerted: false,
            wait_status: None,
            terminate: None,
            tls_array,
            tls_blocks,
            attached: false,
        },
    );
    Ok(tid)
}

/// Releases an ended thread's resources: its owned mutexes are abandoned,
/// its object is signaled with `code`, and its stack, TEB, and TLS blocks
/// are freed.
pub fn destroy(p: &mut Proc, t: Thread, code: u32) {
    p.gui.retire_thread(t.tid);
    if let Err(status) = super::fiber::destroy_active(p, &t) {
        p.fail(format!("fiber teardown failed: {status:#010x}"));
    }
    let tid = t.tid;
    p.objects.free_scheduler_slot(tid);
    if let Err(error) = p.reclaim_scheduler_views() {
        p.fail(format!("scheduler view cleanup failed: {error}"));
    }
    if let Err(status) = super::super::dll::crt::release_thread(p, tid) {
        p.fail(format!("CRT thread teardown failed: {status:#010x}"));
    }
    p.modules.dynamic.tls_blocks.remove(&tid);
    let ids: Vec<ObjId> = p
        .objects
        .iter_mut()
        .filter_map(|(id, o)| match o {
            Object::Mutex { owner, .. } if *owner == Some(tid) => Some(id),
            _ => None,
        })
        .collect();
    for id in ids {
        if let Some(Object::Mutex {
            owner,
            count,
            abandoned,
        }) = p.objects.obj_mut(id)
        {
            *owner = None;
            *count = 0;
            *abandoned = true;
        }
    }
    if let Some(Object::Thread { exit_code, .. }) = p.objects.obj_mut(t.obj) {
        *exit_code = Some(code);
    }
    p.objects.release(t.obj);
    let heap = p.process_heap;
    for b in &t.tls_blocks {
        let _ = p.heaps.free(heap, *b);
    }
    if t.tls_array != 0 {
        let _ = p.heaps.free(heap, t.tls_array);
    }
    if t.thread_stack_alloc != 0 {
        let _ = p.vm.release(t.thread_stack_alloc);
    }
    t.teb_allocation.release(p);
    p.tls
        .fls_discard_context(crate::user::windows::tls::FlsKey::Thread(tid));
}

impl Thread {
    pub(crate) fn check_user_alert(&mut self) -> AlertCheck {
        if std::mem::take(&mut self.user_alerted) {
            AlertCheck::Alerted
        } else if self.apcs.is_empty() {
            AlertCheck::Empty
        } else {
            AlertCheck::PendingApcs
        }
    }

    /// FLS follows the selected fiber; TLS continues to follow this thread.
    pub fn fls_key(&self) -> crate::user::windows::tls::FlsKey {
        self.current_fiber.map_or(
            crate::user::windows::tls::FlsKey::Thread(self.tid),
            crate::user::windows::tls::FlsKey::Fiber,
        )
    }

    /// Whether the thread can run now.
    pub fn runnable(&self) -> bool {
        matches!(self.state, ThreadState::Ready) && self.suspend == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::loader::ModuleTls;
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    fn process() -> WindowsProcess {
        let mut config = WindowsConfig::new("thread-test.exe", Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        WindowsProcess::spawn_image(
            config,
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe").to_vec(),
        )
        .unwrap()
    }

    fn assert_failure_rolls_back(p: &mut Proc, stack_size: u64, expected: u32) {
        let live_blocks = p.heaps.blocks(p.process_heap);
        // HeapFree returns blocks to the allocator but deliberately retains
        // committed pages. Warm the exact small TLS allocation shapes before
        // measuring thread rollback, independent of the loader's heap packing.
        if p.modules.next_tls_index != 0 {
            let array = p
                .heaps
                .alloc(
                    &mut p.vm,
                    p.process_heap,
                    p.arch.ptr_size() * u64::from(p.modules.next_tls_index),
                    true,
                )
                .unwrap();
            let block = p.heaps.alloc(&mut p.vm, p.process_heap, 1, true).unwrap();
            p.heaps.free(p.process_heap, block).unwrap();
            p.heaps.free(p.process_heap, array).unwrap();
        }
        assert_eq!(p.heaps.blocks(p.process_heap), live_blocks);
        let committed = p.vm.committed_bytes();
        let allocations: Vec<_> =
            p.vm.allocations()
                .map(|a| (a.base, a.size, a.kind, a.pages.clone()))
                .collect();
        let thread_count = p.threads.len();
        let object_count = p.objects.iter_mut().count();
        let next_teb = layout::PEB_ADDRESS - 2 * layout::teb_stride(p.arch);
        let before = p.vm.query(next_teb).unwrap();
        assert_eq!(create(p, 0x1234_0000, 0, stack_size, false), Err(expected));
        assert_eq!(p.vm.committed_bytes(), committed);
        assert_eq!(p.heaps.blocks(p.process_heap), live_blocks);
        assert_eq!(
            p.vm.allocations()
                .map(|a| (a.base, a.size, a.kind, a.pages.clone()))
                .collect::<Vec<_>>(),
            allocations
        );
        assert_eq!(p.threads.len(), thread_count);
        assert_eq!(p.objects.iter_mut().count(), object_count);
        assert_eq!(p.vm.query(next_teb).unwrap(), before);
    }

    #[test]
    fn hostile_stack_size_releases_the_unpublished_teb() {
        let mut process = process();
        assert_failure_rolls_back(process.state_mut(), u64::MAX, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn inaccessible_tls_template_releases_stack_teb_and_heap_blocks() {
        let mut process = process();
        let p = process.state_mut();
        p.modules.next_tls_index = 1;
        p.modules.list[0].tls = Some(ModuleTls {
            index: 0,
            template: u64::MAX,
            raw_size: 1,
            zero_fill: 0,
            callbacks: 0,
        });
        assert_failure_rolls_back(p, 0x10000, STATUS_INVALID_IMAGE_FORMAT);
        p.modules.list[0].tls = None;
        p.modules.next_tls_index = 0;
        assert!(create(p, 0x1234_0000, 0, 0x10000, false).is_ok());
    }

    #[test]
    fn overflowing_tls_template_size_and_invalid_index_are_rejected() {
        for (index, raw_size, zero_fill) in [(0, u64::MAX, 1), (1, 0, 0)] {
            let mut process = process();
            let p = process.state_mut();
            p.modules.next_tls_index = 1;
            p.modules.list[0].tls = Some(ModuleTls {
                index,
                template: 0,
                raw_size,
                zero_fill,
                callbacks: 0,
            });
            assert_failure_rolls_back(p, 0x10000, STATUS_INVALID_IMAGE_FORMAT);
        }
    }
}
