//! Table-driven frame handling for x64 and ARM64: function-table lookup,
//! virtual unwinding, exception dispatch to language handlers, and
//! `RtlUnwindEx`.
//!
//! Dispatch (the "Unwind procedure" of the x64 exception-handling
//! documentation, which ARM64 shares): starting from the exception
//! context, look up the function containing the PC; without a function
//! entry the function is a leaf, so return through the return address
//! (x64: `[RSP]`, RSP += 8; ARM64: LR); with one, virtually unwind it,
//! and if its unwind data names an exception handler for this PC, call
//! `handler(ExceptionRecord, EstablisherFrame, ContextRecord,
//! DispatcherContext)`. The handler receives the original exception
//! context; `DISPATCHER_CONTEXT.ContextRecord` is the frame's own context.
//! The walk stops when the PC is 0 or the stack pointer leaves the stack.
//!
//! `RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord, ReturnValue,
//! ContextRecord, HistoryTable)` walks from its caller's frame, calling
//! termination handlers with `EXCEPTION_UNWINDING` (and
//! `EXCEPTION_TARGET_UNWIND` at the target frame), until the frame whose
//! establisher is `TargetFrame`, then resumes at `TargetIp` with
//! `ReturnValue` in RAX/X0 and that frame's registers.
//!
//! Sorted `.pdata` is a Microsoft format prerequisite. Binary lookup checks
//! touched entries and preserves parser faults; it does not globally validate
//! table ordering. Walks are capped at 4096 distinct states. Their tracking is
//! O(n log n) time and O(n) space, in addition to O(n log t + u) decoding for
//! t function-table entries and u total ISA-specific unwind decoding work.

use super::{Records, disposition, handler_continue, trace, unhandled};
use crate::user::image::pe::RvaSource;
use crate::user::windows::arch::WinArch;
use crate::user::windows::context::{
    EXCEPTION_COLLIDED_UNWIND, EXCEPTION_EXIT_UNWIND, EXCEPTION_NONCONTINUABLE,
    EXCEPTION_STACK_INVALID, EXCEPTION_TARGET_UNWIND, EXCEPTION_UNWINDING, ExceptionRecord,
    RegContext,
};
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::process::Proc;
use std::collections::BTreeSet;

/// `UNW_FLAG_NHANDLER`.
pub const UNW_FLAG_NHANDLER: u32 = 0;
/// `UNW_FLAG_EHANDLER`.
pub const UNW_FLAG_EHANDLER: u32 = 1;
/// `UNW_FLAG_UHANDLER`.
pub const UNW_FLAG_UHANDLER: u32 = 2;

/// A function table entry found for a PC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionEntry {
    /// Image base or registered dynamic `BaseAddress`.
    pub image_base: u64,
    /// Guest address of the `RUNTIME_FUNCTION`/ARM64 record.
    pub entry: u64,
    /// Function start RVA.
    pub begin: u32,
    /// x64: `EndAddress` RVA; ARM64: 0.
    pub end: u32,
    /// x64: `UnwindData` RVA; ARM64: the second `.pdata` word.
    pub unwind: u32,
}

/// The result of unwinding one frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unwound {
    /// The language handler for this PC, if one applies to the requested
    /// handler type.
    pub handler: Option<u64>,
    /// The handler's data.
    pub handler_data: u64,
    /// The establisher frame: x64 the base of the fixed stack allocation
    /// (the frame register minus its offset, or RSP after the prolog);
    /// ARM64 the stack pointer at function entry.
    pub establisher: u64,
}

#[derive(Clone, Copy)]
enum Provenance {
    Image { base: u64, size: u64 },
    Dynamic,
}

#[derive(Clone, Copy)]
struct ResolvedFunction {
    entry: FunctionEntry,
    provenance: Provenance,
}

/// Looks up one active entry, retaining its metadata provenance internally.
/// Overlapping image/dynamic or dynamic/dynamic matches fail closed because
/// their native precedence is not established.
fn lookup_resolved(p: &Proc, pc: u64) -> Result<Option<ResolvedFunction>, MemFault> {
    let image = lookup_image(p, pc)?;
    let dynamic = super::dynamic::lookup(p, pc)?;
    match (image, dynamic) {
        (Some(_), Some(_)) => Err(MemFault {
            addr: pc,
            write: false,
        }),
        (Some(entry), None) => {
            let (_, module) = p.modules.by_address(pc).ok_or(MemFault {
                addr: pc,
                write: false,
            })?;
            Ok(Some(ResolvedFunction {
                entry,
                provenance: Provenance::Image {
                    base: module.base,
                    size: module.size,
                },
            }))
        }
        (None, Some(entry)) => Ok(Some(ResolvedFunction {
            entry,
            provenance: Provenance::Dynamic,
        })),
        (None, None) => Ok(None),
    }
}

/// Looks up the function table entry containing `pc` (`RtlLookupFunctionEntry`).
pub fn lookup(p: &Proc, pc: u64) -> Result<Option<FunctionEntry>, MemFault> {
    Ok(lookup_resolved(p, pc)?.map(|resolved| resolved.entry))
}

fn lookup_image(p: &Proc, pc: u64) -> Result<Option<FunctionEntry>, MemFault> {
    let Some((_, m)) = p.modules.by_address(pc) else {
        return Ok(None);
    };
    if m.pdata.rva == 0 || m.pdata.size == 0 {
        return Ok(None);
    }
    let base = m.base;
    let fault = |rva: u64| MemFault {
        addr: base.checked_add(rva).unwrap_or(u64::MAX),
        write: false,
    };
    let rva = u32::try_from(pc - base).map_err(|_| fault(pc - base))?;
    let table_end = u64::from(m.pdata.rva) + u64::from(m.pdata.size);
    if table_end > m.size {
        return Err(fault(table_end));
    }
    let src = GuestRva {
        mem: &p.space,
        base,
        size: m.size,
    };
    match p.arch {
        WinArch::X64 => {
            let Some((at, f)) = crate::user::image::pe::pdata::lookup_x64(&src, m.pdata, rva)
                .map_err(|e| fault(e.rva))?
            else {
                return Ok(None);
            };
            if f.begin >= f.end || u64::from(f.end) > m.size || u64::from(f.unwind_info) >= m.size {
                return Err(fault(u64::from(at)));
            }
            Ok(Some(FunctionEntry {
                image_base: base,
                entry: base + u64::from(at),
                begin: f.begin,
                end: f.end,
                unwind: f.unwind_info,
            }))
        }
        WinArch::Arm64 => {
            let Some((at, f)) = crate::user::image::pe::pdata::lookup_arm64(&src, m.pdata, rva)
                .map_err(|e| fault(e.rva))?
            else {
                return Ok(None);
            };
            let len = match f.packed_length() {
                Some(len) => len,
                None => crate::user::image::pe::pdata::arm64_xdata_length(&src, f.unwind)
                    .map_err(|e| fault(e.rva))?,
            };
            if len == 0 || u64::from(f.begin) + u64::from(len) > m.size {
                return Err(fault(u64::from(at)));
            }
            Ok(Some(FunctionEntry {
                image_base: base,
                entry: base + u64::from(at),
                begin: f.begin,
                end: 0,
                unwind: f.unwind,
            }))
        }
        WinArch::X86 => Ok(None),
    }
}

/// An image in guest memory read by RVA.
pub struct GuestRva<'a> {
    /// Memory.
    pub mem: &'a dyn Mem,
    /// Image base.
    pub base: u64,
    /// Owning image extent: metadata must not borrow adjacent mappings.
    pub size: u64,
}

impl crate::user::image::pe::RvaSource for GuestRva<'_> {
    fn read_rva(&self, rva: u64, buf: &mut [u8]) -> Result<(), crate::user::image::pe::RvaFault> {
        if rva
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(crate::user::image::pe::RvaFault { rva });
        }
        self.mem
            .rd(
                self.base
                    .checked_add(rva)
                    .ok_or(crate::user::image::pe::RvaFault { rva })?,
                buf,
            )
            .map_err(|_| crate::user::image::pe::RvaFault { rva })
    }
}

/// Virtually unwinds `ctx` through function `f` (`RtlVirtualUnwind`),
/// returning the handler of type `handler_type` that applies, if any.
pub fn virtual_unwind(
    p: &Proc,
    handler_type: u32,
    f: &FunctionEntry,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    let resolved = match lookup_resolved(p, ctx.pc())? {
        Some(resolved) if resolved.entry == *f => resolved,
        Some(_) => {
            return Err(MemFault {
                addr: f.entry,
                write: false,
            });
        }
        None => {
            // Preserve the earlier public API's ability to virtually unwind
            // an explicitly supplied image entry without requiring that it
            // be published in the module's `.pdata` directory. Dynamic
            // entries, in contrast, require a live registration.
            let (_, module) = p.modules.by_address(ctx.pc()).ok_or(MemFault {
                addr: ctx.pc(),
                write: false,
            })?;
            if module.base != f.image_base {
                return Err(MemFault {
                    addr: f.entry,
                    write: false,
                });
            }
            ResolvedFunction {
                entry: *f,
                provenance: Provenance::Image {
                    base: module.base,
                    size: module.size,
                },
            }
        }
    };
    virtual_unwind_resolved(p, handler_type, resolved, ctx)
}

fn virtual_unwind_resolved(
    p: &Proc,
    handler_type: u32,
    resolved: ResolvedFunction,
    ctx: &mut RegContext,
) -> Result<Unwound, MemFault> {
    let f = &resolved.entry;
    let metadata = match resolved.provenance {
        Provenance::Image { base, size } => MetadataMem::Image(ImageMem {
            mem: &p.space,
            base,
            size,
        }),
        Provenance::Dynamic => MetadataMem::Dynamic(&p.space),
    };
    let mut next = ctx.clone();
    let result = match p.arch {
        WinArch::X64 => super::x64::virtual_unwind_with_metadata(
            &p.space,
            &metadata,
            handler_type,
            f,
            &mut next,
        )?,
        WinArch::Arm64 => super::arm64::virtual_unwind_with_metadata(
            &p.space,
            &metadata,
            handler_type,
            f,
            &mut next,
        )?,
        WinArch::X86 => {
            return Err(MemFault {
                addr: f.entry,
                write: false,
            });
        }
    };
    if let Provenance::Image { base, size } = resolved.provenance {
        if result.handler.is_some_and(|handler| {
            handler
                .checked_sub(base)
                .is_none_or(|offset| offset >= size)
        }) || (result.handler.is_some()
            && result
                .handler_data
                .checked_sub(base)
                .is_none_or(|offset| offset > size))
        {
            return Err(MemFault {
                addr: result.handler.unwrap_or(f.entry),
                write: false,
            });
        }
    }
    *ctx = next;
    Ok(result)
}

struct ImageMem<'a> {
    mem: &'a dyn Mem,
    base: u64,
    size: u64,
}

enum MetadataMem<'a> {
    Image(ImageMem<'a>),
    Dynamic(&'a dyn Mem),
}

impl Mem for MetadataMem<'_> {
    fn rd(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemFault> {
        match self {
            Self::Image(image) => image.rd(addr, bytes),
            Self::Dynamic(mem) => mem.rd(addr, bytes),
        }
    }

    fn wr(&self, addr: u64, _: &[u8]) -> Result<(), MemFault> {
        Err(MemFault { addr, write: true })
    }
}

impl Mem for ImageMem<'_> {
    fn rd(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemFault> {
        if addr
            .checked_sub(self.base)
            .and_then(|offset| offset.checked_add(bytes.len() as u64))
            .is_none_or(|end| end > self.size)
        {
            return Err(MemFault { addr, write: false });
        }
        self.mem.rd(addr, bytes)
    }

    fn wr(&self, addr: u64, _: &[u8]) -> Result<(), MemFault> {
        Err(MemFault { addr, write: true })
    }
}

/// Unwinds a frame without a function entry: a leaf function.
pub fn unwind_leaf(p: &Proc, ctx: &mut RegContext) -> Result<(), MemFault> {
    if ctx.arch() != p.arch {
        return Err(MemFault {
            addr: ctx.pc(),
            write: false,
        });
    }
    match p.arch {
        WinArch::X64 => {
            let sp = ctx.sp();
            let ret = p.space.u64(sp)?;
            let next_sp = sp.checked_add(8).ok_or(MemFault {
                addr: sp,
                write: false,
            })?;
            ctx.set_pc(ret);
            ctx.set_sp(next_sp);
        }
        WinArch::Arm64 => {
            let lr = ctx.gpr(30);
            ctx.set_pc(lr);
        }
        WinArch::X86 => {
            return Err(MemFault {
                addr: ctx.pc(),
                write: false,
            });
        }
    }
    Ok(())
}

/// Unwinds `ctx` by one frame, by table or as a leaf. Returns the frame's
/// function entry and result.
pub fn step(
    p: &Proc,
    handler_type: u32,
    ctx: &mut RegContext,
) -> Result<(Option<FunctionEntry>, Unwound), MemFault> {
    let mut next = ctx.clone();
    let result = match lookup_resolved(p, ctx.pc())? {
        Some(resolved) => (
            Some(resolved.entry),
            virtual_unwind_resolved(p, handler_type, resolved, &mut next)?,
        ),
        None => {
            let establisher = ctx.sp();
            unwind_leaf(p, &mut next)?;
            (
                None,
                Unwound {
                    establisher,
                    ..Default::default()
                },
            )
        }
    };
    *ctx = next;
    Ok(result)
}

/// A bounded host-side walk, retained across calls to guest handlers. The
/// 4096-state ceiling is a personality policy, not a native Windows limit.
#[derive(Clone, Default)]
struct WalkState {
    seen: BTreeSet<(u64, u64, u64)>,
    exception: crate::user::windows::hle::exception::Search,
}

impl WalkState {
    fn visit(&mut self, ctx: &RegContext) -> Result<(), ApiErr> {
        let key = (
            ctx.pc(),
            ctx.sp(),
            if ctx.arch() == WinArch::Arm64 {
                ctx.gpr(30)
            } else {
                0
            },
        );
        if self.seen.len() >= 4096 || !self.seen.insert(key) {
            return Err(ApiErr::Internal(format!(
                "SEH frame walk cyclic or exceeds 4096 frames at PC {:#x}, SP {:#x}",
                ctx.pc(),
                ctx.sp()
            )));
        }
        Ok(())
    }
}

/// `DISPATCHER_CONTEXT` offsets, identical for x64 and ARM64 up to
/// `ScopeIndex` (winnt.h, verified): ControlPc 0, ImageBase 8,
/// FunctionEntry 0x10, EstablisherFrame 0x18, TargetIp/TargetPc 0x20,
/// ContextRecord 0x28, LanguageHandler 0x30, HandlerData 0x38,
/// HistoryTable 0x40, ScopeIndex 0x48; x64 `Fill0` 0x4C (size 0x50),
/// ARM64 `ControlPcIsUnwound` 0x4C and `NonVolatileRegisters` 0x50 (size
/// 0x58).
#[derive(Clone, Copy, Debug, Default)]
pub struct DispatcherContext {
    /// `ControlPc`.
    pub control_pc: u64,
    /// `ImageBase`.
    pub image_base: u64,
    /// `FunctionEntry`.
    pub function_entry: u64,
    /// `EstablisherFrame`.
    pub establisher: u64,
    /// `TargetIp`.
    pub target_ip: u64,
    /// `ContextRecord`.
    pub context: u64,
    /// `LanguageHandler`.
    pub handler: u64,
    /// `HandlerData`.
    pub handler_data: u64,
    /// `ScopeIndex`.
    pub scope_index: u32,
    /// ARM64 `ControlPcIsUnwound`.
    pub control_pc_is_unwound: bool,
}

/// `sizeof(DISPATCHER_CONTEXT)`.
pub fn dispatcher_context_size(arch: WinArch) -> u64 {
    if arch == WinArch::Arm64 { 0x58 } else { 0x50 }
}

impl DispatcherContext {
    /// Writes exactly the architecture's structure extent at `at`.
    /// x86 uses a registration-chain dispatcher word, not this structure.
    pub fn write(&self, mem: &impl Mem, arch: WinArch, at: u64) -> Result<(), MemFault> {
        if arch == WinArch::X86 {
            return Err(MemFault {
                addr: at,
                write: true,
            });
        }
        let mut b = [0u8; 0x58];
        let put =
            |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put(&mut b, 0x00, self.control_pc);
        put(&mut b, 0x08, self.image_base);
        put(&mut b, 0x10, self.function_entry);
        put(&mut b, 0x18, self.establisher);
        put(&mut b, 0x20, self.target_ip);
        put(&mut b, 0x28, self.context);
        put(&mut b, 0x30, self.handler);
        put(&mut b, 0x38, self.handler_data);
        b[0x48..0x4C].copy_from_slice(&self.scope_index.to_le_bytes());
        if arch == WinArch::Arm64 {
            b[0x4C] = u8::from(self.control_pc_is_unwound);
        }
        mem.wr(at, &b[..dispatcher_context_size(arch) as usize])
    }

    /// Reads `ScopeIndex` back (handlers update it across collided
    /// unwinds).
    pub fn read_scope_index(mem: &impl Mem, at: u64) -> Result<u32, MemFault> {
        mem.u32(at.checked_add(0x48).ok_or(MemFault {
            addr: at,
            write: false,
        })?)
    }
}

fn in_stack(c: &Ctx, sp: u64) -> bool {
    sp >= c.t.stack_alloc && sp <= c.t.stack_base
}

/// Extra stack kept below an exception's dispatcher records so an x64
/// language handler can be re-entered above them (`raise`).
pub(super) const RECORD_RESERVE: u64 = 0x4000;

/// Minimum free space between an anchored handler's stack and the top of the
/// dispatcher records. The handler, the guest's `RtlUnwindEx`, and the guest
/// dispatch frames all run in that space.
const ANCHOR_HANDLER_GAP: u64 = 0x2000;

/// Smallest prolog allocation an anchor delta frame may have: the anchored
/// call frame and the handler's spilled nonvolatiles must stay below the
/// delta frame's hand-written return-address slot.
const ANCHOR_MIN_DELTA: u64 = 0x18;

/// A frameless x64 function whose prolog only allocates stack. Unwinding it
/// moves a fabricated stack pointer to its caller without restoring any
/// register, so a dispatcher can splice it into a synthetic frame chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeltaFrame {
    /// A PC inside the function, after its prolog.
    pc: u64,
    /// Bytes the prolog subtracts from the entry stack pointer.
    delta: u64,
}

/// The exact stack that re-enters an x64 language handler so the guest's own
/// `RtlUnwindEx` walks from it to the fault frame described by `fault`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Anchor {
    /// Stack pointer to enter the handler with.
    sp: u64,
    /// The handler's initial `RBX`: the delta frame's PC.
    delta_pc: u64,
}

/// Builds the synthetic frame chain that makes a guest x64 `RtlUnwindEx`
/// reach the fault frame, and returns the stack to enter `handler` with.
///
/// A guest language handler receives the fault frame's establisher as its
/// `EstablisherFrame` and passes it to `RtlUnwindEx` as `TargetFrame`. That
/// walk starts at `RtlUnwindEx`'s own caller frame and climbs the real stack
/// until a frame's establisher equals `TargetFrame`. A synthetic handler call
/// puts the handler on a stack whose return-address chain is arbitrary, so in
/// native dispatch the walk instead crosses `KiUserExceptionDispatcher`,
/// whose unwind data makes its establisher the faulting stack pointer.
///
/// This builder supplies that missing frame chain explicitly. The handler is
/// entered at `sp`, a leaf frame whose return address is the callback-return
/// trap. The trap is outside every image, so the guest unwinds it as a leaf
/// and takes the next return address from the shadow slot where the handler
/// spills `RBX`; that slot holds `delta_pc`, a frameless function in the
/// fault module that only allocates stack. Unwinding it lands exactly on
/// `TargetFrame` with the fault PC as the return address, so the frame the
/// guest is searching for is the fault context's own frame.
///
/// Returns `None` (leaving the caller's ordinary callback placement to apply)
/// whenever the geometry cannot be established: a non-x64 architecture, a
/// fault frame with a frame pointer, no suitable delta frame, no reserved
/// dispatcher records, or a stack outside the thread's bounds.
fn anchor(
    c: &Ctx,
    fault: &RegContext,
    target: u64,
    records_top: u64,
) -> Result<Option<Anchor>, MemFault> {
    if c.p.arch != WinArch::X64 || target % 8 != 0 {
        return Ok(None);
    }
    // A frame pointer moves the establisher above the fault stack pointer, so
    // the resumed context would not be this frame's own stack.
    if fault.sp() != target {
        return Ok(None);
    }
    let Some(delta) = delta_frame(c.p, fault.pc(), ANCHOR_MIN_DELTA)? else {
        return Ok(None);
    };
    // 16-byte alignment decides whether the delta frame's return address is
    // read directly above the fault frame or one leaf frame further down,
    // where the trap address supplies that return address.
    let sp = match target % 16 {
        8 => target.checked_sub(0x18 + delta.delta),
        0 => target.checked_sub(0x20 + delta.delta),
        _ => return Ok(None),
    };
    let Some(sp) = sp else {
        return Ok(None);
    };
    if sp % 8 != 0 || !in_stack(c, sp) || sp.checked_add(8).is_none_or(|end| end > c.t.stack_base) {
        return Ok(None);
    }
    // The dispatcher's records sit directly below the fault stack pointer
    // unless `raise` reserved room above them. Without that reserve the
    // handler's frames would overwrite the record it is handling.
    if sp < records_top.saturating_add(ANCHOR_HANDLER_GAP) {
        return Ok(None);
    }
    let ret_trap = c.p.traps.callback_return();
    if ret_trap == 0 {
        return Ok(None);
    }
    // The delta frame's return address: the fault frame's PC.
    c.p.space.w64(target - 8, fault.pc())?;
    if target % 16 == 0 {
        // One extra leaf between the delta frame and the fault frame.
        c.p.space.w64(target - 0x10, ret_trap)?;
    }
    Ok(Some(Anchor {
        sp,
        delta_pc: delta.pc,
    }))
}

/// Finds the lowest-address frameless x64 function in `pc`'s image whose
/// prolog only allocates at least `min_delta` bytes of stack.
///
/// The guest unwinder finds this function through the image's own
/// `.pdata`, so the entry must be a real runtime function of the module the
/// fault PC belongs to.
fn delta_frame(p: &Proc, pc: u64, min_delta: u64) -> Result<Option<DeltaFrame>, MemFault> {
    if p.arch != WinArch::X64 {
        return Ok(None);
    }
    let Some((_, m)) = p.modules.by_address(pc) else {
        return Ok(None);
    };
    let table = m.pdata;
    if table.rva == 0 || table.size == 0 {
        return Ok(None);
    }
    let fault = |rva: u64| MemFault {
        addr: m.base.saturating_add(rva),
        write: false,
    };
    let entry_size = crate::user::image::pe::pdata::X64_ENTRY_SIZE;
    if table.size % entry_size != 0 {
        return Err(fault(u64::from(table.rva) + u64::from(table.size)));
    }
    let src = GuestRva {
        mem: &p.space,
        base: m.base,
        size: m.size,
    };
    for i in 0..table.size / entry_size {
        let at = u64::from(table.rva) + u64::from(i) * u64::from(entry_size);
        let begin = u64::from(src.u32_at(at).map_err(|e| fault(e.rva))?);
        let end = u64::from(src.u32_at(at + 4).map_err(|e| fault(e.rva))?);
        let info = src.u32_at(at + 8).map_err(|e| fault(e.rva))?;
        let Some((prolog, delta)) = alloc_only_frame(&src, info).map_err(|e| fault(e.rva))? else {
            continue;
        };
        if delta < min_delta
            || delta % 16 != 8
            || begin >= end
            || begin + u64::from(prolog) >= end
            || end > m.size
        {
            continue;
        }
        return Ok(Some(DeltaFrame {
            pc: m.base + begin + u64::from(prolog),
            delta,
        }));
    }
    Ok(None)
}

/// Whether a raise at `pc` can anchor a language handler.
///
/// `raise` consults this before moving its dispatcher records: only an
/// x64 fault whose module supplies a frameless stack-allocation frame can be
/// re-entered through [`anchor`]. Every other raise keeps the native record
/// placement, so its callbacks are unaffected by the reserve.
pub(super) fn anchor_possible(p: &Proc, pc: u64) -> bool {
    p.arch == WinArch::X64 && matches!(delta_frame(p, pc, ANCHOR_MIN_DELTA), Ok(Some(_)))
}

/// Decodes an x64 `UNWIND_INFO` whose only effects are stack allocations,
/// returning its prolog size and total allocation.
///
/// Version 1 with no flags, no frame register, and only `UWOP_ALLOC_*` codes
/// means the function has no exception handler, restores no register, and
/// cannot change its establisher in any other way.
fn alloc_only_frame(
    src: &impl crate::user::image::pe::RvaSource,
    info: u32,
) -> Result<Option<(u8, u64)>, crate::user::image::pe::RvaFault> {
    let at = u64::from(info);
    let mut header = [0u8; 4];
    src.read_rva(at, &mut header)?;
    let version = header[0] & 7;
    let flags = header[0] >> 3;
    let prolog = header[1];
    let count = usize::from(header[2]);
    let frame = header[3];
    if version != 1 || flags != 0 || frame != 0 || count == 0 {
        return Ok(None);
    }
    let mut at = at + 4;
    let mut slots = 0usize;
    let mut delta = 0u64;
    while slots < count {
        let mut code = [0u8; 2];
        src.read_rva(at, &mut code)?;
        let op = code[1] & 0xf;
        let opinfo = u64::from(code[1] >> 4);
        at += 2;
        slots += 1;
        match op {
            // UWOP_ALLOC_SMALL: (opinfo + 1) * 8 bytes.
            2 => delta = delta.saturating_add(opinfo * 8 + 8),
            // UWOP_ALLOC_LARGE: opinfo 0 scopes a 16-bit count of 8-byte
            // units, opinfo 1 a full 32-bit byte count.
            1 => match opinfo {
                0 => {
                    delta = delta.saturating_add(u64::from(src.u16_at(at)?) * 8);
                    at += 2;
                    slots += 1;
                }
                1 => {
                    delta = delta.saturating_add(u64::from(src.u32_at(at)?));
                    at += 4;
                    slots += 2;
                }
                _ => return Ok(None),
            },
            _ => return Ok(None),
        }
    }
    if delta == 0 {
        return Ok(None);
    }
    Ok(Some((prolog, delta)))
}

/// Dispatches to language handlers found by virtual unwinding.
pub fn dispatch(c: &mut Ctx, rec: ExceptionRecord, recs: Records) -> ApiResult {
    let ctx = RegContext::read(&c.p.space, c.p.arch, recs.context)?;
    let frame_ctx = c.stack_alloc_checked(RegContext::size(c.p.arch) as u64, 16)?;
    let dc = c.stack_alloc_checked(dispatcher_context_size(c.p.arch), 16)?;
    search(c, rec, recs, ctx, frame_ctx, dc, true, WalkState::default())
}

/// Walks frames from `ctx` looking for a handler.
fn search(
    c: &mut Ctx,
    rec: ExceptionRecord,
    recs: Records,
    mut ctx: RegContext,
    frame_ctx: u64,
    dc: u64,
    mut first: bool,
    mut walk: WalkState,
) -> ApiResult {
    loop {
        let pc = ctx.pc();
        if pc == 0 || !in_stack(c, ctx.sp()) {
            return unhandled(c, rec, recs);
        }
        walk.visit(&ctx)?;
        trace(format_args!(
            "search pc={pc:#x} sp={:#x} first={first}",
            ctx.sp()
        ));
        match crate::user::windows::hle::exception::table(c, &rec, &mut ctx, &mut walk.exception)? {
            crate::user::windows::hle::exception::Crossing::Selected(selected) => {
                // Search changed only a virtual context. Real cleanup starts
                // from the original fault, never from the search frontier.
                let fault = RegContext::read(&c.p.space, c.p.arch, recs.context)?;
                c.p.space
                    .w32(recs.record + 4, rec.flags | EXCEPTION_UNWINDING)?;
                return unwind_selected(
                    c,
                    recs,
                    fault,
                    frame_ctx,
                    dc,
                    selected,
                    WalkState::default(),
                    true,
                );
            }
            crate::user::windows::hle::exception::Crossing::Bridged => {
                first = false;
                continue;
            }
            crate::user::windows::hle::exception::Crossing::None => {}
        }
        let this = ctx.clone();
        let (entry, u) = match step(c.p, UNW_FLAG_EHANDLER, &mut ctx) {
            Ok(result) => result,
            Err(_) => {
                // Metadata and genuine stack-pop faults both stop search
                // without committing a synthetic leaf/caller context. Keep
                // the original classified exception; unhandled filtering is
                // a guest callback rather than synchronous redispatch.
                trace(format_args!(
                    "walk stopped at pc={:#x} sp={:#x}",
                    pc,
                    ctx.sp()
                ));
                let mut rec = rec;
                rec.flags |= EXCEPTION_STACK_INVALID;
                c.p.space.w32(recs.record + 4, rec.flags)?;
                return unhandled(c, rec, recs);
            }
        };
        let control_pc_is_unwound = !first && c.p.arch == WinArch::Arm64;
        first = false;
        let (Some(f), Some(handler)) = (entry, u.handler) else {
            continue;
        };
        if !in_stack(c, u.establisher) || u.establisher % 8 != 0 {
            let mut rec = rec;
            rec.flags |= EXCEPTION_STACK_INVALID;
            c.p.space.w32(recs.record + 4, rec.flags)?;
            return unhandled(c, rec, recs);
        }
        this.write(&c.p.space, frame_ctx)?;
        trace(format_args!(
            "handler pc={:#x} establisher={:#x} entry={:#x} image={:#x} data={:#x}",
            handler, u.establisher, f.entry, f.image_base, u.handler_data,
        ));
        DispatcherContext {
            control_pc: pc,
            image_base: f.image_base,
            function_entry: f.entry,
            establisher: u.establisher,
            target_ip: 0,
            context: frame_ctx,
            handler,
            handler_data: u.handler_data,
            scope_index: 0,
            control_pc_is_unwound,
        }
        .write(&c.p.space, c.p.arch, dc)?;
        let next = ctx;
        let then = move |c: &mut Ctx, ret: u64| {
            let rec = ExceptionRecord::read(&c.p.space, c.p.arch, recs.record)?;
            match ret as u32 {
                disposition::CONTINUE_EXECUTION => handler_continue(c, &rec, recs),
                disposition::CONTINUE_SEARCH | disposition::NESTED_EXCEPTION => {
                    search(c, rec, recs, next, frame_ctx, dc, false, walk)
                }
                _ => Ok(Flow::Raise(ExceptionRecord {
                    code: STATUS_INVALID_DISPOSITION,
                    flags: EXCEPTION_NONCONTINUABLE,
                    nested: recs.record,
                    address: rec.address,
                    params: Vec::new(),
                })),
            }
        };
        let records_top = recs.context + RegContext::size(c.p.arch) as u64;
        let anchored = match anchor(c, &this, u.establisher, records_top) {
            Ok(anchor) => anchor,
            // Metadata faults on the anchor path fall back to the ordinary
            // callback placement; the handler still runs.
            Err(_) => None,
        };
        if c.p.arch == WinArch::X64 {
            match anchored {
                Some(anchor) => trace(format_args!(
                    "anchor sp={:#x} delta={:#x} target={:#x}",
                    anchor.sp, anchor.delta_pc, u.establisher
                )),
                None => trace(format_args!(
                    "anchor declined target={:#x} pc={:#x} sp={:#x} records_top={:#x}",
                    u.establisher,
                    this.pc(),
                    this.sp(),
                    records_top
                )),
            }
        }
        return match anchored {
            Some(anchor) => Flow::call_checked_at(
                handler,
                vec![recs.record, u.establisher, recs.context, dc],
                anchor.sp,
                anchor.delta_pc,
                then,
            ),
            None => Flow::call_checked(
                handler,
                vec![recs.record, u.establisher, recs.context, dc],
                then,
            ),
        };
    }
}

/// Run available guest termination handlers before entering a selected HLE
/// scope. The exact selected owner is the target; its original continuation
/// and outer callers are neither unwound nor consumed. This uses the same
/// bounded metadata decoder as ordinary SEH (no invented language personality).
fn unwind_selected(
    c: &mut Ctx,
    recs: Records,
    mut ctx: RegContext,
    frame_ctx: u64,
    dc: u64,
    selected: crate::user::windows::hle::exception::Selected,
    mut walk: WalkState,
    mut first: bool,
) -> ApiResult {
    use crate::user::windows::hle::exception::{UnwindCrossing, table_unwind};
    loop {
        if ctx.pc() == 0 || !in_stack(c, ctx.sp()) {
            return Err(ApiErr::Internal(
                "synthetic SEH unwind did not reach selected owner".into(),
            ));
        }
        walk.visit(&ctx)?;
        match table_unwind(c, &mut ctx, &mut walk.exception, &selected)? {
            UnwindCrossing::Reached => return selected.invoke(c),
            UnwindCrossing::Bridged => {
                first = false;
                continue;
            }
            UnwindCrossing::None => {}
        }
        let this = ctx.clone();
        let (entry, u) = step(c.p, UNW_FLAG_UHANDLER, &mut ctx).map_err(ApiErr::Fault)?;
        let control_pc_is_unwound = !first && c.p.arch == WinArch::Arm64;
        first = false;
        let (Some(f), Some(handler)) = (entry, u.handler) else {
            continue;
        };
        if !in_stack(c, u.establisher) || u.establisher % 8 != 0 {
            return Err(ApiErr::Internal(
                "synthetic SEH unwind invalid establisher frame".into(),
            ));
        }
        let flags = c.p.space.u32(recs.record + 4)?;
        c.p.space.w32(
            recs.record + 4,
            (flags & !(EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)) | EXCEPTION_UNWINDING,
        )?;
        this.write(&c.p.space, frame_ctx)?;
        DispatcherContext {
            control_pc: this.pc(),
            image_base: f.image_base,
            function_entry: f.entry,
            establisher: u.establisher,
            target_ip: 0,
            context: frame_ctx,
            handler,
            handler_data: u.handler_data,
            scope_index: 0,
            control_pc_is_unwound,
        }
        .write(&c.p.space, c.p.arch, dc)?;
        return Flow::call_checked(
            handler,
            vec![recs.record, u.establisher, frame_ctx, dc],
            move |c, ret| {
                if ret as u32 != disposition::CONTINUE_SEARCH {
                    // A collided unwind requires a language-specific restart
                    // context, which this personality does not synthesize.
                    return Err(ApiErr::Internal(format!(
                        "synthetic SEH unwind unsupported disposition {ret:#x}"
                    )));
                }
                unwind_selected(c, recs, ctx, frame_ctx, dc, selected, walk, false)
            },
        );
    }
}

/// The state of an `RtlUnwindEx` in progress.
#[derive(Clone)]
struct UnwindState {
    target_frame: u64,
    target_ip: u64,
    ret_value: u64,
    record: u64,
    ctx_arg: u64,
    frame_ctx: u64,
    dc: u64,
    walk: WalkState,
}

/// `RtlUnwindEx` (x64 and ARM64).
pub fn rtl_unwind_ex(c: &mut Ctx) -> ApiResult {
    let target_frame = c.ptr(0)?;
    let target_ip = c.ptr(1)?;
    let rec_arg = c.ptr(2)?;
    let ret_value = c.arg(3)?;
    let ctx_arg = c.ptr(4)?;
    let arch = c.p.arch;

    // The unwind starts from the caller's context as this call returns.
    let mut ctx = RegContext::capture(&c.t.cpu);
    match arch {
        WinArch::X64 => {
            ctx.set_pc(c.ret_addr);
            ctx.set_sp(c.entry_sp + 8);
        }
        _ => {
            ctx.set_pc(c.ret_addr);
            ctx.set_sp(c.entry_sp);
        }
    }
    let rec_addr = if rec_arg != 0 {
        rec_arg
    } else {
        let a = c.stack_alloc_checked(ExceptionRecord::size(arch), 16)?;
        ExceptionRecord::new(STATUS_UNWIND, c.ret_addr, Vec::new()).write(&c.p.space, arch, a)?;
        a
    };
    let frame_ctx = c.stack_alloc_checked(RegContext::size(arch) as u64, 16)?;
    let dc = c.stack_alloc_checked(dispatcher_context_size(arch), 16)?;
    let st = UnwindState {
        target_frame,
        target_ip,
        ret_value,
        record: rec_addr,
        ctx_arg,
        frame_ctx,
        dc,
        walk: WalkState::default(),
    };
    unwind_frames(c, st, ctx)
}

fn unwind_frames(c: &mut Ctx, mut st: UnwindState, mut ctx: RegContext) -> ApiResult {
    let arch = c.p.arch;
    loop {
        let pc = ctx.pc();
        if pc == 0 || !in_stack(c, ctx.sp()) {
            return Err(ApiErr::Raise(ExceptionRecord {
                code: STATUS_INVALID_UNWIND_TARGET,
                flags: EXCEPTION_NONCONTINUABLE,
                nested: 0,
                address: c.entry_pc,
                params: Vec::new(),
            }));
        }
        st.walk.visit(&ctx)?;
        let this = ctx.clone();
        let (entry, u) = step(c.p, UNW_FLAG_UHANDLER, &mut ctx).map_err(ApiErr::Fault)?;
        let at_target = st.target_frame != 0 && u.establisher == st.target_frame;
        if st.target_frame != 0 && u.establisher > st.target_frame {
            return Err(ApiErr::Raise(ExceptionRecord {
                code: STATUS_INVALID_UNWIND_TARGET,
                flags: EXCEPTION_NONCONTINUABLE,
                nested: 0,
                address: c.entry_pc,
                params: Vec::new(),
            }));
        }
        if let (Some(f), Some(handler)) = (entry, u.handler) {
            let mut flags = EXCEPTION_UNWINDING;
            if st.target_frame == 0 {
                flags |= EXCEPTION_EXIT_UNWIND;
            }
            if at_target {
                flags |= EXCEPTION_TARGET_UNWIND;
            }
            let old = c.p.space.u32(st.record + 4)?;
            c.p.space.w32(
                st.record + 4,
                (old & !(EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)) | flags,
            )?;
            this.write(&c.p.space, st.frame_ctx)?;
            DispatcherContext {
                control_pc: pc,
                image_base: f.image_base,
                function_entry: f.entry,
                establisher: u.establisher,
                target_ip: st.target_ip,
                context: st.frame_ctx,
                handler,
                handler_data: u.handler_data,
                scope_index: 0,
                control_pc_is_unwound: false,
            }
            .write(&c.p.space, arch, st.dc)?;
            let next = ctx;
            return Flow::call(
                handler,
                vec![st.record, u.establisher, st.frame_ctx, st.dc],
                move |c, _ret| {
                    if at_target {
                        finish_unwind(c, &st, next_frame_context(&this, &next, c.p.arch))
                    } else {
                        unwind_frames(c, st, next)
                    }
                },
            );
        }
        if at_target {
            return finish_unwind(c, &st, next_frame_context(&this, &ctx, arch));
        }
    }
}

/// The context to resume at the target frame: the target function's own
/// registers (the context before its unwind), as the target is inside it.
fn next_frame_context(this: &RegContext, _unwound: &RegContext, _arch: WinArch) -> RegContext {
    this.clone()
}

/// Resumes at the unwind's target.
fn finish_unwind(c: &mut Ctx, st: &UnwindState, mut ctx: RegContext) -> ApiResult {
    ctx.set_pc(st.target_ip);
    ctx.set_gpr(0, st.ret_value);
    ctx.set_flags(RegContext::all_flags(c.p.arch));
    if st.ctx_arg != 0 {
        ctx.write(&c.p.space, st.ctx_arg)?;
    }
    Ok(Flow::Resume(Box::new(ctx)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::memory::{mem, prot};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    fn with_context(arch: WinArch, test: impl FnOnce(&mut Ctx)) {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        let mut cfg = WindowsConfig::new("seh-test.exe", Vec::new());
        cfg.seed = Some(1);
        cfg.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let cursor = t.cpu.sp();
        test(&mut Ctx {
            p,
            t: &mut t,
            api: &super::super::DISPATCHER,
            entry_pc: 0,
            entry_sp: cursor,
            ret_addr: 0,
            cursor,
        });
    }

    #[test]
    fn lookup_distinguishes_absence_guest_fault_and_malformed_extent() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_context(arch, |c| {
                let base = c.p.modules.exe().base;
                let size = c.p.modules.exe().size;
                c.p.modules.list[0].pdata =
                    crate::user::image::pe::DataDirectory { rva: 0, size: 0 };
                assert_eq!(lookup(c.p, base + 0x40).unwrap(), None);
                c.p.vm.protect(base, size, prot::READWRITE).unwrap();
                c.p.space.w32(base + 0x1000, 0x10).unwrap();
                let entry_size = if arch == WinArch::X64 {
                    c.p.space.w32(base + 0x1004, 0x80).unwrap();
                    c.p.space.w32(base + 0x1008, 0x1800).unwrap();
                    12
                } else {
                    c.p.space.w32(base + 0x1004, 1 | (64 << 2)).unwrap();
                    8
                };
                c.p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                    rva: 0x1000,
                    size: entry_size,
                };
                assert!(lookup(c.p, base + 0x40).unwrap().is_some());
                c.p.vm
                    .protect(base + 0x1000, 0x1000, prot::NOACCESS)
                    .unwrap();
                let mut context = RegContext::capture(&c.t.cpu);
                context.set_pc(base + 0x40);
                let before = context.clone();
                assert!(step(c.p, UNW_FLAG_EHANDLER, &mut context).is_err());
                assert_eq!(context, before);
                c.p.vm
                    .protect(base + 0x1000, 0x1000, prot::READWRITE)
                    .unwrap();
                c.p.modules.list[0].pdata.size = 3;
                assert!(lookup(c.p, base + 0x40).is_err());
                c.p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                    rva: size as u32 - 4,
                    size: entry_size,
                };
                assert!(lookup(c.p, base + 0x40).is_err());
            });
        }
    }

    #[test]
    fn genuine_leafs_finish_but_repeated_arm64_leaf_fails_closed() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_context(arch, |c| {
                let base = c.p.modules.exe().base;
                c.p.modules.list[0].pdata =
                    crate::user::image::pe::DataDirectory { rva: 0, size: 0 };
                let mut context = RegContext::capture(&c.t.cpu);
                context.set_pc(base + 0x40);
                if arch == WinArch::X64 {
                    c.p.space.w64(context.sp(), 0).unwrap();
                } else {
                    context.set_gpr(30, 0);
                }
                let rec = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, context.pc(), vec![]);
                let recs = Records {
                    record: 0,
                    context: 0,
                    pointers: 0,
                };
                assert!(matches!(
                    search(
                        c,
                        rec.clone(),
                        recs,
                        context.clone(),
                        0,
                        0,
                        true,
                        WalkState::default()
                    ),
                    Ok(Flow::TerminateProcess(STATUS_ACCESS_VIOLATION))
                ));
                if arch == WinArch::Arm64 {
                    context.set_gpr(30, context.pc());
                    assert!(
                        matches!(search(c, rec, recs, context, 0, 0, true, WalkState::default()), Err(ApiErr::Internal(message)) if message.contains("cyclic"))
                    );
                }
            });
        }
    }

    #[test]
    fn failed_metadata_lookup_preserves_original_exception_without_leaf_restoration() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_context(arch, |c| {
                let base = c.p.modules.exe().base;
                c.p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                    rva: 0x1000,
                    size: 3,
                };
                let mut ctx = RegContext::capture(&c.t.cpu);
                ctx.set_pc(base + 0x40);
                let recs = Records {
                    record: c.t.stack_limit + 0x1000,
                    context: c.t.stack_limit + 0x2000,
                    pointers: 0,
                };
                ctx.write(&c.p.space, recs.context).unwrap();
                let rec = ExceptionRecord::new(
                    STATUS_GUARD_PAGE_VIOLATION,
                    ctx.pc(),
                    vec![0, base + 0x1234],
                );
                rec.write(&c.p.space, arch, recs.record).unwrap();
                assert!(matches!(
                    search(c, rec, recs, ctx.clone(), 0, 0, true, WalkState::default()),
                    Ok(Flow::TerminateProcess(STATUS_GUARD_PAGE_VIOLATION))
                ));
                let stored = ExceptionRecord::read(&c.p.space, arch, recs.record).unwrap();
                assert_eq!(stored.code, STATUS_GUARD_PAGE_VIOLATION);
                assert_eq!(stored.params, [0, base + 0x1234]);
                assert_ne!(stored.flags & EXCEPTION_STACK_INVALID, 0);
                assert_eq!(
                    RegContext::read(&c.p.space, arch, recs.context).unwrap(),
                    ctx
                );
            });
        }
    }

    /// Places one x64 runtime function covering `[0x40, 0x80)` whose unwind
    /// info is `info` (written at RVA 0x1800), then returns the module base.
    fn install_unwind(c: &mut Ctx, info: &[u8]) -> u64 {
        let base = c.p.modules.exe().base;
        let size = c.p.modules.exe().size;
        c.p.vm.protect(base, size, prot::READWRITE).unwrap();
        c.p.space.w32(base + 0x1000, 0x40).unwrap();
        c.p.space.w32(base + 0x1004, 0x80).unwrap();
        c.p.space.w32(base + 0x1008, 0x1800).unwrap();
        c.p.space.wr(base + 0x1800, info).unwrap();
        c.p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
            rva: 0x1000,
            size: 12,
        };
        base
    }

    #[test]
    fn delta_frame_scan_accepts_only_frameless_stack_allocation() {
        with_context(WinArch::X64, |c| {
            // ALLOC_SMALL of 0x38 after a 4-byte prolog.
            let base = install_unwind(c, &[0x01, 4, 1, 0, 0x04, 0x62]);
            assert_eq!(
                delta_frame(c.p, base + 0x40, 0x18).unwrap(),
                Some(DeltaFrame {
                    pc: base + 0x44,
                    delta: 0x38,
                })
            );
            // ALLOC_LARGE scoping a 16-bit count of 8-byte units.
            let base = install_unwind(c, &[0x01, 4, 2, 0, 0x04, 0x01, 0x07, 0x00]);
            assert_eq!(
                delta_frame(c.p, base + 0x40, 0x18).unwrap(),
                Some(DeltaFrame {
                    pc: base + 0x44,
                    delta: 0x38,
                })
            );
            // ALLOC_LARGE scoping a byte count.
            let base = install_unwind(c, &[0x01, 4, 3, 0, 0x04, 0x11, 0x38, 0, 0, 0]);
            assert_eq!(
                delta_frame(c.p, base + 0x40, 0x18).unwrap(),
                Some(DeltaFrame {
                    pc: base + 0x44,
                    delta: 0x38,
                })
            );
            // A saved nonvolatile register is restored, not a pure delta.
            let base = install_unwind(c, &[0x01, 4, 1, 0, 0x04, 0x34]);
            assert_eq!(delta_frame(c.p, base + 0x40, 0x18).unwrap(), None);
            // A frame register changes what the establisher means.
            let base = install_unwind(c, &[0x01, 4, 1, 0x05, 0x04, 0x62]);
            assert_eq!(delta_frame(c.p, base + 0x40, 0x18).unwrap(), None);
            // An exception handler would be called during the guest's walk.
            let base = install_unwind(c, &[0x09, 4, 1, 0, 0x04, 0x62]);
            assert_eq!(delta_frame(c.p, base + 0x40, 0x18).unwrap(), None);
            // 16 decimal allocates below the anchor minimum and leaves the
            // fabricated chain 16-byte misaligned.
            let base = install_unwind(c, &[0x01, 4, 1, 0, 0x04, 0x12]);
            assert_eq!(delta_frame(c.p, base + 0x40, 0x18).unwrap(), None);
            // 8 decimal is a valid frame but too small for the anchor call.
            let base = install_unwind(c, &[0x01, 4, 1, 0, 0x04, 0x02]);
            assert_eq!(delta_frame(c.p, base + 0x40, 0x18).unwrap(), None);
            // `raise` reserves record room only where `anchor` can apply.
            assert!(!anchor_possible(c.p, base + 0x40));
            let base = install_unwind(c, &[0x01, 4, 1, 0, 0x04, 0x62]);
            assert!(anchor_possible(c.p, base + 0x40));
            // A PC outside every image has no metadata to promise an anchor.
            assert!(!anchor_possible(c.p, c.p.traps.callback_return()));
        });
    }

    #[test]
    fn anchor_geometry_places_fault_frame_above_a_fabricated_chain() {
        with_context(WinArch::X64, |c| {
            let base = install_unwind(c, &[0x01, 4, 1, 0, 0x04, 0x62]);
            let trap = c.p.traps.callback_return();
            assert_ne!(trap, 0);
            for low in [8u64, 0] {
                let target = ((c.t.stack_limit + 0x800) & !0xF) | low;
                let mut fault = RegContext::capture(&c.t.cpu);
                fault.set_pc(base + 0x40);
                fault.set_sp(target);
                let records_top = target - 0x4000;
                let got = anchor(c, &fault, target, records_top).unwrap().unwrap();
                // The delta frame's allocation moves the fault frame's stack
                // pointer onto the target frame the guest asks for.
                let expected_sp = if low == 8 {
                    target - 0x18 - 0x38
                } else {
                    target - 0x20 - 0x38
                };
                assert_eq!(
                    got,
                    Anchor {
                        sp: expected_sp,
                        delta_pc: base + 0x44,
                    }
                );
                assert_eq!(got.sp % 8, 0, "establishers stay 8-byte aligned");
                assert_eq!(
                    got.sp + 0x10 + 0x38,
                    if low == 8 { target - 8 } else { target - 0x10 },
                    "the delta frame returns through the fabricated slot"
                );
                assert_eq!(c.p.space.u64(target - 8).unwrap(), base + 0x40);
                if low == 0 {
                    assert_eq!(c.p.space.u64(target - 0x10).unwrap(), trap);
                }
                // Records placed directly below the fault stack pointer leave
                // no room for the handler: the anchor must decline.
                assert_eq!(anchor(c, &fault, target, target).unwrap(), None);
                // A frame-pointer fault frame resumes at its establisher, not
                // at its own stack pointer.
                let mut framed = fault.clone();
                framed.set_sp(target + 0x20);
                assert_eq!(anchor(c, &framed, target, records_top).unwrap(), None);
            }
        });
    }

    #[test]
    fn frame_tracker_checks_cycles_lr_and_exact_cap() {
        let mut ctx = RegContext::new(WinArch::Arm64);
        let mut walk = WalkState::default();
        ctx.set_pc(0x1000);
        ctx.set_sp(0x2000);
        walk.visit(&ctx).unwrap();
        ctx.set_gpr(30, 0x3000);
        walk.visit(&ctx).unwrap();
        assert!(walk.visit(&ctx).is_err());
        let mut walk = WalkState::default();
        for i in 0..4096 {
            ctx.set_pc(4 * (i + 1));
            walk.visit(&ctx).unwrap();
        }
        ctx.set_pc(4 * 4097);
        assert!(walk.visit(&ctx).is_err());
        assert_eq!(walk.seen.len(), 4096);
    }

    #[test]
    fn metadata_reader_rejects_adjacent_readable_mapping() {
        with_context(WinArch::X64, |c| {
            let (base, _) =
                c.p.vm
                    .allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap();
            c.p.space.w64(base + 0x1000, 0x1234).unwrap();
            let metadata = ImageMem {
                mem: &c.p.space,
                base,
                size: 0x1000,
            };
            assert!(metadata.u64(base + 0x1000).is_err());
            assert!(metadata.u64(base + 0xFFC).is_err());
            assert!(metadata.u64(u64::MAX - 3).is_err());
            assert!(metadata.u64(base + 0xFF8).is_ok());
        });
    }

    fn dispatcher() -> DispatcherContext {
        DispatcherContext {
            control_pc: 0x1122_3344_5566_7788,
            scope_index: 0x1234_5678,
            control_pc_is_unwound: true,
            ..Default::default()
        }
    }

    #[test]
    fn dispatcher_context_writes_exact_architecture_extent_and_preserves_sentinels() {
        for (arch, size) in [(WinArch::X64, 0x50u64), (WinArch::Arm64, 0x58)] {
            with_context(arch, |c| {
                let (base, _) =
                    c.p.vm
                        .allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                        .unwrap();
                let at = base + 0x80;
                c.p.space
                    .wr(at - 8, &vec![0xA5; size as usize + 24])
                    .unwrap();
                dispatcher().write(&c.p.space, arch, at).unwrap();
                assert_eq!(dispatcher_context_size(arch), size);
                assert_eq!(c.p.space.u64(at).unwrap(), dispatcher().control_pc);
                assert_eq!(c.p.space.u32(at + 0x48).unwrap(), dispatcher().scope_index);
                assert_eq!(
                    c.p.space.u8(at + 0x4C).unwrap(),
                    u8::from(arch == WinArch::Arm64)
                );
                assert_eq!(c.p.space.bytes(at - 8, 8).unwrap(), [0xA5; 8]);
                assert_eq!(c.p.space.bytes(at + size, 16).unwrap(), [0xA5; 16]);
                if arch == WinArch::Arm64 {
                    assert_eq!(c.p.space.u64(at + 0x50).unwrap(), 0);
                }
            });
        }
    }

    #[test]
    fn dispatcher_context_exact_page_boundary_does_not_touch_protected_next_page() {
        for (arch, size) in [(WinArch::X64, 0x50u64), (WinArch::Arm64, 0x58)] {
            with_context(arch, |c| {
                let (base, _) =
                    c.p.vm
                        .allocate(None, 0x10000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                        .unwrap();
                let boundary = base + 0x1000;
                let at = boundary - size;
                for protection in [prot::READONLY, prot::NOACCESS] {
                    c.p.space
                        .wr(at - 8, &vec![0xA5; size as usize + 24])
                        .unwrap();
                    c.p.vm.protect(boundary, 0x1000, protection).unwrap();
                    dispatcher().write(&c.p.space, arch, at).unwrap();
                    assert_eq!(c.p.space.u64(at).unwrap(), dispatcher().control_pc);
                    // A one-byte displacement really crosses the selected
                    // architecture's end and must encounter the protection.
                    assert!(matches!(
                        dispatcher().write(&c.p.space, arch, at + 1),
                        Err(MemFault { write: true, .. })
                    ));
                    assert_eq!(c.p.space.bytes(at - 8, 8).unwrap(), [0xA5; 8]);
                    c.p.vm.protect(boundary, 0x1000, prot::READWRITE).unwrap();
                    assert_eq!(c.p.space.bytes(boundary, 16).unwrap(), [0xA5; 16]);
                }
            });
        }
    }

    #[test]
    fn dispatcher_context_x86_rejection_writes_nothing() {
        with_context(WinArch::X86, |c| {
            let at = c.t.stack_limit + 0x1000;
            c.p.space.wr(at, &[0xA5; 0x58]).unwrap();
            assert!(
                matches!(dispatcher().write(&c.p.space, WinArch::X86, at), Err(MemFault { addr, write: true }) if addr == at)
            );
            assert_eq!(c.p.space.bytes(at, 0x58).unwrap(), [0xA5; 0x58]);
        });
    }

    #[test]
    fn dormant_unwind_context_output_fault_is_not_success() {
        with_context(WinArch::X64, |c| {
            let address = c.t.stack_limit + 0x1000;
            c.p.vm.protect(address, 0x1000, prot::READONLY).unwrap();
            let st = UnwindState {
                target_frame: 0,
                target_ip: 0x1234,
                ret_value: 0,
                record: 0,
                ctx_arg: address,
                frame_ctx: 0,
                dc: 0,
                walk: WalkState::default(),
            };
            let ctx = RegContext::capture(&c.t.cpu);
            assert!(matches!(
                finish_unwind(c, &st, ctx),
                Err(ApiErr::Fault(MemFault { write: true, .. }))
            ));
        });
    }
}
