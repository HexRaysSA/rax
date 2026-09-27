//! High-level emulation of built-in DLL functions.
//!
//! A built-in DLL export is a 16-byte *trap slot* in a page that is mapped
//! readable but not executable. A call into it (`call [__imp_X]`,
//! `blr x16`, a function pointer from `GetProcAddress`) retires normally,
//! and the instruction fetch at the slot faults; the dispatcher recognizes
//! the slot and runs the export's [`Api`] implementation with the thread's
//! registers and stack exactly as the calling convention left them. The
//! implementation returns a [`Flow`]: a return value (written as the
//! convention requires, with the x86 `stdcall` callee cleanup), a call
//! into guest code whose result feeds a continuation, a blocking wait, a
//! full context to resume, a raised exception, or thread/process exit.
//!
//! Slot offset 8 is the export's *resume* trap: a context whose PC is
//! there resumes by returning from the export, which is how an exception
//! raised by `RaiseException` continues after a handler returns
//! `EXCEPTION_CONTINUE_EXECUTION`.
//!
//! Calls from built-in code into guest code push a [`Frame`] on the
//! thread; the guest function returns to the callback-return trap, and the
//! frame's continuation receives its result. A frame whose entry stack
//! pointer lies below the current stack pointer belongs to a call that was
//! abandoned (by `longjmp`, an unwind, or `NtContinue`) and is discarded.

pub mod args;
pub mod dispatch;

use super::arch::WinArch;
use super::context::{ExceptionRecord, RegContext};
use super::memory::{Mem, MemFault};
use super::process::{Proc, Thread};
use super::sync::Wait;
use crate::user::mm::AddressSpace;

pub use args::VaList;

/// A parameter's class, which decides where the calling convention passes
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arg {
    /// A 32-bit integer (`int`, `DWORD`, `BOOL`, `UINT`, `LONG`).
    I32,
    /// A pointer-sized integer (pointers, `HANDLE`, `SIZE_T`, `ULONG_PTR`,
    /// `WPARAM`, `LPARAM`).
    Ptr,
    /// A 64-bit integer (`LONGLONG`, `ULONGLONG`, `LARGE_INTEGER` by
    /// value); two stack slots on x86.
    I64,
    /// `float`.
    F32,
    /// `double`; two stack slots on x86.
    F64,
}

/// The x86 calling convention (x64 and ARM64 have one convention each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conv {
    /// `__stdcall`: the callee removes the arguments (`WINAPI`, `NTAPI`).
    Stdcall,
    /// `__cdecl`: the caller removes the arguments (the C runtime).
    Cdecl,
    /// `__cdecl` with `...` after the listed parameters. On ARM64 every
    /// argument of a variadic function is passed as if it were variadic
    /// (integer registers and stack, no SIMD registers).
    Variadic,
    /// A private register convention (`__chkstk`): the implementation
    /// reads and writes registers itself and returns [`Flow::Done`].
    Custom,
}

/// A built-in function's implementation.
pub type ApiFn = fn(&mut Ctx) -> ApiResult;

/// A built-in function.
pub struct Api {
    /// Export name.
    pub name: &'static str,
    /// Parameters.
    pub args: &'static [Arg],
    /// x86 convention.
    pub conv: Conv,
    /// Implementation.
    pub imp: ApiFn,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

/// Architectures an export exists on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Archs(u8);

impl Archs {
    /// Every architecture.
    pub const ALL: Archs = Archs(7);
    /// x86 only.
    pub const X86: Archs = Archs(1);
    /// x64 only.
    pub const X64: Archs = Archs(2);
    /// ARM64 only.
    pub const ARM64: Archs = Archs(4);
    /// x64 and ARM64 (table-based exception handling).
    pub const WIN64: Archs = Archs(6);
    /// x86 and x64, excluding ARM64.
    pub const X86_FAMILY: Archs = Archs(3);

    /// Whether `arch` is included.
    pub fn has(self, arch: WinArch) -> bool {
        let bit = match arch {
            WinArch::X86 => 1,
            WinArch::X64 => 2,
            WinArch::Arm64 => 4,
        };
        self.0 & bit != 0
    }
}

/// What an export designates.
pub enum Item {
    /// A function.
    Func(Api),
    /// A variable of the given size (bytes, per architecture pointer size
    /// when [`DataSize::Ptrs`]), initialized by the process.
    Data(DataSize),
    /// A forwarder (`"NTDLL.RtlAllocateHeap"`).
    Forward(&'static str),
}

/// The size of a data export.
#[derive(Clone, Copy, Debug)]
pub enum DataSize {
    /// A fixed number of bytes.
    Bytes(u32),
    /// A number of pointer-sized words.
    Ptrs(u32),
}

/// One export of a built-in DLL.
pub struct Export {
    /// Export name.
    pub name: &'static str,
    /// What it designates.
    pub item: Item,
    /// Architectures it exists on.
    pub archs: Archs,
}

impl Export {
    /// A function export.
    pub const fn func(name: &'static str, conv: Conv, args: &'static [Arg], imp: ApiFn) -> Self {
        Export {
            name,
            item: Item::Func(Api {
                name,
                args,
                conv,
                imp,
            }),
            archs: Archs::ALL,
        }
    }

    /// A data export.
    pub const fn data(name: &'static str, size: DataSize) -> Self {
        Export {
            name,
            item: Item::Data(size),
            archs: Archs::ALL,
        }
    }

    /// A forwarder export.
    pub const fn forward(name: &'static str, to: &'static str) -> Self {
        Export {
            name,
            item: Item::Forward(to),
            archs: Archs::ALL,
        }
    }

    /// Restricts the export to `archs`.
    pub const fn only(mut self, archs: Archs) -> Self {
        self.archs = archs;
        self
    }
}

/// A return value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value {
    /// No value (the return registers keep their contents).
    None,
    /// An integer or pointer in EAX/RAX/X0.
    Int(u64),
    /// A 64-bit integer: EDX:EAX on x86, RAX/X0 elsewhere.
    I64(u64),
    /// `double`: ST(0) on x86, XMM0/D0 elsewhere.
    F64(f64),
    /// `float`: ST(0) on x86, XMM0/S0 elsewhere.
    F32(f32),
}

/// A continuation: runs when a guest call returns (with its integer
/// result) or a wait completes (with the wait status).
pub type Cont = Box<dyn FnOnce(&mut Ctx, u64) -> ApiResult>;

/// What a built-in function does next.
pub enum Flow {
    /// Return `Value` to the caller.
    Ret(Value),
    /// Call guest function `target` with integer `args`, then continue.
    Call {
        /// Guest address.
        target: u64,
        /// Integer arguments.
        args: Vec<u64>,
        /// Continuation, given the guest function's return value.
        then: Cont,
    },
    /// Block the thread on `wait`, then continue with the wait's status.
    Block {
        /// The wait.
        wait: Wait,
        /// Continuation.
        then: Cont,
    },
    /// Resume at a full register context (`NtContinue`, `longjmp`, the
    /// target of an unwind).
    Resume(Box<RegContext>),
    /// Raise an exception as `RaiseException` does: the context is the
    /// caller's state inside this export (PC at the resume trap).
    Raise(ExceptionRecord),
    /// Raise a checked memory fault while retaining the operation's exact
    /// continuation. Resuming the same export PC/SP retries that operation,
    /// without reparsing argument registers clobbered by earlier callbacks.
    RetryFault {
        /// Access that failed, classified by the ordinary guard/SEH path.
        fault: MemFault,
        /// Operation to retry; its integer input is ignored.
        retry: Cont,
    },
    /// Return `Value` and end the thread's time slice (`Sleep(0)`,
    /// `SwitchToThread`).
    Yield(Value),
    /// Normal thread exit, including DLL_THREAD_DETACH notifications.
    ExitThread(u32),
    /// Normal process exit, including DLL_PROCESS_DETACH notifications.
    ExitProcess(u32),
    /// Forced thread termination without guest DLL/FLS cleanup callbacks.
    TerminateThread(u32),
    /// Forced process termination without guest DLL/FLS cleanup callbacks.
    TerminateProcess(u32),
    /// Return from SwitchToFiber in the old context, then select the target
    /// context. Its dormant CPU, stack and built-in frames become current.
    SwitchFiber(u64),
    /// The implementation set every register itself ([`Conv::Custom`]).
    Done,
}

impl Flow {
    /// Returns an integer.
    pub fn ret(v: u64) -> ApiResult {
        Ok(Flow::Ret(Value::Int(v)))
    }

    /// Returns a `BOOL`.
    pub fn bool(v: bool) -> ApiResult {
        Ok(Flow::Ret(Value::Int(u64::from(v))))
    }

    /// Returns nothing.
    pub fn void() -> ApiResult {
        Ok(Flow::Ret(Value::None))
    }

    /// Returns a 64-bit integer.
    pub fn ret64(v: u64) -> ApiResult {
        Ok(Flow::Ret(Value::I64(v)))
    }

    /// Returns a `double`.
    pub fn f64(v: f64) -> ApiResult {
        Ok(Flow::Ret(Value::F64(v)))
    }

    /// Calls guest function `target`, then `then`.
    pub fn call(
        target: u64,
        args: Vec<u64>,
        then: impl FnOnce(&mut Ctx, u64) -> ApiResult + 'static,
    ) -> ApiResult {
        Ok(Flow::Call {
            target,
            args,
            then: Box::new(then),
        })
    }

    /// Blocks on `wait`, then `then`.
    pub fn block(wait: Wait, then: impl FnOnce(&mut Ctx, u64) -> ApiResult + 'static) -> ApiResult {
        Ok(Flow::Block {
            wait,
            then: Box::new(then),
        })
    }
}

/// Why a built-in function did not complete normally.
#[derive(Debug)]
pub enum ApiErr {
    /// A guest memory access faulted. The dispatcher raises the classified
    /// access, guard-page, or fixed-stack-guard exception at the call.
    Fault(MemFault),
    /// Raise this exception at the call (a fault inside the function).
    Raise(ExceptionRecord),
    /// A function this implementation does not provide was called.
    Unimplemented(String),
    /// The emulator cannot continue.
    Internal(String),
}

impl From<MemFault> for ApiErr {
    fn from(f: MemFault) -> Self {
        ApiErr::Fault(f)
    }
}

/// The result of a built-in function.
pub type ApiResult = Result<Flow, ApiErr>;

/// A call into built-in code in progress.
pub struct Frame {
    /// The export being executed.
    pub api: &'static Api,
    /// The trap slot that was entered (the export's address in the DLL
    /// that was called).
    pub entry_pc: u64,
    /// Stack pointer at entry (x86/x64: pointing at the return address).
    pub entry_sp: u64,
    /// Return address.
    pub ret_addr: u64,
    /// Lowest address used by the frame's own guest-stack allocations and
    /// callback frames.
    pub cursor: u64,
    /// The continuation awaiting a guest call or a wait.
    pub cont: Option<Cont>,
    /// Checked operation waiting for exception repair, distinct from a guest
    /// callback's continuation. Pruning or abandoning the frame drops it.
    pub retry: Option<Cont>,
}

/// The execution context of a built-in function: the process, the calling
/// thread, and the call's frame.
pub struct Ctx<'a> {
    /// The process.
    pub p: &'a mut Proc,
    /// The calling thread.
    pub t: &'a mut Thread,
    /// The export.
    pub api: &'static Api,
    /// The trap slot that was entered.
    pub entry_pc: u64,
    /// Stack pointer at entry.
    pub entry_sp: u64,
    /// Return address.
    pub ret_addr: u64,
    /// Guest-stack allocation cursor.
    pub cursor: u64,
}

impl<'a> Ctx<'a> {
    /// The guest architecture.
    pub fn arch(&self) -> WinArch {
        self.p.arch
    }

    /// Guest memory.
    pub fn mem(&self) -> &AddressSpace {
        &self.p.space
    }

    /// Pointer size.
    pub fn psize(&self) -> u64 {
        self.p.arch.ptr_size()
    }

    /// Reads a guest pointer.
    pub fn read_ptr(&self, addr: u64) -> Result<u64, MemFault> {
        self.p.space.ptr(addr, self.psize())
    }

    /// Writes a guest pointer.
    pub fn write_ptr(&self, addr: u64, v: u64) -> Result<(), MemFault> {
        self.p.space.wptr(addr, self.psize(), v)
    }

    /// Allocates `size` bytes aligned to `align` on the guest stack below
    /// the frame (for structures passed to guest callbacks).
    pub fn stack_alloc(&mut self, size: u64, align: u64) -> u64 {
        self.cursor = self.cursor.saturating_sub(size) & !(align.max(1) - 1);
        self.cursor
    }

    /// Checked stack allocation with guard-frontier growth before publication.
    /// The historical planning-only stack_alloc API remains available.
    pub fn stack_alloc_checked(&mut self, size: u64, align: u64) -> Result<u64, ApiErr> {
        let fault = MemFault {
            addr: self.cursor,
            write: true,
        };
        if !align.is_power_of_two() {
            return Err(fault.into());
        }
        let address = self.cursor.checked_sub(size).ok_or(fault)? & !(align - 1);
        let bytes = self.cursor.checked_sub(address).ok_or(fault)?;
        super::process::stack::prepare(self.p, self.t, address, bytes)
            .map_err(|fault| fault.into_api(self.entry_pc))?;
        self.cursor = address;
        Ok(address)
    }

    /// Sets the thread's last-error value (`TEB.LastErrorValue`).
    pub fn set_last_error(&mut self, error: u32) -> Result<(), MemFault> {
        let off = super::layout::offsets(self.p.arch).teb_last_error;
        self.p.space.w32(self.t.teb + off, error)
    }

    /// The thread's last-error value.
    pub fn last_error(&self) -> Result<u32, MemFault> {
        let off = super::layout::offsets(self.p.arch).teb_last_error;
        self.p.space.u32(self.t.teb + off)
    }

    /// Sets the last error from `status` (`RtlNtStatusToDosError`) and
    /// returns whether `status` is a success.
    pub fn set_status_error(&mut self, status: u32) -> Result<bool, MemFault> {
        let ok = super::nt::nt_success(status);
        if !ok {
            self.set_last_error(super::nt::status_to_error(status))?;
        }
        Ok(ok)
    }

    /// Fails with `error` as the last error and returns `value`.
    pub fn fail(&mut self, error: u32, value: u64) -> ApiResult {
        self.set_last_error(error)?;
        Flow::ret(value)
    }

    /// An exception to raise at the call for an unimplemented feature of
    /// an otherwise implemented function.
    pub fn unsupported(&self, what: impl Into<String>) -> ApiErr {
        ApiErr::Unimplemented(format!("{}: {}", self.api.name, what.into()))
    }
}
