//! Native execution runtime for SMIR-lowered blocks (the JIT back end's
//! "executor"). This is the bridge that takes the x86-64 machine code produced
//! by [`crate::smir::lower::x86_64::X86_64Lowerer`] and actually runs it on the
//! host CPU, marshalling guest register state in and out.
//!
//! Gated behind the `smir-jit` feature and `target_arch = "x86_64"` — the entry
//! trampoline is hand-written x86-64 assembly, and execution relies on the
//! lowerer's 1:1 identity register map (guest GPR `N` ⇒ the same-named host
//! GPR), so a lowered block reads and writes guest state directly with no
//! per-instruction marshalling. The only marshalling is once on entry and once
//! on exit, in [`enter_native`].
//!
//! Validated bit-exact against KVM by the differential harness in
//! `tests/diff_fuzz.rs` (`smir_native_*` tests) across ALU, shifts, MUL,
//! conditional branches, and whole loops (the "dragon" path).

#![cfg(all(feature = "smir-jit", target_arch = "x86_64"))]

/// Guest register file marshalled in/out of a lowered native block.
///
/// `gpr[i]` is indexed by x86 register *encoding*
/// (0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI, 8..=15=R8..=R15);
/// `rflags` holds the materialized flags. `repr(C)` with a fixed layout — the
/// trampoline reads/writes by byte offset (`gpr[i]` at `i*8`, `rflags` at 128).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestRegs {
    /// General-purpose registers, indexed by x86 encoding.
    pub gpr: [u64; 16],
    /// Materialized RFLAGS.
    pub rflags: u64,
}

// enter_native(rdi = entry ptr, rsi = *mut GuestRegs):
//   preserve host callee-saved -> load guest GPRs+RFLAGS into the identical host
//   regs -> `call` the block -> store the host regs back into GuestRegs.
// RSP (gpr[4]) is NOT loaded — the block runs on the host stack (it owns no
// guest stack). Alignment: 6 callee pushes (48) + `sub rsp,24` (72 total) leaves
// rsp 16-aligned at the `call`.
core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".globl rax_smir_enter_native",
    ".type rax_smir_enter_native,@function",
    "rax_smir_enter_native:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "sub rsp, 24", // [rsp]=entry [rsp+8]=state [rsp+16]=pad ; rsp 16-aligned
    "mov [rsp], rdi",
    "mov [rsp+8], rsi",
    "mov rax, [rsi+128]", // RFLAGS
    "push rax",
    "popfq",
    "mov rax, [rsi+0]",
    "mov rcx, [rsi+8]",
    "mov rdx, [rsi+16]",
    "mov rbx, [rsi+24]",
    "mov rbp, [rsi+40]",
    "mov rdi, [rsi+56]",
    "mov r8,  [rsi+64]",
    "mov r9,  [rsi+72]",
    "mov r10, [rsi+80]",
    "mov r11, [rsi+88]",
    "mov r12, [rsi+96]",
    "mov r13, [rsi+104]",
    "mov r14, [rsi+112]",
    "mov r15, [rsi+120]",
    "mov rsi, [rsi+48]", // rsi last (was the base pointer)
    "call [rsp]",
    "push rax",          // save guest RAX ; state now at [rsp+16]
    "mov rax, [rsp+16]", // rax = *mut GuestRegs
    "mov [rax+8],   rcx",
    "mov [rax+16],  rdx",
    "mov [rax+24],  rbx",
    "mov [rax+40],  rbp",
    "mov [rax+48],  rsi",
    "mov [rax+56],  rdi",
    "mov [rax+64],  r8",
    "mov [rax+72],  r9",
    "mov [rax+80],  r10",
    "mov [rax+88],  r11",
    "mov [rax+96],  r12",
    "mov [rax+104], r13",
    "mov [rax+112], r14",
    "mov [rax+120], r15",
    "pushfq",
    "pop rcx",
    "mov [rax+128], rcx",
    "mov rcx, [rsp]", // saved guest RAX
    "mov [rax+0], rcx",
    "add rsp, 8",  // pop saved RAX
    "add rsp, 24", // pop locals
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
);

unsafe extern "C" {
    fn rax_smir_enter_native(entry: *const u8, state: *mut GuestRegs);
}

/// W^X executable memory holding a finalized lowered block. Maps RW, copies the
/// code in, then flips to RX; unmaps on drop.
pub struct ExecMem {
    ptr: *mut u8,
    len: usize,
}

impl ExecMem {
    /// Map `code` into a fresh W^X region and make it executable.
    pub fn new(code: &[u8]) -> Result<Self, ExecMemError> {
        if code.is_empty() {
            return Err(ExecMemError::Empty);
        }
        let len = (code.len() + 0xFFF) & !0xFFF;
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ExecMemError::Mmap);
        }
        let ptr = ptr as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len()) };
        if unsafe {
            libc::mprotect(ptr as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_EXEC)
        } != 0
        {
            unsafe { libc::munmap(ptr as *mut libc::c_void, len) };
            return Err(ExecMemError::Mprotect);
        }
        Ok(ExecMem { ptr, len })
    }

    /// Execute the block at `entry_offset` (the lowerer's `LowerResult.entry_offset`),
    /// marshalling `regs` in and reading the result back out.
    ///
    /// # Safety
    /// The caller must guarantee that the code was produced by a trusted lowerer
    /// for an identity-register-mapped block that does not require a guest stack
    /// (RSP is not loaded — the block runs on the host stack).
    pub fn run(&self, entry_offset: usize, regs: &mut GuestRegs) {
        let entry = unsafe { self.ptr.add(entry_offset) } as *const u8;
        unsafe { rax_smir_enter_native(entry, regs as *mut GuestRegs) };
    }
}

impl Drop for ExecMem {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

/// Errors mapping/executing a lowered block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMemError {
    /// Empty code buffer.
    Empty,
    /// `mmap` failed.
    Mmap,
    /// `mprotect` to RX failed.
    Mprotect,
}

impl core::fmt::Display for ExecMemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExecMemError::Empty => write!(f, "empty code buffer"),
            ExecMemError::Mmap => write!(f, "mmap failed"),
            ExecMemError::Mprotect => write!(f, "mprotect to RX failed"),
        }
    }
}

impl std::error::Error for ExecMemError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-assembled `mov eax, 0x2a ; ret` — proves ExecMem (W^X map) and the
    // enter_native trampoline marshal a result back out, independent of the
    // lowerer. The lowerer-driven end-to-end paths live in tests/diff_fuzz.rs.
    #[test]
    fn exec_mem_runs_raw_block() {
        let code = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = GuestRegs::default();
        regs.rflags = 0x2;
        mem.run(0, &mut regs);
        assert_eq!(regs.gpr[0], 0x2a, "RAX should be 0x2a");
    }

    // RAX = RBX + RCX, exercising guest-GPR marshal IN as well as OUT.
    //   lea eax,[rbx+rcx] won't preserve 64-bit; use: mov rax,rbx; add rax,rcx; ret
    #[test]
    fn exec_mem_marshals_inputs() {
        // 48 89 D8        mov rax, rbx
        // 48 01 C8        add rax, rcx
        // C3              ret
        let code = [0x48, 0x89, 0xD8, 0x48, 0x01, 0xC8, 0xC3];
        let mem = ExecMem::new(&code).expect("ExecMem map");
        let mut regs = GuestRegs::default();
        regs.gpr[3] = 40; // RBX
        regs.gpr[1] = 2; // RCX
        regs.rflags = 0x2;
        mem.run(0, &mut regs);
        assert_eq!(regs.gpr[0], 42, "RAX should be RBX+RCX");
    }
}
