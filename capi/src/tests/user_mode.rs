//! User-mode execution (`RAX_MODE_USER`, ABI 1.5): system calls, exceptions,
//! and the enforced address space on every user-mode architecture.
use super::*;
use crate::arch::{RAX_MODE_16, RAX_MODE_32, RAX_MODE_ARM, RAX_MODE_USER};
use crate::context::{rax_context_restore, rax_context_save};
use crate::engine::rax_engine_mode;
use crate::fault::*;
use crate::hook::{RAX_HOOK_MEM_WRITE, rax_hook_add_intr, rax_hook_add_mem, rax_hook_add_syscall};
use crate::mem::{RAX_PROT_WRITE, rax_mem_translate};
use crate::run::{RAX_STOP_EXCEPTION, RAX_STOP_SYSCALL, rax_emu_stop, rax_nmi};
use crate::user::*;

const BASE: u64 = 0x10000;
const RODATA: u64 = 0x40000;
const NOEXEC: u64 = 0x41000;

// x86 register ids.
const RBX: i32 = 0x0103;
const R11: i32 = 0x010B;
const RFLAGS: i32 = 0x0012;
const CS: i32 = 0x0601;
// AArch64 / RV64 ids.
const A64_X8: i32 = 0x0108;
const A64_PC: i32 = 0x0011;
const A64_TPIDR_EL0: i32 = 0x0400;
const RV_A0: i32 = 0x010A;
const RV_A7: i32 = 0x0111;

/// A user-mode engine: RWX memory at [`BASE`] (64 KiB), a read-only page at
/// [`RODATA`], and a read/write page without execute at [`NOEXEC`].
struct User(*mut Engine);

impl User {
    fn open(arch: RaxArch, mode: u32) -> Self {
        let cfg = RaxEngineConfig {
            size: std::mem::size_of::<RaxEngineConfig>() as u32,
            arch: arch as i32,
            mode: mode | RAX_MODE_USER,
            backend: crate::arch::RAX_BACKEND_DEFAULT,
            mem_base: BASE,
            mem_size: 0x10000,
            mem_perms: RAX_PROT_ALL,
            flags: 0,
            riscv_ext: 0,
        };
        let mut e = ptr::null_mut();
        assert_eq!(rax_engine_open_config(&cfg, &mut e), RaxStatus::Ok);
        assert_eq!(rax_mem_map(e, RODATA, 0x1000, RAX_PROT_READ), RaxStatus::Ok);
        assert_eq!(
            rax_mem_map(e, NOEXEC, 0x1000, RAX_PROT_READ | RAX_PROT_WRITE),
            RaxStatus::Ok
        );
        User(e)
    }
    fn x86() -> Self {
        Self::open(RaxArch::X86, RAX_MODE_64)
    }
    fn code(&self, bytes: &[u8]) {
        unsafe { write(self.0, BASE, bytes) };
    }
    fn words(&self, insns: &[u32]) {
        let bytes: Vec<u8> = insns.iter().flat_map(|i| i.to_le_bytes()).collect();
        self.code(&bytes);
    }
    fn reg(&self, id: i32) -> u64 {
        unsafe { rd_u64(self.0, id) }
    }
    fn set(&self, id: i32, value: u64) {
        assert_eq!(rax_reg_write_u64(self.0, id, value), RaxStatus::Ok);
    }
    fn pc(&self) -> u64 {
        // RIP, AArch64 PC, and RISC-V PC share id 0x0011 except on x86.
        let arch = crate::engine::rax_engine_arch(self.0);
        self.reg(if arch == RaxArch::X86 as i32 {
            RIP
        } else {
            A64_PC
        })
    }
    fn start(&self, begin: u64) -> RaxStatus {
        rax_emu_start(self.0, begin, RAX_NO_ADDR, 0, 0)
    }
    fn exit(&self) -> ExitInfo {
        let mut x = ExitInfo::none();
        assert_eq!(rax_emu_last_exit(self.0, &mut x), RaxStatus::Ok);
        x
    }
    fn exception(&self) -> RaxExceptionInfo {
        let mut info = RaxExceptionInfo::default();
        assert_eq!(rax_emu_last_exception(self.0, &mut info), RaxStatus::Ok);
        info
    }
    fn fault(&self) -> RaxFaultInfo {
        let mut info = RaxFaultInfo::default();
        assert_eq!(rax_emu_last_fault(self.0, &mut info), RaxStatus::Ok);
        info
    }
}

impl Drop for User {
    fn drop(&mut self) {
        rax_engine_close(self.0);
    }
}

#[test]
fn user_mode_is_validated_and_reported_in_the_mode() {
    for (arch, mode) in [
        (RaxArch::X86, RAX_MODE_64),
        (RaxArch::X86, RAX_MODE_32),
        (RaxArch::Arm64, 0),
        (RaxArch::Riscv64, 0),
    ] {
        let e = User::open(arch, mode);
        assert_ne!(rax_engine_mode(e.0) & RAX_MODE_USER, 0, "{arch:?}");
    }
    for (arch, mode) in [
        (RaxArch::X86, RAX_MODE_16),
        (RaxArch::Arm, RAX_MODE_ARM),
        (RaxArch::Hexagon, 0),
        (RaxArch::CortexM, 0),
    ] {
        let mut e = ptr::null_mut();
        assert_eq!(
            rax_engine_open(arch as i32, mode | RAX_MODE_USER, &mut e),
            RaxStatus::Mode,
            "{arch:?}"
        );
        assert!(e.is_null());
    }
}

#[test]
fn x86_syscall_stops_with_the_instruction_and_resumes_after_it() {
    let e = User::x86();
    // mov eax,1 ; syscall ; mov ebx,eax ; int3
    e.code(&[0xB8, 1, 0, 0, 0, 0x0F, 0x05, 0x89, 0xC3, 0xCC]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let x = e.exit();
    assert_eq!(x.reason, RAX_STOP_SYSCALL);
    assert_eq!(x.address, BASE + 5);
    assert_eq!(x.size, 2);
    assert_eq!(x.port, RAX_SYSCALL_INSN_SYSCALL);
    assert_eq!(x.value, 2, "mov and the completed syscall");
    assert_eq!(e.reg(RIP), BASE + 7);
    // SYSCALL's architectural effects: RCX = return RIP, R11 = RFLAGS.
    assert_eq!(e.reg(RCX), BASE + 7);
    assert_eq!(e.reg(R11), e.reg(RFLAGS));
    // The embedder returns 42 and resumes.
    e.set(RAX, 42);
    assert_eq!(e.start(e.reg(RIP)), RaxStatus::Ok);
    let x = e.exit();
    assert_eq!(x.reason, RAX_STOP_EXCEPTION);
    assert_eq!(x.intno, 3);
    assert_eq!(x.address, BASE + 9);
    assert_eq!(e.reg(RBX), 42);
    // INT3 is a trap: the return address follows it.
    assert_eq!(e.reg(RIP), BASE + 10);
    let info = e.exception();
    assert_eq!(info.vector, 3);
    assert_eq!(info.flags, RAX_EXCEPTION_VALID | RAX_EXCEPTION_SOFTWARE);
    assert_eq!((info.pc, info.return_pc), (BASE + 9, BASE + 10));
}

#[test]
fn x86_step_over_a_system_call_executes_one_instruction() {
    let e = User::x86();
    e.code(&[0x0F, 0x05, 0x90]);
    e.set(RIP, BASE);
    let mut done = 0u64;
    assert_eq!(rax_emu_step(e.0, 1, &mut done), RaxStatus::Ok);
    assert_eq!(done, 1);
    assert_eq!(e.exit().reason, RAX_STOP_SYSCALL);
    assert_eq!(e.reg(RIP), BASE + 2);
}

struct Calls {
    seen: Vec<(u64, u32, u32)>,
}

extern "C" fn serve_syscall(e: *mut Engine, pc: u64, insn: u32, imm: u32, user: *mut c_void) {
    let calls = unsafe { &mut *(user as *mut Calls) };
    calls.seen.push((pc, insn, imm));
    // Return twice the call number in the architecture's result register.
    let arch = crate::engine::rax_engine_arch(e);
    let (nr, ret) = match arch {
        a if a == RaxArch::X86 as i32 => (RAX, RAX),
        a if a == RaxArch::Arm64 as i32 => (A64_X8, ARM64_X0),
        _ => (RV_A7, RV_A0),
    };
    let mut n = 0;
    assert_eq!(rax_reg_read_u64(e, nr, &mut n), RaxStatus::Ok);
    assert_eq!(rax_reg_write_u64(e, ret, n * 2), RaxStatus::Ok);
}

#[test]
fn syscall_hooks_service_calls_on_every_user_architecture() {
    // x86-64: mov eax,21 ; syscall ; mov ebx,eax ; int3
    let e = User::x86();
    e.code(&[0xB8, 21, 0, 0, 0, 0x0F, 0x05, 0x89, 0xC3, 0xCC]);
    let mut calls = Calls { seen: Vec::new() };
    let mut id = 0;
    assert_eq!(
        rax_hook_add_syscall(
            e.0,
            Some(serve_syscall),
            &mut calls as *mut _ as *mut c_void,
            &mut id
        ),
        RaxStatus::Ok
    );
    assert_ne!(id, 0);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.exit().reason, RAX_STOP_EXCEPTION);
    assert_eq!(e.reg(RBX), 42);
    assert_eq!(calls.seen, vec![(BASE + 5, RAX_SYSCALL_INSN_SYSCALL, 0)]);

    // AArch64: movz x8,#64 ; svc #0x80 ; brk #1
    let e = User::open(RaxArch::Arm64, 0);
    e.words(&[0xD280_0808, 0xD400_1001, 0xD420_0020]);
    let mut calls = Calls { seen: Vec::new() };
    assert_eq!(
        rax_hook_add_syscall(
            e.0,
            Some(serve_syscall),
            &mut calls as *mut _ as *mut c_void,
            ptr::null_mut()
        ),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.reg(ARM64_X0), 128);
    assert_eq!(calls.seen, vec![(BASE + 4, RAX_SYSCALL_INSN_SVC, 0x80)]);
    let x = e.exit();
    assert_eq!(
        (x.reason, x.intno, x.address),
        (RAX_STOP_EXCEPTION, 0x3C, BASE + 8)
    );

    // RV64: li a7,93 ; ecall ; ebreak
    let e = User::open(RaxArch::Riscv64, 0);
    e.words(&[0x05D0_0893, 0x0000_0073, 0x0010_0073]);
    let mut calls = Calls { seen: Vec::new() };
    assert_eq!(
        rax_hook_add_syscall(
            e.0,
            Some(serve_syscall),
            &mut calls as *mut _ as *mut c_void,
            ptr::null_mut()
        ),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.reg(RV_A0), 186);
    assert_eq!(calls.seen, vec![(BASE + 4, RAX_SYSCALL_INSN_ECALL, 0)]);
    let x = e.exit();
    assert_eq!(
        (x.reason, x.intno, x.address),
        (RAX_STOP_EXCEPTION, 3, BASE + 8)
    );
}

#[test]
fn syscall_hooks_require_user_mode() {
    let e = open_x86();
    assert_eq!(
        rax_hook_add_syscall(e, Some(serve_syscall), ptr::null_mut(), ptr::null_mut()),
        RaxStatus::Unsupported
    );
    rax_engine_close(e);
}

#[test]
fn arm64_svc_and_rv64_ecall_stop_like_x86_syscall() {
    let e = User::open(RaxArch::Arm64, 0);
    e.words(&[0xD400_1001]); // svc #0x80
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let x = e.exit();
    assert_eq!(x.reason, RAX_STOP_SYSCALL);
    assert_eq!(
        (x.address, x.size, x.port, x.intno),
        (BASE, 4, RAX_SYSCALL_INSN_SVC, 0x80)
    );
    assert_eq!(x.value, 1);
    assert_eq!(e.pc(), BASE + 4);

    let e = User::open(RaxArch::Riscv64, 0);
    e.words(&[0x0000_0073]); // ecall
    let mut done = 0;
    e.set(A64_PC, BASE);
    assert_eq!(rax_emu_step(e.0, 1, &mut done), RaxStatus::Ok);
    assert_eq!(done, 1, "the completed call counts as executed");
    let x = e.exit();
    assert_eq!(x.reason, RAX_STOP_SYSCALL);
    assert_eq!(
        (x.address, x.size, x.port, x.intno),
        (BASE, 4, RAX_SYSCALL_INSN_ECALL, 0)
    );
    assert_eq!(e.pc(), BASE + 4);
}

#[test]
fn exceptions_carry_architectural_vectors_and_syndromes() {
    // x86 HLT at CPL 3 is #GP(0).
    let e = User::x86();
    e.code(&[0xF4]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let x = e.exit();
    assert_eq!(
        (x.reason, x.intno, x.address),
        (RAX_STOP_EXCEPTION, 13, BASE)
    );
    let info = e.exception();
    assert_eq!(info.flags, RAX_EXCEPTION_VALID | RAX_EXCEPTION_SYNDROME);
    assert_eq!((info.syndrome, info.pc, info.return_pc), (0, BASE, BASE));
    assert_eq!(e.reg(RIP), BASE, "a fault does not retire");
    assert_eq!(e.fault().kind, RAX_FAULT_NONE);

    // x86 UD2 is #UD: an invalid instruction for fault diagnostics.
    let e = User::x86();
    e.code(&[0x0F, 0x0B]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.exit().intno, 6);
    assert_eq!(e.exception().flags, RAX_EXCEPTION_VALID);
    let fault = e.fault();
    assert_eq!(
        (fault.kind, fault.pc),
        (RAX_FAULT_INVALID_INSTRUCTION, BASE)
    );

    // AArch64 BRK #0x1234: EC 0x3C with the immediate in the ISS; the PC
    // stays at the BRK (its preferred return address).
    let e = User::open(RaxArch::Arm64, 0);
    e.words(&[0xD422_4680]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let info = e.exception();
    assert_eq!(info.vector, 0x3C);
    assert_eq!(
        info.flags,
        RAX_EXCEPTION_VALID | RAX_EXCEPTION_SYNDROME | RAX_EXCEPTION_SOFTWARE
    );
    assert_eq!(
        (info.syndrome, info.pc, info.return_pc),
        (0x1234, BASE, BASE)
    );
    assert_eq!(e.pc(), BASE);
    assert_eq!(e.fault().kind, RAX_FAULT_NONE);

    // AArch64 UDF: EC 0 (unknown reason), an invalid instruction.
    let e = User::open(RaxArch::Arm64, 0);
    e.words(&[0x0000_0000]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.exit().reason, RAX_STOP_EXCEPTION);
    assert_eq!(e.exception().vector, 0);
    assert_eq!(e.fault().kind, RAX_FAULT_INVALID_INSTRUCTION);

    // RV64 illegal instruction: mcause 2 with the encoding in mtval.
    let e = User::open(RaxArch::Riscv64, 0);
    e.words(&[0xFFFF_FFFF]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let info = e.exception();
    assert_eq!((info.vector, info.pc, info.return_pc), (2, BASE, BASE));
    assert_eq!(info.flags, RAX_EXCEPTION_VALID | RAX_EXCEPTION_SYNDROME);
    assert_eq!(e.fault().kind, RAX_FAULT_INVALID_INSTRUCTION);
}

#[test]
fn exception_query_validates_its_header() {
    let e = User::x86();
    let mut info = RaxExceptionInfo {
        struct_size: 8,
        ..RaxExceptionInfo::default()
    };
    assert_eq!(rax_emu_last_exception(e.0, &mut info), RaxStatus::Arg);
    let mut info = RaxExceptionInfo {
        version: 99,
        ..RaxExceptionInfo::default()
    };
    assert_eq!(
        rax_emu_last_exception(e.0, &mut info),
        RaxStatus::Unsupported
    );
    assert_eq!(info.flags, 0, "output unchanged on failure");
    assert_eq!(rax_emu_last_exception(e.0, ptr::null_mut()), RaxStatus::Arg);
    assert_eq!(
        rax_emu_last_exception(ptr::null(), &mut RaxExceptionInfo::default()),
        RaxStatus::Handle
    );
    // Nothing ran yet: a valid, empty record.
    assert_eq!(e.exception(), RaxExceptionInfo::default());
}

extern "C" fn skip_ud2(e: *mut Engine, intno: u32, user: *mut c_void) {
    let seen = unsafe { &mut *(user as *mut Vec<RaxExceptionInfo>) };
    let mut info = RaxExceptionInfo::default();
    assert_eq!(rax_emu_last_exception(e, &mut info), RaxStatus::Ok);
    assert_eq!(info.vector, intno);
    seen.push(info);
    if intno == 6 {
        // Resume after the two-byte UD2.
        let mut rip = 0;
        assert_eq!(rax_reg_read_u64(e, RIP, &mut rip), RaxStatus::Ok);
        assert_eq!(rip, info.return_pc);
        assert_eq!(rax_reg_write_u64(e, RIP, rip + 2), RaxStatus::Ok);
    } else {
        assert_eq!(rax_emu_stop(e), RaxStatus::Ok);
    }
}

#[test]
fn interrupt_hooks_see_the_return_address_and_may_change_it() {
    let e = User::x86();
    // ud2 ; mov ebx,7 ; int 0x80
    e.code(&[0x0F, 0x0B, 0xBB, 7, 0, 0, 0, 0xCD, 0x80]);
    let mut seen: Vec<RaxExceptionInfo> = Vec::new();
    assert_eq!(
        rax_hook_add_intr(
            e.0,
            Some(skip_ud2),
            &mut seen as *mut _ as *mut c_void,
            ptr::null_mut()
        ),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.exit().reason, crate::run::RAX_STOP_STOPPED);
    assert_eq!(e.reg(RBX), 7);
    assert_eq!(seen.len(), 2);
    assert_eq!(
        (seen[0].vector, seen[0].pc, seen[0].return_pc),
        (6, BASE, BASE)
    );
    // INT 0x80 returns after itself.
    assert_eq!(
        (seen[1].vector, seen[1].pc, seen[1].return_pc),
        (0x80, BASE + 7, BASE + 9)
    );
    assert_eq!(e.reg(RIP), BASE + 9);
}

#[test]
fn x86_compatibility_mode_decodes_32_bit_code() {
    let e = User::open(RaxArch::X86, RAX_MODE_32);
    // mov eax,0x7fffffff ; inc eax (0x40 is a REX prefix in 64-bit mode) ;
    // int 0x80
    e.code(&[0xB8, 0xFF, 0xFF, 0xFF, 0x7F, 0x40, 0xCD, 0x80]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let x = e.exit();
    assert_eq!(
        (x.reason, x.intno, x.address),
        (RAX_STOP_EXCEPTION, 0x80, BASE + 6)
    );
    assert_eq!(e.reg(EAX), 0x8000_0000);
    assert_eq!(e.reg(CS) & 0xFFFF, 0x23, "__USER32_CS");
    assert_eq!(e.reg(RIP), BASE + 8);
    // The same bytes in 64-bit user mode: REX.40 + INT 0x80.
    let e = User::x86();
    e.code(&[0xB8, 0xFF, 0xFF, 0xFF, 0x7F, 0x40, 0xCD, 0x80]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.reg(EAX), 0x7FFF_FFFF);
    assert_eq!(e.reg(CS) & 0xFFFF, 0x33, "__USER_CS");
}

#[test]
fn region_permissions_are_enforced_and_follow_protect() {
    // mov [rbx], eax ; int3
    let e = User::x86();
    e.code(&[0x89, 0x03, 0xCC]);
    e.set(RBX, RODATA + 0x10);
    assert_eq!(e.start(BASE), RaxStatus::Fault);
    let fault = e.fault();
    assert_eq!(fault.kind, RAX_FAULT_PERMISSION);
    assert_eq!(fault.access, RAX_FAULT_ACCESS_WRITE);
    assert_eq!(fault.flags, RAX_FAULT_ADDRESS_VALID);
    assert_eq!(fault.address, RODATA + 0x10);
    assert_eq!(e.reg(RIP), BASE, "the store did not retire");
    // Granting write permission takes effect for the retry.
    assert_eq!(
        rax_mem_protect(e.0, RODATA, 0x1000, RAX_PROT_READ | RAX_PROT_WRITE),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.exit().reason, RAX_STOP_EXCEPTION);

    // Fetching from a page without execute permission.
    let e = User::x86();
    assert_eq!(e.start(NOEXEC), RaxStatus::Fault);
    let fault = e.fault();
    assert_eq!(
        (fault.kind, fault.access, fault.address),
        (RAX_FAULT_PERMISSION, RAX_FAULT_ACCESS_FETCH, NOEXEC)
    );

    // An unmapped load on AArch64 is eligible for fault-in and retry.
    let e = User::open(RaxArch::Arm64, 0);
    e.words(&[0xF940_0020, 0xD400_0001]); // ldr x0, [x1] ; svc #0
    e.set(0x0101, 0x9_0000);
    assert_eq!(e.start(BASE), RaxStatus::Fault);
    let fault = e.fault();
    assert_eq!(
        (fault.kind, fault.access, fault.address),
        (RAX_FAULT_UNMAPPED, RAX_FAULT_ACCESS_READ, 0x9_0000)
    );
    assert_eq!(e.pc(), BASE, "the load did not retire");
    assert_eq!(
        rax_mem_map(e.0, 0x9_0000, 0x1000, RAX_PROT_READ),
        RaxStatus::Ok
    );
    unsafe { write(e.0, 0x9_0000, &0x1122_3344_5566_7788u64.to_le_bytes()) };
    assert_eq!(e.start(e.pc()), RaxStatus::Ok);
    assert_eq!(e.exit().reason, RAX_STOP_SYSCALL);
    assert_eq!(e.reg(ARM64_X0), 0x1122_3344_5566_7788);

    // Virtual translation applies the same permissions (2 = RAX_ACCESS_EXEC).
    let mut pa = 0;
    assert_eq!(rax_mem_translate(e.0, NOEXEC, 2, &mut pa), RaxStatus::Fault);
    assert_eq!(rax_mem_translate(e.0, NOEXEC, 1, &mut pa), RaxStatus::Ok);
    assert_eq!(pa, NOEXEC);
}

#[test]
fn long_runs_are_not_cut_short_by_time_slices() {
    // mov ecx,300000 ; dec ecx ; jnz -4 ; syscall
    let e = User::x86();
    e.code(&[
        0xB9, 0xE0, 0x93, 0x04, 0x00, 0xFF, 0xC9, 0x75, 0xFC, 0x0F, 0x05,
    ]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let x = e.exit();
    assert_eq!(x.reason, RAX_STOP_SYSCALL);
    assert_eq!(
        e.reg(RCX) & 0xFFFF_FFFF,
        BASE + 11,
        "RCX holds the return RIP"
    );
    assert_eq!(x.value, 1 + 2 * 300_000 + 1);
}

#[test]
fn user_mode_rejects_interrupt_injection() {
    let e = User::x86();
    assert_eq!(rax_can_interrupt(e.0), 0);
    assert_eq!(rax_interrupt(e.0, 0x20), RaxStatus::Unsupported);
    assert_eq!(rax_nmi(e.0), RaxStatus::Unsupported);
}

#[test]
fn reset_and_context_restore_keep_the_user_environment() {
    let e = User::x86();
    e.code(&[0x89, 0x03, 0xCC]); // mov [rbx], eax ; int3
    assert_eq!(rax_engine_reset(e.0), RaxStatus::Ok);
    assert_eq!(e.reg(CS) & 0xFFFF, 0x33);

    let mut len = 0;
    assert_eq!(
        rax_context_save(e.0, ptr::null_mut(), 0, &mut len),
        RaxStatus::Ok
    );
    let mut blob = vec![0u8; len];
    assert_eq!(
        rax_context_save(e.0, blob.as_mut_ptr(), blob.len(), &mut len),
        RaxStatus::Ok
    );
    // Restore into a system-mode engine: it becomes a user-mode engine with
    // the saved permissions.
    let restored = open_x86();
    assert_eq!(
        rax_context_restore(restored, blob.as_ptr(), blob.len()),
        RaxStatus::Ok
    );
    assert_ne!(rax_engine_mode(restored) & RAX_MODE_USER, 0);
    assert_eq!(rax_reg_write_u64(restored, RBX, RODATA), RaxStatus::Ok);
    assert_eq!(
        rax_emu_start(restored, BASE, RAX_NO_ADDR, 0, 0),
        RaxStatus::Fault
    );
    let mut fault = RaxFaultInfo::default();
    assert_eq!(rax_emu_last_fault(restored, &mut fault), RaxStatus::Ok);
    assert_eq!((fault.kind, fault.address), (RAX_FAULT_PERMISSION, RODATA));
    rax_engine_close(restored);
}

extern "C" fn count_writes(
    _e: *mut Engine,
    kind: i32,
    addr: u64,
    size: u32,
    value: u64,
    user: *mut c_void,
) {
    let seen = unsafe { &mut *(user as *mut Vec<(i32, u64, u32, u64)>) };
    seen.push((kind, addr, size, value));
}

#[test]
fn memory_hooks_observe_user_mode_accesses() {
    let e = User::x86();
    e.code(&[0x89, 0x03, 0xCC]); // mov [rbx], eax ; int3
    e.set(RAX, 0xDEAD_BEEF);
    e.set(RBX, NOEXEC + 8);
    let mut seen: Vec<(i32, u64, u32, u64)> = Vec::new();
    assert_eq!(
        rax_hook_add_mem(
            e.0,
            RAX_HOOK_MEM_WRITE,
            1,
            0,
            Some(count_writes),
            &mut seen as *mut _ as *mut c_void,
            ptr::null_mut()
        ),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(
        seen,
        vec![(crate::hook::RAX_MEM_WRITE, NOEXEC + 8, 4, 0xDEAD_BEEF)]
    );
}

#[test]
fn arm64_thread_pointer_is_visible_to_el0_code() {
    let e = User::open(RaxArch::Arm64, 0);
    // mrs x0, tpidr_el0 ; svc #0
    e.words(&[0xD53B_D040, 0xD400_0001]);
    e.set(A64_TPIDR_EL0, 0x7FFF_1234_5000);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.exit().reason, RAX_STOP_SYSCALL);
    assert_eq!(e.reg(ARM64_X0), 0x7FFF_1234_5000);
}

#[test]
fn x86_compatibility_mode_sysenter_is_a_system_call() {
    let e = User::open(RaxArch::X86, RAX_MODE_32);
    // mov eax,0xE0 ; sysenter
    e.code(&[0xB8, 0xE0, 0, 0, 0, 0x0F, 0x34]);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let x = e.exit();
    assert_eq!(x.reason, RAX_STOP_SYSCALL);
    assert_eq!(
        (x.address, x.size, x.port, x.intno),
        (BASE + 5, 2, RAX_SYSCALL_INSN_SYSENTER, 0)
    );
    // SYSENTER modifies no register; the resume address follows it.
    assert_eq!(e.reg(RIP), BASE + 7);
    assert_eq!(e.reg(RCX), 0);
    assert_eq!(e.reg(EAX), 0xE0);
}

fn save_context(e: *mut Engine) -> Vec<u8> {
    let mut len = 0;
    assert_eq!(
        rax_context_save(e, ptr::null_mut(), 0, &mut len),
        RaxStatus::Ok
    );
    let mut blob = vec![0u8; len];
    assert_eq!(
        rax_context_save(e, blob.as_mut_ptr(), blob.len(), &mut len),
        RaxStatus::Ok
    );
    blob
}

#[test]
fn arm64_and_rv64_user_contexts_restore_unprivileged() {
    // AArch64: EL0 state, TPIDR_EL0, and the address space survive.
    let e = User::open(RaxArch::Arm64, 0);
    // mrs x0, tpidr_el0 ; str x0, [x1] ; svc #0
    e.words(&[0xD53B_D040, 0xF900_0020, 0xD400_0001]);
    e.set(A64_TPIDR_EL0, 0xABCD);
    e.set(0x0101, RODATA);
    let blob = save_context(e.0);
    let mut r = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::Arm64 as i32, 0, &mut r),
        RaxStatus::Ok
    );
    let r = User(r);
    assert_eq!(
        rax_context_restore(r.0, blob.as_ptr(), blob.len()),
        RaxStatus::Ok
    );
    assert_ne!(rax_engine_mode(r.0) & RAX_MODE_USER, 0);
    assert_eq!(r.reg(0x0012) & 0xF, 0, "PSTATE is EL0t");
    assert_eq!(r.start(BASE), RaxStatus::Fault, "RODATA is still read-only");
    assert_eq!(r.fault().kind, RAX_FAULT_PERMISSION);
    assert_eq!(r.reg(ARM64_X0), 0xABCD);
    r.set(0x0101, NOEXEC);
    assert_eq!(r.start(r.pc()), RaxStatus::Ok);
    assert_eq!(r.exit().reason, RAX_STOP_SYSCALL);

    // RV64: U-mode survives, so ECALL still reaches the embedder.
    let e = User::open(RaxArch::Riscv64, 0);
    e.words(&[0x0000_0073]); // ecall
    let blob = save_context(e.0);
    let r = User(open_riscv_with_ext(0));
    assert_eq!(
        rax_context_restore(r.0, blob.as_ptr(), blob.len()),
        RaxStatus::Ok
    );
    assert_eq!(r.start(BASE), RaxStatus::Ok);
    assert_eq!(r.exit().reason, RAX_STOP_SYSCALL);
}

fn syscall_info(e: &User) -> RaxSyscallInfo {
    let mut info = RaxSyscallInfo::default();
    assert_eq!(rax_emu_last_syscall(e.0, &mut info), RaxStatus::Ok);
    info
}

#[test]
fn syscall_record_covers_architectures_and_lifecycle() {
    for (arch, mode, bytes, instruction, immediate) in [
        (
            RaxArch::X86,
            RAX_MODE_64,
            vec![0x0f, 0x05],
            RAX_SYSCALL_INSN_SYSCALL,
            0,
        ),
        (
            RaxArch::X86,
            RAX_MODE_32,
            vec![0x0f, 0x34],
            RAX_SYSCALL_INSN_SYSENTER,
            0,
        ),
        (
            RaxArch::Arm64,
            0,
            0xd4001001u32.to_le_bytes().to_vec(),
            RAX_SYSCALL_INSN_SVC,
            0x80,
        ),
        (
            RaxArch::Riscv64,
            0,
            0x00000073u32.to_le_bytes().to_vec(),
            RAX_SYSCALL_INSN_ECALL,
            0,
        ),
    ] {
        let e = User::open(arch, mode);
        assert_eq!(syscall_info(&e), RaxSyscallInfo::default());
        e.code(&bytes);
        let context = save_context(e.0);
        assert_eq!(e.start(BASE), RaxStatus::Ok);
        let info = syscall_info(&e);
        assert_eq!(
            (info.flags, info.instruction, info.immediate),
            (RAX_SYSCALL_VALID, instruction, immediate)
        );
        assert_eq!(
            (info.pc, info.resume_pc, info.size),
            (BASE, BASE + bytes.len() as u64, bytes.len() as u32)
        );
        assert_eq!(
            rax_context_restore(e.0, context.as_ptr(), context.len()),
            RaxStatus::Ok
        );
        assert_eq!(syscall_info(&e), RaxSyscallInfo::default());
        assert_eq!(e.start(BASE), RaxStatus::Ok);
        assert_eq!(rax_engine_reset(e.0), RaxStatus::Ok);
        assert_eq!(syscall_info(&e), RaxSyscallInfo::default());
    }
}

extern "C" fn redirect_syscall(e: *mut Engine, pc: u64, _: u32, _: u32, user: *mut c_void) {
    let mut info = RaxSyscallInfo::default();
    assert_eq!(rax_emu_last_syscall(e, &mut info), RaxStatus::Ok);
    unsafe {
        *(user as *mut RaxSyscallInfo) = info;
    }
    assert_eq!(rax_reg_write_u64(e, RIP, pc + 3), RaxStatus::Ok);
    assert_eq!(rax_emu_stop(e), RaxStatus::Ok);
}

#[test]
fn syscall_record_survives_hook_redirect_and_clears_on_next_run() {
    let e = User::x86();
    e.code(&[0x0f, 0x05, 0x90, 0xcc]);
    let mut observed = RaxSyscallInfo::default();
    assert_eq!(
        rax_hook_add_syscall(
            e.0,
            Some(redirect_syscall),
            &mut observed as *mut _ as *mut c_void,
            ptr::null_mut()
        ),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(observed.resume_pc, BASE + 2);
    assert_eq!(syscall_info(&e), observed);
    assert_eq!(e.pc(), BASE + 3);
    assert_eq!(e.start(BASE + 3), RaxStatus::Ok);
    assert_eq!(syscall_info(&e), RaxSyscallInfo::default());
}

#[test]
fn syscall_query_validates_header_and_preserves_tail() {
    let e = User::x86();
    assert_eq!(rax_emu_last_syscall(e.0, ptr::null_mut()), RaxStatus::Arg);
    assert_eq!(
        rax_emu_last_syscall(ptr::null(), &mut RaxSyscallInfo::default()),
        RaxStatus::Handle
    );
    for (size, version, status) in [(8, 1, RaxStatus::Arg), (40, 99, RaxStatus::Unsupported)] {
        let mut info = RaxSyscallInfo {
            struct_size: size,
            version,
            ..Default::default()
        };
        let before = info;
        assert_eq!(rax_emu_last_syscall(e.0, &mut info), status);
        assert_eq!(info, before);
    }
    #[repr(C)]
    struct Extended {
        info: RaxSyscallInfo,
        tail: [u8; 16],
    }
    let mut out = Extended {
        info: RaxSyscallInfo {
            struct_size: 56,
            ..Default::default()
        },
        tail: [0xa5; 16],
    };
    assert_eq!(rax_emu_last_syscall(e.0, &mut out.info), RaxStatus::Ok);
    assert_eq!(out.info, RaxSyscallInfo::default());
    assert_eq!(out.tail, [0xa5; 16]);
}
