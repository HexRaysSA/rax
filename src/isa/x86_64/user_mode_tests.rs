//! User-mode execution contract tests for the x86-64 software CPU.
//!
//! Expected values come from the Intel SDM (SYSCALL/SYSRET operation in Vol.
//! 2B, exception classes in Vol. 3A §6.15, canonical addressing in Vol. 1
//! §3.3.7.1) and from the Linux x86-64 user register conventions, not from
//! the implementation under test. Instruction bytes were produced with
//! `llvm-mc -triple=x86_64 -x86-asm-syntax=intel -show-encoding`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::X86_64Vcpu;
use super::user_mode::{X86EventSource, X86SyscallInsn, X86UserEvent, X86UserTrap};
use crate::error::{Error, GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::{VCpu, VcpuExit};

const R: u8 = 1;
const W: u8 = 2;
const X: u8 = 4;

/// A page-granular test translation: linear page -> (frame, permissions).
#[derive(Default)]
struct TestSpace {
    pages: Mutex<BTreeMap<u64, (u64, u8)>>,
}

impl TestSpace {
    fn map(&self, linear: u64, frame: u64, perms: u8) {
        self.pages
            .lock()
            .unwrap()
            .insert(linear & !0xFFF, (frame, perms));
    }
}

impl FlatTranslation for TestSpace {
    fn translate(&self, linear: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        let pages = self.pages.lock().unwrap();
        let Some(&(frame, perms)) = pages.get(&(linear & !0xFFF)) else {
            return Err(GuestMemoryFault::unmapped(linear, 1, access));
        };
        let need = match access {
            MemoryAccessKind::Read => R,
            MemoryAccessKind::Write => W,
            MemoryAccessKind::Fetch => X,
        };
        if perms & need == 0 {
            return Err(GuestMemoryFault {
                address: linear,
                size: 1,
                access,
                kind: MemoryFaultKind::Permission,
            });
        }
        Ok(frame | (linear & 0xFFF))
    }
}

const CODE: u64 = 0x40_0000;
const DATA: u64 = 0x60_0000;
const RODATA: u64 = 0x61_0000;
const STACK: u64 = 0x7fff_f000;

struct Harness {
    vcpu: X86_64Vcpu,
    mem: Arc<GuestMemoryMmap>,
    space: Arc<TestSpace>,
}

/// Frames: 0x0000 code, 0x1000 data, 0x2000 rodata, 0x3000 stack, 0x4000 spare.
fn harness(code: &[u8]) -> Harness {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    mem.write_slice(code, GuestAddress(0)).unwrap();
    let space = Arc::new(TestSpace::default());
    space.map(CODE, 0x0000, R | X);
    space.map(DATA, 0x1000, R | W);
    space.map(RODATA, 0x2000, R);
    space.map(STACK, 0x3000, R | W);
    let mut vcpu = X86_64Vcpu::new(0, mem.clone());
    vcpu.enable_user_mode(space.clone());
    vcpu.regs.rip = CODE;
    vcpu.regs.rsp = STACK + 0xF00;
    Harness { vcpu, mem, space }
}

/// `run()` also returns `Hlt` at ~1 ms time-slice boundaries without the
/// halted state; resume until a real exit or error.
fn run(vcpu: &mut X86_64Vcpu) -> crate::error::Result<VcpuExit> {
    loop {
        match vcpu.run() {
            Ok(VcpuExit::Hlt) if !vcpu.halted => continue,
            other => return other,
        }
    }
}

fn event(h: &mut Harness) -> X86UserEvent {
    match h.vcpu.take_user_trap() {
        Some(X86UserTrap::Event(e)) => e,
        other => panic!("expected an event trap, got {other:?}"),
    }
}

fn run_event(h: &mut Harness) -> X86UserEvent {
    match run(&mut h.vcpu) {
        Err(Error::GuestEvent { vector }) => {
            let e = event(h);
            assert_eq!(e.vector, vector);
            e
        }
        other => panic!("expected a guest event, got {other:?}"),
    }
}

#[test]
fn user_mode_installs_linux_ring3_state() {
    let h = harness(&[0xF4]);
    let s = &h.vcpu.sregs;
    assert_eq!(s.cs.selector, 0x33);
    assert_eq!(s.ss.selector, 0x2b);
    assert!(s.cs.l && !s.cs.db);
    assert_eq!(s.cs.selector & 3, 3, "user code runs at CPL 3");
    assert_eq!(
        s.cr0 & (1 << 31),
        0,
        "paging is replaced by the flat translation"
    );
    assert_ne!(s.efer & 1, 0, "EFER.SCE enables SYSCALL");
    assert_eq!(h.vcpu.user_rflags(), 0x202);
    assert_eq!(h.vcpu.mxcsr(), 0x1F80);
    assert_eq!(h.vcpu.xcr0(), 0xE7);
    assert!(h.vcpu.user_mode_enabled());
}

#[test]
fn syscall_exits_with_sysret_equivalent_state() {
    // mov eax, 60 ; syscall
    let mut h = harness(&[0xB8, 0x3C, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    // CF | ZF | TF-free flags plus RF (bit 16), which SYSRET's mask clears.
    h.vcpu.set_user_rflags(0x202 | 0x41 | (1 << 16));
    let exit = run(&mut h.vcpu).expect("syscall exit");
    assert!(matches!(exit, VcpuExit::SystemCall));
    assert_eq!(
        h.vcpu.take_user_trap(),
        Some(X86UserTrap::SystemCall {
            insn: X86SyscallInsn::Syscall,
            insn_rip: CODE + 5
        })
    );
    let regs = h.vcpu.user_regs();
    assert_eq!(regs.rax, 60);
    assert_eq!(regs.rip, CODE + 7, "RIP = return address");
    assert_eq!(regs.rcx, CODE + 7, "SYSCALL saves the return RIP in RCX");
    assert_eq!(
        regs.r11,
        0x202 | 0x41 | (1 << 16),
        "SYSCALL saves RFLAGS in R11"
    );
    // SYSRET loads RFLAGS from R11 & 0x3C7FD7 | 2 (SDM Vol. 2B SYSRET).
    assert_eq!(h.vcpu.user_rflags(), (0x202 | 0x41) & 0x3C7FD7 | 2);
    assert_eq!(h.vcpu.sregs.cs.selector, 0x33, "CS stays the user selector");
    assert_eq!(h.vcpu.take_user_trap(), None, "trap is consumed once");
}

#[test]
fn sysenter_exits_without_register_effects() {
    let mut h = harness(&[0x0F, 0x34]);
    h.vcpu.regs.rcx = 0x1111;
    h.vcpu.regs.rsp = STACK + 0x800;
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(
        h.vcpu.take_user_trap(),
        Some(X86UserTrap::SystemCall {
            insn: X86SyscallInsn::Sysenter,
            insn_rip: CODE
        })
    );
    assert_eq!(h.vcpu.regs.rip, CODE + 2);
    assert_eq!(h.vcpu.regs.rcx, 0x1111);
    assert_eq!(h.vcpu.regs.rsp, STACK + 0x800);
}

#[test]
fn int3_reports_trap_with_following_return_rip() {
    let mut h = harness(&[0xCC]);
    let e = run_event(&mut h);
    assert_eq!(
        e,
        X86UserEvent {
            vector: 3,
            error_code: None,
            source: X86EventSource::SoftwareInterrupt,
            insn_rip: CODE,
            return_rip: CODE + 1,
        }
    );
    assert_eq!(
        h.vcpu.regs.rip, CODE,
        "the reporting instruction did not retire"
    );
}

#[test]
fn int_0x80_reports_software_interrupt() {
    let mut h = harness(&[0xB8, 0x14, 0, 0, 0, 0xCD, 0x80]);
    let e = run_event(&mut h);
    assert_eq!(e.vector, 0x80);
    assert_eq!(e.source, X86EventSource::SoftwareInterrupt);
    assert_eq!((e.insn_rip, e.return_rip), (CODE + 5, CODE + 7));
    assert_eq!(h.vcpu.regs.rax, 0x14, "instructions before the INT retired");
}

#[test]
fn ud2_reports_invalid_opcode_fault() {
    let mut h = harness(&[0x0F, 0x0B]);
    let e = run_event(&mut h);
    assert_eq!(
        (e.vector, e.source, e.insn_rip, e.return_rip),
        (6, X86EventSource::Exception, CODE, CODE)
    );
}

#[test]
fn divide_error_is_a_fault_at_the_div() {
    // xor ecx, ecx is not needed: RCX starts at zero. div rcx
    let mut h = harness(&[0x48, 0xF7, 0xF1]);
    h.vcpu.regs.rax = 7;
    let e = run_event(&mut h);
    assert_eq!((e.vector, e.error_code, e.return_rip), (0, None, CODE));
    assert_eq!(h.vcpu.regs.rax, 7, "#DE leaves operands unchanged");
}

#[test]
fn privileged_instructions_raise_gp0_at_cpl3() {
    for code in [
        &[0xF4][..],             // hlt
        &[0x0F, 0x20, 0xD8][..], // mov rax, cr3
        &[0xFA][..],             // cli with IOPL 0
        &[0x0F, 0x30][..],       // wrmsr
        &[0x0F, 0x07][..],       // sysret
    ] {
        let mut h = harness(code);
        let e = run_event(&mut h);
        assert_eq!(
            (e.vector, e.error_code, e.return_rip),
            (13, Some(0), CODE),
            "{code:02x?}"
        );
    }
}

#[test]
fn non_canonical_access_raises_gp0_not_a_page_fault() {
    // movabs rax, 0x0000800000000000 ; mov rcx, [rax]
    let mut h = harness(&[0x48, 0xB8, 0, 0, 0, 0, 0, 0x80, 0, 0, 0x48, 0x8B, 0x08]);
    let e = run_event(&mut h);
    assert_eq!((e.vector, e.error_code), (13, Some(0)));
    assert_eq!(e.insn_rip, CODE + 10);
}

#[test]
fn permission_faults_are_precise() {
    // mov [rbx], rax with RBX in a read-only page.
    let mut h = harness(&[0x48, 0x89, 0x03]);
    h.vcpu.regs.rbx = RODATA + 8;
    h.vcpu.regs.rax = 0xdead_beef;
    match run(&mut h.vcpu) {
        Err(Error::GuestAccess(f)) => {
            assert_eq!(f.address, RODATA + 8);
            assert_eq!(f.access, MemoryAccessKind::Write);
            assert_eq!(f.kind, MemoryFaultKind::Permission);
        }
        other => panic!("expected a write permission fault, got {other:?}"),
    }
    assert_eq!(h.vcpu.regs.rip, CODE);
    let mut b = [0u8; 8];
    h.mem.read_slice(&mut b, GuestAddress(0x2008)).unwrap();
    assert_eq!(b, [0; 8], "a faulting store commits nothing");
    assert_eq!(h.vcpu.take_user_trap(), None);
}

#[test]
fn page_crossing_store_into_readonly_page_commits_nothing() {
    // mov [rbx], rax straddling DATA's last bytes and an unmapped page.
    let mut h = harness(&[0x48, 0x89, 0x03]);
    h.vcpu.regs.rbx = DATA + 0xFFC;
    h.vcpu.regs.rax = u64::MAX;
    match run(&mut h.vcpu) {
        Err(Error::GuestAccess(f)) => {
            assert_eq!(f.address, DATA + 0x1000);
            assert_eq!(f.kind, MemoryFaultKind::Unmapped);
        }
        other => panic!("expected an unmapped fault, got {other:?}"),
    }
    let mut b = [0u8; 4];
    h.mem.read_slice(&mut b, GuestAddress(0x1FFC)).unwrap();
    assert_eq!(b, [0; 4]);
}

#[test]
fn fetch_requires_execute_permission() {
    let mut h = harness(&[0x90]);
    h.mem.write_slice(&[0x90], GuestAddress(0x1000)).unwrap();
    h.vcpu.regs.rip = DATA;
    match run(&mut h.vcpu) {
        Err(Error::GuestAccess(f)) => {
            assert_eq!(f.address, DATA);
            assert_eq!(f.access, MemoryAccessKind::Fetch);
            assert_eq!(f.kind, MemoryFaultKind::Permission);
        }
        other => panic!("expected a fetch permission fault, got {other:?}"),
    }
    // Readable-but-not-executable data remains readable as data.
    h.vcpu.regs.rip = CODE + 1;
    h.mem
        .write_slice(&[0x48, 0x8B, 0x03, 0x0F, 0x05], GuestAddress(1))
        .unwrap();
    h.vcpu.regs.rbx = DATA;
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(h.vcpu.regs.rax & 0xFF, 0x90);
}

#[test]
fn fetch_fault_reports_first_inaccessible_byte() {
    // A 2-byte instruction whose second byte lies in an unmapped page.
    let mut h = harness(&[]);
    h.mem.write_slice(&[0x0F], GuestAddress(0xFFF)).unwrap();
    h.vcpu.regs.rip = CODE + 0xFFF;
    match run(&mut h.vcpu) {
        Err(Error::GuestAccess(f)) => {
            assert_eq!(f.address, CODE + 0x1000);
            assert_eq!(f.access, MemoryAccessKind::Fetch);
        }
        other => panic!("expected a fetch fault, got {other:?}"),
    }
    assert_eq!(h.vcpu.regs.rip, CODE + 0xFFF);
}

#[test]
fn fs_base_addresses_thread_local_storage() {
    // mov rax, fs:[0] ; wrfsbase rdi ; rdfsbase rdx ; syscall
    let mut h = harness(&[
        0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0, 0xF3, 0x48, 0x0F, 0xAE, 0xD7, 0xF3, 0x48, 0x0F,
        0xAE, 0xC2, 0x0F, 0x05,
    ]);
    h.mem
        .write_slice(
            &0x1234_5678_9abc_def0u64.to_le_bytes(),
            GuestAddress(0x1100),
        )
        .unwrap();
    h.vcpu.set_fs_base(DATA + 0x100);
    h.vcpu.regs.rdi = 0x7000_0000;
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(h.vcpu.regs.rax, 0x1234_5678_9abc_def0);
    assert_eq!(h.vcpu.fs_base(), 0x7000_0000);
    assert_eq!(h.vcpu.regs.rdx, 0x7000_0000);
}

#[test]
fn xgetbv_and_avx_are_available_as_under_linux() {
    // xgetbv ; vaddps ymm0, ymm1, ymm2 ; syscall
    let mut h = harness(&[0x0F, 0x01, 0xD0, 0xC5, 0xF4, 0x58, 0xC2, 0x0F, 0x05]);
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(h.vcpu.regs.rax, 0xE7);
    assert_eq!(h.vcpu.regs.rdx, 0);
}

#[test]
fn set_xcr0_applies_xsetbv_rules() {
    let mut h = harness(&[]);
    assert!(h.vcpu.set_xcr0(0).is_err(), "x87 must stay enabled");
    assert!(h.vcpu.set_xcr0(0b101).is_err(), "AVX requires SSE");
    assert!(
        h.vcpu.set_xcr0(0x27).is_err(),
        "AVX-512 state is all-or-none"
    );
    h.vcpu.set_xcr0(0x3).unwrap();
    assert_eq!(h.vcpu.xcr0(), 0x3);
    assert!(h.vcpu.set_mxcsr(1 << 16).is_err());
    h.vcpu.set_mxcsr(0x9FC0).unwrap();
    assert_eq!(h.vcpu.mxcsr(), 0x9FC0);
}

#[test]
fn cpuid_reflects_the_user_mode_xcr0() {
    // CPUID.(EAX=0DH,ECX=0):EBX is the standard-format XSAVE size for the
    // features enabled in XCR0: legacy area (512) + header (64) = 576; AVX
    // state at 576 (+256) ends at 832; opmask at 1088 (+64), ZMM_Hi256 at
    // 1152 (+512), and Hi16_ZMM at 1664 (+1024) end at 2688.
    let mut h = harness(&[]);
    assert_eq!(h.vcpu.cpuid(0xD, 0).1, 2688);
    h.vcpu.set_xcr0(0x7).unwrap();
    assert_eq!(h.vcpu.cpuid(0xD, 0).1, 832);
    h.vcpu.set_xcr0(0x3).unwrap();
    assert_eq!(h.vcpu.cpuid(0xD, 0).1, 576);
    // CPUID.01H:ECX.OSXSAVE[27] mirrors CR4.OSXSAVE, which user mode sets.
    assert_ne!(h.vcpu.cpuid(1, 0).2 & (1 << 27), 0);
}

#[test]
fn host_code_patch_takes_effect_after_invalidation() {
    // loop: add eax, 1 ; dec ecx ; jnz loop ; syscall
    let code = [0x83, 0xC0, 0x01, 0xFF, 0xC9, 0x75, 0xF9, 0x0F, 0x05];
    let mut h = harness(&code);
    h.vcpu.regs.rcx = 10_000; // hot enough for JIT promotion where available
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(h.vcpu.regs.rax, 10_000);
    // On an x86-64 host the loop is compiled, so the patch below is only
    // observed if the invalidation discards native code as well as decodes.
    #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
    if std::env::var_os("RAX_NO_JIT").is_none() {
        assert!(h.vcpu.jit_region_count() > 0, "loop was not JIT-compiled");
    }

    // Patch `add eax, 1` to `add eax, 2` behind the vCPU's back.
    h.mem.write_slice(&[0x02], GuestAddress(2)).unwrap();
    h.vcpu.invalidate_code_range(CODE, 9);
    h.vcpu.regs.rip = CODE;
    h.vcpu.regs.rax = 0;
    h.vcpu.regs.rcx = 10_000;
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(h.vcpu.regs.rax, 20_000);
}

#[test]
fn remapping_the_translation_is_observed_immediately() {
    // mov rax, [rbx] ; syscall -- executed twice with the data page remapped.
    let mut h = harness(&[0x48, 0x8B, 0x03, 0x0F, 0x05]);
    h.mem.write_slice(&[1u8], GuestAddress(0x1000)).unwrap();
    h.mem.write_slice(&[2u8], GuestAddress(0x4000)).unwrap();
    h.vcpu.regs.rbx = DATA;
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(h.vcpu.regs.rax, 1);
    h.space.map(DATA, 0x4000, R);
    h.vcpu.regs.rip = CODE;
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    assert_eq!(h.vcpu.regs.rax, 2);
}

#[test]
fn step_insn_reports_events_like_run() {
    let mut h = harness(&[0x90, 0xCC]);
    assert!(h.vcpu.step_insn().unwrap().is_none());
    match h.vcpu.step_insn() {
        Err(Error::GuestEvent { vector: 3 }) => {}
        other => panic!("expected #BP report, got {other:?}"),
    }
    assert_eq!(event(&mut h).return_rip, CODE + 2);
}

#[test]
fn system_emulation_is_unaffected_without_user_mode() {
    // Without user mode SYSCALL follows LSTAR and HLT exits at any CPL.
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    mem.write_slice(&[0x0F, 0x05], GuestAddress(0)).unwrap();
    mem.write_slice(&[0xF4], GuestAddress(0x2000)).unwrap();
    let mut vcpu = X86_64Vcpu::new(0, mem);
    vcpu.sregs.cr0 = 0x0001_0033;
    vcpu.sregs.efer = 1 | (1 << 8) | (1 << 10);
    vcpu.sregs.cs.l = true;
    vcpu.sregs.lstar = 0x2000;
    assert!(!vcpu.user_mode_enabled());
    assert!(matches!(run(&mut vcpu).unwrap(), VcpuExit::Hlt));
    assert_eq!(vcpu.regs.rip, 0x2001);
    assert_eq!(vcpu.regs.rcx, 2);
    assert_eq!(vcpu.take_user_trap(), None);
}
