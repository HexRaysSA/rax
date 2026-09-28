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

/// The complete x87 image must not change when an operand fault prevents the
/// instruction from retiring, including physical binary80 stack payloads.
fn x87_image(vcpu: &X86_64Vcpu) -> (u16, u16, u16, u64, u64, u16, [[u8; 10]; 8], u8) {
    let f = &vcpu.fpu;
    (
        f.control_word,
        f.status_word,
        f.tag_word,
        f.data_ptr,
        f.instr_ptr,
        f.last_opcode,
        f.st,
        f.top,
    )
}

fn assert_x87_exception(h: &mut Harness, vector: u8, error_code: Option<u64>) {
    let before = x87_image(&h.vcpu);
    let flags = h.vcpu.user_rflags();
    let e = run_event(h);
    assert_eq!(
        (e.vector, e.error_code, e.source, e.insn_rip, e.return_rip),
        (vector, error_code, X86EventSource::Exception, CODE, CODE,)
    );
    assert_eq!(h.vcpu.regs.rip, CODE);
    assert_eq!(h.vcpu.user_rflags(), flags);
    assert_eq!(x87_image(&h.vcpu), before, "fault committed x87 state");
}

#[test]
fn x87_noncanonical_fault_class_tracks_effective_segment() {
    // Intel SDM Vol. 1 §3.3.7.1: stack-base registers default to SS; only
    // FS/GS overrides change that choice in 64-bit mode. SS:[RAX] remains a
    // non-SS access. R12 requires SIB+REX.B; R13 requires disp8=0 because
    // mod=00/rm=101 is RIP-relative even with REX.B.
    const BAD: u64 = 0x0000_8000_0000_0000;
    for (name, code, vector) in [
        ("FLDCW [RBP]", &[0xD9, 0x6D, 0x00][..], 12),
        ("FLDCW [R12]", &[0x41, 0xD9, 0x2C, 0x24][..], 12),
        ("FLDCW [R13]", &[0x41, 0xD9, 0x6D, 0x00][..], 12),
        ("FNSTCW [RBP]", &[0xD9, 0x7D, 0x00][..], 12),
        ("SS:FLDCW [RAX]", &[0x36, 0xD9, 0x28][..], 13),
        ("DS:FLDCW [RBP]", &[0x3E, 0xD9, 0x6D, 0x00][..], 12),
        ("FS:FLDCW [RBP]", &[0x64, 0xD9, 0x6D, 0x00][..], 13),
    ] {
        let mut h = harness(code);
        h.vcpu.regs.rbp = BAD;
        h.vcpu.regs.rax = BAD;
        h.vcpu.regs.r12 = BAD;
        h.vcpu.regs.r13 = BAD;
        let before = x87_image(&h.vcpu);
        let e = run_event(&mut h);
        assert_eq!(
            (e.vector, e.error_code, e.source, e.insn_rip, e.return_rip),
            (vector, Some(0), X86EventSource::Exception, CODE, CODE),
            "{name}"
        );
        assert_eq!(h.vcpu.regs.rip, CODE, "{name} retired");
        assert_eq!(x87_image(&h.vcpu), before, "{name} committed state");
    }
}

#[test]
fn x87_noncanonical_tail_of_two_and_ten_byte_operands_is_ss0() {
    // First byte(s) reside in a mapped canonical page; the last byte lies in
    // the noncanonical hole. Classification must cover the whole operand.
    const LAST_CANONICAL: u64 = 0x0000_7FFF_FFFF_FFFF;
    let first_page = LAST_CANONICAL & !0xFFF;
    let mut h = harness(&[0xD9, 0x6D, 0x00]); // FLDCW m16 [RBP]
    h.space.map(first_page, 0x4000, R);
    h.mem.write_slice(&[0x7F], GuestAddress(0x4FFF)).unwrap();
    h.vcpu.regs.rbp = LAST_CANONICAL;
    assert_x87_exception(&mut h, 12, Some(0));
    let mut first_byte = [0; 1];
    h.mem
        .read_slice(&mut first_byte, GuestAddress(0x4FFF))
        .unwrap();
    assert_eq!(first_byte, [0x7F]);

    let mut h = harness(&[0xDB, 0x7D, 0x00]); // FSTP m80 [RBP]
    h.space.map(first_page, 0x4000, R | W);
    h.mem.write_slice(&[0xA5; 8], GuestAddress(0x4FF8)).unwrap();
    h.vcpu.fpu.push(1.5);
    h.vcpu.regs.rbp = LAST_CANONICAL - 7; // 10-byte operand crosses at byte 8.
    assert_x87_exception(&mut h, 12, Some(0));
    let mut prefix = [0; 8];
    h.mem.read_slice(&mut prefix, GuestAddress(0x4FF8)).unwrap();
    assert_eq!(prefix, [0xA5; 8], "faulting FSTP made a partial store");
}

#[test]
fn x87_control_images_crossing_noncanonical_tail_are_ss0_and_noncommitting() {
    // Intel SDM Vol. 1 §8.1.10: the operand-size attribute selects 14/28 B
    // environment and 94/108 B saved-state images. In 64-bit code, 66h
    // selects the shorter image. Keep this separate from 16-bit-code rules.
    const LAST_CANONICAL: u64 = 0x0000_7FFF_FFFF_FFFF;
    for (name, code, width) in [
        ("FNSTENV m28", &[0xD9, 0x75, 0x00][..], 28usize),
        ("66 FNSTENV m14", &[0x66, 0xD9, 0x75, 0x00][..], 14),
        ("FNSAVE m108", &[0xDD, 0x75, 0x00][..], 108),
        ("66 FNSAVE m94", &[0x66, 0xDD, 0x75, 0x00][..], 94),
    ] {
        let mut h = harness(code);
        h.space.map(LAST_CANONICAL & !0xFFF, 0x4000, R | W);
        let start = LAST_CANONICAL - (width as u64 - 2);
        let physical_start = 0x4000 | (start & 0xFFF);
        let original = vec![0xA5; width - 1];
        h.mem
            .write_slice(&original, GuestAddress(physical_start))
            .unwrap();
        h.vcpu.fpu.push(1.5);
        h.vcpu.fpu.control_word = 0x037E;
        h.vcpu.regs.rbp = start;
        let before = x87_image(&h.vcpu);
        let e = run_event(&mut h);
        assert_eq!(
            (e.vector, e.error_code, e.source, e.insn_rip, e.return_rip),
            (12, Some(0), X86EventSource::Exception, CODE, CODE),
            "{name}"
        );
        assert_eq!(h.vcpu.regs.rip, CODE, "{name} retired");
        assert_eq!(x87_image(&h.vcpu), before, "{name} changed x87 state");
        let mut after = vec![0; width - 1];
        h.mem
            .read_slice(&mut after, GuestAddress(physical_start))
            .unwrap();
        assert_eq!(after, original, "{name} made a partial store");
    }
}

#[test]
fn x87_control_image_66_prefix_selects_shorter_store_width() {
    // At the end of a mapped page the 14/94 B image fits, while its 28/108 B
    // counterpart crosses into an unmapped (but canonical) page. This
    // distinguishes the actual transfer width, not merely the opcode label.
    for (name, opcode, short_width) in [("FNSTENV", 0xD9, 14usize), ("FNSAVE", 0xDD, 94)] {
        let address = DATA + 0x1000 - short_width as u64;
        let frame = 0x1000 + 0x1000 - short_width as u64;
        let original = vec![0xA5; short_width];

        let mut short = harness(&[0x66, opcode, 0x75, 0x00]);
        short.vcpu.regs.rbp = address;
        short.vcpu.fpu.push(1.5);
        short.vcpu.fpu.control_word = 0x037E;
        short
            .mem
            .write_slice(&original, GuestAddress(frame))
            .unwrap();
        assert!(
            short.vcpu.step().unwrap().is_none(),
            "{name} m{short_width}"
        );
        assert_eq!(short.vcpu.regs.rip, CODE + 4, "{name} m{short_width}");
        let mut stored = vec![0; short_width];
        short
            .mem
            .read_slice(&mut stored, GuestAddress(frame))
            .unwrap();
        assert_ne!(stored, original, "{name} m{short_width} stored nothing");

        let mut long = harness(&[opcode, 0x75, 0x00]);
        long.vcpu.regs.rbp = address;
        long.vcpu.fpu.push(1.5);
        long.vcpu.fpu.control_word = 0x037E;
        long.mem
            .write_slice(&original, GuestAddress(frame))
            .unwrap();
        let before = x87_image(&long.vcpu);
        match run(&mut long.vcpu) {
            Err(Error::GuestAccess(fault)) => {
                assert_eq!(fault.address, DATA + 0x1000, "{name} long image");
                assert_eq!(fault.access, MemoryAccessKind::Write, "{name}");
                assert_eq!(fault.kind, MemoryFaultKind::Unmapped, "{name}");
            }
            other => panic!("{name} long image should cross the page: {other:?}"),
        }
        assert_eq!(long.vcpu.regs.rip, CODE, "{name} long image retired");
        assert_eq!(x87_image(&long.vcpu), before, "{name} changed x87 state");
        let mut after = vec![0; short_width];
        long.mem
            .read_slice(&mut after, GuestAddress(frame))
            .unwrap();
        assert_eq!(after, original, "{name} made a partial long store");
    }
}

#[test]
fn x87_nm_and_mf_take_priority_over_noncanonical_ss_operand() {
    // Waiting FLDCW checks device availability, then pending x87 error,
    // before the memory operand. CR0.NE is enabled by the user-mode harness.
    for (name, unavailable, vector) in [
        ("CR0.TS", 1 << 3, 7),
        ("CR0.EM", 1 << 2, 7),
        ("pending #MF", 0, 16),
    ] {
        let mut h = harness(&[0xD9, 0x6D, 0x00]); // FLDCW m16 [RBP]
        h.vcpu.regs.rbp = 0x0000_8000_0000_0000;
        h.vcpu.sregs.cr0 |= unavailable;
        h.vcpu.fpu.control_word &= !1; // unmask invalid operation
        h.vcpu.fpu.status_word |= 0x8081; // IE | ES | B: pending unmasked error
        assert_x87_exception(&mut h, vector, None);
        assert_eq!(h.vcpu.regs.rbp, 0x0000_8000_0000_0000, "{name}");
    }
}

#[test]
fn x87_canonical_unmapped_ss_operand_remains_guest_access_not_ss() {
    for (name, code, access) in [
        ("FLDCW", &[0xD9, 0x6D, 0x00][..], MemoryAccessKind::Read),
        ("FNSTCW", &[0xD9, 0x7D, 0x00][..], MemoryAccessKind::Write),
    ] {
        let mut h = harness(code);
        h.vcpu.regs.rbp = DATA + 0x2000; // canonical, absent from TestSpace
        let before = x87_image(&h.vcpu);
        match run(&mut h.vcpu) {
            Err(Error::GuestAccess(fault)) => {
                assert_eq!(fault.address, DATA + 0x2000, "{name}");
                assert_eq!(fault.access, access, "{name}");
                assert_eq!(fault.kind, MemoryFaultKind::Unmapped, "{name}");
            }
            other => panic!("{name}: expected an unmapped guest access, got {other:?}"),
        }
        assert_eq!(h.vcpu.regs.rip, CODE, "{name}");
        assert_eq!(x87_image(&h.vcpu), before, "{name}");
        assert_eq!(h.vcpu.take_user_trap(), None, "{name}");
    }
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

// ------------------------------------------------ kernel-side xstate images

/// Distinct values in every piece of user extended state.
fn fill_xstate(v: &mut X86_64Vcpu) {
    v.fpu.push(1.5);
    v.fpu.push(-2.25);
    v.fpu.control_word = 0x027F;
    v.fpu.status_word |= 0x0020;
    v.fpu.last_opcode = 0x05D9;
    v.fpu.instr_ptr = 0x40_1234;
    v.fpu.data_ptr = 0x60_0040;
    v.mxcsr = 0x9FC1;
    for i in 0..16u64 {
        v.regs.xmm[i as usize] = [0x1111_0000 + i, 0x2222_0000 + i];
        v.regs.ymm_high[i as usize] = [0x3333_0000 + i, 0x4444_0000 + i];
        v.regs.zmm_high[i as usize] = [0x5500 + i, 0x5600 + i, 0x5700 + i, 0x5800 + i];
        v.regs.zmm_ext[i as usize] = [i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7];
    }
    for i in 0..8u64 {
        v.regs.k[i as usize] = 0x6600 + i;
    }
}

#[test]
fn xsave_image_matches_the_xsave_instruction() {
    // xsave64 [rdi] ; syscall
    let mut h = harness(&[0x48, 0x0F, 0xAE, 0x27, 0x0F, 0x05]);
    fill_xstate(&mut h.vcpu);
    h.mem
        .write_slice(&[0xCC; 0x1000], GuestAddress(0x1000))
        .unwrap();
    h.vcpu.regs.rdi = DATA;
    h.vcpu.regs.rax = 0xFFFF_FFFF;
    h.vcpu.regs.rdx = 0xFFFF_FFFF;
    let image = h.vcpu.xsave_image(u64::MAX);
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    // XCR0 = 0xE7: the standard area ends with Hi16_ZMM at 1664 + 1024.
    assert_eq!(image.bytes.len(), 2688);
    let mut stored = vec![0u8; image.bytes.len()];
    h.mem.read_slice(&mut stored, GuestAddress(0x1000)).unwrap();
    for &(lo, hi) in &image.written {
        assert_eq!(&stored[lo..hi], &image.bytes[lo..hi], "bytes {lo}..{hi}");
    }
    let xstate_bv = u64::from_le_bytes(image.bytes[512..520].try_into().unwrap());
    assert_eq!(xstate_bv, 0xE7);
    // Bytes XSAVE never stores: the reserved legacy bytes 416..512.
    assert!(image.written.iter().all(|&(lo, hi)| hi <= 416 || lo >= 512));
    assert!(stored[416..512].iter().all(|&b| b == 0xCC));
}

#[test]
fn xrstor_image_round_trips_and_initializes_absent_components() {
    let mut h = harness(&[]);
    fill_xstate(&mut h.vcpu);
    let image = h.vcpu.xsave_image(u64::MAX);
    let saved = (
        h.vcpu.regs.xmm,
        h.vcpu.regs.ymm_high,
        h.vcpu.regs.zmm_high,
        h.vcpu.regs.zmm_ext,
        h.vcpu.regs.k,
        h.vcpu.mxcsr,
        h.vcpu.fpu.control_word,
        h.vcpu.fpu.get_st(0),
        h.vcpu.fpu.get_st(1),
    );
    h.vcpu.init_user_xstate(u64::MAX);
    assert_eq!(h.vcpu.mxcsr, 0x1F80);
    assert_eq!(h.vcpu.fpu.control_word, 0x037F);
    assert_eq!(h.vcpu.fpu.tag_word, 0xFFFF);
    assert_eq!(h.vcpu.regs.zmm_ext[3], [0; 8]);
    h.vcpu.xrstor_image(&image.bytes, u64::MAX).unwrap();
    assert_eq!(
        saved,
        (
            h.vcpu.regs.xmm,
            h.vcpu.regs.ymm_high,
            h.vcpu.regs.zmm_high,
            h.vcpu.regs.zmm_ext,
            h.vcpu.regs.k,
            h.vcpu.mxcsr,
            h.vcpu.fpu.control_word,
            h.vcpu.fpu.get_st(0),
            h.vcpu.fpu.get_st(1),
        )
    );
    // XSTATE_BV[2] = 0 initializes AVX state even though the image holds it;
    // components outside RFBM are left alone.
    let mut partial = image.bytes.clone();
    partial[512] &= !0x04;
    h.vcpu.regs.k[0] = 7;
    h.vcpu.xrstor_image(&partial, 0x07).unwrap();
    assert_eq!(h.vcpu.regs.ymm_high[0], [0, 0]);
    assert_eq!(h.vcpu.regs.xmm[0], saved.0[0]);
    assert_eq!(h.vcpu.regs.k[0], 7, "opmask state is outside RFBM");
}

#[test]
fn xrstor_image_refuses_what_xrstor_faults_on() {
    // SDM Vol. 1 §13.8.1: #GP if XSTATE_BV sets a bit outside XCR0, if the
    // standard form's XCOMP_BV or header bytes 23:16 are nonzero, or if the
    // MXCSR it would load sets reserved bits.
    let mut h = harness(&[]);
    fill_xstate(&mut h.vcpu);
    let good = h.vcpu.xsave_image(u64::MAX).bytes;
    let before = h.vcpu.regs.xmm;
    let mut outside = good.clone();
    outside[512 + 1] |= 0x02; // XSTATE_BV bit 9 (PKRU), not in XCR0
    let mut xcomp = good.clone();
    xcomp[520] = 1;
    let mut reserved = good.clone();
    reserved[528] = 1;
    let mut mxcsr = good.clone();
    mxcsr[26] = 1; // MXCSR bit 16
    h.vcpu.regs.xmm[0] = [9, 9];
    use super::XrstorError::*;
    assert_eq!(h.vcpu.xrstor_image(&outside, u64::MAX), Err(Header));
    assert_eq!(h.vcpu.xrstor_image(&xcomp, u64::MAX), Err(Header));
    assert_eq!(h.vcpu.xrstor_image(&reserved, u64::MAX), Err(Header));
    assert_eq!(h.vcpu.xrstor_image(&mxcsr, u64::MAX), Err(Mxcsr));
    assert_eq!(h.vcpu.xrstor_image(&good[..600], u64::MAX), Err(Truncated));
    assert_eq!(
        h.vcpu.regs.xmm[0],
        [9, 9],
        "a refused image changes nothing"
    );
    // Standard-form bytes 63:24 of the header are not checked.
    let mut tail = good.clone();
    tail[540] = 0xFF;
    assert_eq!(h.vcpu.xrstor_image(&tail, u64::MAX), Ok(()));
    assert_eq!(h.vcpu.regs.xmm, before);
}

#[test]
fn xrstor_image_accepts_the_compacted_form() {
    // XCOMP_BV = bit 63 | 0x07: AVX state immediately follows the header.
    let mut h = harness(&[]);
    fill_xstate(&mut h.vcpu);
    let standard = h.vcpu.xsave_image(u64::MAX).bytes;
    let mut compacted = standard[..832].to_vec();
    compacted[520..528].copy_from_slice(&((1u64 << 63) | 0x07).to_le_bytes());
    compacted[512..520].copy_from_slice(&0x07u64.to_le_bytes());
    let want = h.vcpu.regs.ymm_high;
    h.vcpu.init_user_xstate(u64::MAX);
    h.vcpu.xrstor_image(&compacted, 0x07).unwrap();
    assert_eq!(h.vcpu.regs.ymm_high, want);
    // XSTATE_BV must be a subset of XCOMP_BV.
    compacted[512] |= 0x20;
    assert_eq!(
        h.vcpu.xrstor_image(&compacted, u64::MAX),
        Err(super::XrstorError::Header)
    );
}

#[test]
fn fxrstor_image_loads_the_legacy_region() {
    let mut h = harness(&[]);
    fill_xstate(&mut h.vcpu);
    let image = h.vcpu.xsave_image(0x03).bytes;
    let (xmm, mxcsr, st0) = (h.vcpu.regs.xmm, h.vcpu.mxcsr, h.vcpu.fpu.get_st(0));
    h.vcpu.init_user_xstate(u64::MAX);
    h.vcpu.fxrstor_image(&image).unwrap();
    assert_eq!(
        (h.vcpu.regs.xmm, h.vcpu.mxcsr, h.vcpu.fpu.get_st(0)),
        (xmm, mxcsr, st0)
    );
    let mut bad = image.clone();
    bad[27] = 0x80;
    assert_eq!(h.vcpu.fxrstor_image(&bad), Err(super::XrstorError::Mxcsr));
}

#[test]
fn xrstor_image_matches_the_xrstor_instruction() {
    // xrstor64 [rdi] ; syscall — with XSTATE_BV clearing AVX and opmask
    // state so both the load and the init paths are compared.
    let code = [0x48, 0x0F, 0xAE, 0x2F, 0x0F, 0x05];
    let mut source = harness(&[]);
    fill_xstate(&mut source.vcpu);
    let mut image = source.vcpu.xsave_image(u64::MAX).bytes;
    image[512] &= !(0x04 | 0x20);
    let mut by_insn = harness(&code);
    let mut by_image = harness(&code);
    for h in [&mut by_insn, &mut by_image] {
        fill_xstate(&mut h.vcpu);
        h.vcpu.regs.xmm[5] = [0xAB, 0xCD];
        h.vcpu.mxcsr = 0x1F80;
    }
    by_insn
        .mem
        .write_slice(&image, GuestAddress(0x1000))
        .unwrap();
    by_insn.vcpu.regs.rdi = DATA;
    by_insn.vcpu.regs.rax = 0xFFFF_FFFF;
    by_insn.vcpu.regs.rdx = 0xFFFF_FFFF;
    assert!(matches!(
        run(&mut by_insn.vcpu).unwrap(),
        VcpuExit::SystemCall
    ));
    by_image.vcpu.xrstor_image(&image, u64::MAX).unwrap();
    let state = |v: &X86_64Vcpu| {
        (
            v.regs.xmm,
            v.regs.ymm_high,
            v.regs.zmm_high,
            v.regs.zmm_ext,
            v.regs.k,
            v.mxcsr,
            v.fpu.control_word,
            v.fpu.status_word,
            v.fpu.tag_word,
            (0..8)
                .map(|i| v.fpu.get_st(i).to_bits())
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(state(&by_insn.vcpu), state(&by_image.vcpu));
    assert_eq!(by_image.vcpu.regs.ymm_high[0], [0, 0]);
    assert_eq!(by_image.vcpu.regs.k[0], 0);
}

#[test]
fn x87_restores_keep_empty_registers_empty() {
    // FXRSTOR/XRSTOR load the tag word from the abridged FTW: registers it
    // marks empty stay empty (SDM Vol. 1 §10.5.1.1), whatever the image
    // holds in their slots. Two values pushed: TOP = 6, ST0-ST1 valid.
    // fxsave64 [rdi] ; fxrstor64 [rdi] ; xsave64 [rsi] ; xrstor64 [rsi] ;
    // syscall
    let code = [
        0x48, 0x0F, 0xAE, 0x07, 0x48, 0x0F, 0xAE, 0x0F, 0x48, 0x0F, 0xAE, 0x26, 0x48, 0x0F, 0xAE,
        0x2E, 0x0F, 0x05,
    ];
    let mut h = harness(&code);
    h.vcpu.fpu.push(1.5);
    h.vcpu.fpu.push(-2.25);
    let want = (
        h.vcpu.fpu.tag_word,
        h.vcpu.fpu.top,
        h.vcpu.fpu.get_st(0),
        h.vcpu.fpu.get_st(1),
    );
    assert_eq!(want.0, 0x0FFF, "physical registers 6 and 7 valid");
    h.vcpu.regs.rdi = DATA;
    h.vcpu.regs.rsi = DATA + 0x200;
    h.vcpu.regs.rax = 0xFFFF_FFFF;
    h.vcpu.regs.rdx = 0xFFFF_FFFF;
    assert!(matches!(run(&mut h.vcpu).unwrap(), VcpuExit::SystemCall));
    let got = (
        h.vcpu.fpu.tag_word,
        h.vcpu.fpu.top,
        h.vcpu.fpu.get_st(0),
        h.vcpu.fpu.get_st(1),
    );
    assert_eq!(got, want, "instruction round trips");
    // The kernel-side image path agrees.
    let image = h.vcpu.xsave_image(u64::MAX).bytes;
    h.vcpu.init_user_xstate(u64::MAX);
    h.vcpu.xrstor_image(&image, u64::MAX).unwrap();
    assert_eq!(
        (
            h.vcpu.fpu.tag_word,
            h.vcpu.fpu.top,
            h.vcpu.fpu.get_st(0),
            h.vcpu.fpu.get_st(1),
        ),
        want,
        "image round trip"
    );
}
