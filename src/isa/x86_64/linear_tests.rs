//! Segment-relative linear addresses against the Intel SDM (Vol. 1 §3.1.1,
//! §3.7.4.1; Vol. 3A §3.4.4): outside 64-bit mode base + offset wraps at
//! 4 GiB for every kind of access, and 64-bit mode neither wraps nor applies
//! the CS, DS, ES, or SS bases. Memory is mapped both below 4 GiB and just
//! above it, with a different marker at the wrapped (right) and unwrapped
//! (wrong) address, so a missed wrap reads the wrong value instead of
//! faulting.

use super::*;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const RIGHT: u32 = 0x1122_3344;
const WRONG: u32 = 0x5566_7788;
/// Where the code runs.
const CODE: u64 = 0x1000;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
/// CR4.OSFXSR, OSXMMEXCPT, OSXSAVE.
const CR4_SIMD: u64 = (1 << 9) | (1 << 10) | (1 << 18);

#[derive(Clone, Copy, Debug)]
enum Mode {
    /// IA-32e compatibility mode (CS.L = 0, CS.D = 1).
    Compat,
    /// Legacy 32-bit protected mode.
    Protected,
    /// 64-bit mode.
    Long,
}

const NOT_64: [Mode; 2] = [Mode::Compat, Mode::Protected];

/// Memory below 64 KiB and from 0xFFFF_0000 to 0x1_0001_0000 (across 4 GiB).
fn memory() -> Arc<GuestMemoryMmap> {
    Arc::new(
        GuestMemoryMmap::<()>::from_ranges(&[
            (GuestAddress(0), 0x1_0000),
            (GuestAddress(0xFFFF_0000), 0x2_0000),
        ])
        .unwrap(),
    )
}

/// A vCPU in `mode` with flat 4 GiB segments, `code` at [`CODE`].
fn vcpu(mode: Mode, code: &[u8]) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let memory = memory();
    memory.write_slice(code, GuestAddress(CODE)).unwrap();
    let mut v = X86_64Vcpu::new(0, memory.clone());
    v.sregs.cr0 = 1;
    v.sregs.cr4 = CR4_SIMD;
    v.sregs.efer = match mode {
        Mode::Compat => EFER_LME | EFER_LMA,
        Mode::Protected => 0,
        Mode::Long => EFER_LMA,
    };
    for (seg, ty) in [
        (&mut v.sregs.cs, 0xB),
        (&mut v.sregs.ss, 0x3),
        (&mut v.sregs.ds, 0x3),
        (&mut v.sregs.es, 0x3),
        (&mut v.sregs.fs, 0x3),
        (&mut v.sregs.gs, 0x3),
    ] {
        seg.base = 0;
        seg.limit = 0xFFFF_FFFF;
        seg.type_ = ty;
        seg.s = true;
        seg.present = true;
        seg.g = true;
        seg.db = true;
        seg.unusable = false;
    }
    v.sregs.cs.l = matches!(mode, Mode::Long);
    if v.sregs.cs.l {
        v.sregs.cs.db = false;
    }
    v.set_xcr0(0x7).unwrap();
    v.regs.rip = CODE;
    v.regs.rsp = 0x8000;
    v.regs.rflags = 0x2;
    (v, memory)
}

fn put(memory: &GuestMemoryMmap, at: u64, value: u32) {
    memory.write_obj(value, GuestAddress(at)).unwrap();
}

fn get(memory: &GuestMemoryMmap, at: u64) -> u32 {
    memory.read_obj(GuestAddress(at)).unwrap()
}

/// RIGHT at `right`, WRONG at `right + 4 GiB`.
fn mark(memory: &GuestMemoryMmap, right: u64) {
    put(memory, right, RIGHT);
    put(memory, right + (1 << 32), WRONG);
}

fn step(v: &mut X86_64Vcpu, what: &str) {
    v.step().unwrap_or_else(|e| panic!("{what}: {e}"));
}

#[test]
fn memory_operands_wrap_at_4gib() {
    for mode in NOT_64 {
        // mov %gs:-8(%ebx), %eax, then mov %gs:0xFFFFFFF8, %eax (moffs).
        for code in [
            &[0x65, 0x8B, 0x43, 0xF8][..],
            &[0x65, 0xA1, 0xF8, 0xFF, 0xFF, 0xFF],
        ] {
            let (mut v, m) = vcpu(mode, code);
            v.sregs.gs.base = 0x3000;
            v.regs.rbx = 0;
            mark(&m, 0x2FF8);
            step(&mut v, "load");
            assert_eq!(v.regs.rax as u32, RIGHT, "{mode:?} {code:02x?}");
        }
        // The FS/GS base's upper half does not count (compatibility mode).
        if matches!(mode, Mode::Compat) {
            let (mut v, m) = vcpu(mode, &[0x65, 0x8B, 0x03]);
            v.sregs.gs.base = 0x7_0000_3000;
            v.regs.rbx = 0x10;
            mark(&m, 0x3010);
            step(&mut v, "upper base");
            assert_eq!(v.regs.rax as u32, RIGHT);
        }
        // LEA yields the offset, whatever the segment.
        let (mut v, _) = vcpu(mode, &[0x65, 0x8D, 0x43, 0xF8]);
        v.sregs.gs.base = 0x3000;
        v.regs.rbx = 0;
        step(&mut v, "lea");
        assert_eq!(v.regs.rax as u32, 0xFFFF_FFF8, "{mode:?}");
    }
}

#[test]
fn the_stack_wraps_at_4gib() {
    for mode in NOT_64 {
        // push %eax; pop %ecx with SS based at 0x3000 and ESP 0.
        let (mut v, m) = vcpu(mode, &[0x50, 0x59]);
        v.sregs.ss.base = 0x3000;
        v.regs.rsp = 0;
        v.regs.rax = u64::from(RIGHT);
        step(&mut v, "push");
        assert_eq!(v.regs.rsp, 0xFFFF_FFFC);
        assert_eq!(get(&m, 0x2FFC), RIGHT, "{mode:?}");
        assert_eq!(get(&m, 0x1_0000_2FFC), 0);
        step(&mut v, "pop");
        assert_eq!((v.regs.rcx as u32, v.regs.rsp), (RIGHT, 0));
        // pop %es of a null selector (a wrong read would load a bad one).
        let (mut v, m) = vcpu(mode, &[0x07]);
        v.sregs.es.selector = 0x2B;
        v.sregs.ss.base = 0x3000;
        v.regs.rsp = 0xFFFF_FFF8;
        put(&m, 0x2FF8, 0);
        put(&m, 0x1_0000_2FF8, 0xFFF8);
        step(&mut v, "pop es");
        assert_eq!(
            (v.sregs.es.selector, v.regs.rsp),
            (0, 0xFFFF_FFFC),
            "{mode:?}"
        );
        // leave: the saved frame pointer at SS:EBP.
        let (mut v, m) = vcpu(mode, &[0xC9]);
        v.sregs.ss.base = 0x3000;
        v.regs.rbp = 0xFFFF_FFF8;
        mark(&m, 0x2FF8);
        step(&mut v, "leave");
        assert_eq!(v.regs.rbp as u32, RIGHT, "{mode:?}");
    }
}

#[test]
fn instruction_fetch_wraps_at_4gib() {
    for mode in NOT_64 {
        let (mut v, m) = vcpu(mode, &[]);
        v.sregs.cs.base = 0x3000;
        v.regs.rip = 0xFFFF_FFF0;
        // mov $imm32, %eax at the wrapped and the unwrapped address.
        m.write_slice(&[0xB8, 0x44, 0x33, 0x22, 0x11], GuestAddress(0x2FF0))
            .unwrap();
        m.write_slice(&[0xB8, 0x88, 0x77, 0x66, 0x55], GuestAddress(0x1_0000_2FF0))
            .unwrap();
        step(&mut v, "fetch");
        assert_eq!(v.regs.rax as u32, RIGHT, "{mode:?}");
        assert_eq!(v.regs.rip, 0xFFFF_FFF5);
    }
}

#[test]
fn string_instructions_wrap_and_use_es() {
    for mode in NOT_64 {
        // lodsl %gs:(%esi).
        let (mut v, m) = vcpu(mode, &[0x65, 0xAD]);
        v.sregs.gs.base = 0x3000;
        v.regs.rsi = 0xFFFF_FFF8;
        mark(&m, 0x2FF8);
        step(&mut v, "lods");
        assert_eq!(v.regs.rax as u32, RIGHT, "{mode:?}");
        // stosl to ES:EDI, ES based at 0x3000.
        let (mut v, m) = vcpu(mode, &[0xAB]);
        v.sregs.es.base = 0x3000;
        v.regs.rdi = 0xFFFF_FFF8;
        v.regs.rax = u64::from(RIGHT);
        step(&mut v, "stos");
        assert_eq!(get(&m, 0x2FF8), RIGHT, "{mode:?}");
        assert_eq!(get(&m, 0xFFFF_FFF8), 0, "ES's base applies");
        // scasl compares EAX with ES:EDI.
        let (mut v, m) = vcpu(mode, &[0xAF]);
        v.sregs.es.base = 0x3000;
        v.regs.rdi = 0xFFFF_FFF8;
        v.regs.rax = u64::from(RIGHT);
        mark(&m, 0x2FF8);
        put(&m, 0xFFFF_FFF8, WRONG);
        step(&mut v, "scas");
        assert!(v.regs.rflags & 0x40 != 0, "{mode:?}: ZF, equal");
        // cmpsl compares DS:ESI with ES:EDI.
        let (mut v, m) = vcpu(mode, &[0xA7]);
        v.sregs.ds.base = 0x3000;
        v.sregs.es.base = 0x5000;
        v.regs.rsi = 0xFFFF_FFF8;
        v.regs.rdi = 0xFFFF_FFF0;
        mark(&m, 0x2FF8);
        put(&m, 0x4FF0, RIGHT);
        put(&m, 0xFFFF_FFF0, WRONG);
        step(&mut v, "cmps");
        assert!(v.regs.rflags & 0x40 != 0, "{mode:?}: ZF, equal");
        // movsl from DS:ESI to ES:EDI.
        let (mut v, m) = vcpu(mode, &[0xA5]);
        v.sregs.ds.base = 0x3000;
        v.sregs.es.base = 0x5000;
        v.regs.rsi = 0xFFFF_FFF8;
        v.regs.rdi = 0xFFFF_FFF0;
        mark(&m, 0x2FF8);
        step(&mut v, "movs");
        assert_eq!(get(&m, 0x4FF0), RIGHT, "{mode:?}");
        // xlat: DS:[EBX + AL].
        let (mut v, m) = vcpu(mode, &[0xD7]);
        v.sregs.ds.base = 0x3000;
        v.regs.rbx = 0xFFFF_FFF0;
        v.regs.rax = 8;
        mark(&m, 0x2FF8);
        step(&mut v, "xlat");
        assert_eq!(v.regs.rax as u8, RIGHT as u8, "{mode:?}");
    }
}

#[test]
fn a_page_crossing_access_wraps_at_4gib() {
    for mode in NOT_64 {
        // mov (%ebx), %eax at 0xFFFFFFFE: two bytes there, two at 0.
        let (mut v, m) = vcpu(mode, &[0x8B, 0x03]);
        v.regs.rbx = 0xFFFF_FFFE;
        m.write_slice(&[0xAA, 0xBB], GuestAddress(0xFFFF_FFFE))
            .unwrap();
        m.write_slice(&[0xCC, 0xDD], GuestAddress(0)).unwrap();
        m.write_slice(&[0x11, 0x22], GuestAddress(1 << 32)).unwrap();
        step(&mut v, "crossing load");
        assert_eq!(v.regs.rax as u32, 0xDDCC_BBAA, "{mode:?}");
    }
}

#[test]
fn implicit_destinations_wrap_and_use_their_segments() {
    for mode in NOT_64 {
        // maskmovdqu %xmm1, %xmm0 to DS:EDI, every byte selected.
        let (mut v, m) = vcpu(mode, &[0x66, 0x0F, 0xF7, 0xC1]);
        v.sregs.ds.base = 0x3000;
        v.regs.rdi = 0xFFFF_FFF8;
        v.regs.xmm[0] = [u64::from(RIGHT), 0];
        v.regs.xmm[1] = [0x8080_8080_8080_8080; 2];
        step(&mut v, "maskmovdqu");
        assert_eq!(get(&m, 0x2FF8), RIGHT, "{mode:?}");
        assert_eq!(get(&m, 0xFFFF_FFF8), 0);
        // movdir64b (%ebx), %edi: the destination is ES:EDI.
        let (mut v, m) = vcpu(mode, &[0x66, 0x0F, 0x38, 0xF8, 0x3B]);
        v.sregs.es.base = 0x3000;
        v.regs.rdi = 0xFFFF_FFC0;
        v.regs.rbx = 0x5000;
        put(&m, 0x5000, RIGHT);
        step(&mut v, "movdir64b");
        assert_eq!(get(&m, 0x2FC0), RIGHT, "{mode:?}");
        assert_eq!(get(&m, 0xFFFF_FFC0), 0);
    }
}

#[test]
fn vex_gathers_use_32_bit_addresses_and_ds_outside_64bit_mode() {
    for mode in NOT_64 {
        // vpgatherdd %xmm2, (%ebx,%xmm1,1), %xmm0: indices 0, 4, 8, 12.
        let (mut v, m) = vcpu(mode, &[0xC4, 0xE2, 0x69, 0x90, 0x04, 0x0B]);
        v.sregs.ds.base = 0x3000;
        v.regs.rbx = 0xFFFF_FFF0;
        v.regs.xmm[1] = [4 << 32, (12 << 32) | 8];
        v.regs.xmm[2] = [0x8000_0000_8000_0000; 2];
        for i in 0..4u64 {
            put(&m, 0x2FF0 + 4 * i, RIGHT + i as u32);
            put(&m, 0x1_0000_2FF0 + 4 * i, WRONG);
            put(&m, 0xFFFF_FFF0 + 4 * i, WRONG);
        }
        step(&mut v, "vpgatherdd");
        let lanes = [
            v.regs.xmm[0][0] as u32,
            (v.regs.xmm[0][0] >> 32) as u32,
            v.regs.xmm[0][1] as u32,
            (v.regs.xmm[0][1] >> 32) as u32,
        ];
        assert_eq!(lanes, [RIGHT, RIGHT + 1, RIGHT + 2, RIGHT + 3], "{mode:?}");
    }
}

#[test]
fn sixty_four_bit_mode_neither_wraps_nor_uses_legacy_bases() {
    // A DS override's base counts as zero.
    let (mut v, m) = vcpu(Mode::Long, &[0x3E, 0x8B, 0x03]);
    v.sregs.ds.base = 0x1000;
    v.regs.rbx = 0x2000;
    put(&m, 0x2000, RIGHT);
    put(&m, 0x3000, WRONG);
    step(&mut v, "ds override");
    assert_eq!(v.regs.rax as u32, RIGHT);
    // So does ES for a string destination.
    let (mut v, m) = vcpu(Mode::Long, &[0xAB]);
    v.sregs.es.base = 0x1000;
    v.regs.rdi = 0x2000;
    v.regs.rax = u64::from(RIGHT);
    step(&mut v, "stos");
    assert_eq!((get(&m, 0x2000), get(&m, 0x3000)), (RIGHT, 0));
    // GS's full base, past 4 GiB.
    let (mut v, m) = vcpu(Mode::Long, &[0x65, 0x8B, 0x03]);
    v.sregs.gs.base = 1 << 32;
    v.regs.rbx = 0x2000;
    put(&m, 0x1_0000_2000, RIGHT);
    put(&m, 0x2000, WRONG);
    step(&mut v, "gs past 4 GiB");
    assert_eq!(v.regs.rax as u32, RIGHT);
}
