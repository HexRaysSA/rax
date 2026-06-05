//! Real-mode (16-bit) execution tests — the foundation for legacy/BIOS boot
//! (e.g. TempleOS via El-Torito). Built in increments; each test pins one piece
//! of real-mode behavior the TempleOS boot sector relies on.
#![cfg(target_arch = "x86_64")]

use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use rax::backend::emulator::x86_64::X86_64Vcpu;
use rax::cpu::{Registers, Segment, SystemRegisters, VCpu, VcpuExit};

const MEM: u64 = 4 * 1024 * 1024;

fn rm_seg(code: bool) -> Segment {
    Segment {
        base: 0,
        limit: 0xFFFF,
        selector: 0,
        type_: if code { 0x0B } else { 0x03 },
        present: true,
        dpl: 0,
        db: false, // 16-bit
        s: true,
        l: false,
        g: false,
        avl: false,
        unusable: false,
    }
}

/// Real-mode system registers: PE=0, no paging, 16-bit flat segments.
fn real_mode_sregs() -> SystemRegisters {
    let mut s = SystemRegisters::default();
    s.cs = rm_seg(true);
    s.ds = rm_seg(false);
    s.es = rm_seg(false);
    s.fs = rm_seg(false);
    s.gs = rm_seg(false);
    s.ss = rm_seg(false);
    s.idt.limit = 0x3FF;
    s
}

/// Build a real-mode vcpu with `code` at linear `load_linear`, CS base `cs_base`
/// (so IP = load_linear - cs_base), a small stack, and DS/ES/SS base 0.
fn rm_vcpu(code: &[u8], load_linear: u64, cs_base: u64) -> X86_64Vcpu {
    let region = MmapRegion::new(MEM as usize).unwrap();
    let gr = GuestRegionMmap::new(region, GuestAddress(0)).unwrap();
    let mem = Arc::new(GuestMemoryMmap::from_regions(vec![gr]).unwrap());
    mem.write_slice(code, GuestAddress(load_linear)).unwrap();

    let mut v = X86_64Vcpu::new(0, mem);
    let mut s = real_mode_sregs();
    s.cs.base = cs_base;
    v.set_sregs(&s).unwrap();
    let mut r = Registers::default();
    r.rip = load_linear - cs_base;
    r.rsp = 0x2000;
    r.rflags = 0x2;
    v.set_regs(&r).unwrap();
    v
}

fn run(v: &mut X86_64Vcpu, max: usize) {
    for _ in 0..max {
        match v.step() {
            Ok(Some(VcpuExit::Hlt)) => return,
            Ok(_) => {}
            Err(e) => panic!("step error: {e:?}"),
        }
    }
    panic!("no HLT within {max} steps");
}

// ── Increment 1: segment-register load sets base = selector<<4; fetch uses CS base.

#[test]
fn rm_segment_load_sets_base() {
    // mov ax, 0x9660 ; mov es, ax ; hlt   → real mode: es.base = 0x9660<<4
    let code = [0xB8, 0x60, 0x96, 0x8E, 0xC0, 0xF4];
    let mut v = rm_vcpu(&code, 0x7C00, 0);
    run(&mut v, 10);
    assert_eq!(
        v.get_sregs().unwrap().es.base,
        0x9_6600,
        "real-mode segment load must set base = selector<<4"
    );
    assert_eq!(v.get_regs().unwrap().rax & 0xFFFF, 0x9660);
}

#[test]
fn rm_fetch_uses_cs_base() {
    // At linear 0x1100 (CS.base=0x1000, IP=0x100): mov ax,0xBEEF ; hlt
    let code = [0xB8, 0xEF, 0xBE, 0xF4];
    let mut v = rm_vcpu(&code, 0x1100, 0x1000);
    run(&mut v, 10);
    assert_eq!(
        v.get_regs().unwrap().rax & 0xFFFF,
        0xBEEF,
        "instruction fetch must use CS.base + IP"
    );
}
