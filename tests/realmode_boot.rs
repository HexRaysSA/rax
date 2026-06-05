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
/// (so IP = load_linear - cs_base), a small stack, and DS/ES/SS base 0. Returns
/// the guest memory too so tests can seed/inspect data.
fn rm_vcpu(code: &[u8], load_linear: u64, cs_base: u64) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let region = MmapRegion::new(MEM as usize).unwrap();
    let gr = GuestRegionMmap::new(region, GuestAddress(0)).unwrap();
    let mem = Arc::new(GuestMemoryMmap::from_regions(vec![gr]).unwrap());
    mem.write_slice(code, GuestAddress(load_linear)).unwrap();

    let mut v = X86_64Vcpu::new(0, mem.clone());
    let mut s = real_mode_sregs();
    s.cs.base = cs_base;
    v.set_sregs(&s).unwrap();
    let mut r = Registers::default();
    r.rip = load_linear - cs_base;
    r.rsp = 0x2000;
    r.rflags = 0x2;
    v.set_regs(&r).unwrap();
    (v, mem)
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
    let (mut v, _m) = rm_vcpu(&code, 0x7C00, 0);
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
    let (mut v, _m) = rm_vcpu(&code, 0x1100, 0x1000);
    run(&mut v, 10);
    assert_eq!(
        v.get_regs().unwrap().rax & 0xFFFF,
        0xBEEF,
        "instruction fetch must use CS.base + IP"
    );
}

// ── Increment 2: ModR/M + moffs data accesses add the segment base (DS default).

#[test]
fn rm_modrm_uses_ds_base() {
    // mov ax,0x200 ; mov ds,ax (ds.base=0x2000)
    // mov byte [dword 0x35],0x42 ; mov al,[dword 0x35] ; hlt
    // Both the write and the read must target DS.base+0x35 = 0x2035.
    let code = [
        0xB8, 0x00, 0x02, // mov ax, 0x200
        0x8E, 0xD8, // mov ds, ax
        0x67, 0xC6, 0x05, 0x35, 0x00, 0x00, 0x00, 0x42, // mov byte [0x35], 0x42
        0x67, 0x8A, 0x05, 0x35, 0x00, 0x00, 0x00, // mov al, [0x35]
        0xF4, // hlt
    ];
    let (mut v, m) = rm_vcpu(&code, 0x7C00, 0);
    run(&mut v, 20);
    assert_eq!(v.get_regs().unwrap().rax & 0xFF, 0x42, "read via DS.base");
    let mut b = [0u8; 1];
    m.read_slice(&mut b, GuestAddress(0x2035)).unwrap();
    assert_eq!(b[0], 0x42, "write must land at DS.base + 0x35 = 0x2035");
}

#[test]
fn rm_moffs_uses_ds_base() {
    // mov ax,0x300 ; mov ds,ax (ds.base=0x3000) ; mov ax,0xCAFE
    // mov [0x40],ax (moffs16 store, opcode A3) ; hlt — writes to DS.base+0x40.
    let code = [
        0xB8, 0x00, 0x03, // mov ax, 0x300
        0x8E, 0xD8, // mov ds, ax
        0xB8, 0xFE, 0xCA, // mov ax, 0xCAFE
        0xA3, 0x40, 0x00, // mov [0x0040], ax  (moffs16)
        0xF4,
    ];
    let (mut v, m) = rm_vcpu(&code, 0x7C00, 0);
    run(&mut v, 20);
    let mut b = [0u8; 2];
    m.read_slice(&mut b, GuestAddress(0x3040)).unwrap();
    assert_eq!(u16::from_le_bytes(b), 0xCAFE, "moffs write must use DS.base + 0x40");
}
