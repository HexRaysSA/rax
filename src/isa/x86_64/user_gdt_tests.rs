//! The user-mode GDT against Linux's (`arch/x86/kernel/cpu/common.c`
//! `gdt_page`, `setup_getcpu`; `arch/x86/include/asm/segment.h`) and the
//! Intel SDM's segment-load and LSL rules (Vol. 3A §5.4, Vol. 2A MOV and
//! LSL): the descriptor values Linux installs (the well-known
//! 0x00cffb000000ffff, 0x00cff3000000ffff, 0x00affb000000ffff), selector
//! loads of user and kernel entries, a TLS entry's base through %gs in
//! compatibility mode, the accessed bit kept in the table, LSL on the
//! CPU-and-node entry, and the reload after a TLS change.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::super::X86_64Vcpu;
use super::super::user_mode::{X86EventSource, X86UserEvent, X86UserTrap};
use super::{GDT_ENTRY_CPUNODE, GDT_ENTRY_TLS_MIN, USER_GDT_BASE};
use crate::error::{Error, GuestMemoryFault, MemoryAccessKind};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::{VCpu, VcpuExit};

const CODE: u64 = 0x40_0000;
const DATA: u64 = 0x60_0000;

/// Linear page -> frame, every page readable, writable, and executable.
#[derive(Default)]
struct Space(Mutex<BTreeMap<u64, u64>>);

impl FlatTranslation for Space {
    fn translate(&self, linear: u64, access: MemoryAccessKind) -> Result<u64, GuestMemoryFault> {
        match self.0.lock().unwrap().get(&(linear & !0xFFF)) {
            Some(frame) => Ok(frame | (linear & 0xFFF)),
            None => Err(GuestMemoryFault::unmapped(linear, 1, access)),
        }
    }
}

/// A user-mode vCPU with `code` at [`CODE`] and a data page at [`DATA`].
fn vcpu(code: &[u8], compat: bool) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    mem.write_slice(code, GuestAddress(0)).unwrap();
    let space = Arc::new(Space::default());
    space.0.lock().unwrap().insert(CODE, 0);
    space.0.lock().unwrap().insert(DATA, 0x1000);
    let mut v = X86_64Vcpu::new(0, mem.clone());
    v.enable_user_mode(space);
    v.set_user_compat(compat);
    v.regs.rip = CODE;
    v.regs.rsp = DATA + 0xF00;
    (v, mem)
}

/// Runs to the event that ends the program.
fn run_event(v: &mut X86_64Vcpu) -> X86UserEvent {
    loop {
        match v.run() {
            Ok(VcpuExit::Hlt) if !v.halted => continue,
            Err(Error::GuestEvent { .. }) => break,
            other => panic!("expected a guest event, got {other:?}"),
        }
    }
    match v.take_user_trap() {
        Some(X86UserTrap::Event(e)) => e,
        other => panic!("expected an event, got {other:?}"),
    }
}

/// `int $0x80`, the end of each program.
const INT80: [u8; 2] = [0xCD, 0x80];

fn ended_at_int80(e: X86UserEvent) {
    assert_eq!(
        (e.vector, e.source),
        (0x80, X86EventSource::SoftwareInterrupt)
    );
}

#[test]
fn the_gdt_holds_linux_user_descriptors() {
    let (v, _) = vcpu(&INT80, false);
    assert_eq!(v.sregs.gdt.base, USER_GDT_BASE);
    assert_eq!(v.sregs.gdt.limit, 16 * 8 - 1);
    // __USER32_CS, __USER_DS, __USER_CS.
    assert_eq!(v.user_gdt_entry(4), Some(0x00CF_FB00_0000_FFFF));
    assert_eq!(v.user_gdt_entry(5), Some(0x00CF_F300_0000_FFFF));
    assert_eq!(v.user_gdt_entry(6), Some(0x00AF_FB00_0000_FFFF));
    // Kernel code and data, DPL 0.
    assert_eq!(v.user_gdt_entry(2), Some(0x00AF_9B00_0000_FFFF));
    assert_eq!(v.user_gdt_entry(3), Some(0x00CF_9300_0000_FFFF));
    // TLS entries start empty; the CPU/node entry is read-only data, DPL 3.
    assert_eq!(v.user_gdt_entry(GDT_ENTRY_TLS_MIN), Some(0));
    assert_eq!(
        v.user_gdt_entry(GDT_ENTRY_CPUNODE),
        Some(0x0040_F500_0000_0000)
    );
    assert_eq!(v.user_gdt_entry(16), None);
}

#[test]
fn user_selectors_load_and_kernel_ones_fault() {
    // mov $0x2b,%eax; mov %eax,%ds; mov $0x23,%eax; mov %eax,%es; int $0x80
    let code = [
        0xB8, 0x2B, 0, 0, 0, 0x8E, 0xD8, 0xB8, 0x23, 0, 0, 0, 0x8E, 0xC0, 0xCD, 0x80,
    ];
    for compat in [false, true] {
        let (mut v, _) = vcpu(&code, compat);
        ended_at_int80(run_event(&mut v));
        assert_eq!(v.sregs.ds.selector, 0x2B);
        // A readable code segment loads into a data register.
        assert_eq!(v.sregs.es.selector, 0x23);
    }
    // mov $0x18,%eax (__KERNEL_DS, DPL 0); mov %eax,%ds: #GP(0x18).
    let (mut v, _) = vcpu(&[0xB8, 0x18, 0, 0, 0, 0x8E, 0xD8], true);
    let e = run_event(&mut v);
    assert_eq!((e.vector, e.error_code), (13, Some(0x18)));
    // A selector past the table: #GP(selector).
    let (mut v, _) = vcpu(&[0xB8, 0x83, 0, 0, 0, 0x8E, 0xD8], true);
    let e = run_event(&mut v);
    assert_eq!((e.vector, e.error_code), (13, Some(0x80)));
}

#[test]
fn a_tls_entry_bases_gs_in_compatibility_mode() {
    // mov $0x63,%eax; mov %eax,%gs; mov %gs:0x10,%ebx; inc %ebx; int $0x80
    let code = [
        0xB8, 0x63, 0, 0, 0, 0x8E, 0xE8, 0x65, 0x8B, 0x1D, 0x10, 0, 0, 0, 0x43, 0xCD, 0x80,
    ];
    let (mut v, mem) = vcpu(&code, true);
    // Base 0x00600000, limit 0xFFFFF pages, writable data, DPL 3, 32-bit,
    // not yet accessed (type 2).
    let tls = 0x00CF_F260_0000_FFFF;
    assert!(v.set_user_tls_entry(GDT_ENTRY_TLS_MIN, tls));
    mem.write_obj(0x4141_4140u32, GuestAddress(0x1010)).unwrap();
    ended_at_int80(run_event(&mut v));
    assert_eq!(v.sregs.gs.selector, 0x63);
    assert_eq!(v.sregs.gs.base, DATA);
    // 0x40 is INC EAX-class (here INC EBX, 0x43): compatibility decoding.
    assert_eq!(v.regs.rbx as u32, 0x4141_4141);
    // The load set the accessed bit in the table.
    assert_eq!(v.user_gdt_entry(GDT_ENTRY_TLS_MIN), Some(tls | 1 << 40));
    // Only TLS entries can be set.
    assert!(!v.set_user_tls_entry(GDT_ENTRY_CPUNODE, 0));
}

#[test]
fn lsl_reads_the_cpu_and_node() {
    // mov $0x7b,%eax; mov $-1,%ecx; lsl %eax,%ecx; int $0x80
    let code = [
        0xB8, 0x7B, 0, 0, 0, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x03, 0xC8, 0xCD, 0x80,
    ];
    for compat in [false, true] {
        let (mut v, _) = vcpu(&code, compat);
        ended_at_int80(run_event(&mut v));
        assert_eq!(v.regs.rcx as u32, 0, "CPU 0, node 0");
        assert!(v.regs.rflags & 0x40 != 0, "ZF: the selector was valid");
    }
}

#[test]
fn a_changed_tls_entry_is_reloaded_where_it_is_held() {
    // mov $0x63,%eax; mov %eax,%gs; int $0x80
    let (mut v, _) = vcpu(&[0xB8, 0x63, 0, 0, 0, 0x8E, 0xE8, 0xCD, 0x80], true);
    v.set_user_tls_entry(GDT_ENTRY_TLS_MIN, 0x00CF_F360_0000_FFFF);
    ended_at_int80(run_event(&mut v));
    assert_eq!(v.sregs.gs.base, 0x0060_0000);
    // A new base at 0x12345000: the cached descriptor stands until reloaded.
    v.set_user_tls_entry(GDT_ENTRY_TLS_MIN, 0x12CF_F334_5000_FFFF);
    assert_eq!(v.sregs.gs.base, 0x0060_0000);
    v.reload_user_segments(0x63);
    assert_eq!(v.sregs.gs.base, 0x1234_5000);
    // Emptied: the reload fails and the register becomes null.
    v.set_user_tls_entry(GDT_ENTRY_TLS_MIN, 0);
    v.reload_user_segments(0x63);
    assert_eq!(v.sregs.gs.selector & !3, 0);
}

#[test]
fn compatibility_mode_switches_cs() {
    let (mut v, _) = vcpu(&INT80, true);
    assert_eq!(v.sregs.cs.selector, 0x23);
    assert!(!v.sregs.cs.l && v.sregs.cs.db);
    assert!(v.user_compat());
    v.set_user_compat(false);
    assert_eq!(v.sregs.cs.selector, 0x33);
    assert!(v.sregs.cs.l && !v.sregs.cs.db && !v.user_compat());
}
