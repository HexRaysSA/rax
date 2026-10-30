//! Live task priority in direct helpers and actual compiled x86 regions.
use super::*;
use crate::devices::lapic::LocalApic;
use std::sync::{Arc, Mutex};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
fn fixture(code: &[u8]) -> (X86_64Vcpu, Arc<Mutex<LocalApic>>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    let mut cpu = X86_64Vcpu::new(1, memory);
    cpu.sregs.cr0 = 0x50033;
    cpu.sregs.cr4 = 1 << 5;
    cpu.sregs.efer = (1 << 8) | (1 << 10);
    cpu.sregs.cs.l = true;
    cpu.sregs.cs.selector = 0;
    cpu.regs.rip = 0;
    cpu.regs.rsp = 0x8000;
    cpu.regs.rbp = 0x7000;
    cpu.regs.rflags = 0x8d7 | (1 << 10);
    let owner = Arc::new(Mutex::new(LocalApic::new(1)));
    cpu.attach_local_apic(owner.clone());
    (cpu, owner)
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn real_native_control_helpers_use_the_attached_priority_and_preserve_failure_inputs() {
    let (mut cpu, owner) = fixture(&[0xf4]);
    let handle = owner.lock().unwrap().priority_handle();
    let mut frame = crate::smir::lower::runtime::GuestRegs {
        ctx: &mut cpu as *mut _ as u64,
        cr0: 1,
        cpl: 0,
        cs_l: 1,
        ..Default::default()
    };
    for class in 0..16 {
        // SAFETY: frame and its owning CPU remain live and exclusively used.
        assert_eq!(unsafe { rax_jit_write_control(&mut frame, 8, class) }, 1);
        assert_eq!(handle.load(), (class << 4) as u32);
        handle.store(((class << 4) | 7) as u32);
        // SAFETY: the separate frame and its owning CPU remain live; the
        // synchronous callback reads only the stable atomic priority owner.
        assert_eq!(unsafe { rax_jit_read_cr8(&mut frame) }, class + 1);
    }
    let before = frame;
    // SAFETY: the same exclusive live-frame/CPU binding remains in scope.
    assert_eq!(unsafe { rax_jit_write_control(&mut frame, 8, 16) }, 0);
    assert_eq!(frame, before);
    assert_eq!(handle.load(), 0xf7);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn compiled_region_reads_an_mmio_priority_change_in_the_same_block() {
    let (mut cpu, owner) = fixture(&[
        0xc7, 0x03, 0xa7, 0, 0, 0, // mov dword [rbx],0xa7
        0x44, 0x0f, 0x20, 0xc2, // mov rdx,cr8
        0xeb, 0, 0xf4,
    ]);
    cpu.regs.rbx = 0xfee0_0080;
    cpu.set_jit_mem(true);
    let before_flags = cpu.regs.rflags;
    let region = cpu
        .jit_compile_region()
        .unwrap()
        .expect("priority sequence is native eligible");
    cpu.jit_run_region_native(&region);
    assert_eq!(cpu.regs.rip, 12, "complete compiled block must execute");
    assert_eq!(cpu.regs.rdx, 0xa);
    assert_eq!(owner.lock().unwrap().priority_handle().load(), 0xa7);
    assert_eq!(cpu.regs.rflags, before_flags);
    assert_eq!(cpu.get_sregs().unwrap().cr8, 0xa);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn verified_native_cr8_write_restores_the_full_priority_for_replay_and_adoption() {
    let (mut cpu, owner) = fixture(&[0x44, 0x0f, 0x22, 0xc0, 0xeb, 0, 0xf4]);
    cpu.regs.rax = 0xb;
    owner.lock().unwrap().priority_handle().store(0xa7);
    let region = cpu
        .jit_compile_region()
        .unwrap()
        .expect("CR8 write is native eligible");
    cpu.jit_run_region_verified(&region);
    assert_eq!(cpu.regs.rip, 4);
    assert_eq!(owner.lock().unwrap().priority_handle().load(), 0xb0);
    assert_eq!(cpu.get_sregs().unwrap().cr8, 0xb);
}

#[test]
fn unavailable_live_priority_deoptimizes_before_destination_or_flag_commit() {
    use crate::smir::ir::ops::{OpKind, X86ControlReg};
    use crate::smir::ir::types::{ArchReg, FunctionId, VReg, X86Reg};
    use crate::smir::ir::{FunctionBuilder, Terminator};
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};
    use crate::smir::lower::{SmirLowerer, x86_64::X86_64Lowerer};

    extern "C" fn unavailable(_: *mut GuestRegs) -> u64 {
        0
    }
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::X86ReadControl {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            control: X86ControlReg::Cr8,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(true);
    let lowered = lowerer.lower_function(&builder.finish()).unwrap();
    let executable = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
    let mut frame = GuestRegs {
        cr0: 1,
        cs_l: 1,
        cr8: 0xa,
        rflags: 0x8d7 | (1 << 10),
        control_read_fn: unavailable as usize as u64,
        ..Default::default()
    };
    for (index, value) in frame.gpr.iter_mut().enumerate() {
        *value = 0xa500_0000_0000_0000 | index as u64;
    }
    let before = frame;
    executable.run(lowered.entry_offset, &mut frame);
    assert_eq!(frame.exit_pc, 0x1000);
    assert_eq!(frame.gpr, before.gpr);
    assert_eq!(frame.rflags, before.rflags);
    assert_eq!(frame.cr8, before.cr8);
}
