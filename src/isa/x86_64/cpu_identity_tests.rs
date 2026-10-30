//! Per-CPU initial APIC identity and writable bootstrap-processor state.
use super::*;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn fixture(id: u32, code: &[u8]) -> X86_64Vcpu {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap());
    memory.write_slice(code, GuestAddress(0)).unwrap();
    let mut cpu = X86_64Vcpu::new(id, memory);
    cpu.sregs.cr0 = 0x50033;
    cpu.sregs.cr4 = 1 << 5;
    cpu.sregs.efer = (1 << 8) | (1 << 10);
    cpu.sregs.cs.l = true;
    cpu.sregs.cs.selector = 0;
    cpu.regs.rip = 0;
    cpu.regs.rsp = 0x8000;
    cpu.regs.rbp = 0x7000;
    cpu.regs.rflags = 2;
    cpu
}

#[test]
fn configured_initial_apic_identity_reaches_public_and_actual_guest_cpuid() {
    for id in [0, 1, 2, 3, 127, 254] {
        let mut cpu = fixture(id, &[0x0f, 0xa2]);
        assert_eq!(cpu.cpuid(1, 0).1 >> 24, id);
        cpu.regs.rax = 1;
        assert!(cpu.step_insn().unwrap().is_none());
        assert_eq!(cpu.regs.rbx >> 24, u64::from(id));
    }
}

#[test]
fn standalone_lapic_starts_with_configured_identity_and_restores_current_identity() {
    let code = [0x8b, 0x03, 0x89, 0x03, 0x8b, 0x03]; // MOV EAX,[RBX]; MOV [RBX],EAX; MOV EAX,[RBX]
    for id in [0, 1, 3, 254] {
        let mut source = fixture(id, &code);
        source.regs.rbx = 0xfee0_0020;
        assert!(source.step_insn().unwrap().is_none());
        assert_eq!(source.regs.rax >> 24, u64::from(id));
        assert_eq!(source.cpuid(1, 0).1 >> 24, id);
        let current = id + 1;
        source.regs.rax = u64::from(current << 24);
        assert!(source.step_insn().unwrap().is_none());
        let raw = source.save_context().unwrap();
        let mut target = fixture(id, &code);
        target.restore_context(&raw).unwrap();
        assert_eq!(target.save_context().unwrap(), raw);
        assert!(target.step_insn().unwrap().is_none());
        assert_eq!(target.regs.rax >> 24, u64::from(current));
        assert_eq!(target.cpuid(1, 0).1 >> 24, id);
    }
}

#[test]
fn only_the_boot_processor_starts_with_the_bsp_flag() {
    for id in [0, 1, 2, 3, 254] {
        let mut cpu = fixture(id, &[0x0f, 0x32]);
        cpu.regs.rcx = 0x1b;
        assert!(cpu.step_insn().unwrap().is_none());
        assert_eq!(cpu.regs.rax, 0xfee0_0800 | if id == 0 { 256 } else { 0 });
        assert_eq!(cpu.regs.rdx, 0);
    }
}

#[test]
fn changing_current_lapic_id_does_not_rewrite_initial_cpuid_identity() {
    let mut cpu = fixture(3, &[0x0f, 0xa2]);
    let controller = Arc::new(std::sync::Mutex::new(
        crate::devices::lapic::LocalApic::new(3),
    ));
    cpu.attach_local_apic(controller.clone());
    controller.lock().unwrap().write_register(0x20, 7 << 24);
    cpu.regs.rax = 1;
    assert!(cpu.step_insn().unwrap().is_none());
    assert_eq!(cpu.regs.rbx >> 24, 3);
    assert_eq!(controller.lock().unwrap().read_register(0x20) >> 24, 7);
}

#[test]
fn bsp_flag_writes_are_real_state_changes() {
    let mut cpu = fixture(0, &[0x0f, 0x30, 0x0f, 0x32]);
    cpu.regs.rcx = 0x1b;
    cpu.regs.rax = 0xfee0_0800;
    cpu.regs.rdx = 0;
    assert!(cpu.step_insn().unwrap().is_none());
    assert!(cpu.step_insn().unwrap().is_none());
    assert_eq!(cpu.regs.rax, 0xfee0_0800);
    assert_eq!(cpu.regs.rdx, 0);
}

#[test]
fn context_preserves_written_bsp_state_and_reads_actual_legacy_v2_inputs() {
    for id in [0, 1] {
        let expected = 0xfee0_0800 | if id == 0 { 0 } else { 256 };
        let mut source = fixture(id, &[0x0f, 0x30, 0x0f, 0x32]);
        source.regs.rcx = 0x1b;
        source.regs.rax = expected;
        source.regs.rdx = 0;
        assert!(source.step_insn().unwrap().is_none());
        let raw = source.save_context().unwrap();
        assert!(raw.starts_with(b"RAXX8603"));
        let mut target = fixture(id, &[0x0f, 0x30, 0x0f, 0x32]);
        target.restore_context(&raw).unwrap();
        assert_eq!(target.save_context().unwrap(), raw);
        assert!(target.step_insn().unwrap().is_none());
        assert_eq!(target.regs.rax, expected);
        assert_eq!(target.cpuid(1, 0).1 >> 24, id);

        let legacy: &[u8] = if id == 0 {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/development/x86-cpu-identity/legacy-v2-cpu-0.bin"
            ))
        } else {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/development/x86-cpu-identity/legacy-v2-cpu-1.bin"
            ))
        };
        let mut target = fixture(id, &[0x0f, 0x32]);
        target.restore_context(legacy).unwrap();
        assert_eq!(
            target.apic_base,
            super::super::identity::initial_apic_base(id)
        );
        assert_eq!(target.cpuid(1, 0).1 >> 24, id);
        assert!(target.save_context().unwrap().starts_with(b"RAXX8603"));
    }
}

#[test]
fn init_preserves_written_bsp_state_but_reset_restores_the_selected_boot_identity() {
    for id in [0, 1, 3] {
        let mut cpu = fixture(id, &[0x90]);
        let initial = cpu.apic_base;
        cpu.apic_base ^= 256;
        let written = cpu.apic_base;
        cpu.deliver_init().unwrap();
        assert_eq!(cpu.apic_base, written);
        assert_eq!(cpu.cpuid(1, 0).1 >> 24, id);
        cpu.reset_state();
        assert_eq!(cpu.apic_base, initial);
        assert_eq!(cpu.cpuid(1, 0).1 >> 24, id);
    }
}

#[test]
fn lifted_smir_identity_and_bsp_state_survive_all_optimization_levels() {
    use crate::smir::interpret::SmirInterpreter;
    use crate::smir::ir::context::{ArchRegState, SmirContext, X86RegState};
    use crate::smir::ir::memory::FlatMemory;
    use crate::smir::ir::types::{FunctionId, SourceArch};
    use crate::smir::ir::{FunctionBuilder, Terminator};
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};
    use crate::smir::optimize::{OptLevel, optimize_function};
    for id in [0, 1, 3, 254] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut ctx = SmirContext::new_x86_64();
            ctx.arch_regs = ArchRegState::X86_64(X86RegState::with_initial_apic_id(id));
            let mut expected_base = 0xfee0_0800 | if id == 0 { 256 } else { 0 };
            for (bytes, write, leaf) in [
                (&[0x0f, 0xa2][..], false, 1),
                (&[0x0f, 0x32][..], false, 0x1b),
                (&[0x0f, 0x30][..], true, 0x1b),
                (&[0x0f, 0x32][..], false, 0x1b),
            ] {
                let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
                    unreachable!()
                };
                x86.gpr[1] = if leaf == 1 { 0 } else { leaf };
                x86.gpr[0] = if leaf == 1 {
                    1
                } else if write {
                    0xfee0_0800 | if id == 0 { 0 } else { 256 }
                } else {
                    0
                };
                x86.gpr[2] = 0;
                let mut lifter = X86_64Lifter::strict();
                let ops = lifter
                    .lift_insn(0x1000, bytes, &mut LiftContext::new(SourceArch::X86_64))
                    .unwrap()
                    .ops;
                let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
                builder.set_terminator(Terminator::Return { values: vec![] });
                let mut function = builder.finish();
                function.blocks[0].ops = ops;
                optimize_function(&mut function, level);
                SmirInterpreter::new().execute_block(
                    &mut ctx,
                    &mut FlatMemory::new(4096),
                    &function.blocks[0],
                );
                assert!(ctx.exit_reason.is_none(), "{:?}", ctx.exit_reason);
                let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
                    unreachable!()
                };
                if leaf == 1 {
                    assert_eq!(x86.gpr[3] >> 24, u64::from(id));
                } else if write {
                    expected_base ^= 256;
                    assert_eq!(x86.apic.base, expected_base);
                } else {
                    assert_eq!(x86.gpr[0], expected_base);
                }
            }
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn compiled_cpuid_and_verified_msr_accesses_use_the_owning_cpu_identity_and_state() {
    for id in [0, 1, 3, 254] {
        let mut cpu = fixture(id, &[0x0f, 0xa2, 0xeb, 0, 0xf4]);
        cpu.regs.rax = 1;
        let region = cpu
            .jit_compile_region()
            .unwrap()
            .expect("CPUID native region");
        cpu.jit_run_region_native(&region);
        assert_eq!(cpu.regs.rip, 4);
        assert_eq!(cpu.regs.rbx >> 24, u64::from(id));

        let mut cpu = fixture(id, &[0x0f, 0x30, 0x0f, 0x32, 0xeb, 0, 0xf4]);
        let expected = cpu.apic_base ^ 256;
        cpu.regs.rcx = 0x1b;
        cpu.regs.rax = expected;
        cpu.regs.rdx = 0;
        let region = cpu
            .jit_compile_region()
            .unwrap()
            .expect("WRMSR native region");
        cpu.jit_run_region_verified(&region);
        assert_eq!(cpu.regs.rip, 2);
        assert_eq!(cpu.apic_base, expected);
        let region = cpu
            .jit_compile_region()
            .unwrap()
            .expect("RDMSR native region");
        cpu.jit_run_region_native(&region);
        assert_eq!(cpu.regs.rip, 6);
        assert_eq!(cpu.regs.rax, expected);
        assert_eq!(cpu.regs.rdx, 0);
    }
}
