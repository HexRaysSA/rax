use super::*;
use crate::error::{GuestMemoryFault, MemoryAccessKind};
use crate::isa::x86_64::gdt_entry;
use crate::vm::memory::FlatTranslation;
use crate::vm::snapshot::ResourcesSnapshot;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn cpu(code: &[u8]) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(0x100)).unwrap();
    let mut cpu = X86_64Vcpu::new(0, memory.clone());
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.rip = 0x100;
    state.regs.rsp = 0x7000;
    state.regs.rax = 0x11223344;
    state.regs.rflags = 2;
    state.sregs.cr0 = 0;
    state.sregs.cr3 = 0;
    state.sregs.cr4 = 0;
    state.sregs.efer = 0;
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    state.sregs.cs.limit = 0xffff;
    state.sregs.cs.present = true;
    state.sregs.cs.type_ = 11;
    state.sregs.cs.s = true;
    state.sregs.cs.db = false;
    state.sregs.cs.l = false;
    state.sregs.ss = state.sregs.cs.clone();
    state.sregs.ss.type_ = 3;
    state.sregs.ds = state.sregs.ss.clone();
    state.sregs.es = state.sregs.ss.clone();
    state.sregs.idt.limit = 0x3ff;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    (cpu, memory)
}
fn rax(cpu: &X86_64Vcpu) -> u64 {
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.rax
}

#[test]
fn private_profile_counters_fpu_lazy_state_and_controls_roundtrip_exactly() {
    let (mut source, _) = cpu(&[0x90]);
    source.insn_count = 0x123456789abcdef0;
    source.instruction_faulted = true;
    source.xeon_phi_avx512 = true;
    source.vp2intersect = true;
    source.sse4a = true;
    source.tbm = true;
    source.xop = true;
    source.avx10_media = true;
    source.avx10_vminmax = true;
    source.avx10_sat_convert = true;
    source.apx = true;
    source.set_xcr0((1 << 19) | 0x2e7).unwrap();
    source.set_xgetbv1_value(0x123456789);
    source.regs.xmm[15] = [0x123, 0x456];
    source.regs.zmm_ext[15] = [0xfeed; 8];
    source.regs.k[7] = 0x765;
    source.fpu.st[3] = [0xa5; 10];
    source.fpu.top = 3;
    source.lazy_flags = LazyFlags {
        op: LazyFlagOp::Add,
        result: 0xff,
        src: 1,
        dst: 0xfe,
        size: 1,
    };
    source.halted = true;
    source.interrupt_inhibit = true;
    source.jit_disabled_by_embedder = true;
    source.jit_mem = false;
    source.jit_call = false;
    source.jit_vsib_resume_pc = Some(0x777);
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0x90]);
    target.restore_context(&raw).unwrap();
    assert_eq!(target.save_context().unwrap(), raw);
}

#[test]
fn pending_register_input_completes_once_with_the_original_retirement_count() {
    let (mut source, _) = cpu(&[0xe4, 0x80, 0xf4]);
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(VcpuExit::IoIn {
            port: 0x80,
            size: 1
        })
    ));
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0xe4, 0x80, 0xf4]);
    target.restore_context(&raw).unwrap();
    source.complete_io_in(&[0xa5]);
    target.complete_io_in(&[0xa5]);
    assert_eq!(rax(&source), 0x112233a5);
    assert_eq!(rax(&target), rax(&source));
    assert_eq!(target.instruction_count(), source.instruction_count());
    target.complete_io_in(&[0x77]);
    assert_eq!(rax(&target), 0x112233a5);
    assert!(matches!(target.step_insn().unwrap(), Some(VcpuExit::Hlt)));
}

#[test]
fn repeated_string_input_restores_the_exact_pending_destination_in_both_directions() {
    for backward in [false, true] {
        let (mut source, memory) = cpu(&[0xf3, 0x6c, 0xf4]);
        source.regs.rdi = 0x2004;
        source.regs.rcx = 3;
        source.regs.rdx = 0x80;
        if backward {
            source.regs.rflags |= flags::bits::DF;
        }
        assert!(matches!(
            source.step_insn().unwrap(),
            Some(VcpuExit::IoIn {
                port: 0x80,
                size: 1
            })
        ));
        let raw = source.save_context().unwrap();
        let (mut target, other) = cpu(&[0xf3, 0x6c, 0xf4]);
        target.restore_context(&raw).unwrap();
        for value in [0x11, 0x22, 0x33] {
            source.complete_io_in(&[value]);
            target.complete_io_in(&[value]);
            // A duplicate completion must not consume the next REP element.
            target.complete_io_in(&[0xff]);
            if value != 0x33 {
                assert!(matches!(
                    source.step_insn().unwrap(),
                    Some(VcpuExit::IoIn {
                        port: 0x80,
                        size: 1
                    })
                ));
                assert!(matches!(
                    target.step_insn().unwrap(),
                    Some(VcpuExit::IoIn {
                        port: 0x80,
                        size: 1
                    })
                ));
            }
        }
        for (lane, value) in [0x11u8, 0x22, 0x33].into_iter().enumerate() {
            let address = if backward {
                0x2004 - lane as u64
            } else {
                0x2004 + lane as u64
            };
            assert_eq!(memory.read_obj::<u8>(GuestAddress(address)).unwrap(), value);
            assert_eq!(other.read_obj::<u8>(GuestAddress(address)).unwrap(), value);
        }
        assert_eq!(target.current_pc(), 0x102);
        assert_eq!(
            target.save_context().unwrap(),
            source.save_context().unwrap()
        );
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn actual_native_input_exit_survives_restore_without_replay_or_extra_retirement() {
    // ADD EBX,1; IN AL,80h; INC ECX; HLT. Save between the native
    // helper's publication and the public run loop's delivery of the exit.
    let code = [0x83, 0xc3, 1, 0xe4, 0x80, 0xff, 0xc1, 0xf4];
    let (mut source, _) = cpu(&code);
    source.sregs.cr0 = 1;
    source.sregs.efer = 1 << 10;
    source.sregs.cs.l = true;
    source.regs.rbx = 9;
    source.regs.rcx = 7;
    source.set_jit_mem(false);
    source.set_jit_call(false);
    let region = source
        .jit_compile_region()
        .unwrap()
        .expect("native scalar-I/O admission");
    assert!(region.uses_io);
    assert!(source.jit_try_block().unwrap());
    assert!(matches!(
        source.jit_callout_exit,
        Some(VcpuExit::IoIn {
            port: 0x80,
            size: 1
        })
    ));
    assert_eq!(source.regs.rbx, 10);
    assert_eq!(source.regs.rcx, 7);
    let raw = source.save_context().unwrap();
    let (mut target, memory) = cpu(&[0xb0, 0x77, 0xf4]);
    target.step_insn().unwrap(); // Populate the target's old decode cache.
    memory.write_slice(&code, GuestAddress(0x100)).unwrap();
    target.restore_context(&raw).unwrap();
    let count = source.instruction_count();
    assert_eq!(count, 2);
    for cpu in [&mut source, &mut target] {
        assert!(matches!(
            cpu.step_insn().unwrap(),
            Some(VcpuExit::IoIn {
                port: 0x80,
                size: 1
            })
        ));
        assert_eq!(cpu.instruction_count(), count);
        cpu.complete_io_in(&[0xa5]);
        assert_eq!(cpu.regs.rax, 0x112233a5);
        cpu.complete_io_in(&[0x77]);
        assert_eq!(cpu.regs.rax, 0x112233a5);
        assert!(cpu.step_insn().unwrap().is_none());
        assert_eq!(cpu.regs.rcx, 8);
        assert_eq!(cpu.instruction_count(), count + 1);
    }
    assert_eq!(
        source.save_context().unwrap(),
        target.save_context().unwrap()
    );
}

struct Identity;
impl FlatTranslation for Identity {
    fn translate(
        &self,
        address: u64,
        _: MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        Ok(address)
    }
}

#[test]
fn user_syscall_trap_survives_import_and_is_consumed_once() {
    let (mut source, _) = cpu(&[0x0f, 0x05]);
    source.enable_user_mode(Arc::new(Identity));
    source.regs.rip = 0x100;
    assert!(matches!(
        source.step_insn().unwrap(),
        Some(VcpuExit::SystemCall)
    ));
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0x0f, 0x05]);
    target.enable_user_mode(Arc::new(Identity));
    target.restore_context(&raw).unwrap();
    let trap = source.take_user_trap().expect("source syscall trap");
    assert_eq!(target.take_user_trap(), Some(trap));
    assert_eq!(target.take_user_trap(), None);
    assert_eq!(source.current_pc(), 0x102);
    assert_eq!(target.current_pc(), 0x102);
    assert_eq!(target.instruction_count(), 1);
    assert_eq!(
        target.save_context().unwrap(),
        source.save_context().unwrap()
    );
}
#[test]
fn actual_user_tls_selector_load_succeeds_after_full_context_import() {
    let (mut source, _) = cpu(&[0x8e, 0xe0, 0xf4]);
    source.enable_user_mode(Arc::new(Identity));
    source.regs.rip = 0x100;
    source.regs.rax = 0x63;
    assert!(source.set_user_tls_entry(12, gdt_entry(0xc0f3, 0x12345000, 0xfffff)));
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0x8e, 0xe0, 0xf4]);
    target.enable_user_mode(Arc::new(Identity));
    target.restore_context(&raw).unwrap();
    assert!(source.step_insn().unwrap().is_none());
    assert!(target.step_insn().unwrap().is_none());
    assert_eq!(source.sregs.fs.base, 0x12345000);
    assert_eq!(
        crate::codec::serialize(&target.sregs.fs).unwrap(),
        crate::codec::serialize(&source.sregs.fs).unwrap()
    );
}

#[test]
fn detached_complete_bios_resource_restores_a_fresh_cpu_before_unread_sector_access() {
    let (mut source, memory) = cpu(&[0xcd, 0x13, 0xf4]);
    let mut dap = [0; 16];
    dap[0] = 16;
    dap[2] = 1;
    dap[5] = 0x10;
    memory.write_slice(&dap, GuestAddress(0x800)).unwrap();
    source.regs.rax = 0x4200;
    source.regs.rsi = 0x800;
    source.regs.rdx = 0xe0;
    source.attach_x86_64_bios(Some(Arc::new(vec![0xa5; 2048])), 128 << 20);
    let raw = source.save_context().unwrap();
    let media = ResourcesSnapshot::capture(source.checkpoint_media().unwrap())
        .unwrap()
        .prepare()
        .unwrap();
    let (mut target, other) = cpu(&[0xcd, 0x13, 0xf4]);
    other.write_slice(&dap, GuestAddress(0x800)).unwrap();
    let before = target.save_context().unwrap();
    assert!(target.restore_context(&raw).is_err());
    assert_eq!(target.save_context().unwrap(), before);
    target.restore_context_with_resources(&raw, &media).unwrap();
    source.step_insn().unwrap();
    target.step_insn().unwrap();
    let mut a = [0; 2048];
    let mut b = [0; 2048];
    memory.read_slice(&mut a, GuestAddress(0x1000)).unwrap();
    other.read_slice(&mut b, GuestAddress(0x1000)).unwrap();
    assert_eq!(a, [0xa5; 2048]);
    assert_eq!(a, b);
    assert_eq!(source.current_pc(), target.current_pc());
}

#[test]
fn xgetbv_observes_the_preserved_extended_control_register() {
    let (mut source, _) = cpu(&[0x0f, 0x01, 0xd0, 0xf4]);
    source.sregs.cr4 = 1 << 18;
    source.regs.rcx = 0;
    source.set_xcr0(3).unwrap();
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0x0f, 0x01, 0xd0, 0xf4]);
    target.restore_context(&raw).unwrap();
    source.step_insn().unwrap();
    target.step_insn().unwrap();
    assert_eq!(rax(&source), 3);
    assert_eq!(rax(&target), 3);
}

#[test]
fn every_truncation_and_public_private_disagreement_rejects_before_mutation() {
    let (source, _) = cpu(&[0x90]);
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0x90]);
    target.regs.rax = 0x99;
    let before = target.save_context().unwrap();
    for end in 0..raw.len() {
        assert!(target.restore_context(&raw[..end]).is_err(), "prefix{end}");
        assert_eq!(target.save_context().unwrap(), before);
    }
    let mut trailer = raw.clone();
    trailer.push(0);
    assert!(target.restore_context(&trailer).is_err());
    assert_eq!(target.save_context().unwrap(), before);
    let mut state = source.get_state().unwrap();
    let CpuState::X86_64(s) = &mut state else {
        panic!()
    };
    s.regs.rax ^= 1;
    let context = crate::vm::snapshot::BackendContext {
        kind: crate::vm::snapshot::X86_64_CONTEXT,
        data: raw,
    };
    assert!(
        target
            .validate_checkpoint_context(
                &state,
                &source.get_emulator_state().unwrap(),
                Some(&context)
            )
            .is_err()
    );
    assert_eq!(target.save_context().unwrap(), before);
}

#[test]
fn saved_deferred_exit_precedes_execution_and_is_published_only_once() {
    let (mut source, _) = cpu(&[0xb0, 0x31, 0xf4]);
    source.insn_count = 5;
    source.jit_callout_exit = Some(VcpuExit::IoOut {
        port: 0x80,
        data: vec![0x5a],
    });
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0xb0, 0x31, 0xf4]);
    target.restore_context(&raw).unwrap();
    assert!(
        matches!(target.step_insn().unwrap(),Some(VcpuExit::IoOut {port:0x80,data}) if data==[0x5a])
    );
    assert_eq!(target.instruction_count(), 5);
    assert_eq!(target.current_pc(), 0x100);
    assert!(target.step_insn().unwrap().is_none());
    assert_eq!(target.instruction_count(), 6);
    assert_eq!(rax(&target) & 0xff, 0x31);
}

#[test]
fn architectural_reset_clears_portable_pending_state_and_retains_isa_selection() {
    let (mut source, _) = cpu(&[0xe4, 0x80]);
    let config = X86_64Config {
        apx: true,
        sse4a: true,
        ..Default::default()
    };
    source.set_x86_configuration(config).unwrap();
    source.step_insn().unwrap();
    source.jit_callout_exit = Some(VcpuExit::IoOut {
        port: 0x80,
        data: vec![7],
    });
    source.jit_vsib_resume_pc = Some(0x100);
    source.reset().unwrap();
    assert!(source.io_pending.is_none());
    assert!(source.jit_callout_exit.is_none());
    assert!(source.jit_vsib_resume_pc.is_none());
    assert_eq!(source.instruction_count(), 0);
    assert_eq!(source.xcr0(), 1);
    assert_eq!(source.x86_configuration(), config);
}

#[test]
fn incompatible_isa_reconfiguration_preserves_the_existing_context() {
    let (mut source, _) = cpu(&[0x90]);
    source
        .set_x86_configuration(X86_64Config {
            apx: true,
            ..Default::default()
        })
        .unwrap();
    source.set_xcr0((1 << 19) | 1).unwrap();
    let before = source.save_context().unwrap();
    assert!(
        source
            .set_x86_configuration(X86_64Config::default())
            .is_err()
    );
    assert_eq!(source.save_context().unwrap(), before);
}

#[test]
fn pre_integration_user_context_retains_its_original_wire_layout() {
    let raw = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/x86-context-integration/user-v1.bin"
    ));
    let (mut target, _) = cpu(&[0x0f, 0x05]);
    target.enable_user_mode(Arc::new(Identity));
    target.restore_context(raw).unwrap();
    assert_eq!(target.current_pc(), 0x102);
    assert_eq!(target.instruction_count(), 1);
    assert_eq!(target.last_user_debug_status(), 0);
    assert!(matches!(
        target.take_user_trap(),
        Some(crate::isa::x86_64::X86UserTrap::SystemCall {
            insn: crate::isa::x86_64::X86SyscallInsn::Syscall,
            insn_rip: 0x100
        })
    ));
    assert_eq!(target.take_user_trap(), None);
}

#[test]
fn versioned_user_context_preserves_consumed_debug_status() {
    let (mut source, _) = cpu(&[0x90]);
    source.enable_user_mode(Arc::new(Identity));
    source.sregs.dr6 = (1 << 14) | (1 << 13);
    let status = source.capture_user_debug_status();
    assert_eq!(status, (1 << 14) | (1 << 13));
    let raw = source.save_context().unwrap();
    assert!(raw.starts_with(b"RAXX8603"));
    let (mut target, _) = cpu(&[0x90]);
    target.enable_user_mode(Arc::new(Identity));
    target.restore_context(&raw).unwrap();
    assert_eq!(target.sregs.dr6, 0);
    assert_eq!(target.last_user_debug_status(), status);
    assert_eq!(target.save_context().unwrap(), raw);
}

#[test]
fn debug_status_binding_and_version_mismatches_reject_before_mutation() {
    for user_mode in [false, true] {
        let (mut source, _) = cpu(&[0x90]);
        let (mut target, _) = cpu(&[0x90]);
        if user_mode {
            source.enable_user_mode(Arc::new(Identity));
            target.enable_user_mode(Arc::new(Identity));
        }
        let raw = source.save_context().unwrap();
        let before = target.save_context().unwrap();
        let context = Context::decode(&raw, &source).unwrap();
        let bad = Version2 {
            base: &context,
            user_debug_status: if user_mode { None } else { Some(0) },
        };
        let mut invalid = VERSION2_TAG.to_vec();
        invalid.extend_from_slice(&crate::codec::serialize(&bad).unwrap());
        assert!(target.restore_context(&invalid).is_err());
        assert_eq!(target.save_context().unwrap(), before);

        let mut wrong_version = raw;
        wrong_version[..TAG.len()].copy_from_slice(LEGACY_TAG);
        assert!(target.restore_context(&wrong_version).is_err());
        assert_eq!(target.save_context().unwrap(), before);
    }
}

#[test]
fn every_versioned_user_context_prefix_rejects_before_mutation() {
    let (mut source, _) = cpu(&[0x90]);
    source.enable_user_mode(Arc::new(Identity));
    source.sregs.dr6 = 1 << 14;
    source.capture_user_debug_status();
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0x90]);
    target.enable_user_mode(Arc::new(Identity));
    target.regs.rax = 0x99;
    let before = target.save_context().unwrap();
    for end in 0..raw.len() {
        assert!(target.restore_context(&raw[..end]).is_err(), "prefix {end}");
        assert_eq!(target.save_context().unwrap(), before);
    }
}

#[test]
fn invalid_extended_controls_reject_on_capture_and_before_import_mutation() {
    let (mut source, _) = cpu(&[0x90]);
    source.set_apx_enabled(true);
    source.set_xcr0((1 << 19) | 1).unwrap();
    source.set_apx_enabled(false);
    assert!(source.save_context().is_err());
    let (valid, _) = cpu(&[0x90]);
    let raw = valid.save_context().unwrap();
    let mut context = Context::decode(&raw, &valid).unwrap();
    context.xcr0 = 0;
    let bad = context.encode().unwrap();
    let (mut target, _) = cpu(&[0x90]);
    let before = target.save_context().unwrap();
    assert!(target.restore_context(&bad).is_err());
    assert_eq!(target.save_context().unwrap(), before);
}

#[cfg(feature = "debug")]
#[test]
fn saved_debug_breakpoint_and_pending_exit_keep_delivery_order() {
    let (mut source, _) = cpu(&[0x90]);
    source.set_debugger_active(true);
    source.set_debug_breakpoint(0x100).unwrap();
    source.jit_callout_exit = Some(VcpuExit::IoOut {
        port: 0x80,
        data: vec![7],
    });
    let raw = source.save_context().unwrap();
    let (mut target, _) = cpu(&[0x90]);
    target.restore_context(&raw).unwrap();
    assert!(matches!(
        target.step_insn().unwrap(),
        Some(VcpuExit::IoOut { .. })
    ));
    assert!(matches!(
        target.step_insn().unwrap(),
        Some(VcpuExit::GdbBreakpoint { addr: 0x100 })
    ));
    assert_eq!(target.instruction_count(), 0);
}
