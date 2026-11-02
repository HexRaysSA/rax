use super::*;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn memory() -> Arc<GuestMemoryMmap> {
    Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap())
}

fn context(cpu: &Aarch64Vcpu) -> Context {
    let raw = cpu.capture_backend_context().unwrap().unwrap();
    Context::decode(&raw.data, cpu).unwrap()
}

fn add_legacy_offset_alias(context: &mut Context, public: &mut CpuState, offset: u64) {
    let encoding =
        crate::isa::arm::common::sysreg::Aarch64SysRegEncoding::new(3, 4, 14, 0, 3).encode();
    let mut value = serde_json::to_value(&context.core).unwrap();
    value["sysregs"]["impl_defined"][encoding.to_string()] = serde_json::json!(offset);
    context.core = serde_json::from_value(value).unwrap();
    let CpuState::Aarch64(public) = public else {
        panic!()
    };
    public
        .sregs
        .execution
        .as_mut()
        .unwrap()
        .sysregs
        .impl_defined
        .insert(encoding, offset);
}

#[test]
fn legacy_offset_alias_is_imported_into_the_modeled_virtual_counter_bank() {
    let mut source = Aarch64Vcpu::new(0, memory());
    source.cpu.set_generic_counter(1234);
    let mut state = source.get_state().unwrap();
    let mut image = context(&source);
    add_legacy_offset_alias(&mut image, &mut state, 13);
    let raw = image.record().unwrap();
    assert!(raw.data.starts_with(TAG));
    let destination = memory();
    destination
        .write_slice(&0xd53b_e040u32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    let mut target = Aarch64Vcpu::new(0, destination);
    target
        .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
        .unwrap();
    assert!(!target.cpu.has_legacy_counter_offset());
    target.step_insn().unwrap();
    assert_eq!(target.cpu.get_gpr(0), 1234 + 16 - 13);
}

#[test]
fn shared_counter_records_reject_legacy_offset_shadows_before_publication() {
    use crate::vm::timing::{ClockMode, TimingContext};
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let source = Aarch64Vcpu::new(0, memory());
    let mut state = source.get_state().unwrap();
    let mut image = context(&source);
    add_legacy_offset_alias(&mut image, &mut state, 13);
    let raw = image.record().unwrap();
    assert!(raw.data.starts_with(counter_clock::TAG));
    let mut target = Aarch64Vcpu::new(0, memory());
    let before = CoreCheckpoint::capture(&target.cpu).unwrap();
    assert!(
        target
            .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
            .unwrap_err()
            .to_string()
            .contains("legacy offset shadow")
    );
    assert_eq!(CoreCheckpoint::capture(&target.cpu).unwrap(), before);
}

#[test]
fn counter_replacement_retains_target_clock_and_does_not_sample_it_while_preparing() {
    use crate::vm::timing::{ClockMode, TimingContext};
    let source_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    source_clock.set_resume_base(1_000_000_000);
    let mut source = {
        let _scope = source_clock.enter();
        Aarch64Vcpu::new(0, memory())
    };
    source.cpu.set_generic_counter(1234); // Retain an older cached sample.
    let state = source.get_state().unwrap();
    let raw = source.capture_backend_context().unwrap().unwrap();
    let target_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    target_clock.set_resume_base(160); // Ten ticks at the platform frequency.
    let destination = memory();
    destination
        .write_slice(&0xd53b_e020u32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    let mut target = {
        let _scope = target_clock.enter();
        Aarch64Vcpu::new(0, destination)
    };
    let before = CoreCheckpoint::capture(&source.cpu).unwrap();
    target
        .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
        .unwrap();
    assert_eq!(CoreCheckpoint::capture(&target.cpu).unwrap(), before);
    let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    foreign.set_resume_base(4_000_000_000);
    let _foreign = foreign.enter();
    target.step_insn().unwrap();
    assert_eq!(target.cpu.get_gpr(0), 10);
    assert_eq!(target_clock.elapsed_nanos(), 160);
}

#[test]
fn legacy_instruction_counter_records_do_not_silently_acquire_a_vm_clock() {
    use crate::vm::timing::{ClockMode, TimingContext};
    let mut source = Aarch64Vcpu::new(0, memory());
    source.cpu.set_generic_counter(1234);
    let state = source.get_state().unwrap();
    let raw = source.capture_backend_context().unwrap().unwrap();
    assert!(raw.data.starts_with(TAG));
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    clock.set_resume_base(1_000_000_000);
    let destination = memory();
    destination
        .write_slice(&0xd53b_e020u32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    let mut target = {
        let _scope = clock.enter();
        Aarch64Vcpu::new(0, destination)
    };
    assert!(target.cpu.system_counter_state().is_some());
    target
        .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
        .unwrap();
    assert!(target.cpu.system_counter_state().is_none());
    target.step_insn().unwrap();
    assert_eq!(target.cpu.get_gpr(0), 1250);
    assert_eq!(clock.elapsed_nanos(), 1_000_000_000);
}

#[test]
fn counter_output_lock_failure_does_not_acknowledge_the_unpublished_timer_level() {
    use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
    use crate::vm::timing::{ClockMode, TimingContext};
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut cpu = Aarch64Vcpu::new(0, memory());
    cpu.cpu
        .write_sysreg(Aarch64SysRegEncoding::new(3, 3, 14, 2, 1), 1)
        .unwrap();
    let before = CoreCheckpoint::capture(&cpu.cpu).unwrap();
    let gic = cpu.cpu.gic_handle().unwrap();
    assert!(
        std::thread::spawn(move || {
            let _guard = gic.lock().unwrap();
            panic!("deliberate test-only GIC lock poisoning");
        })
        .join()
        .is_err()
    );
    assert!(
        cpu.poll_vm_clock()
            .unwrap_err()
            .to_string()
            .contains("GIC lock poisoned")
    );
    assert_eq!(CoreCheckpoint::capture(&cpu.cpu).unwrap(), before);
    assert_eq!(clock.retirement_count(), Some(0));
}

#[test]
fn counter_record_rejects_mode_frequency_and_header_defects_without_changing_target() {
    use crate::vm::timing::{ClockMode, TimingContext};
    let source_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let source = {
        let _scope = source_clock.enter();
        Aarch64Vcpu::new(0, memory())
    };
    let raw = source.capture_backend_context().unwrap().unwrap();
    assert!(raw.data.starts_with(counter_clock::TAG));
    let state = source.get_state().unwrap();
    let target_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let mut target = {
        let _scope = target_clock.enter();
        Aarch64Vcpu::new(0, memory())
    };
    let before = CoreCheckpoint::capture(&target.cpu).unwrap();
    for defect in 0..7 {
        let mut bad = raw.clone();
        match defect {
            0 => bad.data.truncate(16),
            1 => bad.data[8] = 2,
            2 => bad.data[8] = 0,
            3 => bad.data[9..17].copy_from_slice(&0u64.to_le_bytes()),
            4 => bad.data[9..17].copy_from_slice(&62_500_001u64.to_le_bytes()),
            5 => bad.data[9..17].copy_from_slice(&u64::MAX.to_le_bytes()),
            6 => bad.data.push(0),
            _ => unreachable!(),
        }
        assert!(
            target
                .restore_checkpoint_context(&state, &Default::default(), Some(&bad))
                .is_err(),
            "defect {defect}"
        );
        assert_eq!(CoreCheckpoint::capture(&target.cpu).unwrap(), before);
        assert_eq!(target_clock.retirement_count(), Some(0));
    }
}

#[test]
fn detached_cpu_cannot_run_until_ram_and_reservation_publication_complete() {
    let source_memory = memory();
    source_memory
        .write_slice(&0x885f_7c20u32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    source_memory
        .write_slice(&0x8802_7c20u32.to_le_bytes(), GuestAddress(4))
        .unwrap();
    source_memory
        .write_slice(&0x1234_5678u32.to_le_bytes(), GuestAddress(0x100))
        .unwrap();
    let mut source = Aarch64Vcpu::new_micro(0, source_memory.clone());
    source.cpu.set_gpr(1, 0x100);
    assert_eq!(source.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(
        source.exclusive.get(),
        Some(Reservation {
            address: 0x100,
            size: 4
        })
    );
    let state = source.get_state().unwrap();
    let raw = source.capture_backend_context().unwrap().unwrap();
    let destination = memory();
    let target = Aarch64Vcpu::new_micro(0, destination.clone());
    let mut prepared = target.prepare_private_checkpoint(&state, &raw).unwrap();
    assert!(prepared.step_insn().is_err());
    assert!(prepared.exclusive.get().is_none());
    let bindings = CheckpointBindings::new(&destination, prepared.checkpoint_owned_gics());
    {
        let scope = bindings.enter().unwrap();
        let permit = prepared.publication(&scope).unwrap();
        let mut bytes = vec![0; 0x4000];
        source_memory
            .read_slice(&mut bytes, GuestAddress(0))
            .unwrap();
        scope.write(0, &bytes).unwrap();
        assert!(prepared.exclusive.get().is_none());
        permit.commit();
        assert_eq!(prepared.exclusive.get(), source.exclusive.get());
    }
    assert_eq!(prepared.run_retirement_budget(1).unwrap().retired, 1);
    assert_eq!(prepared.cpu.get_gpr(2), 0);
    assert!(prepared.exclusive.get().is_none());
}

#[test]
fn adapter_observations_owned_controller_and_execution_flags_roundtrip() {
    let mut source = Aarch64Vcpu::new_micro(0, memory());
    source.insn_count.store(91, Ordering::Relaxed);
    source.trace_reg_last = 0xfeed;
    source.heartbeat_offset = std::time::Duration::from_secs(17);
    source.shutdown = true;
    source.powered_off = true;
    source.recorder.enabled.store(true, Ordering::Relaxed);
    source
        .recorder
        .record(MemAccess::Write, 0x100, &[1, 2, 3, 4]);
    source
        .cpu
        .gic_handle()
        .unwrap()
        .lock()
        .unwrap()
        .set_pending(40);
    let expected = context(&source);
    let raw = source.capture_backend_context().unwrap().unwrap();
    let mut target = Aarch64Vcpu::new_micro(0, memory());
    target
        .restore_checkpoint_context(
            &source.get_state().unwrap(),
            &Default::default(),
            Some(&raw),
        )
        .unwrap();
    let restored = context(&target);
    assert_eq!(restored.core, expected.core);
    assert_eq!(restored.observed_instructions, 91);
    assert_eq!(restored.trace_reg_last, 0xfeed);
    assert!(restored.heartbeat_age >= std::time::Duration::from_secs(17));
    assert!(restored.shutdown && restored.powered_off && restored.recording);
    assert_eq!(restored.observations, expected.observations);
    assert_eq!(
        crate::codec::serialize(&restored.owned_gic).unwrap(),
        crate::codec::serialize(&expected.owned_gic).unwrap()
    );
    let mut records = Vec::new();
    target.drain_mem_records(&mut records);
    assert_eq!(records, expected.observations);
    target.drain_mem_records(&mut records);
    assert_eq!(records, expected.observations);
}

#[test]
fn malformed_contexts_and_projection_disagreement_do_not_change_live_cpu_or_ram() {
    let source = Aarch64Vcpu::new_micro(0, memory());
    let state = source.get_state().unwrap();
    let raw = source.capture_backend_context().unwrap().unwrap();
    let destination = memory();
    destination
        .write_slice(&[0x77; 16], GuestAddress(0x100))
        .unwrap();
    let mut target = Aarch64Vcpu::new_micro(0, destination.clone());
    target.cpu.set_gpr(9, 0xbeef);
    let before = CoreCheckpoint::capture(&target.cpu).unwrap();
    for defect in 0..8 {
        let mut bad = raw.clone();
        match defect {
            0 => bad.data[0] ^= 1,
            1 => {
                bad.data.pop();
            }
            2 => bad.data.push(0),
            3 => bad.kind = crate::vm::snapshot::X86_64_CONTEXT,
            4..=7 => {
                let mut payload = Context::decode(&raw.data, &source).unwrap();
                match defect {
                    4 => payload.id = 1,
                    5 => payload.clustered = true,
                    6 => {
                        payload.reservation = Some(Reservation {
                            address: 3,
                            size: 8,
                        })
                    }
                    7 => {
                        payload.reservation = Some(Reservation {
                            address: 0x4000,
                            size: 8,
                        })
                    }
                    _ => unreachable!(),
                }
                bad.data = TAG.to_vec();
                bad.data
                    .extend_from_slice(&crate::codec::serialize(&payload).unwrap());
            }
            _ => unreachable!(),
        }
        assert!(
            target
                .restore_checkpoint_context(&state, &Default::default(), Some(&bad))
                .is_err(),
            "defect {defect}"
        );
        assert_eq!(CoreCheckpoint::capture(&target.cpu).unwrap(), before);
        let mut bytes = [0; 16];
        destination
            .read_slice(&mut bytes, GuestAddress(0x100))
            .unwrap();
        assert_eq!(bytes, [0x77; 16]);
    }
    assert!(
        target
            .prepare_private_checkpoint(&target.get_state().unwrap(), &raw)
            .is_err()
    );
}

struct Identity;
impl FlatTranslation for Identity {
    fn translate(
        &self,
        address: u64,
        _access: MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        Ok(address)
    }
}

#[test]
fn ordered_user_traps_and_nonretirement_survive_private_context_restore() {
    for opcode in [0xd402_4681u32, 0xd420_0200] {
        let backing = memory();
        backing
            .write_slice(&opcode.to_le_bytes(), GuestAddress(0))
            .unwrap();
        let mut source = Aarch64Vcpu::new_user(0, backing, Arc::new(Identity));
        let _ = source.step_insn();
        let expected = source.user.as_ref().unwrap();
        assert!(expected.trap.is_some());
        let trap = expected.trap;
        let not_retired = expected.not_retired;
        let state = source.get_state().unwrap();
        let raw = source.capture_backend_context().unwrap().unwrap();
        let mut target = Aarch64Vcpu::new_user(0, memory(), Arc::new(Identity));
        target
            .restore_checkpoint_context(&state, &Default::default(), Some(&raw))
            .unwrap();
        assert_eq!(target.user.as_ref().unwrap().not_retired, not_retired);
        assert_eq!(target.take_user_trap(), trap);
        assert!(target.take_user_trap().is_none());
        assert_eq!(target.instruction_count(), source.instruction_count());
    }
}

#[test]
fn memory_map_reconstruction_discards_only_the_old_reservation_right() {
    let source = Aarch64Vcpu::new_micro(0, memory());
    source.exclusive.mark(0x100, 4);
    let raw = source.checkpoint_for_remap().unwrap();
    let restored = Context::decode(&raw.data, &source).unwrap();
    assert!(restored.reservation.is_none());
    assert_eq!(
        source.exclusive.get(),
        Some(Reservation {
            address: 0x100,
            size: 4
        })
    );
}

#[test]
fn legacy_migration_cannot_hide_conflicting_ids_and_new_records_require_coherence() {
    let source = Aarch64Vcpu::new_micro(0, memory());
    let mut raw_context = context(&source);
    let mut core = serde_json::to_value(&raw_context.core).unwrap();
    let pfr = core["sysregs"]["id_aa64pfr0_el1"].as_u64().unwrap();
    let isar = core["sysregs"]["id_aa64isar0_el1"].as_u64().unwrap();
    let legacy_pfr = (pfr & !((15 << 16) | (15 << 20))) | (2 << 16) | (1 << 20);
    let legacy_isar = (isar & !(15 << 48)) | (1 << 48);
    core["sysregs"]["id_aa64pfr0_el1"] = legacy_pfr.into();
    core["sysregs"]["id_aa64isar0_el1"] = legacy_isar.into();
    raw_context.core = serde_json::from_value(core).unwrap();
    let mut state = source.get_state().unwrap();
    let CpuState::Aarch64(arm) = &mut state else {
        panic!()
    };
    let sys = &mut arm.sregs.execution.as_mut().unwrap().sysregs;
    sys.id_aa64pfr0_el1 = legacy_pfr;
    sys.id_aa64isar0_el1 = legacy_isar;
    let payload = crate::codec::serialize(&raw_context).unwrap();
    let mut data = LEGACY_TAG.to_vec();
    data.extend_from_slice(&payload);
    let raw = BackendContext {
        kind: AARCH64_CONTEXT,
        data,
    };
    let mut target = Aarch64Vcpu::new_micro(0, memory());
    let before = target.get_state().unwrap();
    let prepared = target.prepare_private_checkpoint(&state, &raw).unwrap();
    prepared.cpu.validate_fp_profile().unwrap();
    assert_eq!(
        (prepared
            .cpu
            .export_sregs()
            .execution
            .unwrap()
            .sysregs
            .id_aa64isar0_el1
            >> 48)
            & 15,
        0
    );
    let mut conflicting = state.clone();
    let CpuState::Aarch64(arm) = &mut conflicting else {
        panic!()
    };
    arm.sregs
        .execution
        .as_mut()
        .unwrap()
        .sysregs
        .id_aa64isar0_el1 ^= 1 << 48;
    assert!(
        target
            .restore_checkpoint_context(
                &conflicting,
                &crate::vm::snapshot::EmulatorState::default(),
                Some(&raw)
            )
            .is_err()
    );
    let mut new_data = TAG.to_vec();
    new_data.extend_from_slice(&payload);
    assert!(
        target
            .restore_checkpoint_context(
                &state,
                &crate::vm::snapshot::EmulatorState::default(),
                Some(&BackendContext {
                    kind: AARCH64_CONTEXT,
                    data: new_data
                })
            )
            .is_err()
    );
    let (CpuState::Aarch64(actual), CpuState::Aarch64(expected)) =
        (target.get_state().unwrap(), before)
    else {
        panic!()
    };
    assert_eq!(actual, expected);
}

#[test]
fn complete_public_state_import_canonicalizes_the_legacy_virtual_offset_bank() {
    let mut source = Aarch64Vcpu::new(0, memory());
    source.cpu.set_generic_counter(1234);
    let CpuState::Aarch64(mut state) = source.get_state().unwrap() else {
        panic!()
    };
    let encoding =
        crate::isa::arm::common::sysreg::Aarch64SysRegEncoding::new(3, 4, 14, 0, 3).encode();
    state
        .sregs
        .execution
        .as_mut()
        .unwrap()
        .sysregs
        .impl_defined
        .insert(encoding, 13);
    let destination = memory();
    destination
        .write_slice(&0xd53b_e040u32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    let mut target = Aarch64Vcpu::new(0, destination);
    target.set_state(&CpuState::Aarch64(state)).unwrap();
    assert!(!target.cpu.has_legacy_counter_offset());
    target.step_insn().unwrap();
    assert_eq!(target.cpu.get_gpr(0), 1234 + 16 - 13);
}
