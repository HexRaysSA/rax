use super::*;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn memory() -> Arc<GuestMemoryMmap> {
    Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap())
}

fn context(cpu: &Aarch64Vcpu) -> Context {
    let raw = cpu.capture_backend_context().unwrap().unwrap();
    Context::decode(&raw.data, cpu).unwrap()
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
