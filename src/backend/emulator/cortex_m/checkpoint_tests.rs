//! Preservation, admission and publication of represented Cortex-M state.
use super::*;
use crate::isa::arm::common::cpu::ArmException;

fn cpu(variant: CortexMVariant) -> CortexMVcpu {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory
        .write_slice(&[0x00, 0xbf, 0x00, 0xbf], GuestAddress(0x1000))
        .unwrap();
    let mut cpu = CortexMVcpu::with_variant(3, memory, variant);
    cpu.set_current_pc(0x1000).unwrap();
    cpu
}
fn restored(source: &CortexMVcpu, target: &mut CortexMVcpu) {
    target
        .restore_checkpoint_context(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            Some(&source.capture_private().unwrap()),
        )
        .unwrap();
}

#[test]
fn all_models_retain_controller_side_effects_and_adapter_reservations() {
    use CortexMVariant::*;
    for variant in [
        CortexM0,
        CortexM0Plus,
        CortexM1,
        CortexM3,
        CortexM4,
        CortexM7,
        CortexM23,
        CortexM33,
        CortexM35P,
        CortexM55,
        CortexM85,
    ] {
        let mut source = cpu(variant);
        source.cpu.nvic_mut().enable(7);
        source.cpu.nvic_mut().set_pending(7);
        source.cpu.nvic_mut().set_priority(7, 0xa0);
        source.cpu.nvic_mut().set_primask(true);
        source.cpu.scb_mut().write_aircr(0x05fa_0304); // PRIGROUP and SYSRESETREQ.
        source.cpu.scb_mut().set_nmi_pending(true);
        source.cpu.systick_mut().write_rvr(5);
        source.cpu.systick_mut().write_csr(7);
        assert!(source.cpu.systick_mut().tick(7)); // sticky COUNTFLAG plus pending and phase.
        source
            .cpu
            .inject_exception(ArmException::UndefinedInstruction)
            .unwrap();
        source.cpu.memory_mut().mark_exclusive(0x2000, 4);
        *source.fault.lock().unwrap() = Some(GuestMemoryFault::unmapped(
            0x5000,
            4,
            MemoryAccessKind::Read,
        ));
        let mut target = cpu(variant);
        let memory = target.memory.clone();
        restored(&source, &mut target);
        assert!(Arc::ptr_eq(&memory, &target.memory));
        assert_eq!(
            target.capture_private().unwrap().data,
            source.capture_private().unwrap().data,
            "{variant:?}"
        );
        assert!(target.cpu.nvic().is_pending(7));
        assert!(target.cpu.nvic().is_enabled(7));
        assert!(target.cpu.scb_mut().take_reset_request());
        assert!(!target.cpu.scb_mut().take_reset_request());
        assert_ne!(target.cpu.systick_mut().read_csr() & (1 << 16), 0);
        assert_eq!(target.cpu.systick_mut().read_csr() & (1 << 16), 0);
        assert!(target.cpu.systick_mut().take_pending());
        assert!(!target.cpu.systick_mut().take_pending());
        assert!(target.cpu.memory_mut().check_exclusive(0x2000, 4));
        assert!(!target.cpu.memory_mut().check_exclusive(0x2000, 4));
        assert_eq!(
            target.cpu.pending_exceptions(),
            source.cpu.pending_exceptions()
        );
    }
}

#[test]
fn canceled_candidate_cannot_enter_or_capture_and_leaves_live_cpu_unchanged() {
    let mut source = cpu(CortexMVariant::CortexM4);
    source.step_insn().unwrap();
    let mut target = cpu(CortexMVariant::CortexM4);
    let before = target.capture_private().unwrap().data;
    let raw = source.capture_private().unwrap();
    let state = source.get_state().unwrap();
    let mut candidate = target.prepare_private(&state, &raw).unwrap();
    assert!(candidate.capture_private().is_err());
    assert!(candidate.step_insn().is_err());
    assert!(candidate.run().is_err());
    assert!(candidate.run_retirement_budget(0).is_ok());
    {
        let bindings = CheckpointBindings::new(&target.memory, vec![]);
        let scope = bindings.enter().unwrap();
        drop(candidate.publication(&scope).unwrap());
    }
    assert!(candidate.step_insn().is_err());
    assert_eq!(target.capture_private().unwrap().data, before);
    {
        let bindings = CheckpointBindings::new(&target.memory, vec![]);
        let scope = bindings.enter().unwrap();
        candidate.publication(&scope).unwrap().commit();
    }
    assert!(candidate.step_insn().unwrap().is_none());
    assert_eq!(candidate.instruction_count(), 2);
    assert_eq!(target.instruction_count(), 0);
    target.step_insn().unwrap();
    assert_eq!(target.instruction_count(), 1);
}

#[test]
fn malformed_or_conflicting_records_do_not_mutate_target_or_ram() {
    let source = cpu(CortexMVariant::CortexM4);
    let mut target = cpu(CortexMVariant::CortexM4);
    let before = target.capture_private().unwrap().data;
    let state = source.get_state().unwrap();
    let raw = source.capture_private().unwrap();
    let mut wrong_id: Context = crate::codec::deserialize(&raw.data[8..]).unwrap();
    wrong_id.id += 1;
    let mut bad_id = raw.clone();
    bad_id.data.truncate(8);
    bad_id
        .data
        .extend(crate::codec::serialize(&wrong_id).unwrap());
    let mut bad_tag = raw.clone();
    bad_tag.data[0] ^= 1;
    let mut truncated = raw.clone();
    truncated.data.pop();
    let mut wrong_kind = raw.clone();
    wrong_kind.kind += 1;
    let wrong_model = cpu(CortexMVariant::CortexM0).capture_private().unwrap();
    for bad in [bad_id, bad_tag, truncated, wrong_kind, wrong_model] {
        assert!(
            target
                .restore_checkpoint_context(&state, &EmulatorState::default(), Some(&bad))
                .is_err()
        );
        assert_eq!(target.capture_private().unwrap().data, before);
    }
    let mut conflict = source.get_state().unwrap();
    let CpuState::CortexM(ref mut s) = conflict else {
        unreachable!()
    };
    s.regs.r[0] ^= 1;
    assert!(
        target
            .restore_checkpoint_context(&conflict, &EmulatorState::default(), Some(&raw))
            .is_err()
    );
    assert_eq!(target.capture_private().unwrap().data, before);
    let mut bytes = [0; 4];
    target
        .memory
        .read_slice(&mut bytes, GuestAddress(0x1000))
        .unwrap();
    assert_eq!(bytes, [0x00, 0xbf, 0x00, 0xbf]);
}

#[test]
fn detached_cpu_rejects_publication_in_a_foreign_memory_domain() {
    let source = cpu(CortexMVariant::CortexM4);
    let mut candidate = source
        .prepare_private(
            &source.get_state().unwrap(),
            &source.capture_private().unwrap(),
        )
        .unwrap();
    let foreign = cpu(CortexMVariant::CortexM4);
    let bindings = CheckpointBindings::new(&foreign.memory, vec![]);
    let scope = bindings.enter().unwrap();
    assert!(candidate.publication(&scope).is_err());
    assert!(candidate.step_insn().is_err());
}
