//! Independent field witnesses, resource admission and detached execution.
use super::*;
use crate::vm::memory::checkpoint::CheckpointBindings;
use crate::vm::vcpu::RetirementStop;
const CODE: u64 = 0x1000;
fn memory() -> Arc<GuestMemoryMmap> {
    Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40_0000usize)]).unwrap())
}
fn source() -> GscVcpu {
    let mut c = GscVcpu::new(0, memory());
    c.cpu.set_pc(CODE);
    c.reset_entry = CODE;
    c.bridge
        .mem
        .write_slice(&0x0000_0013u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    c
}
fn prepared(source: &GscVcpu, target: &GscVcpu) -> GscVcpu {
    let (raw, r) = source.checkpoint_parts().unwrap();
    let r = PreparedResources::from_bindings(r).unwrap();
    target
        .prepare_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &raw,
            &r,
        )
        .unwrap()
}
fn publish(c: &GscVcpu) {
    let m = c.bridge.mem.clone();
    let bindings = CheckpointBindings::new(&m, vec![]);
    let scope = bindings.enter().unwrap();
    c.publication(&scope).unwrap().commit();
}
fn replace_image(
    raw: &BackendContext,
    mut image: Image,
    edit: impl FnOnce(&mut Image),
    source: &GscVcpu,
) -> (BackendContext, PreparedResources) {
    edit(&mut image);
    let resource = CheckpointResource::gsc_state(image.encode().unwrap()).unwrap();
    let ap = CheckpointResource::gsc_ap_flash(source.bridge.ap_flash.clone()).unwrap();
    let mut d = Descriptor::decode(source.id, raw).unwrap();
    d.state = resource.key();
    (
        d.encode().unwrap(),
        PreparedResources::from_bindings(vec![resource, ap]).unwrap(),
    )
}
#[test]
fn checkpoint_target_has_default_state_and_never_writes_guest_rom() {
    let ordinary = GscVcpu::new(0, memory());
    let mem = memory();
    mem.write_slice(&[0x73; 32], GuestAddress(CRYPTOLIB_HEADER))
        .unwrap();
    let target = GscVcpu::new_checkpoint_target(0, mem.clone()).unwrap();
    let mut bytes = [0; 32];
    mem.read_slice(&mut bytes, GuestAddress(CRYPTOLIB_HEADER))
        .unwrap();
    assert_eq!(bytes, [0x73; 32]);
    assert_eq!(
        Image::capture(&ordinary).unwrap().encode().unwrap(),
        Image::capture(&target).unwrap().encode().unwrap()
    );
}
#[test]
fn direct_resource_bindings_are_deterministic_and_deduplicated() {
    let c = source();
    let (a, mut resources) = c.checkpoint_parts().unwrap();
    let (b, other) = c.checkpoint_parts().unwrap();
    assert_eq!(a, b);
    assert_eq!(
        resources.iter().map(|r| r.key()).collect::<Vec<_>>(),
        other.iter().map(|r| r.key()).collect::<Vec<_>>()
    );
    resources.extend(other);
    let p = PreparedResources::from_bindings(resources).unwrap();
    assert_eq!(p.keys().count(), 2);
    assert_eq!(c.resource_references(Some(&a)).unwrap().len(), 2);
}
#[test]
fn detached_cancel_foreign_scope_and_zero_budget_do_not_enable_entry() {
    let src = source();
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    let mut c = prepared(&src, &target);
    assert!(Arc::ptr_eq(&c.bridge.mem, &target.bridge.mem));
    assert!(!Arc::ptr_eq(&c.bridge.mem, &src.bridge.mem));
    assert!(c.step_insn().is_err());
    assert!(c.checkpoint_parts().is_err());
    let z = c.run_retirement_budget(0).unwrap();
    assert_eq!(z.retired, 0);
    assert!(matches!(z.stop, RetirementStop::BudgetExhausted));
    let wrong = memory();
    let bindings = CheckpointBindings::new(&wrong, vec![]);
    let scope = bindings.enter().unwrap();
    assert!(c.publication(&scope).is_err());
    drop(scope);
    let m = c.bridge.mem.clone();
    let bindings = CheckpointBindings::new(&m, vec![]);
    let scope = bindings.enter().unwrap();
    drop(c.publication(&scope).unwrap());
    drop(scope);
    assert!(c.step_insn().is_err());
    let scope = bindings.enter().unwrap();
    scope.write(CODE, &0x02a0_0513u32.to_le_bytes()).unwrap();
    c.publication(&scope).unwrap().commit();
    drop(scope);
    assert!(c.step_insn().unwrap().is_none());
    assert_eq!(c.cpu.x(10), 42);
    assert_eq!(c.instruction_count(), 1);
}
#[test]
fn missing_resources_public_conflicts_and_foreign_ids_reject_without_mutation() {
    let src = source();
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    target
        .bridge
        .mem
        .write_slice(&[0x5a; 16], GuestAddress(CODE))
        .unwrap();
    let before = target.checkpoint_parts().unwrap().0;
    let (raw, r) = src.checkpoint_parts().unwrap();
    let resources = PreparedResources::from_bindings(r).unwrap();
    let public = src.get_state().unwrap();
    assert!(
        target
            .prepare_private(
                &public,
                &EmulatorState::default(),
                &raw,
                &PreparedResources::default()
            )
            .is_err()
    );
    let mut bad_public = public.clone();
    let CpuState::RiscV(p) = &mut bad_public else {
        panic!()
    };
    p.regs.x[10] = 7;
    assert!(
        target
            .prepare_private(&bad_public, &EmulatorState::default(), &raw, &resources)
            .is_err()
    );
    let (bad, resources) = replace_image(&raw, Image::capture(&src).unwrap(), |i| i.id = 1, &src);
    assert!(
        target
            .prepare_private(&public, &EmulatorState::default(), &bad, &resources)
            .is_err()
    );
    assert_eq!(target.checkpoint_parts().unwrap().0, before);
    let mut bytes = [0; 16];
    target
        .bridge
        .mem
        .read_slice(&mut bytes, GuestAddress(CODE))
        .unwrap();
    assert_eq!(bytes, [0x5a; 16]);
}
#[test]
fn malformed_runtime_and_profile_phases_reject_before_binding() {
    let src = source();
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    let (raw, _) = src.checkpoint_parts().unwrap();
    let public = src.get_state().unwrap();
    let edits: [fn(&mut Image); 7] = [
        |i| i.cfg.timer_div = 0,
        |i| i.bridge_cfg.uart_base = u64::MAX,
        |i| i.break_hit = 0,
        |i| i.break_hits_seen = i.break_hit,
        |i| i.tpm.next = 1,
        |i| i.shared.ap_spi_data = vec![0],
        |i| i.shared.read_counts = vec![(MMIO_LO, SPIN_THRESHOLD)],
    ];
    for edit in edits {
        let mut image = Image::capture(&src).unwrap();
        edit(&mut image);
        let bytes = image.encode().unwrap();
        let resource = CheckpointResource::gsc_state(bytes).unwrap();
        let ap = CheckpointResource::gsc_ap_flash(src.bridge.ap_flash.clone()).unwrap();
        let bad = Descriptor {
            id: 0,
            state: resource.key(),
            ap_flash: ap.key(),
        }
        .encode()
        .unwrap();
        let resources = PreparedResources::from_bindings(vec![resource, ap]).unwrap();
        assert!(
            target
                .prepare_private(&public, &EmulatorState::default(), &bad, &resources)
                .is_err()
        );
    }
}
#[test]
fn descriptor_and_state_truncation_and_trailing_bytes_are_rejected() {
    let src = source();
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    let (raw, r) = src.checkpoint_parts().unwrap();
    let resources = PreparedResources::from_bindings(r).unwrap();
    let public = src.get_state().unwrap();
    for end in 0..raw.data.len() {
        let mut bad = raw.clone();
        bad.data.truncate(end);
        assert!(
            target
                .prepare_private(&public, &EmulatorState::default(), &bad, &resources)
                .is_err()
        );
    }
    let state = Image::capture(&src).unwrap().encode().unwrap();
    for end in [9, state.len() / 2, state.len() - 1] {
        let r = CheckpointResource::gsc_state(state[..end].to_vec()).unwrap();
        let ap = CheckpointResource::gsc_ap_flash(src.bridge.ap_flash.clone()).unwrap();
        let bad = Descriptor {
            id: 0,
            state: r.key(),
            ap_flash: ap.key(),
        }
        .encode()
        .unwrap();
        let rs = PreparedResources::from_bindings(vec![r, ap]).unwrap();
        assert!(
            target
                .prepare_private(&public, &EmulatorState::default(), &bad, &rs)
                .is_err()
        );
    }
    let mut extra = raw.clone();
    extra.data.push(0);
    assert!(
        target
            .prepare_private(&public, &EmulatorState::default(), &extra, &resources)
            .is_err()
    );
    let mut bytes = state;
    bytes.push(0);
    assert!(Image::decode(&bytes).is_err());
}
#[test]
fn variable_field_counts_reject_before_elements_are_read() {
    #[derive(Debug, Deserialize)]
    struct Data(#[serde(deserialize_with = "data")] Vec<u8>);
    #[derive(Debug, Deserialize)]
    struct Rows(#[serde(deserialize_with = "words")] Vec<(u64, u32)>);
    #[derive(Debug, Deserialize)]
    struct Spi(#[serde(deserialize_with = "spi")] Vec<u8>);
    #[derive(Debug, Deserialize)]
    struct Fifo(#[serde(deserialize_with = "fifo")] Vec<u8>);
    #[derive(Debug, Deserialize)]
    struct Commands(#[serde(deserialize_with = "commands")] Vec<Vec<u8>>);
    for n in [MAX_STATE as u64 + 1, u64::MAX] {
        assert!(
            crate::codec::deserialize_strict::<Data>(&n.to_le_bytes())
                .unwrap_err()
                .to_string()
                .contains("count exceeds bound")
        );
    }
    assert!(crate::codec::deserialize_strict::<Rows>(&((ROWS + 1) as u64).to_le_bytes()).is_err());
    assert!(crate::codec::deserialize_strict::<Spi>(&257u64.to_le_bytes()).is_err());
    assert!(
        crate::codec::deserialize_strict::<Fifo>(&((GSC_FIFO_RAM_LEN + 1) as u64).to_le_bytes())
            .is_err()
    );
    assert!(crate::codec::deserialize_strict::<Commands>(&u64::MAX.to_le_bytes()).is_err());
}
#[test]
fn restored_entropy_continues_the_source_stream_at_a_state_only_boundary() {
    let mut src = source();
    src.entropy_state = 0x1234_5678_9abc_def0;
    src.cpu.set_pc(TPM_RAND_GENERATE);
    src.cpu.set_x(1, CODE);
    src.cpu.set_x(11, 0x2000);
    src.cpu.set_x(12, 16);
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    let mut c = prepared(&src, &target);
    publish(&c);
    for cpu in [&mut src, &mut c] {
        let out = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(out.retired, 0);
        assert!(matches!(out.stop, RetirementStop::StateChange));
        assert_eq!(cpu.current_pc(), CODE);
        assert_eq!(cpu.cpu.x(10), 16);
    }
    let mut a = [0; 16];
    let mut b = [0; 16];
    src.cpu.read_memory(0x2000, &mut a).unwrap();
    c.cpu.read_memory(0x2000, &mut b).unwrap();
    assert_ne!(a, [0; 16]);
    assert_eq!(a, b);
    assert_eq!(src.entropy_state, c.entropy_state);
}
#[test]
fn restored_maximum_reset_count_has_a_defined_terminal_transition() {
    let mut src = source();
    src.reset_count = u32::MAX;
    src.cpu.set_x(10, 0x4000_0000);
    src.cpu.set_x(11, u64::from(PMU_RESET_MAGIC));
    src.bridge
        .mem
        .write_slice(&0x00b5_2423u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    target
        .bridge
        .mem
        .write_slice(&0x00b5_2423u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    let mut c = prepared(&src, &target);
    publish(&c);
    let out = c.run_retirement_budget(1).unwrap();
    assert_eq!(out.retired, 1);
    assert!(
        matches!(out.stop,RetirementStop::Exit(VcpuExit::Unknown(ref s)) if s.contains("reboot loop"))
    );
    assert_eq!(c.reset_count, u32::MAX);
}

#[test]
fn every_runtime_and_shared_field_has_an_independent_nondefault_witness() {
    let mut src = source();
    src.halted = true;
    src.reset_entry = 0x1234;
    src.reset_count = 5;
    src.break_pc = Some(0x1300);
    src.break_hit = 7;
    src.break_ra = Some(0x2000);
    src.break_saved_ra = Some(0x3000);
    src.break_stack_bytes = 0x80;
    src.break_stop = true;
    src.syscall_trace = true;
    src.print_trace = true;
    src.ap_ro_stub = true;
    src.ap_ro_crypto_stub = true;
    src.break_hits_seen = 3;
    src.broke = true;
    src.tpm_cmds = vec![vec![1, 2, 3]];
    src.tpm_trigger = 0x5678;
    src.tpm_yield_mode = true;
    src.tpm_wired = true;
    src.plt_rst_event = true;
    src.plt_rst_fired = true;
    src.entropy_hooks = false;
    src.entropy_state = 0xfeed_1234_5678;
    src.cfg.open_bus = 0x8765;
    src.cpu.csr_write(0x340, 0x3344).unwrap();
    src.cpu.import_csrs(&[(0xc02, 37)]);
    src.cpu.set_x(4, 0x5678);
    src.pc_cell.store(0x2200, Ordering::Relaxed);
    src.time_cell.store(77, Ordering::Relaxed);
    src.tpm.awaiting = true;
    src.tpm.trace_budget = 13;
    src.tpm.saved_x = [9; 32];
    src.tpm.saved_pc = 0x80000;
    src.tpm.saved_mstatus = 8;
    src.tpm.saved_mie = 0x80;
    src.tpm.cap_slot = 0x12340;
    src.tpm.bufptr_slot = 0x12344;
    src.tpm.call_start_instret = 11;
    {
        let mut sh = src.shared.lock().unwrap();
        sh.console = b"already emitted".to_vec();
        sh.uart_rx = vec![b'Q', b'R'].into();
        sh.uart_irq_armed = true;
        sh.seen.insert(0x4000_0020);
        sh.read_counts.insert(MMIO_LO + 0x80, 7);
        sh.store.insert(PMU_RSTSRC_REG + 0x4c, 42);
        sh.spin_phase.insert(MMIO_LO + 0x80, true);
        sh.reset_requested = true;
        sh.rstsrc = 0x22;
        sh.flash_pe_en = true;
        sh.flash_trans = 0x1234;
        sh.flash_read_trans = 0x2345;
        sh.flash_wr_data = [1, 2];
        sh.flash_dout = [[3, 4], [5, 6]];
        sh.flash_error = 7;
        sh.flash_info.insert(0x100, 8);
        sh.ap_spi_data = vec![0xaa; AP_SPI_DATA_LEN];
        sh.trng_state = 0x5566;
        sh.timer_compare = 0x7788;
        sh.tpm_active = true;
        sh.fifo_ram = vec![0xbb; GSC_FIFO_RAM_LEN];
    }
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    let mut c = prepared(&src, &target);
    publish(&c);
    assert_eq!(c.cpu.instret(), 37);
    assert_eq!(c.cpu.csr_read(0x340).unwrap(), 0x3344);
    assert_eq!(c.cpu.x(4), 0x5678);
    assert_eq!(c.pc_cell.load(Ordering::Relaxed), 0x2200);
    assert_eq!(c.time_cell.load(Ordering::Relaxed), 77);
    assert_eq!(c.id, src.id);
    assert_eq!(
        crate::codec::serialize(&c.cfg).unwrap(),
        crate::codec::serialize(&src.cfg).unwrap()
    );
    assert_eq!(c.halted, src.halted);
    assert_eq!(c.reset_entry, src.reset_entry);
    assert_eq!(c.reset_count, src.reset_count);
    assert_eq!(c.break_pc, src.break_pc);
    assert_eq!(c.break_hit, src.break_hit);
    assert_eq!(c.break_ra, src.break_ra);
    assert_eq!(c.break_saved_ra, src.break_saved_ra);
    assert_eq!(c.break_stack_bytes, src.break_stack_bytes);
    assert_eq!(c.break_stop, src.break_stop);
    assert_eq!(c.syscall_trace, src.syscall_trace);
    assert_eq!(c.print_trace, src.print_trace);
    assert_eq!(c.ap_ro_stub, src.ap_ro_stub);
    assert_eq!(c.ap_ro_crypto_stub, src.ap_ro_crypto_stub);
    assert_eq!(c.break_hits_seen, src.break_hits_seen);
    assert_eq!(c.broke, src.broke);
    assert_eq!(c.tpm_cmds, src.tpm_cmds);
    assert_eq!(c.tpm_trigger, src.tpm_trigger);
    assert_eq!(c.tpm_yield_mode, src.tpm_yield_mode);
    assert_eq!(c.tpm_wired, src.tpm_wired);
    assert_eq!(
        crate::codec::serialize(&c.tpm).unwrap(),
        crate::codec::serialize(&src.tpm).unwrap()
    );
    assert_eq!(c.plt_rst_event, src.plt_rst_event);
    assert_eq!(c.plt_rst_fired, src.plt_rst_fired);
    assert_eq!(c.entropy_hooks, src.entropy_hooks);
    assert_eq!(c.entropy_state, src.entropy_state);
    assert!(!Arc::ptr_eq(&c.shared, &src.shared));
    {
        let a = src.shared.lock().unwrap();
        let b = c.shared.lock().unwrap();
        assert_eq!(a.console, b.console);
        assert_eq!(a.uart_rx, b.uart_rx);
        assert_eq!(a.uart_irq_armed, b.uart_irq_armed);
        assert_eq!(a.seen, b.seen);
        assert_eq!(a.read_counts, b.read_counts);
        assert_eq!(a.store, b.store);
        assert_eq!(a.spin_phase, b.spin_phase);
        assert_eq!(a.reset_requested, b.reset_requested);
        assert_eq!(a.rstsrc, b.rstsrc);
        assert_eq!(a.flash_pe_en, b.flash_pe_en);
        assert_eq!(a.flash_trans, b.flash_trans);
        assert_eq!(a.flash_read_trans, b.flash_read_trans);
        assert_eq!(a.flash_wr_data, b.flash_wr_data);
        assert_eq!(a.flash_dout, b.flash_dout);
        assert_eq!(a.flash_error, b.flash_error);
        assert_eq!(a.flash_info, b.flash_info);
        assert_eq!(a.ap_spi_data, b.ap_spi_data);
        assert_eq!(a.trng_state, b.trng_state);
        assert_eq!(a.timer_compare, b.timer_compare);
        assert_eq!(a.tpm_active, b.tpm_active);
        assert_eq!(a.fifo_ram, b.fifo_ram);
    }
    assert!(matches!(c.step_insn().unwrap(), Some(VcpuExit::Hlt)));
}
#[test]
fn in_flight_tpm_call_restores_saved_return_frame_before_terminal_exit() {
    let mut src = source();
    src.tpm_cmds = vec![vec![0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x7b]];
    src.tpm_yield_mode = false;
    src.tpm.in_call = true;
    src.tpm.saved_x[1] = 0x2345;
    src.tpm.saved_x[12] = 0x3344;
    src.tpm.saved_pc = CODE;
    src.tpm.saved_mstatus = 8;
    src.tpm.saved_mie = 0x80;
    src.tpm.cap_slot = TPM_SCRATCH_CAP;
    src.tpm.bufptr_slot = TPM_SCRATCH_BUFPTR;
    src.cpu.set_pc(TPM_CALL_SENTINEL);
    let response = [0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0];
    for (at, bytes) in [
        (TPM_SCRATCH_CAP, 10u32.to_le_bytes().to_vec()),
        (TPM_SCRATCH_BUFPTR, 0x2000u32.to_le_bytes().to_vec()),
        (0x2000, response.to_vec()),
    ] {
        src.bridge
            .mem
            .write_slice(&bytes, GuestAddress(at))
            .unwrap();
    }
    let target = GscVcpu::new_checkpoint_target(0, memory()).unwrap();
    for (at, bytes) in [
        (TPM_SCRATCH_CAP, 10u32.to_le_bytes().to_vec()),
        (TPM_SCRATCH_BUFPTR, 0x2000u32.to_le_bytes().to_vec()),
        (0x2000, response.to_vec()),
    ] {
        target
            .bridge
            .mem
            .write_slice(&bytes, GuestAddress(at))
            .unwrap();
    }
    let mut c = prepared(&src, &target);
    publish(&c);
    for cpu in [&mut src, &mut c] {
        let out = cpu.run_retirement_budget(1).unwrap();
        assert_eq!(out.retired, 0);
        assert!(matches!(out.stop, RetirementStop::Exit(VcpuExit::Shutdown)));
        assert_eq!(cpu.current_pc(), CODE);
        assert_eq!(cpu.cpu.x(1), 0x2345);
        assert_eq!(cpu.cpu.x(12), 0x3344);
        assert_eq!(cpu.tpm.next, 1);
        assert!(!cpu.tpm.in_call);
        assert_eq!(cpu.cpu.csr_read(0x304).unwrap(), 0x80);
    }
}
