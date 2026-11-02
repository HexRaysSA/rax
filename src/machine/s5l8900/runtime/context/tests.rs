//! Actual S5L producer admission, detached owners and continuation frontiers.
use super::super::time::{ElapsedClock, ElapsedImage};
use super::*;
use crate::vm::memory::checkpoint::CheckpointBindings;
use vm_memory::{Bytes, GuestAddress};
pub(super) fn fixture() -> S5L8900Vcpu {
    let mem = Arc::new(
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(IBOOT_BASE as u64), 0x8000)]).unwrap(),
    );
    let bytes = [0xe1a00000u32, 0xe1a00000, 0xe320f003]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    mem.write_slice(&bytes, GuestAddress(IBOOT_BASE as u64))
        .unwrap();
    let mut cpu = S5L8900Vcpu::new(0, mem);
    cpu.cpu.regs[15] = IBOOT_BASE;
    cpu.bridge.inner.borrow_mut().nand = S5lNand::new(None);
    cpu
}
fn parts(cpu: &S5L8900Vcpu) -> (BackendContext, PreparedResources) {
    let (raw, resources) = cpu.capture_parts(None, None).unwrap();
    (raw, PreparedResources::from_bindings(resources).unwrap())
}
fn publish(cpu: &mut S5L8900Vcpu) {
    let owners = cpu.checkpoint_owned_s3c_uarts();
    let bindings = CheckpointBindings::new(&cpu.bridge.mem, vec![]).with_s3c_uarts(owners);
    let scope = bindings.enter().unwrap();
    cpu.publication(&scope).unwrap().commit();
}
fn normalize_clocks(cpu: &mut S5L8900Vcpu) {
    cpu.boot_clock = ElapsedClock::suspended(ElapsedImage::zero()).unwrap();
    cpu.heartbeat_clock = ElapsedClock::suspended(ElapsedImage::zero()).unwrap();
}
#[test]
fn complete_private_image_roundtrips_banked_fp_mmu_devices_and_pending_work() {
    let mut source = fixture();
    normalize_clocks(&mut source);
    source.cpu.regs[0] = 0x12345678;
    source.cpu.regs_fiq[0] = 0x98765432;
    source.cpu.vfp.write_d_bits(31, 0x0123456789abcdef);
    source.cpu.cp15.contextidr = 0x99887766;
    source.insn_count = 123456;
    source.excl.address = Some(IBOOT_BASE + 0x100);
    source.excl.size = 4;
    source.pc_ring[511] = 0xabcdef;
    source.pc_ring_idx = 511;
    source.zero_slide = 47;
    source.wmr_init_active = true;
    source.input_payload = Some(vec![0x41, 0x42]);
    source.input_seeded = false;
    source.sparse_vfl_mask_seeded = [true, false, true, false, true, false, true, false];
    source.timer_irq_clock = 0x123456789;
    source.last_irq_trace = u128::MAX;
    {
        let mut b = source.bridge.inner.borrow_mut();
        b.mmu.ttbr0 = 0x12344000;
        b.mmu.ttbcr_n = 3;
        b.last_fault.addr = 0xfeed0000;
        b.last_fault.fsr = 7;
        b.privileged = false;
        b.cur_pc = 0x1234;
        b.cur_insn = 998;
        b.kernel_started = true;
        b.vic0.write(0x10, 0x800000ff);
        b.vic1.write(0x18, 0x20);
        b.vic1_adm_daisy_latched = true;
        b.vic1_adm_daisy_in_service = true;
        b.nand.begin_page_write(2, 99);
        b.nand.write(0x80, 0x11223344);
        b.adm_data2 = 0x11110000;
        b.adm_data3 = 0x22220000;
        b.adm_req = Some(0x300);
        b.adm_irq = true;
        b.engine_8900_req = Some(0x33330000);
        b.aes.write(0x4, 1);
        b.nand_ecc.write(0xc, 1);
        b.sdio.write(0, 0xdeadbeef);
        b.lcd.tick(199999);
    }
    let source_bytes = image::Image::capture(&source, None)
        .unwrap()
        .encode()
        .unwrap();
    let (raw, resources) = parts(&source);
    let mut target = fixture();
    let mut candidate = target
        .prepare_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &raw,
            &resources,
        )
        .unwrap();
    assert!(candidate.step_insn().is_err());
    assert!(candidate.capture_backend_context().is_err());
    publish(&mut candidate);
    candidate.finish_publication().unwrap();
    normalize_clocks(&mut candidate);
    assert_eq!(
        image::Image::capture(&candidate, None)
            .unwrap()
            .encode()
            .unwrap(),
        source_bytes
    );
    assert_eq!(
        candidate
            .bridge
            .inner
            .borrow()
            .nand
            .checkpoint_controller_state()
            .unwrap(),
        source
            .bridge
            .inner
            .borrow()
            .nand
            .checkpoint_controller_state()
            .unwrap()
    );
    // The current target was never replaced or entered by preparation.
    assert_eq!(target.instruction_count(), 0);
    assert_eq!(target.cpu.regs[0], 0);
    target.cpu.regs[0] = 9;
    assert_eq!(candidate.cpu.regs[0], 0x12345678);
}
#[test]
fn source_preparation_rejects_foreign_owner_and_changed_core_or_nand() {
    let mut source = fixture();
    let prepared = source.prepare_source().unwrap();
    let other = fixture();
    assert!(other.capture_parts(None, Some(&prepared)).is_err());
    source.cpu.regs[0] = 1;
    assert!(source.capture_parts(None, Some(&prepared)).is_err());
    source.cpu.regs[0] = 0;
    assert!(source.capture_parts(None, Some(&prepared)).is_ok());
    source.bridge.inner.borrow_mut().nand.fmdnum = 77;
    assert!(source.capture_parts(None, Some(&prepared)).is_err());
}
#[test]
fn prepared_cpu_requires_matching_ram_and_repeated_publication_does_not_restart_clock() {
    let source = fixture();
    let (raw, resources) = parts(&source);
    let target = fixture();
    let mut candidate = target
        .prepare_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &raw,
            &resources,
        )
        .unwrap();
    let foreign = fixture();
    let bindings = CheckpointBindings::new(&foreign.bridge.mem, vec![]);
    let scope = bindings.enter().unwrap();
    assert!(candidate.publication(&scope).is_err());
    assert!(candidate.step_insn().is_err());
    drop(scope);
    let bindings = CheckpointBindings::new(&candidate.bridge.mem, vec![]);
    let scope = bindings.enter().unwrap();
    let epoch = candidate
        .checkpoint_publication
        .as_ref()
        .unwrap()
        .epoch
        .clone();
    let first = candidate.publication(&scope).unwrap();
    let second = candidate.publication(&scope).unwrap();
    assert!(epoch.get().is_none());
    first.commit();
    let start = epoch.get().unwrap().clone();
    second.commit();
    assert_eq!(epoch.get(), Some(&start));
    drop(scope);
    assert!(candidate.step_insn().unwrap().is_none());
    assert_eq!(candidate.insn_count, 1);
}
#[test]
fn descriptor_and_state_corruption_reject_before_target_or_uart_changes() {
    let mut source = fixture();
    let owner = Arc::new(Mutex::new(S3cUart::new()));
    owner.lock().unwrap().queue_input(b"source");
    source.attach_s3c_uart(owner);
    let (raw, resources) = parts(&source);
    let mut target = fixture();
    let live = Arc::new(Mutex::new(S3cUart::new()));
    live.lock().unwrap().queue_input(b"live");
    target.attach_s3c_uart(live.clone());
    let before = crate::codec::serialize(&*live.lock().unwrap()).unwrap();
    let state = source.get_state().unwrap();
    for end in 0..raw.data.len() {
        let mut bad = raw.clone();
        bad.data.truncate(end);
        assert!(
            target
                .prepare_private(&state, &EmulatorState::default(), &bad, &resources)
                .is_err()
        );
    }
    let d = Descriptor::decode(0, &raw).unwrap();
    let bytes = resources.resolve(d.state).unwrap();
    for bytes in [
        bytes[..9].to_vec(),
        {
            let mut x = bytes.to_vec();
            x.push(0);
            x
        },
        {
            let mut x = bytes.to_vec();
            x[0] ^= 1;
            x
        },
    ] {
        let bad_state = CheckpointResource::s5l_state(bytes).unwrap();
        let bad = Descriptor {
            id: 0,
            state: bad_state.key(),
            nand: d.nand,
        }
        .encode()
        .unwrap();
        let nand = resources.resolve(d.nand).unwrap();
        let resources = PreparedResources::from_bindings(vec![
            bad_state,
            CheckpointResource::s5l_nand(nand.to_vec()).unwrap(),
        ])
        .unwrap();
        assert!(
            target
                .prepare_private(&state, &EmulatorState::default(), &bad, &resources)
                .is_err()
        );
    }
    assert_eq!(
        crate::codec::serialize(&*live.lock().unwrap()).unwrap(),
        before
    );
    assert_eq!(target.instruction_count(), 0);
}
#[test]
fn shared_uart_is_unmodified_until_publication_and_source_writes_are_excluded() {
    let mut source = fixture();
    let saved = Arc::new(Mutex::new(S3cUart::new()));
    saved.lock().unwrap().queue_input(b"saved");
    source.attach_s3c_uart(saved);
    let (raw, resources) = parts(&source);
    let mut target = fixture();
    let live = Arc::new(Mutex::new(S3cUart::new()));
    live.lock().unwrap().queue_input(b"live");
    target.attach_s3c_uart(live.clone());
    let before = crate::codec::serialize(&*live.lock().unwrap()).unwrap();
    let mut candidate = target
        .prepare_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &raw,
            &resources,
        )
        .unwrap();
    assert_eq!(
        crate::codec::serialize(&*live.lock().unwrap()).unwrap(),
        before
    );
    publish(&mut candidate);
    let after = crate::codec::serialize(&*live.lock().unwrap()).unwrap();
    assert_ne!(after, before);
    assert!(Arc::ptr_eq(candidate.uart.get().unwrap(), &live));
}

#[test]
fn prepared_media_capture_does_not_reopen_deleted_source_under_uart_lock() {
    let root = std::env::temp_dir().join(format!("rax-prepared-s5l-media-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("bank0")).unwrap();
    std::fs::write(root.join("bank0/2.page"), 0x78563412u32.to_le_bytes()).unwrap();
    let mut source = fixture();
    source.bridge.inner.borrow_mut().nand = S5lNand::new(Some(root.clone()));
    let uart = Arc::new(Mutex::new(S3cUart::new()));
    source.attach_s3c_uart(uart.clone());
    let prepared = source.prepare_source().unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    let bindings =
        CheckpointBindings::new(&source.bridge.mem, vec![]).with_s3c_uarts(vec![uart.clone()]);
    let scope = bindings.enter().unwrap();
    assert!(matches!(
        uart.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    assert!(source.capture_parts(Some(&scope), None).is_err());
    let (_, resources) = source.capture_parts(Some(&scope), Some(&prepared)).unwrap();
    let nand = resources
        .iter()
        .find(|r| r.key().kind() == S5L_NAND_RESOURCE)
        .unwrap();
    let key = nand.key();
    let resources = PreparedResources::from_bindings(resources).unwrap();
    let bytes = resources.resolve(key).unwrap();
    let mut restored = S5lNand::from_checkpoint(bytes.as_slice(), bytes.len()).unwrap();
    restored.set_bank(0);
    restored.write(0x30, 2047);
    restored.write(0xc, 2 << 16);
    assert_eq!(restored.read(0x80), 0x78563412);
}
#[test]
fn shared_uart_conflict_leaves_clocks_unpublished_and_compatible_cpus_share_epoch() {
    let mut source = fixture();
    let saved = Arc::new(Mutex::new(S3cUart::new()));
    saved.lock().unwrap().queue_input(b"saved");
    source.attach_s3c_uart(saved.clone());
    let (raw, resources) = parts(&source);
    saved.lock().unwrap().queue_input(b"conflict");
    let (bad_raw, bad_resources) = parts(&source);
    let mut target = fixture();
    let live = Arc::new(Mutex::new(S3cUart::new()));
    live.lock().unwrap().queue_input(b"live");
    target.attach_s3c_uart(live.clone());
    let state = source.get_state().unwrap();
    let prepare = |raw: &BackendContext, resources: &PreparedResources| {
        target
            .prepare_private(&state, &EmulatorState::default(), raw, resources)
            .unwrap()
    };
    let mut first = prepare(&raw, &resources);
    let mut bad = prepare(&bad_raw, &bad_resources);
    let first_epoch = first.checkpoint_publication.as_ref().unwrap().epoch.clone();
    let bad_epoch = bad.checkpoint_publication.as_ref().unwrap().epoch.clone();
    let before = crate::codec::serialize(&*live.lock().unwrap()).unwrap();
    let bindings =
        CheckpointBindings::new(&target.bridge.mem, vec![]).with_s3c_uarts(vec![live.clone()]);
    {
        let scope = bindings.enter().unwrap();
        let permit = first.publication(&scope).unwrap();
        assert!(bad.publication(&scope).is_err());
        assert!(first_epoch.get().is_none());
        assert!(bad_epoch.get().is_none());
        drop(permit);
    }
    assert_eq!(
        crate::codec::serialize(&*live.lock().unwrap()).unwrap(),
        before
    );
    assert!(first.step_insn().is_err());
    let mut second = prepare(&raw, &resources);
    let second_epoch = second
        .checkpoint_publication
        .as_ref()
        .unwrap()
        .epoch
        .clone();
    {
        let scope = bindings.enter().unwrap();
        let a = first.publication(&scope).unwrap();
        let b = second.publication(&scope).unwrap();
        a.commit();
        b.commit();
        assert_eq!(first_epoch.get(), second_epoch.get());
        assert!(first_epoch.get().is_some());
    }
    first.finish_publication().unwrap();
    second.finish_publication().unwrap();
}

#[test]
fn selected_private_clock_image_is_unchanged_by_host_delay_or_foreign_scope() {
    use crate::vm::timing::{ClockMode, TimingContext};
    let owner = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _owner = owner.enter();
    let source = fixture();
    owner.advance_retired(192).unwrap();
    let first = image::Image::capture(&source, None)
        .unwrap()
        .encode()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    foreign.advance_retired(3_000_000_000).unwrap();
    let _foreign = foreign.enter();
    assert_eq!(
        image::Image::capture(&source, None)
            .unwrap()
            .encode()
            .unwrap(),
        first
    );
}

#[test]
fn selected_replacement_retains_target_clock_and_denies_foreign_publication_before_mutation() {
    use crate::vm::timing::{ClockMode, TimingContext};
    let source_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let source_guard = source_clock.enter();
    let source = fixture();
    source_clock.advance_retired(192).unwrap();
    let (raw, resources) = parts(&source);
    drop(source_guard);
    let target_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    target_clock.advance_retired(3000).unwrap();
    let target_guard = target_clock.enter();
    let target = fixture();
    drop(target_guard);
    let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let foreign_guard = foreign.enter();
    let mut candidate = target
        .prepare_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &raw,
            &resources,
        )
        .unwrap();
    let owners = candidate.checkpoint_owned_s3c_uarts();
    let bindings = CheckpointBindings::new(&candidate.bridge.mem, vec![]).with_s3c_uarts(owners);
    let scope = bindings.enter().unwrap();
    assert!(candidate.publication(&scope).is_err());
    assert!(candidate.check_publication().is_err());
    assert_eq!(
        candidate
            .bridge
            .mem
            .read_obj::<u32>(GuestAddress(u64::from(IBOOT_BASE)))
            .unwrap(),
        0xe1a00000
    );
    drop(scope);
    drop(foreign_guard);
    let _target = target_clock.enter();
    let scope = bindings.enter().unwrap();
    candidate.publication(&scope).unwrap().commit();
    drop(scope);
    assert_eq!(
        candidate.boot_clock.elapsed(),
        std::time::Duration::from_nanos(64)
    );
    target_clock.advance_retired(3).unwrap();
    assert_eq!(
        candidate.boot_clock.elapsed(),
        std::time::Duration::from_nanos(65)
    );
    candidate.finish_publication().unwrap();
    assert_eq!(
        candidate.boot_clock.elapsed(),
        std::time::Duration::from_nanos(65)
    );
}

#[test]
fn legacy_calendar_private_producer_rejects_retired_target_before_state_change_and_keeps_wall_import()
 {
    use crate::vm::timing::{ClockMode, TimingContext};
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let source = fixture();
    let (raw, mut resources) = source.capture_parts(None, None).unwrap();
    let mut descriptor = Descriptor::decode(0, &raw).unwrap();
    let old = descriptor.state;
    let prepared = PreparedResources::from_bindings(resources.clone()).unwrap();
    let mut image = prepared.resolve(old).unwrap().as_ref().clone();
    image[..8].copy_from_slice(b"RAXSLI01");
    let resource = crate::vm::snapshot::CheckpointResource::s5l_state(image).unwrap();
    descriptor.state = resource.key();
    resources.retain(|r| r.key() != old);
    resources.push(resource);
    let resources = PreparedResources::from_bindings(resources).unwrap();
    let raw = descriptor.encode().unwrap();
    let target = fixture();
    let before = parts(&target).0;
    let mut ram = vec![0; 0x8000];
    target
        .bridge
        .mem
        .read_slice(&mut ram, GuestAddress(u64::from(IBOOT_BASE)))
        .unwrap();
    let result = target.prepare_private(
        &source.get_state().unwrap(),
        &EmulatorState::default(),
        &raw,
        &resources,
    );
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("legacy S5L calendar")
    );
    assert_eq!(parts(&target).0.data, before.data);
    let mut after = vec![0; 0x8000];
    target
        .bridge
        .mem
        .read_slice(&mut after, GuestAddress(u64::from(IBOOT_BASE)))
        .unwrap();
    assert_eq!(after, ram);
    let wall = Arc::new(TimingContext::with_mode(ClockMode::Wall));
    let _wall = wall.enter();
    let target = fixture();
    let mut candidate = target
        .prepare_private(
            &source.get_state().unwrap(),
            &EmulatorState::default(),
            &raw,
            &resources,
        )
        .unwrap();
    publish(&mut candidate);
    candidate.finish_publication().unwrap();
    assert!(!candidate.bridge.inner.borrow().i2c1.uses_retired_calendar());
}
