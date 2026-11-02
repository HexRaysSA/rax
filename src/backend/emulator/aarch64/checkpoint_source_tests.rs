//! Owned GIC input provenance, legacy admission and transactional rejection.
use super::*;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::timing::{ClockMode, TimingContext};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn memory() -> Arc<GuestMemoryMmap> {
    Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap())
}
fn state(cpu: &Aarch64Vcpu) -> Context {
    Context::decode(&cpu.capture_backend_context().unwrap().unwrap().data, cpu).unwrap()
}
fn graph(cpu: &Aarch64Vcpu) -> Vec<u8> {
    crate::codec::serialize(&cpu.cpu.gic_handle().unwrap().lock().unwrap().checkpoint()).unwrap()
}

#[test]
fn owned_source_records_roundtrip_both_clock_profiles_and_preserve_controller_arcs() {
    for mode in [None, Some(ClockMode::Wall), Some(ClockMode::Retired)] {
        let clock = mode.map(|mode| Arc::new(TimingContext::with_mode(mode)));
        let _scope = clock.as_ref().map(|clock| clock.enter());
        let source = Aarch64Vcpu::new(0, memory());
        {
            let handle = source.cpu.gic_handle().unwrap();
            let mut gic = handle.lock().unwrap();
            gic.set_spi_level(40, true);
            gic.write_dist(0x204, 1 << 8);
        }
        let public = source.get_state().unwrap();
        let raw = source.capture_backend_context().unwrap().unwrap();
        assert!(raw.data.starts_with(if mode.is_some() {
            counter_clock::OWNED_TAG
        } else {
            gic_sources::TAG
        }));
        let mut target = Aarch64Vcpu::new(0, memory());
        let handle = target.cpu.gic_handle().unwrap();
        target
            .restore_checkpoint_context(&public, &Default::default(), Some(&raw))
            .unwrap();
        assert!(Arc::ptr_eq(&handle, &target.cpu.gic_handle().unwrap()));
        assert_eq!(graph(&source), graph(&target));
        assert_eq!(
            target.get_state().unwrap().as_aarch64(),
            public.as_aarch64()
        );
        let mut gic = handle.lock().unwrap();
        gic.set_spi_level(40, false);
        assert_ne!(gic.read_dist(0x204) & (1 << 8), 0);
        gic.write_dist(0x284, 1 << 8);
        assert_eq!(gic.read_dist(0x204) & (1 << 8), 0);
    }
}

#[test]
fn legacy_owned_gics_admit_unique_sources_and_reject_ambiguous_sources_transactionally() {
    let source = Aarch64Vcpu::new(0, memory());
    let public = source.get_state().unwrap();
    let mut old = TAG.to_vec();
    old.extend_from_slice(&gic_sources::legacy_payload_for_test(&state(&source)));
    let mut target = Aarch64Vcpu::new(0, memory());
    target
        .restore_checkpoint_context(
            &public,
            &Default::default(),
            Some(&BackendContext {
                kind: AARCH64_CONTEXT,
                data: old,
            }),
        )
        .unwrap();
    assert!(
        target
            .capture_backend_context()
            .unwrap()
            .unwrap()
            .data
            .starts_with(gic_sources::TAG)
    );
    for edge in [false, true] {
        let handle = source.cpu.gic_handle().unwrap();
        {
            let mut gic = handle.lock().unwrap();
            gic.reset();
            if edge {
                gic.write_dist(0xc08, 2 << 16);
            } else {
                gic.set_spi_level(40, true);
            }
        }
        let mut old = TAG.to_vec();
        old.extend_from_slice(&gic_sources::legacy_payload_for_test(&state(&source)));
        let before = CoreCheckpoint::capture(&target.cpu).unwrap();
        let controller = graph(&target);
        let error = target
            .restore_checkpoint_context(
                &public,
                &Default::default(),
                Some(&BackendContext {
                    kind: AARCH64_CONTEXT,
                    data: old,
                }),
            )
            .unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
        assert_eq!(CoreCheckpoint::capture(&target.cpu).unwrap(), before);
        assert_eq!(graph(&target), controller);
    }
}

#[test]
fn owned_source_mismatch_and_invalid_source_bytes_reject_before_cpu_or_ram_publication() {
    let mut source = Aarch64Vcpu::new(0, memory());
    source
        .cpu
        .write_sysreg(Aarch64SysRegEncoding::new(3, 3, 14, 2, 1), 1)
        .unwrap();
    source.cpu.tick_system(0).unwrap();
    source
        .cpu
        .gic_handle()
        .unwrap()
        .lock()
        .unwrap()
        .write_redist(0, 0x10200, 1 << 30);
    let public = source.get_state().unwrap();
    let original = source.capture_backend_context().unwrap().unwrap();
    let mut value = serde_json::to_value(state(&source)).unwrap();
    value["owned_gic"]["sources"]["ppis"][0][14]["line"] = false.into();
    value["owned_gic"]["sources"]["ppis"][0][14]["software"] = true.into();
    let malformed: Context = serde_json::from_value(value).unwrap();
    assert!(
        malformed
            .record()
            .unwrap_err()
            .to_string()
            .contains("timer inputs")
    );
    let mut raw = gic_sources::TAG.to_vec();
    raw.extend_from_slice(&crate::codec::serialize(&malformed).unwrap());
    let mut cases = vec![(
        BackendContext {
            kind: AARCH64_CONTEXT,
            data: raw,
        },
        Some("timer inputs"),
    )];
    let mut bad_bool = original.clone();
    *bad_bool.data.last_mut().unwrap() = 2;
    cases.push((bad_bool, None));
    let mut bad_shape = original;
    let index = bad_shape.data.len() - 3;
    bad_shape.data[index] = 1;
    cases.push((bad_shape, None));
    let destination = memory();
    destination
        .write_slice(&[0x77; 16], GuestAddress(0x100))
        .unwrap();
    let mut target = Aarch64Vcpu::new(0, destination.clone());
    for (raw, message) in cases {
        let before = CoreCheckpoint::capture(&target.cpu).unwrap();
        let controller = graph(&target);
        let error = target
            .restore_checkpoint_context(&public, &Default::default(), Some(&raw))
            .unwrap_err();
        if let Some(message) = message {
            assert!(error.to_string().contains(message));
        }
        assert_eq!(CoreCheckpoint::capture(&target.cpu).unwrap(), before);
        assert_eq!(graph(&target), controller);
        let mut bytes = [0; 16];
        destination
            .read_slice(&mut bytes, GuestAddress(0x100))
            .unwrap();
        assert_eq!(bytes, [0x77; 16]);
    }
}

#[test]
fn uart_boundary_and_guest_read_publish_physical_levels_without_clearing_software_pending() {
    let mut source = Aarch64Vcpu::new(0, memory());
    let uart = Arc::new(Mutex::new(Pl011::new()));
    assert!(source.late.uart.set(uart.clone()).is_ok());
    let mut device = Pl011MmioDevice::new(UART_BASE, uart.clone());
    crate::devices::bus::MmioDevice::write(&mut device, UART_BASE + 0x30, &0x301u32.to_le_bytes());
    crate::devices::bus::MmioDevice::write(
        &mut device,
        UART_BASE + 0x38,
        &(1u32 << 4).to_le_bytes(),
    );
    uart.lock().unwrap().queue_input(b"Q");
    assert!(uart.lock().unwrap().irq_pending());
    source.sync_uart_irq();
    let handle = source.cpu.gic_handle().unwrap();
    handle.lock().unwrap().write_dist(0x204, 1 << 1);
    let byte = source.cpu.read_memory(UART_BASE, 1).unwrap();
    assert_eq!(byte, b"Q");
    assert!(!uart.lock().unwrap().irq_pending());
    assert_ne!(handle.lock().unwrap().read_dist(0x204) & (1 << 1), 0);
    handle.lock().unwrap().write_dist(0x284, 1 << 1);
    assert_eq!(handle.lock().unwrap().read_dist(0x204) & (1 << 1), 0);
}
