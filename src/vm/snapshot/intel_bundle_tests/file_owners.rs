//! Materialized native Intel files require the target PC's complete owners.
use super::*;
use crate::config::StorageConfig;
use crate::devices::bus::{IoBus, MmioBus};
use crate::machine::{Machine, pc::PcMachine};
use crate::vm::runtime::pci_state::PciDevices;
use std::sync::Arc;

pub(super) fn with_owned_devices(mut bundle: SnapshotBundle) -> SnapshotBundle {
    let pc = PcMachine::new()
        .setup_owned_devices(&mut IoBus::new(), &mut MmioBus::new())
        .unwrap()
        .unwrap();
    let (state, resources) = pc
        .checkpoint_with(|state, resources| Ok((state, resources)))
        .unwrap();
    let mut execution = bundle.execution.take().unwrap();
    execution.pc = Some(state);
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
    let pci = PciDevices::new(memory, &StorageConfig::default(), false).unwrap();
    // The source models and RAM owner are dropped when this helper returns.
    bundle
        .with_machine_state(execution, resources)
        .unwrap()
        .with_pci(pci.checkpoint().unwrap())
        .unwrap()
}

fn detach_source(bundle: &mut SnapshotBundle) {
    let shared = bundle.vm_context.as_mut().unwrap();
    let mut context = GlobalContext::decode(&shared.data).unwrap();
    context.pending_irqs = vec![20]; // Unique and in range; source phase is absent.
    shared.data = context.encode().unwrap();
}

fn assert_destination_preserved(bundle: &SnapshotBundle) {
    let path = TestPath::new();
    std::fs::write(&path.0, b"existing checkpoint").unwrap();
    assert!(bundle.save(&path.0).is_err());
    assert_eq!(std::fs::read(&path.0).unwrap(), b"existing checkpoint");
}

#[test]
fn detached_irq_sources_reject_before_replacing_a_native_file() {
    for count in [1, 2, 4] {
        let mut bundle = complete(count);
        detach_source(&mut bundle);
        assert!(bundle.validate().is_ok()); // Intermediate/raw record inspection.
        assert_destination_preserved(&bundle);
    }
}

#[test]
fn missing_pc_inventory_rejects_before_replacing_a_native_file() {
    for count in [1, 2, 4] {
        let mut bundle = complete(count);
        bundle.execution.as_mut().unwrap().pc = None;
        assert!(bundle.validate().is_ok());
        assert_destination_preserved(&bundle);
    }
}

#[test]
fn missing_pci_bridge_rejects_before_replacing_a_native_file() {
    for count in [1, 2, 4] {
        let mut bundle = complete(count);
        bundle.pci = None;
        assert!(bundle.validate().is_ok());
        assert_destination_preserved(&bundle);
    }
}

#[test]
fn portable_reader_rejects_detached_sources_and_missing_controller_owners() {
    for count in [1, 2, 4] {
        for omitted in 0..3 {
            let mut bundle = complete(count);
            match omitted {
                0 => detach_source(&mut bundle),
                1 => bundle.execution.as_mut().unwrap().pc = None,
                _ => bundle.pci = None,
            }
            let path = TestPath::new();
            // Encode historical/incomplete input through the internal framing
            // helper. The public validated writer must reject this graph.
            codec::save_bundle_atomic(&bundle, &path.0).unwrap();
            assert!(
                SnapshotBundle::load(&path.0).is_err(),
                "{count} CPUs, case {omitted}"
            );
        }
    }
}
