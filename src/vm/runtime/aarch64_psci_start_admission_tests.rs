//! Admission of a pending guest PSCI CPU_ON before publishing a checkpoint.
use super::*;
use crate::machine::arm_virt::{AARCH64_GICD_BASE, AARCH64_UART_BASE};
use crate::vm::snapshot::SnapshotBundle;

const ENTRY: u64 = CODE + 0x100;
const MARKER: u64 = CODE + 0x200;

fn write(vm: &Vmm, address: u64, value: u32) {
    vm.guest_mem
        .memory()
        .write_slice(&value.to_le_bytes(), GuestAddress(address))
        .unwrap();
}

fn read(vm: &Vmm, address: u64) -> u32 {
    let mut bytes = [0; 4];
    vm.guest_mem
        .memory()
        .read_slice(&mut bytes, GuestAddress(address))
        .unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn invalid_saved_psci_start_cannot_publish_any_live_owner() {
    let mut source = Fixture::with_clock(2, ClockMode::Retired);
    write(&source.vm, CODE, 0xd400_0002); // HVC #0.
    write(&source.vm, ENTRY, 0x9100_0404); // ADD X4, X0, #1.
    write(&source.vm, MARKER, 0xfeed_beef);
    let CpuState::Aarch64(mut caller) = source.vm.vcpus[0].get_state().unwrap() else {
        panic!("expected an Arm BSP");
    };
    caller.regs.x[..4].copy_from_slice(&[0xc400_0003, 1, ENTRY, 0x1234]);
    source.vm.vcpus[0]
        .update_state(&CpuState::Aarch64(caller))
        .unwrap();
    assert_eq!(
        source.vm.vcpus[0].run_retirement_budget(1).unwrap().retired,
        1
    );
    assert_eq!(source.cluster().affinity_info(1, 0).unwrap(), 2);

    let source_kernel = source.kernel.clone();
    let path = source_kernel.with_extension("rxc");
    let bundle = source.vm.take_snapshot_bundle(1).unwrap();
    bundle.save(&path).unwrap();
    drop(bundle);
    drop(source);
    assert!(!source_kernel.exists());
    let mut incoming = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();

    let mut target = Fixture::with_clock(2, ClockMode::Retired);
    write(&target.vm, MARKER, 0xf001_cafe);
    let before_cpus = format!("{:?}", target.vm.capture_cpu_states().unwrap());
    let before_graph = target.graph();
    let before_coordinator = target.vm.coordinator.clone();
    let before_clock = target.vm.timing_context.checkpoint_state();
    let execution = incoming.take_execution().unwrap();
    let graph = serde_json::to_value(execution.arm_cluster.as_ref().unwrap()).unwrap();

    for entry in [u64::MAX & !3, AARCH64_GICD_BASE, AARCH64_UART_BASE] {
        let mut damaged = execution.clone();
        let mut value = graph.clone();
        value["control"]["requests"][0]["Start"]["entry"] = entry.into();
        damaged.arm_cluster = Some(serde_json::from_value(value).unwrap());
        let mut bad = incoming.with_execution(damaged).unwrap();
        let error = target.vm.restore_snapshot_bundle(&bad);
        assert!(
            matches!(error, Err(error) if error.to_string().contains("saved startup entry")),
            "malformed entry {entry:#x} reached VMM publication"
        );
        assert_eq!(
            format!("{:?}", target.vm.capture_cpu_states().unwrap()),
            before_cpus
        );
        assert_eq!(target.graph(), before_graph);
        assert_eq!(target.vm.coordinator, before_coordinator);
        assert_eq!(target.vm.timing_context.checkpoint_state(), before_clock);
        assert_eq!(read(&target.vm, MARKER), 0xf001_cafe);
        bad.take_execution().unwrap();
        incoming = bad;
    }

    let mut damaged = execution.clone();
    let mut value = graph;
    value["control"]["requests"][0]["Start"]["pstate"] = (1u64 << 63).into();
    damaged.arm_cluster = Some(serde_json::from_value(value).unwrap());
    assert!(damaged.validate(incoming.base()).is_err());

    target
        .vm
        .restore_snapshot_bundle(&incoming.with_execution(execution).unwrap())
        .unwrap();
    assert_eq!(target.cluster().affinity_info(1, 0).unwrap(), 2);
    target.vm.route_interprocessor_requests().unwrap();
    assert_eq!(target.vm.coordinator.online, [true, true]);
    assert_eq!(
        target.vm.vcpus[1].run_retirement_budget(1).unwrap().retired,
        1
    );
    let secondary = target.vm.vcpus[1].get_state().unwrap();
    assert_eq!(secondary.as_aarch64().unwrap().regs.x[4], 0x1235);
    assert_eq!(read(&target.vm, MARKER), 0xfeed_beef);
}
