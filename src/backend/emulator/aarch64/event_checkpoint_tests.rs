//! Detached event publication and stable platform bindings after restoration.
use super::*;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn cpu() -> (Aarch64Vcpu, Arc<cluster::ArmCluster>, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory
        .write_slice(&0xd503_205fu32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    let cluster = Arc::new(cluster::ArmCluster::new(2, 0x4000).unwrap());
    (
        Aarch64Vcpu::new_in_cluster(0, memory.clone(), cluster.clone()).unwrap(),
        cluster,
        memory,
    )
}

#[test]
fn cancelled_permits_leave_target_latches_unchanged_and_published_cpus_receive_peer_events() {
    for saved in [false, true] {
        let (source, _, _) = cpu();
        source
            .cpu
            .event_register_handle()
            .store(saved, Ordering::Release);
        let state = source.get_state().unwrap();
        let raw = source.capture_backend_context().unwrap().unwrap();
        let (target, cluster, memory) = cpu();
        let live = target.cpu.event_register_handle();
        live.store(!saved, Ordering::Release);
        let mut prepared = target.prepare_private_checkpoint(&state, &raw).unwrap();
        assert_eq!(live.load(Ordering::Acquire), !saved);
        assert_eq!(prepared.cpu.event_pending(), saved);
        let bindings = CheckpointBindings::new(&memory, vec![]);
        {
            let scope = bindings.enter().unwrap();
            let permit = prepared.publication(&scope).unwrap();
            assert!(Arc::ptr_eq(&live, &prepared.cpu.event_register_handle()));
            assert_eq!(live.load(Ordering::Acquire), !saved);
            assert!(Context::capture(&prepared, &scope).is_err());
            drop(permit);
            assert_eq!(live.load(Ordering::Acquire), !saved);
            assert!(prepared.step_insn().is_err());
            prepared.publication(&scope).unwrap().commit();
            assert_eq!(live.load(Ordering::Acquire), saved);
        }
        assert!(Arc::ptr_eq(&live, &cluster.event_handle(0).unwrap()));
        // Signal after publication but before the restored CPU's first step.
        cluster.broadcast_event().unwrap();
        assert!(prepared.cpu.event_pending());
        let result = prepared.run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1);
        assert!(matches!(
            result.stop,
            crate::vm::vcpu::RetirementStop::BudgetExhausted
        ));
        assert!(!prepared.cpu.event_pending());
    }
}
