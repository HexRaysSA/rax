//! A stopped checkpoint must acquire exclusion while public run awaits an exit.
use rax::backend::{
    Backend, Vm,
    kvm::{KvmBackend, KvmVm},
};
use rax::vm::memory::{
    GuestMemoryWrapper,
    vm::{Bytes, GuestAddress},
};
use rax::vm::vcpu::{CpuState, VcpuExit};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

fn checkpoint_writer_stops_entry(limit: Option<Duration>) {
    let backend = KvmBackend::new().unwrap();
    let vm: Arc<dyn Vm> = Arc::from(backend.create_vm().unwrap());
    vm.configure_cpu_topology(1, 2 * 1024 * 1024).unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.as_any()
        .downcast_ref::<KvmVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    // LOCK INC DWORD PTR [0x8000]; JMP back. Observing the counter establishes
    // actual native execution before the checkpoint writer requests exclusion.
    memory
        .memory()
        .write_slice(
            &[0xf0, 0x66, 0xff, 0x06, 0x00, 0x80, 0xeb, 0xf8],
            GuestAddress(0x1000),
        )
        .unwrap();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let CpuState::X86_64(mut state) = cpu.get_state().unwrap() else {
        panic!("native x86 state expected")
    };
    state.regs.rip = 0x1000;
    state.regs.rflags = 2;
    state.sregs.cs.base = 0;
    state.sregs.cs.selector = 0;
    state.sregs.ds.base = 0;
    state.sregs.ds.selector = 0;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    let runner = std::thread::spawn(move || {
        let result = match limit {
            Some(limit) => cpu.run_host_slice(limit),
            None => cpu.run().map(Some),
        };
        // Retain membership even if a finite slice returns before the writer
        // acquires exclusion. Dropping the wrapper would invalidate the graph.
        (result, cpu)
    });
    let entered_by = Instant::now() + Duration::from_secs(5);
    let entered = loop {
        if memory
            .memory()
            .read_obj::<u32>(GuestAddress(0x8000))
            .unwrap()
            != 0
        {
            break true;
        }
        if Instant::now() >= entered_by || runner.is_finished() {
            break false;
        }
        std::thread::yield_now();
    };
    let (acquired, acquired_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let target = vm.clone();
    let writer = std::thread::spawn(move || {
        let boundary = target.checkpoint_boundary();
        let accepted = boundary.is_ok();
        acquired.send(accepted).unwrap();
        if accepted {
            release_rx.recv().unwrap();
        }
        drop(boundary);
    });
    let stopped = acquired_rx.recv_timeout(Duration::from_secs(2));
    let mut stable = false;
    let mut no_architectural_exit = false;
    if matches!(stopped, Ok(true)) {
        let before = memory
            .memory()
            .read_obj::<u32>(GuestAddress(0x8000))
            .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        stable = memory
            .memory()
            .read_obj::<u32>(GuestAddress(0x8000))
            .unwrap()
            == before;
        no_architectural_exit = limit.is_some() || !runner.is_finished();
    }
    // Cleanup also releases the pre-fix loop: poisoning is an atomic owner
    // fence, independent of writer exclusion, checked before the next entry.
    vm.poison_checkpoint_restore();
    if matches!(stopped, Ok(true)) {
        release.send(()).unwrap();
    }
    let (result, _cpu) = runner.join().unwrap();
    writer.join().unwrap();
    assert!(entered, "guest never executed its native counter loop");
    assert!(
        matches!(stopped, Ok(true)),
        "checkpoint writer stayed blocked across native entry {limit:?}: {stopped:?}"
    );
    assert!(
        stable,
        "guest continued writing RAM while the checkpoint boundary was held"
    );
    assert!(
        no_architectural_exit,
        "a scheduling slice became a guest-visible exit"
    );
    assert!(result.is_err() || matches!(result, Ok(None) | Ok(Some(VcpuExit::Shutdown))));
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn checkpoint_writer_quiesces_public_run_without_waiting_for_a_guest_exit() {
    for _ in 0..4 {
        checkpoint_writer_stops_entry(None);
        checkpoint_writer_stops_entry(Some(Duration::from_secs(5)));
    }
}
