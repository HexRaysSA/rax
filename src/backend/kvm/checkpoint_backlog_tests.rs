//! Retained native witness for the still-open complete KVM producer.
use super::*;

#[test]
#[ignore = "C-STATE: complete KVM private/shared producer remains required"]
fn native_checkpoint_declares_and_captures_its_private_producer() {
    let backend = KvmBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(2 * 1024 * 1024).unwrap();
    vm.configure_cpu_topology(1, memory.size()).unwrap();
    vm.as_any()
        .downcast_ref::<KvmVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    assert!(cpu.required_private_checkpoint_kind().is_some());
    let record = cpu.capture_backend_context().unwrap().unwrap();
    assert_eq!(Some(record.kind), cpu.required_private_checkpoint_kind());
    assert!(!record.data.is_empty());
}
