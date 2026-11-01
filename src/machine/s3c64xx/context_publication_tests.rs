//! Admission cancellation, retained UART ownership and detached entry controls.
use super::*;
use crate::vm::memory::checkpoint::CheckpointBindings;
use crate::vm::vcpu::RetirementStop;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[test]
fn cancelled_publication_preserves_uart_and_repeated_commit_does_not_rewind_input() {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
    memory
        .write_slice(&0xe1a0_0000u32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    let saved_uart = Arc::new(Mutex::new(S3cUart::new()));
    saved_uart.lock().unwrap().queue_input(&[0x39, 0xa6]);
    let mut source = Armv6Vcpu::new(0, memory.clone());
    source.attach_s3c_uart(saved_uart);
    let public = source.get_state().unwrap();
    let raw = source.capture_context_record().unwrap();
    let live = Arc::new(Mutex::new(S3cUart::new()));
    live.lock().unwrap().queue_input(&[0x77]);
    let mut target = Armv6Vcpu::new(0, memory.clone());
    target.attach_s3c_uart(live.clone());
    target.trace_log_budget = 7;
    target.bridge.inner.borrow_mut().watch_va = Some(0x1234);
    let mut prepared = target.prepare_context_replacement(&public, &raw).unwrap();
    assert!(Arc::ptr_eq(prepared.uart.get().unwrap(), &live));
    assert_eq!(prepared.trace_log_budget, 7);
    assert_eq!(prepared.bridge.inner.borrow().watch_va, Some(0x1234));
    assert!(prepared.step_insn().is_err());
    assert!(prepared.run().is_err());
    assert!(prepared.capture_context_record().is_err());
    let zero = prepared.run_retirement_budget(0).unwrap();
    assert_eq!(zero.retired, 0);
    assert!(matches!(zero.stop, RetirementStop::BudgetExhausted));
    let bindings = CheckpointBindings::new(&memory, vec![])
        .with_s3c_uarts(prepared.checkpoint_owned_s3c_uarts());
    {
        let scope = bindings.enter().unwrap();
        drop(prepared.publication(&scope).unwrap());
        assert_eq!(scope.capture_s3c_uart(&live).unwrap().read(0x24), 0x77);
        assert!(prepared.step_insn().is_err());
    }
    assert_eq!(live.lock().unwrap().read(0x24), 0x77);
    {
        let scope = bindings.enter().unwrap();
        prepared.publication(&scope).unwrap().commit();
    }
    assert_eq!(live.lock().unwrap().read(0x24), 0x39);
    live.lock().unwrap().queue_input(&[0x5b]);
    {
        let scope = bindings.enter().unwrap();
        prepared.publication(&scope).unwrap().commit();
    }
    let mut uart = live.lock().unwrap();
    assert_eq!(uart.read(0x24), 0xa6);
    assert_eq!(uart.read(0x24), 0x5b);
    assert_eq!(uart.read(0x10) & 1, 0);
    drop(uart);
    assert!(prepared.step_insn().is_ok());
    assert!(prepared.checkpoint_publication.is_none());
}

#[test]
fn unattached_cpu_requires_publication_and_foreign_uart_binding_rejects() {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
    memory
        .write_slice(&0xe1a0_0000u32.to_le_bytes(), GuestAddress(0))
        .unwrap();
    let source = Armv6Vcpu::new(0, memory.clone());
    let public = source.get_state().unwrap();
    let raw = source.capture_context_record().unwrap();
    let mut prepared = source.prepare_context_replacement(&public, &raw).unwrap();
    assert!(prepared.step_insn().is_err());
    let bindings = CheckpointBindings::new(&memory, vec![]);
    {
        let scope = bindings.enter().unwrap();
        prepared.publication(&scope).unwrap().commit();
    }
    assert!(prepared.step_insn().is_ok());
    let mut source = Armv6Vcpu::new(0, memory.clone());
    source.attach_s3c_uart(Arc::new(Mutex::new(S3cUart::new())));
    let public = source.get_state().unwrap();
    let raw = source.capture_context_record().unwrap();
    let mut prepared = source.prepare_context_replacement(&public, &raw).unwrap();
    let unrelated = Arc::new(Mutex::new(S3cUart::new()));
    let bindings = CheckpointBindings::new(&memory, vec![]).with_s3c_uarts(vec![unrelated]);
    let scope = bindings.enter().unwrap();
    assert!(prepared.publication(&scope).is_err());
    assert!(prepared.step_insn().is_err());
}
