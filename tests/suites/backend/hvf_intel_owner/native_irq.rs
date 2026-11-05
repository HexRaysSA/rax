//! Controller-before-native-exclusion is observable without a guest entry.
use super::*;
use rax::devices::bus::MmioDevice;
use std::sync::TryLockError;
use std::time::{Duration, Instant};

#[test]
fn source_publication_locks_the_controller_before_native_exclusion() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let controller = Arc::new(Mutex::new(rax::devices::ioapic::IoApic::new()));
    {
        let mut model = controller.lock().unwrap();
        model.write(0xfec0_0000, &[0x38]);
        model.write(0xfec0_0010, &0x8051u32.to_le_bytes());
    }
    let (vm, _memory) = fixture_with_ioapic(controller.clone());
    let vm: Arc<dyn rax::backend::Vm> = Arc::from(vm);
    let boundary = vm.checkpoint_boundary().unwrap();
    let publisher = vm.clone();
    let publication = thread::spawn(move || publisher.set_irq_line(20, true));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut controller_owned = false;
    while Instant::now() < deadline {
        match controller.try_lock() {
            Ok(guard) => drop(guard),
            Err(TryLockError::WouldBlock) => {
                controller_owned = true;
                break;
            }
            Err(TryLockError::Poisoned(_)) => break,
        }
        thread::sleep(Duration::from_millis(1));
    }
    // Always release the writer and join before asserting. The old ordering
    // therefore fails finitely instead of leaving a blocked publication thread.
    drop(boundary);
    publication.join().unwrap().unwrap();
    assert_eq!(controller.lock().unwrap().pending().len(), 1);
    assert!(
        controller_owned,
        "source publication waited for native exclusion before acquiring the controller"
    );
}
