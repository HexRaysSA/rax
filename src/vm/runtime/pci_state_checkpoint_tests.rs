//! A late PCI lock or caller failure must not publish any PCI candidate.
use super::*;
use crate::vm::memory::vm::{Bytes, GuestAddress};
use std::sync::atomic::{AtomicUsize, Ordering};
fn poison<T: Send + 'static>(lock: Arc<Mutex<T>>) {
    assert!(
        std::thread::spawn(move || {
            let _guard = lock.lock().unwrap();
            panic!("owned PCI commit lock fixture");
        })
        .join()
        .is_err()
    );
}
fn current(d: &PciDevices) -> PciDeviceCheckpoint {
    let bridge = d
        .bridge
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .checkpoint()
        .unwrap();
    let endpoints = d.endpoints.as_ref().map(|e| PciEndpointCheckpoint {
        e1000: e
            .e1000
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .checkpoint()
            .unwrap(),
        uhci: e
            .uhci
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .checkpoint()
            .unwrap(),
        nvme: e
            .nvme
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .checkpoint()
            .unwrap(),
        ahci: e
            .ahci
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .checkpoint()
            .unwrap(),
        ac97: e
            .ac97
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .checkpoint()
            .unwrap(),
    });
    PciDeviceCheckpoint { bridge, endpoints }
}
fn modified(d: &PciDevices) -> PciDeviceCheckpoint {
    let mut p = d.checkpoint().unwrap();
    p.bridge.state[8..12].copy_from_slice(&0x80000010u32.to_le_bytes());
    if let Some(e) = &mut p.endpoints {
        e.nvme.state[33..37].copy_from_slice(&0x10u32.to_le_bytes());
        e.ac97.state[12..14].copy_from_slice(&0x16u16.to_le_bytes());
    }
    p
}
#[test]
fn every_poisoned_pci_lock_prevents_callback_and_all_live_assignment() {
    for which in 0..6 {
        let m = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        m.write_slice(&[0xa5; 4096], GuestAddress(0)).unwrap();
        let d = PciDevices::new(m.clone(), &Default::default(), true).unwrap();
        let before = current(&d);
        let cp = modified(&d);
        let e = d.endpoints.as_ref().unwrap();
        match which {
            0 => poison(d.bridge.clone()),
            1 => poison(e.e1000.clone()),
            2 => poison(e.uhci.clone()),
            3 => poison(e.nvme.clone()),
            4 => poison(e.ahci.clone()),
            5 => poison(e.ac97.clone()),
            _ => unreachable!(),
        };
        let calls = AtomicUsize::new(0);
        assert!(
            d.restore_checkpoint_with(cp, || {
                calls.fetch_add(1, Ordering::SeqCst);
                m.write_slice(&[0x33; 4096], GuestAddress(0)).unwrap();
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(current(&d), before);
        let mut raw = [0; 4096];
        m.read_slice(&mut raw, GuestAddress(0)).unwrap();
        assert_eq!(raw, [0xa5; 4096]);
    }
}
#[test]
fn caller_error_keeps_pci_old_and_success_publishes_exact_candidates() {
    for enabled in [false, true] {
        let m = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let d = PciDevices::new(m.clone(), &Default::default(), enabled).unwrap();
        let before = current(&d);
        let cp = modified(&d);
        let calls = AtomicUsize::new(0);
        let result = d.restore_checkpoint_with(cp.clone(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(Error::InvalidConfig("owned caller rejection".to_string()))
        });
        assert!(result.is_err());
        assert_eq!(current(&d), before);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        d.restore_checkpoint_with(cp.clone(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            m.write_slice(&[0x33; 4096], GuestAddress(0)).unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(current(&d), cp);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let mut raw = [0; 4096];
        m.read_slice(&mut raw, GuestAddress(0)).unwrap();
        assert_eq!(raw, [0x33; 4096]);
    }
}
