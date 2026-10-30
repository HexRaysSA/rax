//! Actual VM lease/lifetime policy with only SDK destruction substituted.
#[path = "../../../../src/backend/hvf/intel_vm.rs"]
mod intel_vm;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

static SERIAL: Mutex<()> = Mutex::new(());
static SDK: Mutex<(usize, bool)> = Mutex::new((0, false));
mod bindings {
    pub const HV_SUCCESS: i32 = 0;
    pub fn hv_error_string(_: i32) -> &'static str {
        "injected VM destruction failure"
    }
    pub unsafe fn hv_vm_destroy() -> i32 {
        let mut sdk = super::SDK.lock().unwrap();
        sdk.0 += 1;
        if sdk.1 { -1 } else { 0 }
    }
}
mod native_memory {
    use super::*;
    pub(super) type Shared = Arc<RwLock<Option<Arc<Backing>>>>;
    pub(super) struct Backing(pub Arc<AtomicUsize>);
    impl Drop for Backing {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[test]
fn vm_destruction_waits_for_every_retained_lifetime() {
    let _serial = SERIAL.lock().unwrap();
    *SDK.lock().unwrap() = (0, false);
    let vm = Arc::new(intel_vm::Lifetime::default());
    let first = vm.clone();
    let second = vm.clone();
    drop(vm);
    drop(first);
    assert_eq!(SDK.lock().unwrap().0, 0);
    drop(second);
    assert_eq!(SDK.lock().unwrap().0, 1);
}

#[test]
fn checkpoint_boundary_excludes_ordinary_owner_requests() {
    let _serial = SERIAL.lock().unwrap();
    *SDK.lock().unwrap() = (0, false);
    let vm = Arc::new(intel_vm::Lifetime::default());
    let boundary = vm.stopped().unwrap();
    boundary.require_owner(vm.identity()).unwrap();
    let other = vm.clone();
    let (started, starting) = mpsc::channel();
    let (finished, finishing) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        started.send(()).unwrap();
        let _request = other.quiescence.read().unwrap();
        other.ready().unwrap();
        finished.send(()).unwrap();
    });
    starting.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(finishing.try_recv(), Err(mpsc::TryRecvError::Empty));
    drop(boundary);
    finishing.recv_timeout(Duration::from_secs(5)).unwrap();
    thread.join().unwrap();
}

#[test]
fn foreign_boundaries_and_failed_vm_lifetimes_are_rejected() {
    let _serial = SERIAL.lock().unwrap();
    *SDK.lock().unwrap() = (0, false);
    let first = intel_vm::Lifetime::default();
    let second = intel_vm::Lifetime::default();
    let boundary = first.stopped().unwrap();
    assert!(boundary.require_owner(second.identity()).is_err());
    second.poison("injected owner loss".into());
    assert!(second.ready().is_err());
    assert!(second.stopped().is_err());
    drop(boundary);
}

#[test]
fn mapped_backing_survives_failed_sdk_vm_destruction() {
    let _serial = SERIAL.lock().unwrap();
    for failed in [false, true] {
        *SDK.lock().unwrap() = (0, failed);
        let vm = intel_vm::Lifetime::default();
        let drops = Arc::new(AtomicUsize::new(0));
        let backing = Arc::new(native_memory::Backing(drops.clone()));
        let weak = Arc::downgrade(&backing);
        *vm.memory_layout.write().unwrap() = Some(backing);
        drop(vm);
        assert_eq!(SDK.lock().unwrap().0, 1);
        assert_eq!(weak.upgrade().is_some(), failed);
        assert_eq!(drops.load(Ordering::SeqCst), usize::from(!failed));
        // A failed destruction intentionally quarantines one small test Arc,
        // just as the product must retain SDK-owned mapped memory.
    }
}
