//! Permanent-owner lifecycle, including a deliberately non-Send native core.
#[path = "../../../src/backend/hvf/intel_owner.rs"]
mod intel_owner;
use intel_owner::{Failure, Owner, StartError};
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, ThreadId};

#[cfg(feature = "hvf")]
mod error {
    pub use rax::error::{Error, Result};
}
#[cfg(feature = "hvf")]
#[path = "../../../src/backend/checkpoint.rs"]
mod backend;
#[cfg(feature = "hvf")]
#[path = "hvf_owner/lifetime.rs"]
mod lifetime;

struct Core {
    born: ThreadId,
    dropped: mpsc::Sender<(ThreadId, ThreadId)>,
    panic_on_drop: bool,
    _not_send: Rc<()>,
}
impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.dropped.send((self.born, thread::current().id()));
        assert!(!self.panic_on_drop, "injected native destructor panic");
    }
}
fn failure() -> (Failure, Arc<Mutex<Vec<String>>>) {
    let errors = Arc::new(Mutex::new(Vec::new()));
    let copy = errors.clone();
    (
        Arc::new(move |error| copy.lock().unwrap().push(error)),
        errors,
    )
}
fn owner(
    panic_on_drop: bool,
) -> (
    Owner<Core>,
    mpsc::Receiver<(ThreadId, ThreadId)>,
    Arc<Mutex<Vec<String>>>,
) {
    let (dropped, receiver) = mpsc::channel();
    let (failed, errors) = failure();
    let owner = Owner::spawn(
        "test-native-owner".into(),
        move || {
            Ok::<_, String>(Core {
                born: thread::current().id(),
                dropped,
                panic_on_drop,
                _not_send: Rc::new(()),
            })
        },
        failed,
    )
    .unwrap_or_else(|_| panic!("owner spawn failed"));
    (owner, receiver, errors)
}

#[test]
fn non_send_core_stays_on_one_thread_when_frontend_moves_twice() {
    let (owner, dropped, errors) = owner(false);
    let born = owner.call(|core| core.born).unwrap();
    assert_ne!(born, thread::current().id());
    let owner = thread::spawn(move || {
        assert_eq!(
            owner
                .call(|core| (core.born, thread::current().id()))
                .unwrap(),
            (born, born)
        );
        owner
    })
    .join()
    .unwrap();
    thread::spawn(move || drop(owner)).join().unwrap();
    assert_eq!(dropped.recv().unwrap(), (born, born));
    assert!(errors.lock().unwrap().is_empty());
}

#[test]
fn factory_errors_return_the_exact_payload_and_join_without_poisoning_peers() {
    let (failed, errors) = failure();
    let result = Owner::<Core>::spawn("failing-native-owner".into(), || Err(17u64), failed);
    assert!(matches!(result, Err(StartError::Create(17))));
    assert!(errors.lock().unwrap().is_empty());
}

#[test]
fn factory_panics_are_observed_before_creation_returns() {
    let (failed, errors) = failure();
    let result = Owner::<Core>::spawn(
        "panicking-native-owner".into(),
        || -> Result<Core, ()> { panic!("injected factory panic") },
        failed,
    );
    assert!(matches!(result, Err(StartError::Owner(_))));
    assert!(!errors.lock().unwrap().is_empty());
}

#[test]
fn operation_panic_drops_the_core_on_owner_and_fences_the_transport() {
    let (mut owner, dropped, errors) = owner(false);
    let born = owner.call(|core| core.born).unwrap();
    assert!(
        owner
            .call(|_| panic!("injected native operation panic"))
            .is_err()
    );
    assert!(owner.close().is_err());
    assert_eq!(dropped.recv().unwrap(), (born, born));
    assert!(
        owner
            .call(|_| panic!("closed owner executed a later operation"))
            .is_err()
    );
    assert!(!errors.lock().unwrap().is_empty());
}

#[test]
fn destructor_panic_is_reported_without_unwinding_the_caller() {
    let (mut owner, dropped, errors) = owner(true);
    let born = owner.call(|core| core.born).unwrap();
    assert!(owner.close().is_err());
    assert_eq!(dropped.recv().unwrap(), (born, born));
    assert!(!errors.lock().unwrap().is_empty());
    owner.close().unwrap();
}

#[test]
fn close_is_idempotent_and_drops_core_before_returning() {
    let (mut owner, dropped, errors) = owner(false);
    owner.close().unwrap();
    let (born, destroyed) = dropped.try_recv().unwrap();
    assert_eq!(born, destroyed);
    owner.close().unwrap();
    drop(owner);
    assert!(errors.lock().unwrap().is_empty());
}
