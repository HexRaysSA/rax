//! Mach semaphores (`osfmk/kern/sync_sema.c`).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A counting semaphore (`semaphore_create`).
#[derive(Debug)]
pub struct Semaphore {
    /// Identity, for wait keys.
    pub id: u64,
    /// The count; negative while threads wait.
    pub count: Mutex<i64>,
    /// `SYNC_POLICY_*`.
    pub policy: u32,
    /// Destroyed (`semaphore_destroy`): waiters return
    /// `KERN_TERMINATED`.
    pub destroyed: Mutex<bool>,
}

impl PartialEq for Semaphore {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Semaphore {}

impl Semaphore {
    /// A semaphore with `value`.
    pub fn new(policy: u32, value: i64) -> Self {
        Semaphore {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            count: Mutex::new(value),
            policy,
            destroyed: Mutex::new(false),
        }
    }
}
