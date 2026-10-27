//! VM-owned wall clock, diagnostic tick counter and pending-timer flag.
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Anchor {
    base: u64,
    start: Instant,
}
/// A VM's existing wall-time domain. Clone its Arc into a worker and enter it
/// there explicitly; ambient bindings are local to the calling thread.
pub struct TimingContext {
    anchor: Mutex<Anchor>,
    instructions: AtomicU64,
    timer_pending: AtomicBool,
}
impl Default for TimingContext {
    fn default() -> Self {
        Self::new()
    }
}
impl TimingContext {
    pub fn new() -> Self {
        Self {
            anchor: Mutex::new(Anchor {
                base: 0,
                start: Instant::now(),
            }),
            instructions: AtomicU64::new(0),
            timer_pending: AtomicBool::new(false),
        }
    }
    pub fn elapsed_nanos(&self) -> u64 {
        let anchor = self.anchor.lock().unwrap_or_else(|p| p.into_inner());
        anchor
            .base
            .wrapping_add(anchor.start.elapsed().as_nanos() as u64)
    }
    /// Re-anchor this context now, including repeated restore in one process.
    pub fn set_resume_base(&self, base: u64) {
        let mut anchor = self.anchor.lock().unwrap_or_else(|p| p.into_inner());
        anchor.base = base;
        anchor.start = Instant::now();
    }
    pub fn tick(&self) -> u64 {
        self.instructions
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }
    pub fn instruction_count(&self) -> u64 {
        self.instructions.load(Ordering::Relaxed)
    }
    pub fn set_timer_pending(&self) {
        self.timer_pending.store(true, Ordering::Release);
    }
    pub fn take_timer_pending(&self) -> bool {
        self.timer_pending.swap(false, Ordering::AcqRel)
    }
    pub fn is_timer_pending(&self) -> bool {
        self.timer_pending.load(Ordering::Acquire)
    }
    /// Preserve the old reset contract: counters/notification only, not time.
    pub fn reset(&self) {
        self.instructions.store(0, Ordering::Relaxed);
        self.timer_pending.store(false, Ordering::Release);
    }
    pub fn enter(self: &Arc<Self>) -> TimingGuard {
        let token = Rc::new(());
        CURRENT.with(|stack| {
            stack.borrow_mut().push(Binding {
                token: token.clone(),
                clock: self.clone(),
            })
        });
        TimingGuard { token }
    }
}
struct Binding {
    token: Rc<()>,
    clock: Arc<TimingContext>,
}
thread_local! { static CURRENT: RefCell<Vec<Binding>> = const { RefCell::new(Vec::new()) }; }
/// Thread-bound scope. Dropping nested guards out of order removes only the
/// matching binding, leaving the latest surviving context active.
pub struct TimingGuard {
    token: Rc<()>,
}
impl Drop for TimingGuard {
    fn drop(&mut self) {
        let _ = CURRENT.try_with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(index) = stack.iter().position(|b| Rc::ptr_eq(&b.token, &self.token)) {
                stack.remove(index);
            }
        });
    }
}
pub(super) fn with_current<T>(f: impl FnOnce(&TimingContext) -> T) -> Option<T> {
    // Release the TLS borrow before calling code that can enter another scope.
    let clock = CURRENT.with(|stack| stack.borrow().last().map(|b| b.clock.clone()));
    clock.map(|clock| f(&clock))
}
