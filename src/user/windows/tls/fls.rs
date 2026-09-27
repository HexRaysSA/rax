//! FLS ownership and cleanup receipts. Public callback triggers are specified by
//! FlsFree and PFLS_CALLBACK_FUNCTION; ordering/reentrancy bounds are profiles.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::{FLS_MAXIMUM_AVAILABLE, TlsState};

/// Disjoint host-authoritative FLS context identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlsKey {
    /// An ordinary thread's implicit FLS context.
    Thread(u32),
    /// A live fiber identity, validated by the fiber engine.
    Fiber(u64),
}

/// Registry failure; only invalid input/OOM map to Win32 errors. Other failures
/// are explicit personality diagnostics, not invented native statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlsError {
    InvalidIndex,
    NoMemory,
    GenerationExhausted,
    Busy,
    NonConvergent,
}

/// One VOID guest callback. Its value is captured before invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlsCallback {
    pub key: FlsKey,
    pub index: u32,
    pub generation: u64,
    pub callback: u64,
    pub value: u64,
}

/// An unfinished guest cleanup escaped its continuation. Forced termination may
/// explicitly discard this receipt; ordinary scheduling reports a diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlsAbandoned {
    pub tid: u32,
    pub kind: &'static str,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SlotState {
    #[default]
    Free,
    Allocated,
    Closing,
}

#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    state: SlotState,
    generation: u64,
    callback: u64,
}

#[derive(Clone, Copy, Debug)]
struct Value {
    generation: u64,
    value: u64,
}

#[derive(Debug, Default)]
struct Registry {
    slots: Vec<Slot>,
    values: HashMap<FlsKey, HashMap<u32, Value>>,
    cleaning: HashSet<FlsKey>,
    active: usize,
    abandoned: Vec<FlsAbandoned>,
}

impl Registry {
    fn allocated(&self, index: u32) -> Result<Slot, FlsError> {
        self.slots
            .get(index as usize)
            .copied()
            .filter(|s| index != 0 && s.state == SlotState::Allocated)
            .ok_or(FlsError::InvalidIndex)
    }

    fn reserve_receipt(&mut self) -> Result<(), FlsError> {
        let next = self
            .active
            .checked_add(1)
            .ok_or(FlsError::GenerationExhausted)?;
        // Reserve for every outstanding ticket, not just current receipt count:
        // Drop must not allocate while abandoning guest continuations.
        self.abandoned
            .try_reserve(next)
            .map_err(|_| FlsError::NoMemory)?;
        self.active = next;
        Ok(())
    }

    fn release_receipt(&mut self, owner: Option<u32>, finished: bool, kind: &'static str) {
        self.active -= 1;
        if !finished && let Some(tid) = owner {
            self.abandoned.push(FlsAbandoned { tid, kind });
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct FlsRegistry(Rc<RefCell<Registry>>);

/// FlsFree's immutable callback plan. Closing admission prevents recycling the
/// index until all callbacks finish (or an explicit abandonment drops the plan).
pub struct FlsFree {
    registry: Rc<RefCell<Registry>>,
    index: u32,
    generation: u64,
    calls: Vec<FlsCallback>,
    cursor: usize,
    owner: Option<u32>,
    finished: bool,
}

impl FlsFree {
    pub fn set_owner(&mut self, tid: u32) {
        self.owner = Some(tid);
    }
    pub fn next(&mut self) -> Option<FlsCallback> {
        let call = self.calls.get(self.cursor).copied()?;
        self.cursor += 1;
        Some(call)
    }
    pub fn finish(&mut self) -> Result<(), FlsError> {
        if self.finished {
            return Ok(());
        }
        if self.cursor != self.calls.len() {
            return Err(FlsError::Busy);
        }
        let mut r = self.registry.borrow_mut();
        let slot = &mut r.slots[self.index as usize];
        if slot.state != SlotState::Closing || slot.generation != self.generation {
            return Err(FlsError::InvalidIndex);
        }
        slot.state = SlotState::Free;
        slot.callback = 0;
        self.finished = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_keys_migrate_without_aliasing_or_overwriting() {
        let mut t = TlsState::default();
        let slot = t.fls_alloc(0).unwrap();
        let (a, b) = (FlsKey::Thread(8), FlsKey::Fiber(8));
        t.fls_set(a, slot, 0x1234).unwrap();
        assert_eq!(t.fls_get(b, slot), Ok(0));
        t.fls_move_context(a, b).unwrap();
        assert_eq!(t.fls_get(a, slot), Ok(0));
        assert_eq!(t.fls_get(b, slot), Ok(0x1234));
        t.fls_set(a, slot, 0x5678).unwrap();
        assert_eq!(t.fls_move_context(b, a), Err(FlsError::Busy));
        assert_eq!(t.fls_get(b, slot), Ok(0x1234));
        t.fls_set(a, slot, 0).unwrap();
        t.fls_move_context(b, a).unwrap();
        assert_eq!(t.fls_get(a, slot), Ok(0x1234));
        t.fls_discard_context(a);
        assert_eq!(t.fls_get(a, slot), Ok(0));
    }

    #[test]
    fn free_is_all_context_nonnull_and_recycling_waits_for_completion() {
        let mut t = TlsState::default();
        let slot = t.fls_alloc(0x1000).unwrap();
        for (key, value) in [
            (FlsKey::Thread(8), 11),
            (FlsKey::Fiber(8), 12),
            (FlsKey::Thread(12), 0),
        ] {
            t.fls_set(key, slot, value).unwrap();
        }
        let mut free = t.fls_begin_free(slot).unwrap();
        assert_eq!(free.finish(), Err(FlsError::Busy));
        assert!(!t.fls_allocated(slot));
        assert!(matches!(
            t.fls_begin_free(slot),
            Err(FlsError::InvalidIndex)
        ));
        assert_eq!(
            t.fls_set(FlsKey::Thread(8), slot, 99),
            Err(FlsError::InvalidIndex)
        );
        let other = t.fls_alloc(0).unwrap();
        assert_ne!(other, slot);
        let first = free.next().unwrap();
        assert_eq!(
            (first.key, first.callback, first.value),
            (FlsKey::Thread(8), 0x1000, 11)
        );
        let second = free.next().unwrap();
        assert_eq!((second.key, second.value), (FlsKey::Fiber(8), 12));
        assert!(free.next().is_none());
        free.finish().unwrap();
        free.finish().unwrap();
        drop(free);
        assert_eq!(t.fls_alloc(0x2000), Ok(slot));
        assert_eq!(t.fls_get(FlsKey::Thread(8), slot), Ok(0));
        assert_eq!(t.fls_get(FlsKey::Fiber(8), slot), Ok(0));
    }

    #[test]
    fn cleanup_uses_live_generations_and_handles_rearmed_values() {
        let mut t = TlsState::default();
        let key = FlsKey::Thread(8);
        let a = t.fls_alloc(0x1000).unwrap();
        let b = t.fls_alloc(0x2000).unwrap();
        t.fls_set(key, a, 11).unwrap();
        t.fls_set(key, b, 22).unwrap();
        let mut cleanup = t.fls_begin_cleanup(key).unwrap();
        assert_eq!(
            t.fls_move_context(key, FlsKey::Fiber(8)),
            Err(FlsError::Busy)
        );
        let first = cleanup.next().unwrap().unwrap();
        assert_eq!((first.index, first.value), (a, 11));
        assert_eq!(t.fls_get(key, a), Ok(0));
        t.fls_set(key, a, 33).unwrap();
        let mut free = t.fls_begin_free(b).unwrap();
        assert_eq!(free.next().unwrap().value, 22);
        assert!(free.next().is_none());
        free.finish().unwrap();
        drop(free);
        assert_eq!(t.fls_alloc(0x3000), Ok(b));
        t.fls_set(key, b, 44).unwrap();
        assert_eq!(cleanup.next().unwrap().unwrap().value, 33);
        let latest = cleanup.next().unwrap().unwrap();
        assert_eq!(
            (latest.index, latest.callback, latest.value),
            (b, 0x3000, 44)
        );
        assert_eq!(cleanup.next(), Ok(None));
        cleanup.finish().unwrap();
        assert!(t.fls_take_abandoned().is_empty());
    }

    #[test]
    fn finished_ticket_drop_cannot_clear_a_new_cleanup_admission() {
        let mut t = TlsState::default();
        let key = FlsKey::Thread(8);
        let mut first = t.fls_begin_cleanup(key).unwrap();
        assert_eq!(first.next(), Ok(None));
        first.finish().unwrap();
        let second = t.fls_begin_cleanup(key).unwrap();
        drop(first);
        assert_eq!(
            t.fls_move_context(key, FlsKey::Fiber(8)),
            Err(FlsError::Busy)
        );
        assert!(matches!(t.fls_begin_cleanup(key), Err(FlsError::Busy)));
        drop(second);
        t.fls_move_context(key, FlsKey::Fiber(8)).unwrap();
    }

    #[test]
    fn nonconvergent_cleanup_is_bounded_and_abandonment_is_reported() {
        let mut t = TlsState::default();
        let key = FlsKey::Fiber(0x10000);
        let slot = t.fls_alloc(0x2000).unwrap();
        t.fls_set(key, slot, 1).unwrap();
        let mut cleanup = t.fls_begin_cleanup(key).unwrap();
        cleanup.set_owner(8);
        for _ in 0..CLEANUP_CALLBACK_LIMIT {
            assert!(cleanup.next().unwrap().is_some());
            t.fls_set(key, slot, 1).unwrap();
        }
        assert_eq!(cleanup.next(), Err(FlsError::NonConvergent));
        assert_eq!(t.fls_get(key, slot), Ok(1));
        drop(cleanup);
        assert_eq!(
            t.fls_take_abandoned(),
            vec![FlsAbandoned {
                tid: 8,
                kind: "FLS context cleanup"
            }]
        );
        t.fls_discard_context(key);
        assert_eq!(t.fls_get(key, slot), Ok(0));
    }

    #[test]
    fn abandoned_free_releases_closing_slot_without_success_or_stale_values() {
        let mut t = TlsState::default();
        let slot = t.fls_alloc(0x1000).unwrap();
        t.fls_set(FlsKey::Thread(8), slot, 11).unwrap();
        let mut free = t.fls_begin_free(slot).unwrap();
        free.set_owner(8);
        assert!(free.next().is_some());
        drop(free);
        assert_eq!(
            t.fls_take_abandoned(),
            vec![FlsAbandoned {
                tid: 8,
                kind: "FlsFree"
            }]
        );
        assert_eq!(t.fls_alloc(0), Ok(slot));
        assert_eq!(t.fls_get(FlsKey::Thread(8), slot), Ok(0));
    }

    #[test]
    fn bounded_slots_and_generation_overflow_fail_without_publication() {
        let mut t = TlsState::default();
        for i in 1..FLS_MAXIMUM_AVAILABLE {
            assert_eq!(t.fls_alloc(0), Ok(i));
        }
        assert_eq!(t.fls_alloc(0), Err(FlsError::NoMemory));
        assert_eq!(t.fls_get(FlsKey::Thread(8), 0), Err(FlsError::InvalidIndex));
        assert_eq!(
            t.fls_get(FlsKey::Thread(8), u32::MAX),
            Err(FlsError::InvalidIndex)
        );
        let mut free = t.fls_begin_free(1).unwrap();
        assert!(free.next().is_none());
        free.finish().unwrap();
        drop(free);
        t.fls.0.borrow_mut().slots[1].generation = u64::MAX;
        assert_eq!(t.fls_alloc(0), Err(FlsError::GenerationExhausted));
        assert!(!t.fls_allocated(1));
    }
}

impl Drop for FlsFree {
    fn drop(&mut self) {
        let mut r = self.registry.borrow_mut();
        let slot = &mut r.slots[self.index as usize];
        if slot.state == SlotState::Closing && slot.generation == self.generation {
            slot.state = SlotState::Free;
            slot.callback = 0;
        }
        r.release_receipt(self.owner, self.finished, "FlsFree");
    }
}

/// Maximum callbacks per context cleanup, including values rearmed by callbacks.
/// This is a finite RAX profile bound, not a Windows destructor-pass contract.
pub const CLEANUP_CALLBACK_LIMIT: usize = 4096;

/// Context deletion/normal-exit cleanup. Each next call reads live registry
/// generations so a callback that frees/reallocates another slot cannot invoke
/// that slot's stale destructor. No registry borrow crosses guest execution.
pub struct FlsCleanup {
    registry: Rc<RefCell<Registry>>,
    key: FlsKey,
    calls: usize,
    owner: Option<u32>,
    finished: bool,
}

impl FlsCleanup {
    pub fn set_owner(&mut self, tid: u32) {
        self.owner = Some(tid);
    }
    pub fn next(&mut self) -> Result<Option<FlsCallback>, FlsError> {
        if self.finished {
            return Ok(None);
        }
        let mut r = self.registry.borrow_mut();
        loop {
            let index = r
                .values
                .get(&self.key)
                .and_then(|m| m.keys().copied().min());
            let Some(index) = index else {
                return Ok(None);
            };
            let value = r.values[&self.key][&index];
            let slot = r.allocated(index).ok();
            let callable = slot.filter(|s| {
                s.generation == value.generation && s.callback != 0 && value.value != 0
            });
            if callable.is_some() && self.calls == CLEANUP_CALLBACK_LIMIT {
                return Err(FlsError::NonConvergent);
            }
            r.values.get_mut(&self.key).unwrap().remove(&index);
            if let Some(slot) = callable {
                self.calls += 1;
                return Ok(Some(FlsCallback {
                    key: self.key,
                    index,
                    generation: slot.generation,
                    callback: slot.callback,
                    value: value.value,
                }));
            }
        }
    }
    pub fn finish(&mut self) -> Result<(), FlsError> {
        if self.finished {
            return Ok(());
        }
        let mut r = self.registry.borrow_mut();
        if r.values.get(&self.key).is_some_and(|m| !m.is_empty()) {
            return Err(FlsError::Busy);
        }
        r.values.remove(&self.key);
        r.cleaning.remove(&self.key);
        self.finished = true;
        Ok(())
    }
}

impl Drop for FlsCleanup {
    fn drop(&mut self) {
        let mut r = self.registry.borrow_mut();
        // A finished ticket may outlive admission of a newer cleanup for the
        // same key. Only an unfinished ticket still owns the admission marker.
        if !self.finished {
            r.cleaning.remove(&self.key);
        }
        r.release_receipt(self.owner, self.finished, "FLS context cleanup");
    }
}

impl TlsState {
    pub fn fls_alloc(&mut self, callback: u64) -> Result<u32, FlsError> {
        let mut r = self.fls.0.borrow_mut();
        let free = (1..r.slots.len()).find(|&i| r.slots[i].state == SlotState::Free);
        let index = match free {
            Some(i) => i,
            None => {
                let i = r.slots.len().max(1);
                if i >= FLS_MAXIMUM_AVAILABLE as usize {
                    return Err(FlsError::NoMemory);
                }
                let add = i + 1 - r.slots.len();
                r.slots.try_reserve(add).map_err(|_| FlsError::NoMemory)?;
                r.slots.resize(i + 1, Slot::default());
                i
            }
        };
        let s = &mut r.slots[index];
        let generation = s
            .generation
            .checked_add(1)
            .ok_or(FlsError::GenerationExhausted)?;
        *s = Slot {
            state: SlotState::Allocated,
            generation,
            callback,
        };
        Ok(index as u32)
    }

    pub fn fls_allocated(&self, index: u32) -> bool {
        self.fls.0.borrow().allocated(index).is_ok()
    }

    pub fn fls_get(&self, key: FlsKey, index: u32) -> Result<u64, FlsError> {
        let r = self.fls.0.borrow();
        let slot = r.allocated(index)?;
        Ok(r.values
            .get(&key)
            .and_then(|m| m.get(&index))
            .filter(|v| v.generation == slot.generation)
            .map_or(0, |v| v.value))
    }

    pub fn fls_set(&mut self, key: FlsKey, index: u32, value: u64) -> Result<(), FlsError> {
        let mut r = self.fls.0.borrow_mut();
        let generation = r.allocated(index)?.generation;
        if value == 0 {
            if let Some(m) = r.values.get_mut(&key) {
                m.remove(&index);
            }
            return Ok(());
        }
        if let Some(m) = r.values.get_mut(&key) {
            if !m.contains_key(&index) {
                m.try_reserve(1).map_err(|_| FlsError::NoMemory)?;
            }
            m.insert(index, Value { generation, value });
        } else {
            r.values.try_reserve(1).map_err(|_| FlsError::NoMemory)?;
            let mut m = HashMap::new();
            m.try_reserve(1).map_err(|_| FlsError::NoMemory)?;
            m.insert(index, Value { generation, value });
            r.values.insert(key, m);
        }
        Ok(())
    }

    /// Move conversion/reconversion storage without callbacks or overwriting a
    /// live destination. Reservation occurs before source removal.
    pub fn fls_move_context(&mut self, from: FlsKey, to: FlsKey) -> Result<(), FlsError> {
        if from == to {
            return Ok(());
        }
        let mut r = self.fls.0.borrow_mut();
        if r.cleaning.contains(&from)
            || r.cleaning.contains(&to)
            || r.values.get(&to).is_some_and(|m| !m.is_empty())
        {
            return Err(FlsError::Busy);
        }
        r.values.try_reserve(1).map_err(|_| FlsError::NoMemory)?;
        if let Some(values) = r.values.remove(&from) {
            r.values.insert(to, values);
        }
        Ok(())
    }

    pub fn fls_discard_context(&mut self, key: FlsKey) {
        self.fls.0.borrow_mut().values.remove(&key);
    }
    pub fn fls_discard_all(&mut self) {
        self.fls.0.borrow_mut().values.clear();
    }

    pub fn fls_begin_free(&mut self, index: u32) -> Result<FlsFree, FlsError> {
        let (generation, calls) = {
            let mut r = self.fls.0.borrow_mut();
            let slot = r.allocated(index)?;
            let mut calls = Vec::new();
            if slot.callback != 0 {
                calls
                    .try_reserve(r.values.len())
                    .map_err(|_| FlsError::NoMemory)?;
                for (&key, values) in &r.values {
                    if let Some(value) = values.get(&index)
                        && value.generation == slot.generation
                        && value.value != 0
                    {
                        calls.push(FlsCallback {
                            key,
                            index,
                            generation: slot.generation,
                            callback: slot.callback,
                            value: value.value,
                        });
                    }
                }
                calls.sort_unstable_by_key(|c| c.key);
            }
            r.reserve_receipt()?;
            r.slots[index as usize].state = SlotState::Closing;
            for values in r.values.values_mut() {
                values.remove(&index);
            }
            (slot.generation, calls)
        };
        Ok(FlsFree {
            registry: Rc::clone(&self.fls.0),
            index,
            generation,
            calls,
            cursor: 0,
            owner: None,
            finished: false,
        })
    }

    pub fn fls_begin_cleanup(&mut self, key: FlsKey) -> Result<FlsCleanup, FlsError> {
        {
            let mut r = self.fls.0.borrow_mut();
            if r.cleaning.contains(&key) {
                return Err(FlsError::Busy);
            }
            r.cleaning.try_reserve(1).map_err(|_| FlsError::NoMemory)?;
            r.reserve_receipt()?;
            r.cleaning.insert(key);
        }
        Ok(FlsCleanup {
            registry: Rc::clone(&self.fls.0),
            key,
            calls: 0,
            owner: None,
            finished: false,
        })
    }

    pub fn fls_take_abandoned(&mut self) -> Vec<FlsAbandoned> {
        // Preserve reserved capacity for active ticket Drop; taking the Vec
        // itself would invalidate the no-allocation abandonment guarantee.
        let mut r = self.fls.0.borrow_mut();
        r.abandoned.drain(..).collect()
    }
    pub fn fls_discard_abandoned(&mut self) {
        self.fls.0.borrow_mut().abandoned.clear();
    }
    /// Forced thread termination drops only its own abandoned-continuation
    /// diagnostics; unrelated owners must still be reported at the frontier.
    pub fn fls_discard_abandoned_owner(&mut self, tid: u32) {
        self.fls.0.borrow_mut().abandoned.retain(|a| a.tid != tid);
    }
}
