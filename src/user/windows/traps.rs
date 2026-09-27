//! Trap slots: the addresses whose instruction fetch enters built-in code.
//!
//! Each built-in DLL image has a code section of 16-byte slots mapped
//! without execute permission. [`Traps`] maps a faulting fetch address to
//! what it means: slot offset 0 is an export's entry, offset 8 its resume
//! point; two slots at the start of `ntdll`'s section are the
//! callback-return and thread-start traps.

use std::sync::Arc;

use super::hle::Api;

/// Bytes per trap slot.
pub const SLOT_SIZE: u64 = 16;
/// Offset of the resume trap inside a slot.
pub const RESUME_OFFSET: u64 = 8;

/// What a slot designates.
#[derive(Clone, Debug)]
pub enum SlotKind {
    /// A built-in function.
    Api(&'static Api),
    /// An import this implementation does not provide
    /// (`"KERNEL32.DLL!Name"`): calling it ends the process.
    Missing(Arc<str>),
    /// Guest code called by built-in code returns here.
    CallbackReturn,
    /// A new thread starts here (`ntdll!RtlUserThreadStart`).
    ThreadStart,
}

/// A decoded trap.
#[derive(Clone, Debug)]
pub enum Trap {
    /// Entry to a built-in function.
    Entry(&'static Api),
    /// A context resuming inside a built-in function: return from it.
    Resume(&'static Api),
    /// A call to a missing function.
    Missing(Arc<str>),
    /// A guest callback returned.
    CallbackReturn,
    /// A thread starts.
    ThreadStart,
}

#[derive(Debug)]
struct Range {
    start: u64,
    slots: Vec<SlotKind>,
    /// Capacity in slots (the section's size).
    capacity: usize,
}

/// Every trap range of the process.
#[derive(Debug, Default)]
pub struct Traps {
    ranges: Vec<Range>,
    callback_return: u64,
    thread_start: u64,
}

impl Traps {
    /// Registers a code section at `start` holding `slots` with room for
    /// `capacity` slots. Returns the range's index.
    pub fn add(&mut self, start: u64, slots: Vec<SlotKind>, capacity: usize) -> usize {
        for (i, s) in slots.iter().enumerate() {
            let at = start + i as u64 * SLOT_SIZE;
            match s {
                SlotKind::CallbackReturn => self.callback_return = at,
                SlotKind::ThreadStart => self.thread_start = at,
                _ => {}
            }
        }
        let pos = self.ranges.partition_point(|r| r.start < start);
        self.ranges.insert(
            pos,
            Range {
                start,
                slots,
                capacity,
            },
        );
        pos
    }

    /// Appends a slot to the range starting at `start`; its address, or
    /// `None` when the section is full.
    pub fn append(&mut self, start: u64, kind: SlotKind) -> Option<u64> {
        let r = self.ranges.iter_mut().find(|r| r.start == start)?;
        if r.slots.len() >= r.capacity {
            return None;
        }
        r.slots.push(kind);
        Some(r.start + (r.slots.len() as u64 - 1) * SLOT_SIZE)
    }

    /// The trap at `addr`, if it is one.
    pub fn lookup(&self, addr: u64) -> Option<Trap> {
        let i = self.ranges.partition_point(|r| r.start <= addr);
        let r = self.ranges.get(i.checked_sub(1)?)?;
        let delta = addr - r.start;
        let slot = r.slots.get((delta / SLOT_SIZE) as usize)?;
        match (delta % SLOT_SIZE, slot) {
            (0, SlotKind::Api(api)) => Some(Trap::Entry(api)),
            (RESUME_OFFSET, SlotKind::Api(api)) => Some(Trap::Resume(api)),
            (0, SlotKind::Missing(name)) => Some(Trap::Missing(name.clone())),
            (0, SlotKind::CallbackReturn) => Some(Trap::CallbackReturn),
            (0, SlotKind::ThreadStart) => Some(Trap::ThreadStart),
            _ => None,
        }
    }

    /// Whether `addr` lies in a trap section (a built-in DLL's code).
    pub fn contains(&self, addr: u64) -> bool {
        let i = self.ranges.partition_point(|r| r.start <= addr);
        i.checked_sub(1).is_some_and(|i| {
            let r = &self.ranges[i];
            addr < r.start + r.capacity as u64 * SLOT_SIZE
        })
    }

    /// The callback-return trap.
    pub fn callback_return(&self) -> u64 {
        self.callback_return
    }

    /// The thread-start trap.
    pub fn thread_start(&self) -> u64 {
        self.thread_start
    }

    /// The entry address of `api` in the first range that holds it.
    pub fn address_of(&self, api: &'static Api) -> Option<u64> {
        self.ranges.iter().find_map(|r| {
            r.slots
                .iter()
                .position(|s| matches!(s, SlotKind::Api(a) if std::ptr::eq(*a, api)))
                .map(|i| r.start + i as u64 * SLOT_SIZE)
        })
    }
}
