//! Single-node virt PLIC register map and level-triggered gateways.
//! The platform lock covers each operation and its resulting output levels.

use serde::{Deserialize, Serialize};

pub(super) const BASE: u64 = 0x0c00_0000;
pub(super) const LEN: u64 = 0x60_0000;
pub(super) const UART_SOURCE: u32 = 10;
const SOURCE_COUNT: usize = 96;
const SOURCE_MASK: u128 = ((1u128 << SOURCE_COUNT) - 1) & !1;
const PRIORITY_MASK: u8 = 7;
const MAX_CONTEXTS: usize = u8::MAX as usize * 2;
const PENDING_BASE: u64 = 0x1000;
const ENABLE_BASE: u64 = 0x2000;
const ENABLE_STRIDE: u64 = 0x80;
const TARGET_BASE: u64 = 0x20_0000;
const TARGET_STRIDE: u64 = 0x1000;
const BITMAP_BYTES: u64 = SOURCE_COUNT as u64 / 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Target {
    enable: u128,
    threshold: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Plic {
    priorities: [[u8; 32]; SOURCE_COUNT / 32],
    levels: u128,
    pending: u128,
    claimed: u128,
    #[serde(deserialize_with = "targets")]
    targets: Vec<Target>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AccessError {
    Range,
    Alignment,
}

fn targets<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Target>, D::Error> {
    crate::devices::checkpoint_serde::vector::<Target, D, MAX_CONTEXTS>(d)
}

enum Register {
    Priority(u32),
    Pending(u32),
    Enable(usize, u32),
    Threshold(usize),
    Claim(usize),
    Reserved,
}

pub(super) fn overlaps(address: u64, size: usize) -> bool {
    size != 0 && address < BASE + LEN && u128::from(address) + size as u128 > u128::from(BASE)
}

impl Plic {
    pub(super) fn new(harts: u8) -> Self {
        Self {
            priorities: [[0; 32]; SOURCE_COUNT / 32],
            levels: 0,
            pending: 0,
            claimed: 0,
            targets: vec![Target::default(); usize::from(harts) * 2],
        }
    }

    pub(super) fn validate(&self, harts: usize) -> Result<(), &'static str> {
        if harts == 0 || harts > MAX_CONTEXTS / 2 || self.targets.len() != harts * 2 {
            return Err("invalid context count");
        }
        if (self.levels | self.pending | self.claimed) & !SOURCE_MASK != 0
            || self.pending & self.claimed != 0
            || self.levels & !(self.pending | self.claimed) != 0
        {
            return Err("invalid gateway state");
        }
        if self.priority(0) != 0
            || self.priorities.iter().flatten().any(|&v| v > PRIORITY_MASK)
            || self
                .targets
                .iter()
                .any(|t| t.enable & !SOURCE_MASK != 0 || t.threshold > PRIORITY_MASK)
        {
            return Err("invalid priority, enable or threshold state");
        }
        Ok(())
    }

    pub(super) fn set_level(&mut self, source: u32, asserted: bool) -> Result<(), &'static str> {
        if !(1..SOURCE_COUNT as u32).contains(&source) {
            return Err("invalid interrupt source");
        }
        let bit = 1u128 << source;
        if asserted {
            self.levels |= bit;
            if self.claimed & bit == 0 {
                self.pending |= bit;
            }
        } else {
            // The pending request has already left the gateway. Falling
            // level only affects whether it can re-pend after completion.
            self.levels &= !bit;
        }
        Ok(())
    }

    pub(super) fn uart_level(&self) -> bool {
        self.levels & (1 << UART_SOURCE) != 0
    }

    pub(super) fn hart_lines(&self, id: usize) -> (bool, bool) {
        let machine = id * 2;
        (self.notification(machine), self.notification(machine + 1))
    }

    fn notification(&self, target: usize) -> bool {
        self.select(target, self.targets[target].threshold) != 0
    }

    fn priority(&self, source: u32) -> u8 {
        let source = source as usize;
        self.priorities[source / 32][source % 32]
    }

    // The caller chooses the notification threshold or zero for a claim.
    // Each step inspects one pending, enabled source in ID order.
    fn select(&self, target: usize, mut threshold: u8) -> u32 {
        let mut candidates = self.pending & self.targets[target].enable;
        let mut selected = 0;
        while candidates != 0 {
            let source = candidates.trailing_zeros();
            let priority = self.priority(source);
            if priority > threshold {
                selected = source;
                threshold = priority;
            }
            candidates &= candidates - 1;
        }
        selected
    }

    pub(super) fn probe(&self, address: u64, size: usize) -> Result<(), AccessError> {
        self.register(address, size).map(|_| ())
    }

    fn register(&self, address: u64, size: usize) -> Result<Register, AccessError> {
        if size != 4 || !(BASE..BASE + LEN).contains(&address) {
            return Err(AccessError::Range);
        }
        if address & 3 != 0 {
            return Err(AccessError::Alignment);
        }
        let offset = address - BASE;
        if (4..SOURCE_COUNT as u64 * 4).contains(&offset) {
            return Ok(Register::Priority((offset / 4) as u32));
        }
        if (PENDING_BASE..PENDING_BASE + BITMAP_BYTES).contains(&offset) {
            return Ok(Register::Pending(((offset - PENDING_BASE) * 8) as u32));
        }
        if (ENABLE_BASE..TARGET_BASE).contains(&offset) {
            let offset = offset - ENABLE_BASE;
            let context = (offset / ENABLE_STRIDE) as usize;
            let slot = offset % ENABLE_STRIDE;
            if context < self.targets.len() && slot < BITMAP_BYTES {
                return Ok(Register::Enable(context, (slot * 8) as u32));
            }
        }
        if offset >= TARGET_BASE {
            let offset = offset - TARGET_BASE;
            let context = (offset / TARGET_STRIDE) as usize;
            if context < self.targets.len() {
                return Ok(match offset % TARGET_STRIDE {
                    0 => Register::Threshold(context),
                    4 => Register::Claim(context),
                    _ => Register::Reserved,
                });
            }
        }
        Ok(Register::Reserved)
    }

    pub(super) fn read(&mut self, address: u64) -> Result<u32, AccessError> {
        Ok(match self.register(address, 4)? {
            Register::Priority(source) => u32::from(self.priority(source)),
            Register::Pending(shift) => (self.pending >> shift) as u32,
            Register::Enable(context, shift) => (self.targets[context].enable >> shift) as u32,
            Register::Threshold(context) => u32::from(self.targets[context].threshold),
            Register::Claim(context) => {
                let source = self.select(context, 0);
                if source != 0 {
                    let bit = 1u128 << source;
                    self.pending &= !bit;
                    self.claimed |= bit;
                }
                source
            }
            Register::Reserved => 0,
        })
    }

    pub(super) fn write(&mut self, address: u64, value: u32) -> Result<(), AccessError> {
        match self.register(address, 4)? {
            Register::Priority(source) => {
                let source = source as usize;
                self.priorities[source / 32][source % 32] = (value as u8) & PRIORITY_MASK;
            }
            Register::Enable(context, shift) => {
                let mask = u128::from(u32::MAX) << shift;
                let target = &mut self.targets[context];
                target.enable =
                    ((target.enable & !mask) | (u128::from(value) << shift)) & SOURCE_MASK;
            }
            Register::Threshold(context) => {
                self.targets[context].threshold = (value as u8) & PRIORITY_MASK;
            }
            Register::Claim(context) => self.complete(context, value),
            Register::Pending(_) | Register::Reserved => {}
        }
        Ok(())
    }

    fn complete(&mut self, context: usize, source: u32) {
        if !(1..SOURCE_COUNT as u32).contains(&source) {
            return;
        }
        let bit = 1u128 << source;
        if self.targets[context].enable & self.claimed & bit != 0 {
            self.claimed &= !bit;
            self.pending |= self.levels & bit;
        }
    }
}

#[cfg(test)]
#[path = "plic_tests.rs"]
mod tests;
