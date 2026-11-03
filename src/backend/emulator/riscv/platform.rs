//! One classic CLINT per generic RV64 VMM, shared by every configured hart.
//!
//! Register semantics follow the retained ACLINT 1.0-rc4 compatibility map.
//! The platform supplies a 10 MHz clock; this is independent of CPU retirement
//! frequency. Unimplemented slots read zero and ignore writes. Unsupported
//! widths, alignment and boundary crossings fault before any state changes.
use crate::error::{Error, Result};
use crate::isa::riscv::{MemError, MemResult};
use crate::vm::timing::TimingContext;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(crate) const BASE: u64 = 0x0200_0000;
pub(crate) const LEN: u64 = 0x1_0000;
pub(crate) const FREQUENCY_HZ: u64 = 10_000_000;
const COMPARE: u64 = 0x4000;
const TIME: u64 = 0xbff8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlatformCheckpoint {
    version: u8,
    ram_end: u64,
    msip: Vec<bool>,
    compare: Vec<u64>,
    offset: u64,
}
impl PlatformCheckpoint {
    pub(crate) fn validate(&self, count: usize, ram_end: u64) -> Result<()> {
        if self.version != 1
            || count == 0
            || count > 255
            || self.ram_end != ram_end
            || self.msip.len() != count
            || self.compare.len() != count
        {
            return Err(invalid("checkpoint topology or version differs"));
        }
        Ok(())
    }
}
struct State {
    enabled: bool,
    registers: PlatformCheckpoint,
}
/// The VMM owns this object and retains its selected clock before CPU creation.
/// MMIO samples the clock before taking `state`. Capture/restore hold `state`
/// across their publication closure. No guest callback runs under this lock;
/// callers must quiesce guest execution before checkpointing a VM.
pub(crate) struct Platform {
    state: Mutex<State>,
    enabled: AtomicBool,
    clock: Arc<TimingContext>,
    count: usize,
    ram_end: u64,
}
fn invalid(message: &str) -> Error {
    Error::Emulator(format!("RISC-V CLINT: {message}"))
}
fn fault(address: u64, size: usize) -> MemError {
    MemError::OutOfBounds {
        addr: address,
        size,
    }
}
pub(crate) fn overlaps(address: u64, size: usize) -> bool {
    size != 0
        && u128::from(address) < u128::from(BASE + LEN)
        && u128::from(address) + size as u128 > u128::from(BASE)
}
enum Register {
    Software(usize),
    Compare(usize, u32),
    Time(u32),
    Reserved,
}
fn register(address: u64, size: usize, count: usize) -> MemResult<Register> {
    if !matches!(size, 4 | 8)
        || address < BASE
        || address
            .checked_add(size as u64)
            .is_none_or(|end| end > BASE + LEN)
    {
        return Err(fault(address, size));
    }
    if address & (size as u64 - 1) != 0 {
        return Err(MemError::Misaligned {
            addr: address,
            size,
        });
    }
    let offset = address - BASE;
    if offset < COMPARE {
        if size != 4 {
            return Err(fault(address, size));
        }
        let index = (offset / 4) as usize;
        return Ok(if index < count {
            Register::Software(index)
        } else {
            Register::Reserved
        });
    }
    if (TIME..TIME + 8).contains(&offset) {
        return Ok(Register::Time(((offset - TIME) * 8) as u32));
    }
    if offset < TIME {
        let index = ((offset - COMPARE) / 8) as usize;
        return Ok(if index < count {
            Register::Compare(index, ((offset & 7) * 8) as u32)
        } else {
            Register::Reserved
        });
    }
    Ok(Register::Reserved)
}
impl Platform {
    pub(crate) fn new(count: u8, ram_end: u64, clock: Arc<TimingContext>) -> Result<Self> {
        if count == 0 {
            return Err(invalid("empty hart topology"));
        }
        let offset = clock.counter_ticks(FREQUENCY_HZ).wrapping_neg();
        Ok(Self {
            state: Mutex::new(State {
                enabled: true,
                registers: PlatformCheckpoint {
                    version: 1,
                    ram_end,
                    msip: vec![false; usize::from(count)],
                    compare: vec![u64::MAX; usize::from(count)],
                    offset,
                },
            }),
            enabled: AtomicBool::new(true),
            clock,
            count: usize::from(count),
            ram_end,
        })
    }
    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    pub(crate) fn contains_hart(&self, id: u32) -> bool {
        (id as usize) < self.count
    }
    pub(crate) fn claims(&self, address: u64, size: usize) -> bool {
        self.enabled() && overlaps(address, size)
    }
    pub(crate) fn probe(&self, address: u64, size: usize) -> MemResult<()> {
        register(address, size, self.count).map(|_| ())
    }
    pub(crate) fn read(&self, address: u64, bytes: &mut [u8]) -> MemResult<()> {
        let reg = register(address, bytes.len(), self.count)?;
        let ticks = self.clock.counter_ticks(FREQUENCY_HZ);
        let state = self.state.lock().map_err(|_| fault(address, bytes.len()))?;
        if !state.enabled {
            return Err(fault(address, bytes.len()));
        }
        let value = match reg {
            Register::Software(id) => u64::from(state.registers.msip[id]),
            Register::Compare(id, shift) => state.registers.compare[id] >> shift,
            Register::Time(shift) => ticks.wrapping_add(state.registers.offset) >> shift,
            Register::Reserved => 0,
        };
        bytes.copy_from_slice(&value.to_le_bytes()[..bytes.len()]);
        Ok(())
    }
    pub(crate) fn write(&self, address: u64, bytes: &[u8]) -> MemResult<()> {
        let reg = register(address, bytes.len(), self.count)?;
        let ticks = self.clock.counter_ticks(FREQUENCY_HZ);
        let mut state = self.state.lock().map_err(|_| fault(address, bytes.len()))?;
        if !state.enabled {
            return Err(fault(address, bytes.len()));
        }
        let mut raw = [0; 8];
        raw[..bytes.len()].copy_from_slice(bytes);
        let value = u64::from_le_bytes(raw);
        let merge = |old: u64, shift: u32| {
            if bytes.len() == 8 {
                value
            } else {
                let mask = u64::from(u32::MAX) << shift;
                (old & !mask) | ((value << shift) & mask)
            }
        };
        match reg {
            Register::Software(id) => state.registers.msip[id] = value & 1 != 0,
            Register::Compare(id, shift) => {
                state.registers.compare[id] = merge(state.registers.compare[id], shift);
            }
            Register::Time(shift) => {
                state.registers.offset =
                    merge(ticks.wrapping_add(state.registers.offset), shift).wrapping_sub(ticks);
            }
            Register::Reserved => {}
        }
        Ok(())
    }
    pub(crate) fn signals(&self, id: u32) -> Result<Option<(u64, bool, bool)>> {
        if !self.contains_hart(id) {
            return Err(invalid("hart outside topology"));
        }
        let ticks = self.clock.counter_ticks(FREQUENCY_HZ);
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("state lock poisoned"))?;
        if !state.enabled {
            return Ok(None);
        }
        let now = ticks.wrapping_add(state.registers.offset);
        Ok(Some((
            now,
            state.registers.msip[id as usize],
            now >= state.registers.compare[id as usize],
        )))
    }
    pub(crate) fn checkpoint(&self) -> Result<Option<PlatformCheckpoint>> {
        self.checkpoint_with(Ok)
    }
    pub(crate) fn checkpoint_with<T>(
        &self,
        capture: impl FnOnce(Option<PlatformCheckpoint>) -> Result<T>,
    ) -> Result<T> {
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("capture lock poisoned"))?;
        capture(state.enabled.then(|| state.registers.clone()))
    }
    pub(crate) fn validate_checkpoint(&self, saved: Option<&PlatformCheckpoint>) -> Result<()> {
        if let Some(saved) = saved {
            saved.validate(self.count, self.ram_end)?;
        }
        Ok(())
    }
    pub(crate) fn restore_with<T>(
        &self,
        saved: Option<PlatformCheckpoint>,
        commit: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.validate_checkpoint(saved.as_ref())?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("restore lock poisoned"))?;
        let result = commit()?;
        state.enabled = saved.is_some();
        if let Some(saved) = saved {
            state.registers = saved;
        }
        self.enabled.store(state.enabled, Ordering::Release);
        Ok(result)
    }
}
#[cfg(test)]
#[path = "platform_tests.rs"]
mod tests;
