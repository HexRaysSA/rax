//! One classic CLINT and PLIC per generic RV64 VMM, shared by every hart.
//!
//! Register semantics follow the retained ACLINT 1.0-rc4 compatibility map.
//! The platform supplies a 10 MHz clock; this is independent of CPU retirement
//! frequency. Unimplemented slots read zero and ignore writes. Unsupported
//! widths, alignment and boundary crossings fault before any state changes.
use crate::devices::bus::MmioDevice;
use crate::devices::serial::Serial16550;
use crate::error::{Error, Result};
use crate::isa::riscv::{MemError, MemResult};
use crate::vm::timing::{CLOCK_EPOCH_QUANTA, ClockMode, RETIREMENT_FREQUENCY_HZ, TimingContext};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU8, Ordering},
};

mod plic;

pub(crate) const BASE: u64 = 0x0200_0000;
pub(crate) const LEN: u64 = 0x1_0000;
pub(crate) const PLIC_BASE: u64 = plic::BASE;
pub(crate) const PLIC_LEN: u64 = plic::LEN;
pub(crate) const UART_BASE: u64 = 0x1000_0000;
pub(crate) const UART_LEN: u64 = 8;
pub(crate) const FINISHER_BASE: u64 = 0x0010_0000;
const FINISHER_LEN: u64 = 0x1000;
const FINISHER_PASS: u32 = 0x5555;
pub(crate) const FREQUENCY_HZ: u64 = 10_000_000;
const COMPARE: u64 = 0x4000;
const TIME: u64 = 0xbff8;
const CLINT_PROFILE: u8 = 1;
const PLIC_PROFILE: u8 = 2;
const ARCHITECTURAL_TRAPS_PROFILE: u8 = 4;
const SV39_PROFILE: u8 = 8;
const FINISHER_PROFILE: u8 = 16;
const SHUTDOWN: u8 = 32;
const CLINT_VERSION: u8 = 1;
const PLIC_VERSION: u8 = 2;
const ARCHITECTURAL_TRAPS_VERSION: u8 = 3;
const SV39_VERSION: u8 = 4;
const FINISHER_VERSION: u8 = 5;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlatformCheckpoint {
    version: u8,
    ram_end: u64,
    #[serde(deserialize_with = "saved_software")]
    msip: Vec<bool>,
    #[serde(deserialize_with = "saved_compare")]
    compare: Vec<u64>,
    offset: u64,
    #[serde(skip)]
    plic: Option<plic::Plic>,
    #[serde(skip)]
    shutdown: bool,
}

fn saved_software<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<bool>, D::Error> {
    crate::devices::checkpoint_serde::vector::<bool, D, { u8::MAX as usize }>(d)
}

fn saved_compare<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<u64>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u64, D, { u8::MAX as usize }>(d)
}
impl PlatformCheckpoint {
    pub(crate) fn validate(&self, count: usize, ram_end: u64) -> Result<()> {
        if !matches!(
            (self.version, self.plic.is_some()),
            (CLINT_VERSION, false)
                | (
                    PLIC_VERSION | ARCHITECTURAL_TRAPS_VERSION | SV39_VERSION | FINISHER_VERSION,
                    true
                )
        ) || count == 0
            || count > 255
            || self.ram_end != ram_end
            || self.msip.len() != count
            || self.compare.len() != count
            || self.shutdown && self.version != FINISHER_VERSION
        {
            return Err(invalid("checkpoint topology or version differs"));
        }
        if let Some(plic) = &self.plic {
            plic.validate(count).map_err(invalid)?;
        }
        Ok(())
    }

    pub(crate) fn plic_enabled(&self) -> bool {
        self.plic.is_some()
    }

    pub(crate) fn sv39_enabled(&self) -> bool {
        matches!(self.version, SV39_VERSION | FINISHER_VERSION)
    }

    fn profile(&self) -> u8 {
        let mut profile = CLINT_PROFILE;
        if self.plic_enabled() {
            profile |= PLIC_PROFILE;
        }
        if self.version == ARCHITECTURAL_TRAPS_VERSION || self.sv39_enabled() {
            profile |= ARCHITECTURAL_TRAPS_PROFILE;
        }
        if self.sv39_enabled() {
            profile |= SV39_PROFILE;
        }
        if self.version == FINISHER_VERSION {
            profile |= FINISHER_PROFILE;
            if self.shutdown {
                profile |= SHUTDOWN;
            }
        }
        profile
    }

    pub(crate) fn validate_uart(&self, serial: &Serial16550) -> Result<()> {
        if let Some(plic) = &self.plic
            && plic.uart_level() != serial.interrupt_output()
        {
            return Err(invalid(
                "saved PLIC UART line disagrees with the serial device",
            ));
        }
        Ok(())
    }

    pub(crate) fn encode(&self, limit: usize) -> Result<Vec<u8>> {
        match &self.plic {
            Some(plic) if self.version == FINISHER_VERSION => {
                crate::codec::serialize_limited(&(self, plic, self.shutdown), limit)
            }
            Some(plic) => crate::codec::serialize_limited(&(self, plic), limit),
            None => crate::codec::serialize_limited(self, limit),
        }
        .map_err(|e| invalid(&e.to_string()))
    }

    pub(crate) fn decode<const LIMIT: usize>(bytes: &[u8]) -> Result<Self> {
        let invalid_payload = |e: uklad::error::DecodeError| invalid(&e.to_string());
        match bytes.first().copied() {
            Some(CLINT_VERSION) => {
                crate::codec::deserialize_limited::<_, LIMIT>(bytes).map_err(invalid_payload)
            }
            Some(PLIC_VERSION | ARCHITECTURAL_TRAPS_VERSION | SV39_VERSION) => {
                let (mut state, plic): (Self, plic::Plic) =
                    crate::codec::deserialize_limited::<_, LIMIT>(bytes)
                        .map_err(invalid_payload)?;
                state.plic = Some(plic);
                Ok(state)
            }
            Some(FINISHER_VERSION) => {
                let (mut state, plic, shutdown): (Self, plic::Plic, bool) =
                    crate::codec::deserialize_limited::<_, LIMIT>(bytes)
                        .map_err(invalid_payload)?;
                state.plic = Some(plic);
                state.shutdown = shutdown;
                Ok(state)
            }
            _ => Err(invalid("unknown checkpoint version")),
        }
    }
}
struct State {
    enabled: bool,
    registers: PlatformCheckpoint,
}
/// The VMM owns this object and retains its selected clock before CPU creation.
/// MMIO samples the clock before taking `state`. Capture, restore and
/// synchronous UART reads take the platform lock before the serial lock.
/// The coordinator publishes a deferred UART write after releasing its
/// bus and serial locks. No instruction runs between these operations.
pub(crate) struct Platform {
    state: Mutex<State>,
    profile: AtomicU8,
    serial: OnceLock<Arc<Mutex<Serial16550>>>,
    clock: Arc<TimingContext>,
    count: usize,
    ram_end: u64,
}
fn invalid(message: &str) -> Error {
    Error::Emulator(format!("RISC-V platform: {message}"))
}
fn fault(address: u64, size: usize) -> MemError {
    MemError::OutOfBounds {
        addr: address,
        size,
    }
}
pub(crate) fn overlapping_controller(address: u64, size: usize) -> Option<&'static str> {
    if overlaps_clint(address, size) {
        Some("CLINT")
    } else if plic::overlaps(address, size) {
        Some("PLIC")
    } else {
        None
    }
}

pub(crate) fn overlaps_finisher(address: u64, size: usize) -> bool {
    size != 0
        && address < FINISHER_BASE + FINISHER_LEN
        && u128::from(address) + size as u128 > u128::from(FINISHER_BASE)
}

fn overlaps_clint(address: u64, size: usize) -> bool {
    size != 0
        && u128::from(address) < u128::from(BASE + LEN)
        && u128::from(address) + size as u128 > u128::from(BASE)
}

fn plic_fault(error: plic::AccessError, addr: u64, size: usize) -> MemError {
    match error {
        plic::AccessError::Range => fault(addr, size),
        plic::AccessError::Alignment => MemError::Misaligned { addr, size },
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Signals {
    pub(crate) time: u64,
    pub(crate) software: bool,
    pub(crate) timer: bool,
    pub(crate) external: Option<(bool, bool)>,
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
    pub(crate) fn new(
        count: u8,
        ram_end: u64,
        clock: Arc<TimingContext>,
        architectural_traps: bool,
    ) -> Result<Self> {
        if count == 0 {
            return Err(invalid("empty hart topology"));
        }
        let offset = clock.counter_ticks(FREQUENCY_HZ).wrapping_neg();
        let registers = PlatformCheckpoint {
            version: if architectural_traps {
                FINISHER_VERSION
            } else {
                PLIC_VERSION
            },
            ram_end,
            msip: vec![false; usize::from(count)],
            compare: vec![u64::MAX; usize::from(count)],
            offset,
            plic: Some(plic::Plic::new(count)),
            shutdown: false,
        };
        let profile = AtomicU8::new(registers.profile());
        Ok(Self {
            state: Mutex::new(State {
                enabled: true,
                registers,
            }),
            profile,
            serial: OnceLock::new(),
            clock,
            count: usize::from(count),
            ram_end,
        })
    }
    pub(crate) fn enabled(&self) -> bool {
        self.profile.load(Ordering::Acquire) & CLINT_PROFILE != 0
    }
    /// The Sv39 firmware platform can wait on wall time. Restore checks the
    /// recorded profile before publishing it to the shared controller.
    pub(super) fn supports_interrupt_wait(&self, firmware_profile: bool) -> bool {
        match self.clock.mode() {
            ClockMode::Wall => firmware_profile,
            ClockMode::Retired => false,
            ClockMode::RetiredWithIdle => true,
        }
    }
    pub(crate) fn plic_enabled(&self) -> bool {
        self.profile.load(Ordering::Acquire) & PLIC_PROFILE != 0
    }
    pub(crate) fn architectural_traps(&self) -> bool {
        self.profile.load(Ordering::Acquire) & ARCHITECTURAL_TRAPS_PROFILE != 0
    }
    pub(super) fn sv39_enabled(&self) -> bool {
        self.profile.load(Ordering::Acquire) & SV39_PROFILE != 0
    }
    pub(crate) fn shutdown(&self) -> bool {
        self.profile.load(Ordering::Acquire) & SHUTDOWN != 0
    }
    pub(crate) fn bind_serial(&self, serial: Arc<Mutex<Serial16550>>) -> Result<()> {
        self.serial
            .set(serial)
            .map_err(|_| invalid("serial already bound"))
    }
    pub(crate) fn set_irq_line(&self, source: u32, level: bool) -> Result<()> {
        if source == plic::UART_SOURCE && self.serial.get().is_some() {
            return Err(invalid("the serial device owns its PLIC input"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("IRQ lock poisoned"))?;
        if state.enabled
            && let Some(plic) = &mut state.registers.plic
        {
            plic.set_level(source, level).map_err(invalid)?;
        }
        Ok(())
    }
    fn with_serial(&self, operation: impl FnOnce(&mut Serial16550)) -> Result<bool> {
        let Some(serial) = self.serial.get() else {
            return Ok(false);
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("serial line lock poisoned"))?;
        if !state.enabled {
            return Ok(false);
        }
        let Some(plic) = &mut state.registers.plic else {
            return Ok(false);
        };
        let mut serial = serial.lock().map_err(|_| invalid("serial lock poisoned"))?;
        operation(&mut serial);
        plic.set_level(plic::UART_SOURCE, serial.interrupt_output())
            .map_err(invalid)?;
        Ok(true)
    }
    pub(crate) fn read_uart(&self, addr: u64, bytes: &mut [u8]) -> MemResult<bool> {
        let size = bytes.len();
        self.with_serial(|serial| serial.read(addr, bytes))
            .map_err(|_| fault(addr, size))
    }
    pub(crate) fn queue_uart_input(&self, bytes: &[u8]) -> Result<bool> {
        self.with_serial(|serial| serial.queue_input(bytes))
    }
    pub(crate) fn publish_uart_write(&self) -> Result<()> {
        self.with_serial(|_| ())?;
        Ok(())
    }
    pub(crate) fn contains_hart(&self, id: u32) -> bool {
        (id as usize) < self.count
    }
    pub(crate) fn claims(&self, address: u64, size: usize) -> bool {
        let profile = self.profile.load(Ordering::Acquire);
        profile & CLINT_PROFILE != 0 && overlaps_clint(address, size)
            || profile & PLIC_PROFILE != 0 && plic::overlaps(address, size)
            || profile & FINISHER_PROFILE != 0 && overlaps_finisher(address, size)
    }
    fn finisher_access(&self, address: u64, size: usize) -> MemResult<bool> {
        if self.profile.load(Ordering::Acquire) & FINISHER_PROFILE == 0
            || !overlaps_finisher(address, size)
        {
            return Ok(false);
        }
        if !matches!(size, 2 | 4)
            || address < FINISHER_BASE
            || u128::from(address) + size as u128 > u128::from(FINISHER_BASE + FINISHER_LEN)
        {
            return Err(fault(address, size));
        }
        if address & (size as u64 - 1) != 0 {
            return Err(MemError::Misaligned {
                addr: address,
                size,
            });
        }
        Ok(true)
    }
    pub(crate) fn probe(&self, address: u64, size: usize) -> MemResult<()> {
        if self.finisher_access(address, size)? {
            return Ok(());
        }
        if plic::overlaps(address, size) {
            let state = self.state.lock().map_err(|_| fault(address, size))?;
            if !state.enabled {
                return Err(fault(address, size));
            }
            let plic = state
                .registers
                .plic
                .as_ref()
                .ok_or_else(|| fault(address, size))?;
            return plic
                .probe(address, size)
                .map_err(|error| plic_fault(error, address, size));
        }
        register(address, size, self.count).map(|_| ())
    }
    pub(crate) fn read(&self, address: u64, bytes: &mut [u8]) -> MemResult<()> {
        if self.finisher_access(address, bytes.len())? {
            bytes.fill(0);
            return Ok(());
        }
        if plic::overlaps(address, bytes.len()) {
            let size = bytes.len();
            let mut state = self.state.lock().map_err(|_| fault(address, size))?;
            if !state.enabled {
                return Err(fault(address, size));
            }
            let plic = state
                .registers
                .plic
                .as_mut()
                .ok_or_else(|| fault(address, size))?;
            if size != 4 {
                return Err(fault(address, size));
            }
            let value = plic
                .read(address)
                .map_err(|error| plic_fault(error, address, size))?;
            bytes.copy_from_slice(&value.to_le_bytes());
            return Ok(());
        }
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
        if self.finisher_access(address, bytes.len())? {
            if address == FINISHER_BASE {
                let mut raw = [0; 4];
                raw[..bytes.len()].copy_from_slice(bytes);
                match u32::from_le_bytes(raw) {
                    FINISHER_PASS => {
                        let mut state =
                            self.state.lock().map_err(|_| fault(address, bytes.len()))?;
                        if !state.enabled || state.registers.version != FINISHER_VERSION {
                            return Err(fault(address, bytes.len()));
                        }
                        state.registers.shutdown = true;
                        self.profile.fetch_or(SHUTDOWN, Ordering::Release);
                    }
                    // The firmware profile implements the zero-code power-off
                    // command. Reject reset and coded termination explicitly.
                    other if matches!(other & 0xffff, 0x3333 | 0x5555 | 0x7777) => {
                        return Err(fault(address, bytes.len()));
                    }
                    _ => (),
                }
            }
            return Ok(());
        }
        if plic::overlaps(address, bytes.len()) {
            let size = bytes.len();
            let mut state = self.state.lock().map_err(|_| fault(address, size))?;
            if !state.enabled {
                return Err(fault(address, size));
            }
            let plic = state
                .registers
                .plic
                .as_mut()
                .ok_or_else(|| fault(address, size))?;
            let raw = bytes.try_into().map_err(|_| fault(address, size))?;
            return plic
                .write(address, u32::from_le_bytes(raw))
                .map_err(|error| plic_fault(error, address, size));
        }
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
    pub(crate) fn signals(&self, id: u32) -> Result<Option<Signals>> {
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
        let id = id as usize;
        Ok(Some(Signals {
            time: now,
            software: state.registers.msip[id],
            timer: now >= state.registers.compare[id],
            external: state
                .registers
                .plic
                .as_ref()
                .map(|plic| plic.hart_lines(id)),
        }))
    }

    pub(super) fn next_timer_assertion(&self, id: u32) -> Result<Option<u128>> {
        let clock = self.clock.checkpoint_state();
        let ticks = clock.counter_ticks(FREQUENCY_HZ);
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("state lock poisoned"))?;
        if !state.enabled {
            return Ok(None);
        }
        let compare = *state
            .registers
            .compare
            .get(id as usize)
            .ok_or_else(|| invalid("hart outside topology"))?;
        let offset = state.registers.offset;
        let now = ticks.wrapping_add(offset);
        if now >= compare {
            return Ok(None);
        }
        const QUANTA_PER_TICK: u128 = (RETIREMENT_FREQUENCY_HZ / FREQUENCY_HZ) as u128;
        let before_wrap = (u128::from(ticks) + u128::from(compare - now)) * QUANTA_PER_TICK;
        let asserted_at = if before_wrap < CLOCK_EPOCH_QUANTA {
            before_wrap
        } else {
            // At elapsed-clock wrap, the base tick resets to zero, while
            // the guest-programmed MTIME offset is retained.
            CLOCK_EPOCH_QUANTA + u128::from(compare.saturating_sub(offset)) * QUANTA_PER_TICK
        };
        let delay = asserted_at - clock.elapsed_quanta();
        Ok((delay < CLOCK_EPOCH_QUANTA).then_some(delay))
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
        let profile = if state.enabled {
            state.registers.profile()
        } else {
            0
        };
        self.profile.store(profile, Ordering::Release);
        Ok(result)
    }
}
#[cfg(test)]
#[path = "platform_tests.rs"]
mod tests;
