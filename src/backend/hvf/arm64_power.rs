//! Native PSCI transitions, retained until the coordinator acknowledges them.
//! DEN 0022D sections 5.5-5.7 and 6.4; flat Aff0 topology, EL1 AArch64.
use crate::error::{Error, Result};
use crate::vm::vcpu::CpuPowerRequest;
use serde::{Deserialize, Serialize};

pub(crate) const ENTRY_PSTATE: u64 = 0x3c5;
pub(crate) const INVALID_PARAMETERS: u64 = -2i64 as u64;
pub(crate) const INVALID_ADDRESS: u64 = -9i64 as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum State {
    On,
    Off,
    Starting,
    Stopping,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Pending {
    pub request: CpuPowerRequest,
    pub big_endian: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Power {
    pub states: Vec<State>,
    pub pending: Vec<Pending>,
    pub shutdown: bool,
}

fn invalid() -> Error {
    Error::InvalidConfig("inconsistent native PSCI power graph".into())
}
impl Power {
    pub fn new(count: u8) -> Self {
        let mut states = vec![State::Off; usize::from(count)];
        if let Some(bsp) = states.first_mut() {
            *bsp = State::On;
        }
        Self {
            states,
            pending: Vec::new(),
            shutdown: false,
        }
    }
    pub fn validate(&self, count: u8, ram_base: u64, ram_size: u64) -> Result<()> {
        if count == 0
            || self.states.len() != usize::from(count)
            || self.pending.len() > usize::from(count)
        {
            return Err(invalid());
        }
        let end = ram_base.checked_add(ram_size).ok_or_else(invalid)?;
        let mut seen = vec![false; usize::from(count)];
        for transition in &self.pending {
            let (cpu_id, expected) = match transition.request {
                CpuPowerRequest::Start {
                    cpu_id,
                    entry,
                    pstate,
                    ..
                } => {
                    if entry & 3 != 0
                        || entry < ram_base
                        || entry.checked_add(4).is_none_or(|value| value > end)
                        || pstate != ENTRY_PSTATE
                    {
                        return Err(invalid());
                    }
                    (cpu_id, State::Starting)
                }
                CpuPowerRequest::Off { cpu_id } => {
                    if transition.big_endian {
                        return Err(invalid());
                    }
                    (cpu_id, State::Stopping)
                }
            };
            let id = cpu_id as usize;
            if id >= seen.len() || seen[id] || self.states[id] != expected {
                return Err(invalid());
            }
            seen[id] = true;
        }
        for (state, seen) in self.states.iter().zip(seen) {
            if matches!(state, State::Starting | State::Stopping) != seen {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn validate_online(&self, online: &[bool]) -> Result<()> {
        if online.len() != self.states.len() {
            return Err(invalid());
        }
        for (&state, &online) in self.states.iter().zip(online) {
            // A stop may have disabled the coordinator immediately before its
            // acknowledgement failed. Retaining it makes that stop retryable.
            if state != State::Stopping && online != (state == State::On) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn cpu_on(
        &mut self,
        target: u64,
        entry: u64,
        context: u64,
        big_endian: bool,
        ram_base: u64,
        ram_size: u64,
    ) -> u64 {
        let Ok(id) = usize::try_from(target) else {
            return INVALID_PARAMETERS;
        };
        let Some(state) = self.states.get_mut(id) else {
            return INVALID_PARAMETERS;
        };
        if entry & 3 != 0
            || entry < ram_base
            || entry
                .checked_add(4)
                .zip(ram_base.checked_add(ram_size))
                .is_none_or(|(end, limit)| end > limit)
        {
            return INVALID_ADDRESS;
        }
        match state {
            State::On | State::Stopping => return -4i64 as u64,
            State::Starting => return -5i64 as u64,
            State::Off => (),
        }
        *state = State::Starting;
        self.pending.push(Pending {
            request: CpuPowerRequest::Start {
                cpu_id: id as u32,
                entry,
                context,
                pstate: ENTRY_PSTATE,
            },
            big_endian,
        });
        0
    }
    pub fn cpu_off(&mut self, id: u32) -> Result<()> {
        let state = self.states.get_mut(id as usize).ok_or_else(invalid)?;
        if *state != State::On {
            return Err(invalid());
        }
        *state = State::Stopping;
        self.pending.push(Pending {
            request: CpuPowerRequest::Off { cpu_id: id },
            big_endian: false,
        });
        Ok(())
    }
    pub fn affinity_info(&self, target: u64, level: u64) -> u64 {
        if level != 0 {
            return INVALID_PARAMETERS;
        }
        match usize::try_from(target)
            .ok()
            .and_then(|id| self.states.get(id))
        {
            Some(State::On | State::Stopping) => 0,
            Some(State::Off) => 1,
            Some(State::Starting) => 2,
            None => INVALID_PARAMETERS,
        }
    }
    pub fn start_endianness(&self, id: u32, entry: u64, context: u64, pstate: u64) -> Result<bool> {
        self.pending
            .iter()
            .find_map(|pending| {
                (pending.request
                    == CpuPowerRequest::Start {
                        cpu_id: id,
                        entry,
                        context,
                        pstate,
                    })
                .then_some(pending.big_endian)
            })
            .ok_or_else(invalid)
    }
    pub fn complete(&mut self, id: u32, start: bool) -> Result<()> {
        let expected = if start {
            State::Starting
        } else {
            State::Stopping
        };
        if self.states.get(id as usize) != Some(&expected) {
            return Err(invalid());
        }
        let index = self
            .pending
            .iter()
            .position(|pending| match pending.request {
                CpuPowerRequest::Start { cpu_id, .. } => start && cpu_id == id,
                CpuPowerRequest::Off { cpu_id } => !start && cpu_id == id,
            })
            .ok_or_else(invalid)?;
        self.pending.remove(index);
        self.states[id as usize] = if start { State::On } else { State::Off };
        Ok(())
    }
}

#[cfg(test)]
#[path = "arm64_power_tests.rs"]
mod tests;
