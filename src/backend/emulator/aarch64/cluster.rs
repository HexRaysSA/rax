//! VM-owned GIC and asynchronous PSCI power state.
//!
//! Lock order is control, then GIC. Guest instruction execution holds neither
//! control lock across memory callbacks nor a GIC lock across firmware calls.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::isa::arm::aarch64::gic::{Gic, GicConfig, checkpoint::GicCheckpoint};
use crate::vm::vcpu::CpuPowerRequest;

const INVALID_PARAMETERS: i32 = -2;
const ALREADY_ON: i32 = -4;
const ON_PENDING: i32 = -5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum PowerState {
    On,
    Off,
    OnPending,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Control {
    states: Vec<PowerState>,
    requests: VecDeque<CpuPowerRequest>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ArmClusterCheckpoint {
    control: Control,
    gic: GicCheckpoint,
    high_redist_base: u64,
}

pub struct ArmCluster {
    pub(super) gic: Arc<Mutex<Gic>>,
    control: Mutex<Control>,
    count: u8,
    pub(super) high_redist_base: u64,
}

fn invalid(message: &str) -> Error {
    Error::Emulator(format!("AArch64 cluster: {message}"))
}

impl ArmCluster {
    pub fn new(count: u8, ram_end: u64) -> Result<Self> {
        if count == 0 {
            return Err(invalid("empty CPU topology"));
        }
        let mut states = vec![PowerState::Off; usize::from(count)];
        states[0] = PowerState::On;
        Ok(Self {
            gic: Arc::new(Mutex::new(Gic::new(GicConfig {
                num_cpus: count,
                ..GicConfig::default()
            }))),
            control: Mutex::new(Control {
                states,
                requests: VecDeque::new(),
            }),
            count,
            high_redist_base: crate::machine::arm_virt::aarch64_redist_high_base(ram_end)?,
        })
    }

    pub fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        if !(32..288).contains(&irq) {
            return Err(invalid("external IRQ is outside the configured SPI domain"));
        }
        let mut gic = self.gic.lock().map_err(|_| invalid("GIC lock poisoned"))?;
        if level {
            gic.set_pending(irq);
        } else {
            gic.clear_pending(irq);
        }
        Ok(())
    }

    pub fn count(&self) -> u8 {
        self.count
    }

    /// This machine has flat affinities 0..count; reject all reserved MPIDR bits
    /// and unimplemented higher affinity nodes rather than truncating them.
    fn target(&self, affinity: u64) -> Option<usize> {
        (affinity < u64::from(self.count)).then_some(affinity as usize)
    }

    pub fn request_on(&self, affinity: u64, entry: u64, context: u64, pstate: u64) -> Result<i32> {
        let Some(target) = self.target(affinity) else {
            return Ok(INVALID_PARAMETERS);
        };
        if entry & (if pstate & 0x30 == 0x30 { 1 } else { 3 }) != 0 {
            return Ok(-9);
        }
        let mut control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        match control.states[target] {
            PowerState::On => return Ok(ALREADY_ON),
            PowerState::OnPending => return Ok(ON_PENDING),
            PowerState::Off => {}
        }
        control.states[target] = PowerState::OnPending;
        control.requests.push_back(CpuPowerRequest::Start {
            cpu_id: target as u32,
            entry,
            context,
            pstate,
        });
        Ok(0)
    }

    pub fn request_off(&self, cpu_id: u32) -> Result<()> {
        let mut control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        let state = control
            .states
            .get_mut(cpu_id as usize)
            .ok_or_else(|| invalid("unknown CPU"))?;
        if *state != PowerState::On {
            return Err(invalid("CPU_OFF from a non-running CPU"));
        }
        *state = PowerState::Off;
        control.requests.push_back(CpuPowerRequest::Off { cpu_id });
        Ok(())
    }

    pub fn affinity_info(&self, affinity: u64, level: u32) -> Result<i32> {
        if level > 3 {
            return Ok(INVALID_PARAMETERS);
        }
        let mask = match level {
            0 => u64::MAX,
            1 => !0xff,
            2 => !0xffff,
            _ => !0xff_ffff,
        };
        // Reserved bits must be zero even when the requested affinity ignores
        // lower levels. Only Aff0 exists on this machine.
        if affinity & !0xff != 0 {
            return Ok(INVALID_PARAMETERS);
        }
        let control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        let mut selected = control
            .states
            .iter()
            .enumerate()
            .filter(|(id, _)| (*id as u64 & mask) == (affinity & mask));
        let Some((_, first)) = selected.next() else {
            return Ok(INVALID_PARAMETERS);
        };
        let mut result = *first;
        for (_, state) in selected {
            if *state == PowerState::On {
                result = PowerState::On;
                break;
            }
            if result == PowerState::Off && *state == PowerState::OnPending {
                result = *state;
            }
        }
        Ok(match result {
            PowerState::On => 0,
            PowerState::Off => 1,
            PowerState::OnPending => 2,
        })
    }

    pub fn take_requests(&self) -> Result<Vec<CpuPowerRequest>> {
        Ok(self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?
            .requests
            .drain(..)
            .collect())
    }

    pub fn complete_start(&self, cpu_id: u32) -> Result<()> {
        let mut control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        let state = control
            .states
            .get_mut(cpu_id as usize)
            .ok_or_else(|| invalid("unknown startup CPU"))?;
        if *state != PowerState::OnPending {
            return Err(invalid("startup completion without pending CPU_ON"));
        }
        *state = PowerState::On;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<ArmClusterCheckpoint> {
        let control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        let gic = self.gic.lock().map_err(|_| invalid("GIC lock poisoned"))?;
        Ok(ArmClusterCheckpoint {
            control: control.clone(),
            gic: gic.checkpoint(),
            high_redist_base: self.high_redist_base,
        })
    }

    pub fn validate_checkpoint(&self, state: &ArmClusterCheckpoint, online: &[bool]) -> Result<()> {
        state.validate(online)?;
        if state.high_redist_base != self.high_redist_base {
            return Err(invalid("redistributor mapping mismatch"));
        }
        if state.control.states.len() != usize::from(self.count) {
            return Err(invalid("CPU topology mismatch"));
        }
        self.gic
            .lock()
            .map_err(|_| invalid("GIC lock poisoned"))?
            .validate_checkpoint(&state.gic)
    }

    /// Hold both publication locks before invoking the VMM's admitted CPU/RAM
    /// commit. The shared graph is published only when that commit succeeds.
    pub fn restore_with<T>(
        &self,
        state: ArmClusterCheckpoint,
        commit: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        let mut gic = self.gic.lock().map_err(|_| invalid("GIC lock poisoned"))?;
        gic.validate_checkpoint(&state.gic)?;
        let result = commit()?;
        gic.restore_checkpoint(state.gic);
        *control = state.control;
        Ok(result)
    }
}

impl ArmClusterCheckpoint {
    pub(crate) fn validate(&self, online: &[bool]) -> Result<()> {
        if self.high_redist_base < crate::machine::arm_virt::AARCH64_GICR_HIGH_BASE
            || self.high_redist_base & 0x1_ffff != 0
            || self.high_redist_base.checked_add(255 * 0x2_0000).is_none()
        {
            return Err(invalid("invalid high redistributor mapping"));
        }
        if self.control.states.len() != online.len() || online.is_empty() || online.len() > 255 {
            return Err(invalid("invalid saved CPU count"));
        }
        // Captures happen after each request was drained. A pending queue is
        // retained for explicit API callers, and its power transition must
        // agree with the still-uncommitted coordinator state.
        if self.control.requests.len() > online.len() {
            return Err(invalid("power queue exceeds CPU count"));
        }
        let mut expected = online.to_vec();
        let mut seen = vec![false; online.len()];
        for request in &self.control.requests {
            let (id, next) = match request {
                CpuPowerRequest::Start {
                    cpu_id,
                    entry,
                    pstate,
                    ..
                } => {
                    if entry & (if pstate & 0x30 == 0x30 { 1 } else { 3 }) != 0 {
                        return Err(invalid("unaligned saved startup entry"));
                    }
                    (*cpu_id as usize, PowerState::OnPending)
                }
                CpuPowerRequest::Off { cpu_id } => (*cpu_id as usize, PowerState::Off),
            };
            if id >= online.len()
                || seen[id]
                || self.control.states[id] != next
                || (next == PowerState::OnPending && online[id])
                || (next == PowerState::Off && !online[id])
            {
                return Err(invalid("invalid or duplicate power request"));
            }
            seen[id] = true;
            expected[id] = false;
        }
        for (id, state) in self.control.states.iter().enumerate() {
            let runnable = *state == PowerState::On;
            if runnable != expected[id] || (*state == PowerState::OnPending && !seen[id]) {
                return Err(invalid("power state disagrees with coordinator"));
            }
        }
        self.gic.validate_shape(online.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_power_request_and_online_state_must_agree() {
        let cluster = ArmCluster::new(2, 0x8000).unwrap();
        assert_eq!(cluster.request_on(1, 0x1000, 99, 0x3c5).unwrap(), 0);
        let mut state = cluster.checkpoint().unwrap();
        state.validate(&[true, false]).unwrap();
        assert!(state.validate(&[true, true]).is_err());
        state.control.requests.clear();
        assert!(state.validate(&[true, false]).is_err());
    }

    #[test]
    fn failed_guest_commit_leaves_the_entire_shared_graph_unchanged() {
        let cluster = ArmCluster::new(2, 0x8000).unwrap();
        let saved = cluster.checkpoint().unwrap();
        cluster.gic.lock().unwrap().set_priority_mask(0, 0x70);
        let before =
            crate::codec::serialize_limited(&cluster.checkpoint().unwrap(), 1_000_000).unwrap();
        assert!(
            cluster
                .restore_with(saved, || Err::<(), _>(invalid(
                    "injected CPU commit failure"
                )))
                .is_err()
        );
        let after =
            crate::codec::serialize_limited(&cluster.checkpoint().unwrap(), 1_000_000).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn restoration_republishes_irq_levels_into_existing_pe_handles() {
        let cluster = ArmCluster::new(2, 0x8000).unwrap();
        let line = {
            let mut gic = cluster.gic.lock().unwrap();
            gic.set_group_enable(1, true, true);
            gic.write_redist(1, 0x10100, 1 << 7);
            gic.raise_sgi((7 << 24) | 2);
            gic.irq_line(1).unwrap()
        };
        assert!(line.load(std::sync::atomic::Ordering::Acquire));
        let saved = cluster.checkpoint().unwrap();
        cluster.gic.lock().unwrap().write_redist(1, 0x10280, 1 << 7);
        assert!(!line.load(std::sync::atomic::Ordering::Acquire));
        cluster.restore_with(saved, || Ok(())).unwrap();
        assert!(line.load(std::sync::atomic::Ordering::Acquire));
        assert!(Arc::ptr_eq(
            &line,
            &cluster.gic.lock().unwrap().irq_line(1).unwrap()
        ));
    }
}
