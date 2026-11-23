//! VM-owned GIC and asynchronous PSCI power state.
//!
//! Lock order is control, then GIC. Guest instruction execution holds neither
//! control lock across memory callbacks nor a GIC lock across firmware calls.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::aarch64::gic::{Gic, GicConfig, checkpoint::GicCheckpoint};
use crate::machine::arm_virt::{AARCH64_GICD_BASE, AARCH64_UART_IRQ, aarch64_redist_frame};
use crate::vm::vcpu::{Aarch64SystemRegisters, CpuPowerRequest};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

use super::{GICD_SIZE, UART_BASE, UART_SIZE, in_window};

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
    pub(crate) shutdown: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyCluster<GicState> {
    control: Control,
    gic: GicState,
    high_redist_base: u64,
}

impl<GicState> LegacyCluster<GicState> {
    fn decode(raw: &[u8]) -> Result<Self>
    where
        GicState: serde::de::DeserializeOwned,
    {
        crate::codec::deserialize_limited::<_, { 64 * 1024 * 1024 }>(raw)
            .map_err(|error| invalid(&error.to_string()))
    }

    fn upgrade(
        self,
        migrate_gic: impl FnOnce(GicState) -> Result<GicCheckpoint>,
    ) -> Result<ArmClusterCheckpoint> {
        Ok(ArmClusterCheckpoint {
            control: self.control,
            gic: migrate_gic(self.gic)?,
            high_redist_base: self.high_redist_base,
            shutdown: false,
        })
    }
}

pub struct ArmCluster {
    pub(super) gic: Arc<Mutex<Gic>>,
    control: Mutex<Control>,
    // Writers hold control, while the execution gate reads this without a lock.
    shutdown: AtomicBool,
    events: Vec<Arc<AtomicBool>>,
    count: u8,
    pub(super) high_redist_base: u64,
}

fn invalid(message: &str) -> Error {
    Error::Emulator(format!("AArch64 cluster: {message}"))
}

fn start_width(pstate: u64) -> usize {
    if pstate & 0x30 == 0x30 { 2 } else { 4 }
}

fn valid_start_address(
    memory: &GuestMemoryMmap,
    count: u8,
    high_redist_base: u64,
    entry: u64,
    pstate: u64,
) -> bool {
    let width = start_width(pstate);
    entry & (width as u64 - 1) == 0
        && !in_window(entry, AARCH64_GICD_BASE, GICD_SIZE)
        && aarch64_redist_frame(entry, count, high_redist_base).is_none()
        && !in_window(entry, UART_BASE, UART_SIZE)
        && memory.check_range(GuestAddress(entry), width)
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
            shutdown: AtomicBool::new(false),
            count,
            events: (0..count)
                .map(|_| Arc::new(AtomicBool::new(false)))
                .collect(),
            high_redist_base: crate::machine::arm_virt::aarch64_redist_high_base(ram_end)?,
        })
    }

    pub fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        if !(32..288).contains(&irq) {
            return Err(invalid("external IRQ is outside the configured SPI domain"));
        }
        let mut gic = self.gic.lock().map_err(|_| invalid("GIC lock poisoned"))?;
        gic.set_spi_level(irq, level);
        Ok(())
    }

    pub(super) fn event_handle(&self, id: u32) -> Result<Arc<AtomicBool>> {
        self.events
            .get(id as usize)
            .cloned()
            .ok_or_else(|| invalid("unknown event CPU"))
    }

    /// Serialize fanout with cohort capture/restoration. No GIC lock or guest
    /// callback is taken here. One bit per configured PE coalesces repeated SEV.
    pub(super) fn broadcast_event(&self) -> Result<()> {
        let _control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        for event in &self.events {
            event.store(true, Ordering::Release);
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

    pub(super) fn valid_start_address(
        &self,
        memory: &GuestMemoryMmap,
        entry: u64,
        pstate: u64,
    ) -> bool {
        valid_start_address(memory, self.count, self.high_redist_base, entry, pstate)
    }

    pub fn request_on(&self, affinity: u64, entry: u64, context: u64, pstate: u64) -> Result<i32> {
        let Some(target) = self.target(affinity) else {
            return Ok(INVALID_PARAMETERS);
        };
        if AArch64Cpu::validate_pstate_bits(pstate).is_err() {
            return Ok(INVALID_PARAMETERS);
        }
        if entry & (start_width(pstate) as u64 - 1) != 0 {
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
        // Off is the execution state as soon as CPU_OFF parks the owner.
        // PSCI still reports ON until the coordinator acknowledges the stop.
        if control.requests.iter().any(|request| {
            matches!(request, CpuPowerRequest::Off { cpu_id } if *cpu_id as usize == target)
        }) {
            return Ok(ALREADY_ON);
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
        // DEN 0022D 6.6: an unacknowledged stop is still ON to firmware.
        if result != PowerState::On
            && control.requests.iter().any(|request| {
                matches!(request, CpuPowerRequest::Off { cpu_id }
                    if u64::from(*cpu_id) & mask == affinity & mask)
            })
        {
            result = PowerState::On;
        }
        Ok(match result {
            PowerState::On => 0,
            PowerState::Off => 1,
            PowerState::OnPending => 2,
        })
    }

    pub(in crate::backend::emulator) fn shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub(super) fn set_shutdown(&self, shutdown: bool) -> Result<()> {
        self.replace_terminal_with(shutdown, || Ok(()))
    }

    pub(crate) fn replace_terminal_with<T>(
        &self,
        shutdown: bool,
        commit: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        let result = commit()?;
        self.shutdown.store(shutdown, Ordering::Release);
        Ok(result)
    }

    pub(super) fn install_cpu_start(&self, install: impl FnOnce() -> Result<()>) -> Result<()> {
        let _control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        self.require_running()?;
        install()
    }

    fn require_running(&self) -> Result<()> {
        if self.shutdown() {
            return Err(invalid(
                "power transition cannot publish while the VM is shut down",
            ));
        }
        Ok(())
    }

    /// Observe requests without consuming them across fallible CPU operations.
    pub fn pending_requests(&self) -> Result<Vec<CpuPowerRequest>> {
        let control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        if self.shutdown() {
            return Ok(Vec::new());
        }
        Ok(control.requests.iter().cloned().collect())
    }

    pub fn complete_start(&self, cpu_id: u32) -> Result<()> {
        self.complete_power_transition(cpu_id, true)
    }

    pub fn complete_stop(&self, cpu_id: u32) -> Result<()> {
        self.complete_power_transition(cpu_id, false)
    }

    fn complete_power_transition(&self, cpu_id: u32, starting: bool) -> Result<()> {
        let mut control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        self.require_running()?;
        let expected = if starting {
            PowerState::OnPending
        } else {
            PowerState::Off
        };
        if control.states.get(cpu_id as usize) != Some(&expected) {
            return Err(invalid("power completion disagrees with CPU state"));
        }
        let index = control
            .requests
            .iter()
            .position(|request| match request {
                CpuPowerRequest::Start { cpu_id: target, .. } => starting && *target == cpu_id,
                CpuPowerRequest::Off { cpu_id: target } => !starting && *target == cpu_id,
            })
            .ok_or_else(|| invalid("power completion without matching request"))?;
        control.requests.remove(index);
        if starting {
            control.states[cpu_id as usize] = PowerState::On;
        }
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<ArmClusterCheckpoint> {
        self.checkpoint_with(Ok)
    }

    /// Keep the shared controller and power graph frozen through CPU/RAM capture.
    pub(crate) fn checkpoint_with<T>(
        &self,
        capture: impl FnOnce(ArmClusterCheckpoint) -> Result<T>,
    ) -> Result<T> {
        let control = self
            .control
            .lock()
            .map_err(|_| invalid("control lock poisoned"))?;
        let gic = self.gic.lock().map_err(|_| invalid("GIC lock poisoned"))?;
        capture(ArmClusterCheckpoint {
            control: control.clone(),
            gic: gic.checkpoint(),
            high_redist_base: self.high_redist_base,
            shutdown: self.shutdown(),
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
        self.shutdown.store(state.shutdown, Ordering::Release);
        Ok(result)
    }
}

#[cfg(test)]
impl ArmCluster {
    pub(crate) fn irq_line_for_test(&self, id: usize) -> Arc<AtomicBool> {
        self.gic.lock().unwrap().irq_line(id).unwrap()
    }
}

impl ArmClusterCheckpoint {
    #[cfg(test)]
    pub(crate) fn legacy_bytes_for_test(&self) -> Vec<u8> {
        use crate::isa::arm::aarch64::gic::checkpoint::LegacyGicCheckpoint;
        let mut value = serde_json::to_value(self).unwrap();
        value["gic"] = self.gic.legacy_fields_for_test();
        let old: LegacyCluster<LegacyGicCheckpoint> = serde_json::from_value(value).unwrap();
        crate::codec::serialize(&old).unwrap()
    }

    pub(crate) fn decode_legacy(raw: &[u8]) -> Result<Self> {
        use crate::isa::arm::aarch64::gic::checkpoint::LegacyGicCheckpoint;
        LegacyCluster::<LegacyGicCheckpoint>::decode(raw)?.upgrade(LegacyGicCheckpoint::upgrade)
    }

    #[cfg(test)]
    pub(crate) fn previous_source_bytes_for_test(&self) -> Vec<u8> {
        use crate::isa::arm::aarch64::gic::checkpoint::SourceGicCheckpoint;
        let mut value = serde_json::to_value(self).unwrap();
        value["gic"] = self.gic.legacy_fields_for_test();
        let old: LegacyCluster<SourceGicCheckpoint> = serde_json::from_value(value).unwrap();
        crate::codec::serialize(&old).unwrap()
    }

    pub(crate) fn decode_previous_sources(raw: &[u8]) -> Result<Self> {
        use crate::isa::arm::aarch64::gic::checkpoint::SourceGicCheckpoint;
        LegacyCluster::<SourceGicCheckpoint>::decode(raw)?.upgrade(SourceGicCheckpoint::upgrade)
    }

    pub(crate) fn decode_without_terminal(raw: &[u8]) -> Result<Self> {
        LegacyCluster::<GicCheckpoint>::decode(raw)?.upgrade(Ok)
    }

    #[cfg(test)]
    pub(crate) fn without_terminal_bytes_for_test(&self) -> Vec<u8> {
        crate::codec::serialize(&LegacyCluster {
            control: self.control.clone(),
            gic: &self.gic,
            high_redist_base: self.high_redist_base,
        })
        .unwrap()
    }

    pub(crate) fn validate_timer_inputs(&self, cpu: usize, levels: (bool, bool)) -> Result<()> {
        self.gic.validate_timer_inputs(cpu, levels)
    }

    pub(crate) fn validate_uart_irq(&self, level: bool) -> Result<()> {
        if self.gic.spi_level(AARCH64_UART_IRQ) != Some(level) {
            return Err(invalid(
                "GIC physical SPI level disagrees with PL011 output",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_cpu_power(&self, id: usize, powered_off: bool) -> Result<()> {
        let expected = match self.control.states.get(id) {
            Some(PowerState::On) => false,
            Some(PowerState::Off | PowerState::OnPending) => true,
            None => return Err(invalid("missing CPU power state")),
        };
        if expected != powered_off {
            return Err(invalid(
                "private CPU power state differs from shared PSCI state",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_start_targets<'a>(
        &self,
        memory: &GuestMemoryMmap,
        system: impl Fn(usize) -> Option<&'a Aarch64SystemRegisters>,
    ) -> Result<()> {
        // The execution graph has already validated the count and every target ID.
        for request in &self.control.requests {
            let CpuPowerRequest::Start {
                cpu_id,
                entry,
                pstate,
                ..
            } = *request
            else {
                continue;
            };
            if !valid_start_address(
                memory,
                self.control.states.len() as u8,
                self.high_redist_base,
                entry,
                pstate,
            ) {
                return Err(invalid(
                    "saved startup entry is outside guest instruction RAM",
                ));
            }
            let registers = system(cpu_id as usize)
                .ok_or_else(|| invalid("missing startup target CPU state"))?;
            AArch64Cpu::validate_psci_pstate(pstate, registers)
                .map_err(|error| invalid(&format!("saved startup target PSTATE: {error}")))?;
        }
        Ok(())
    }

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
        // Power transitions stay queued until acknowledged. For a stop, the
        // coordinator may have already cleared the scheduling bit.
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
                    AArch64Cpu::validate_pstate_bits(*pstate).map_err(|error| {
                        invalid(&format!("invalid saved startup PSTATE: {error}"))
                    })?;
                    if entry & (start_width(*pstate) as u64 - 1) != 0 {
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
        let mut saved = cluster.checkpoint().unwrap();
        saved.shutdown = true;
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
        assert!(!cluster.shutdown());
    }

    #[test]
    fn restoration_republishes_irq_levels_into_existing_pe_handles() {
        let cluster = ArmCluster::new(2, 0x8000).unwrap();
        let line = {
            let mut gic = cluster.gic.lock().unwrap();
            gic.write_dist(0, 2);
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

#[cfg(test)]
#[path = "cluster/retirement_error_tests.rs"]
mod retirement_error_tests;

#[cfg(test)]
#[path = "cluster/event_tests.rs"]
mod event_tests;

#[cfg(test)]
#[path = "cluster/source_tests.rs"]
mod source_tests;
