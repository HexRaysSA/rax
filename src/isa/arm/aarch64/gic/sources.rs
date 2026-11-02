//! Physical input history and software pending latches, independent of active state.
use super::{
    CpuInterface, Gic, InterruptConfig, NUM_PPI, NUM_SGI, SPI_END, SPI_START, TriggerType,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct InputState {
    line: bool,
    software: bool,
    edge: bool,
}

impl InputState {
    fn pending(&self, trigger: TriggerType) -> bool {
        self.software
            || if trigger == TriggerType::Level {
                self.line
            } else {
                self.edge
            }
    }

    fn publish(&self, config: &mut InterruptConfig) {
        if self.pending(config.trigger) {
            config.state.set_pending();
        } else {
            config.state.clear_pending();
        }
    }

    // Observable raw CPU-interface pending-bit changes become software state.
    // Idempotent raw bit assignments convey no event; request-generating callers
    // use the pending setters or MMIO methods. Raw edits cannot withdraw an
    // independently asserted physical level. Changes
    // between edge/level modes while pending are architecturally UNKNOWN; this
    // model retains an existing aggregate request as a software latch.
    fn reconcile(&mut self, config: &mut InterruptConfig) {
        if config.trigger == TriggerType::Level {
            self.edge = false;
        }
        let pending = self.pending(config.trigger);
        if config.state.is_pending() && !pending {
            self.software = true;
        }
        if !config.state.is_pending() && pending {
            self.software = false;
            self.edge = false;
        }
        self.publish(config);
    }

    pub(super) fn software_pending(&mut self, config: &mut InterruptConfig, pending: bool) {
        self.reconcile(config);
        self.software = pending;
        if !pending {
            self.edge = false;
        }
        self.publish(config);
    }

    fn drive(&mut self, config: &mut InterruptConfig, level: bool) {
        self.reconcile(config);
        if level && !self.line && config.trigger == TriggerType::Edge {
            self.edge = true;
        }
        self.line = level;
        self.publish(config);
    }

    fn acknowledge(&mut self, config: &mut InterruptConfig) {
        if config.trigger == TriggerType::Edge {
            self.software = false;
            self.edge = false;
        }
        // Keep the existing implementation-defined level software-pending
        // acknowledgement policy: software clears it through ICPENDR.
        self.publish(config);
    }

    fn valid(&self, config: &InterruptConfig) -> bool {
        !(config.trigger == TriggerType::Level && self.edge)
            && self.pending(config.trigger) == config.state.is_pending()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct SourceBank {
    pub(super) ppis: Vec<[InputState; NUM_PPI]>,
    pub(super) spis: Vec<InputState>,
}

impl SourceBank {
    pub(super) fn new(cpus: usize, spis: usize) -> Self {
        Self {
            ppis: vec![[InputState::default(); NUM_PPI]; cpus],
            spis: vec![InputState::default(); spis],
        }
    }

    pub(super) fn reconcile(&mut self, cpus: &mut [CpuInterface], spis: &mut [InterruptConfig]) {
        for (inputs, cpu) in self.ppis.iter_mut().zip(cpus) {
            for (input, config) in inputs
                .iter_mut()
                .zip(&mut cpu.private_interrupts[NUM_SGI..])
            {
                input.reconcile(config);
            }
        }
        for (input, config) in self.spis.iter_mut().zip(spis) {
            input.reconcile(config);
        }
    }

    pub(super) fn valid(&self, cpus: &[CpuInterface], spis: &[InterruptConfig]) -> bool {
        self.ppis.len() == cpus.len()
            && self.spis.len() == spis.len()
            && self.ppis.iter().zip(cpus).all(|(inputs, cpu)| {
                inputs
                    .iter()
                    .zip(&cpu.private_interrupts[NUM_SGI..])
                    .all(|(input, config)| input.valid(config))
            })
            && self
                .spis
                .iter()
                .zip(spis)
                .enumerate()
                .all(|(index, (input, config))| {
                    if index + SPI_START as usize > SPI_END as usize {
                        *input == InputState::default()
                            && !config.state.is_pending()
                            && !config.state.is_active()
                    } else {
                        input.valid(config)
                    }
                })
    }

    pub(super) fn ppi_level(&self, cpu: usize, intid: u32) -> Option<bool> {
        let index = usize::try_from(intid).ok()?.checked_sub(NUM_SGI)?;
        self.ppis.get(cpu)?.get(index).map(|input| input.line)
    }
}

impl Gic {
    pub(super) fn reconcile_sources(&mut self) {
        self.sources
            .reconcile(&mut self.cpu_interfaces, &mut self.spis);
    }

    pub(super) fn acknowledge_source(&mut self, cpu_id: usize, intid: u32) {
        if intid > SPI_END {
            return;
        }
        if let Some(index) = intid.checked_sub(SPI_START).map(|n| n as usize) {
            if let (Some(input), Some(config)) =
                (self.sources.spis.get_mut(index), self.spis.get_mut(index))
            {
                input.acknowledge(config);
            }
        } else if (NUM_SGI as u32..SPI_START).contains(&intid)
            && let (Some(inputs), Some(cpu)) = (
                self.sources.ppis.get_mut(cpu_id),
                self.cpu_interfaces.get_mut(cpu_id),
            )
        {
            inputs[intid as usize - NUM_SGI]
                .acknowledge(&mut cpu.private_interrupts[intid as usize]);
        }
    }

    /// Drive a physical PPI input. Its line is independent of software pending.
    pub fn set_ppi_level(&mut self, cpu_id: usize, intid: u32, level: bool) {
        if !(NUM_SGI as u32..SPI_START).contains(&intid) {
            return;
        }
        if let (Some(inputs), Some(cpu)) = (
            self.sources.ppis.get_mut(cpu_id),
            self.cpu_interfaces.get_mut(cpu_id),
        ) {
            inputs[intid as usize - NUM_SGI]
                .drive(&mut cpu.private_interrupts[intid as usize], level);
            self.update_all_cpus();
        }
    }

    /// Drive a physical SPI input, retaining edge history across acknowledgement.
    pub fn set_spi_level(&mut self, intid: u32, level: bool) {
        if !(SPI_START..=SPI_END).contains(&intid) {
            return;
        }
        let Some(index) = intid.checked_sub(SPI_START).map(|n| n as usize) else {
            return;
        };
        if let (Some(input), Some(config)) =
            (self.sources.spis.get_mut(index), self.spis.get_mut(index))
        {
            input.drive(config, level);
            self.update_all_cpus();
        }
    }
}
