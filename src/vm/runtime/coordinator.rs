//! Single-owner CPU selection and architectural x86 secondary startup.
use super::*;
use crate::vm::snapshot::PendingIpiDelivery;
use crate::vm::timing::ClockMode;
use crate::vm::vcpu::{ClockIdle, DEFAULT_HOST_SLICE, DEFAULT_RETIREMENT_QUANTUM, RetirementStop};
use std::collections::VecDeque;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExecutionCoordinator {
    pub(super) cursor: usize,
    pub(super) retired: u64,
    pub(super) online: Vec<bool>,
    pub(super) pending_ipi: Option<PendingIpiDelivery>,
}

#[derive(Debug)]
pub(super) struct ExecutionTurn {
    pub(super) cpu_index: usize,
    pub(super) exit: VcpuExit,
    #[cfg(feature = "debug")]
    pub(super) debug_step_completed: bool,
}

impl ExecutionCoordinator {
    pub(super) fn new(count: usize) -> Self {
        let mut online = vec![false; count];
        if let Some(bsp) = online.first_mut() {
            *bsp = true;
        }
        Self {
            cursor: 0,
            retired: 0,
            online,
            pending_ipi: None,
        }
    }

    fn next(&mut self) -> Option<usize> {
        let count = self.online.len();
        for _ in 0..count {
            let index = self.cursor;
            self.cursor = (index + 1) % count;
            if self.online[index] {
                return Some(index);
            }
        }
        None
    }
}

impl Vmm {
    fn advance_idle_clock(&mut self) -> Result<()> {
        let mut earliest = None;
        for (index, online) in self.coordinator.online.iter().enumerate() {
            if !online {
                continue;
            }
            #[cfg(feature = "debug")]
            if !self.debugger_allows_cpu(index) {
                return Ok(());
            }
            match self.vcpus[index].clock_idle()? {
                ClockIdle::Runnable => return Ok(()),
                ClockIdle::Waiting {
                    timer_delay_quanta: Some(delay),
                } => {
                    earliest = Some(earliest.map_or(delay, |previous: u128| previous.min(delay)));
                }
                ClockIdle::Waiting {
                    timer_delay_quanta: None,
                } => (),
            }
        }
        if let Some(delay) = earliest {
            self.timing_context.advance_idle(delay)?;
            self.poll_vm_clocks()?;
        }
        Ok(())
    }

    fn poll_vm_clocks(&mut self) -> Result<()> {
        if !matches!(
            self.checkpoint_config.arch,
            ArchKind::Aarch64 | ArchKind::Riscv64 | ArchKind::X86_64
        ) {
            return Ok(());
        }
        for (cpu, online) in self.vcpus.iter_mut().zip(&self.coordinator.online) {
            if *online {
                cpu.poll_vm_clock()?;
            }
        }
        Ok(())
    }

    pub(super) fn capture_execution_state(&self) -> Result<crate::vm::snapshot::ExecutionSnapshot> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let now = std::time::Instant::now();
        let mut local_apics = Vec::with_capacity(self.local_apics.len());
        for controller in &self.local_apics {
            local_apics.push(
                controller
                    .lock()
                    .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                    .checkpoint_at(now),
            );
        }
        Ok(crate::vm::snapshot::ExecutionSnapshot {
            cursor: self.coordinator.cursor,
            retired: self.coordinator.retired,
            last_snapshot_insn: self
                .snapshot_config
                .as_ref()
                .map(|_| self.last_snapshot_insn),
            online: self.coordinator.online.clone(),
            pending_ipi: self.coordinator.pending_ipi.clone(),
            local_apics,
            pc: self
                .pc_devices
                .as_ref()
                .map(|devices| devices.checkpoint_with(|pc, _| Ok(pc)))
                .transpose()?,
            pl011: self
                .pl011
                .as_ref()
                .map(|uart| {
                    uart.lock()
                        .map_err(|_| Error::Emulator("PL011 lock poisoned".into()))?
                        .checkpoint()
                })
                .transpose()?,
            riscv_platform: self
                .vm
                .as_any()
                .downcast_ref::<crate::backend::emulator::EmulatorVm>()
                .and_then(|vm| vm.riscv_platform())
                .map(|platform| platform.checkpoint())
                .transpose()?
                .flatten(),
            arm_cluster: self
                .vm
                .as_any()
                .downcast_ref::<crate::backend::emulator::EmulatorVm>()
                .and_then(|vm| vm.arm_cluster())
                .map(|cluster| cluster.checkpoint())
                .transpose()?,
        })
    }

    /// The software coordinator drains platform requests after each instruction,
    /// including instructions that retire I/O, before entering another CPU.
    pub(super) fn execute_turn(&mut self) -> Result<Option<ExecutionTurn>> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let _timing = self.timing_context.enter();
        self.route_interprocessor_requests()?;
        self.poll_vm_clocks()?;
        if self.timing_context.mode() == ClockMode::RetiredWithIdle {
            self.advance_idle_clock()?;
        }
        let mut selected = None;
        for _ in 0..self.vcpus.len() {
            let Some(index) = self.coordinator.next() else {
                break;
            };
            #[cfg(feature = "debug")]
            if !self.debugger_allows_cpu(index) {
                continue;
            }
            selected = Some(index);
            break;
        }
        let Some(index) = selected else {
            return Ok(None);
        };
        #[cfg(feature = "debug")]
        {
            self.debugger.last_cpu = index;
        }
        if !self.vcpus[index].supports_stepping() {
            // Native host yields carry no architectural exit or retirement.
            // Backends opt in separately; legacy entry remains unchanged for
            // those which do not implement this contract.
            let exit = if self.vcpus[index].supports_host_slices() {
                let limit = self.host_slice_limit()?;
                self.vcpus[index].run_host_slice(limit)?
            } else {
                Some(self.vcpus[index].run()?)
            };
            self.route_interprocessor_requests()?;
            self.poll_vm_clocks()?;
            if !self.coordinator.online[index] {
                return Ok(None);
            }
            return Ok(exit.map(|exit| ExecutionTurn {
                cpu_index: index,
                exit,
                #[cfg(feature = "debug")]
                debug_step_completed: false,
            }));
        }
        let service_pc_interrupts = self.uses_retired_pc_interrupt_timing();
        for _ in 0..DEFAULT_RETIREMENT_QUANTUM {
            // Retirement updates the VM clock at the end of each step. Give
            // timers and queued controllers that boundary before another step.
            if service_pc_interrupts {
                self.service_retired_pc_interrupts(index)?;
            }
            let result = self.vcpus[index].run_retirement_budget(1)?;
            let (retired, wrapped) = self.coordinator.retired.overflowing_add(result.retired);
            self.coordinator.retired = retired;
            if wrapped {
                self.last_snapshot_insn = 0;
            }
            self.route_interprocessor_requests()?;
            self.poll_vm_clocks()?;
            if !self.coordinator.online[index] {
                return Ok(None);
            }
            match result.stop {
                RetirementStop::BudgetExhausted => (),
                RetirementStop::Exit(exit) => {
                    return Ok(Some(ExecutionTurn {
                        cpu_index: index,
                        exit,
                        #[cfg(feature = "debug")]
                        debug_step_completed: result.retired != 0
                            && self.vcpus[index].is_single_step(),
                    }));
                }
                RetirementStop::StateChange => return Ok(None),
                RetirementStop::Fault(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn host_slice_limit(&self) -> Result<std::time::Duration> {
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
        if self.vm.uses_native_x86_irqchip() {
            let pit = self
                .pit
                .lock()
                .map_err(|_| Error::Emulator("PIT deadline lock poisoned".into()))?;
            if let Some(deadline) = pit.next_irq_nanos() {
                let now = self.timing_context.elapsed_nanos();
                // Let KVM execute even when the guest's PIT divisor is shorter
                // than a host entry. Such edges can coalesce at the PIC.
                let delay = std::time::Duration::from_nanos(deadline.saturating_sub(now));
                return Ok(delay.clamp(std::time::Duration::from_micros(100), DEFAULT_HOST_SLICE));
            }
        }
        Ok(DEFAULT_HOST_SLICE)
    }

    pub(super) fn route_interprocessor_requests(&mut self) -> Result<()> {
        if self.checkpoint_config.arch == ArchKind::Aarch64 {
            for request in self.vm.take_cpu_power_requests()? {
                match request {
                    crate::vm::vcpu::CpuPowerRequest::Start {
                        cpu_id,
                        entry,
                        context,
                        pstate,
                    } => {
                        let index = cpu_id as usize;
                        let cpu = self.vcpus.get_mut(index).ok_or_else(|| {
                            Error::Emulator("CPU_ON target exceeds VMM topology".into())
                        })?;
                        cpu.start_aarch64_cpu(entry, context, pstate)?;
                        self.vm.complete_cpu_start(cpu_id)?;
                        self.coordinator.online[index] = true;
                    }
                    crate::vm::vcpu::CpuPowerRequest::Off { cpu_id } => {
                        let online = self
                            .coordinator
                            .online
                            .get_mut(cpu_id as usize)
                            .ok_or_else(|| {
                                Error::Emulator("CPU_OFF target exceeds VMM topology".into())
                            })?;
                        *online = false;
                        self.vm.complete_cpu_stop(cpu_id)?;
                    }
                }
            }
            return Ok(());
        }
        if self.checkpoint_config.arch != ArchKind::X86_64 {
            return Ok(());
        }
        self.route_pc_interrupts()?;
        for (index, cpu) in self.vcpus.iter_mut().enumerate() {
            if let Some(eligible) = cpu.native_run_eligibility()? {
                self.coordinator.online[index] = eligible;
            }
        }
        self.resume_ipi_delivery()?;
        for source in 0..self.local_apics.len() {
            loop {
                let request = self.local_apics[source]
                    .lock()
                    .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                    .take_pending_ipi();
                let Some(request) = request else {
                    break;
                };
                self.coordinator.pending_ipi = Some(PendingIpiDelivery {
                    source: source as u8,
                    request,
                    remaining: None,
                });
                self.resume_ipi_delivery()?;
            }
        }
        Ok(())
    }

    fn ipi_targets(&self, source: usize, target: &IpiTarget) -> Result<Vec<usize>> {
        let mut targets = Vec::new();
        for (index, controller) in self.local_apics.iter().enumerate() {
            let controller = controller
                .lock()
                .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?;
            let selected = match target {
                IpiTarget::ToSelf => index == source,
                IpiTarget::AllIncludingSelf => true,
                IpiTarget::AllExcludingSelf => index != source,
                IpiTarget::Physical(id) => *id == 0xff || controller.apic_id() == *id,
                IpiTarget::Logical { destination } => {
                    let logical_id = (controller.read_register(0xd0) >> 24) as u8;
                    let format = controller.read_register(0xe0) >> 28;
                    if *destination == 0xff {
                        true
                    } else if format == 0xf {
                        logical_id & destination != 0
                    } else if format == 0 {
                        logical_id & 0xf0 == destination & 0xf0
                            && logical_id & destination & 0x0f != 0
                    } else {
                        false
                    }
                }
            };
            if selected {
                targets.push(index);
            }
        }
        Ok(targets)
    }

    fn resolve_ipi_targets(&self, source: usize, request: &IpiRequest) -> Result<VecDeque<u8>> {
        let mut targets = self.ipi_targets(source, request.target())?;
        if matches!(request, IpiRequest::LowestPriority { .. }) {
            let mut lowest = None;
            for index in targets {
                if !self.coordinator.online[index] {
                    continue;
                }
                let lapic = self.local_apics[index]
                    .lock()
                    .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?;
                if !lapic.is_enabled() {
                    continue;
                }
                let priority = lapic.read_register(0xa0) & 0xff;
                let key = (priority, lapic.apic_id(), index);
                if lowest.is_none_or(|previous| key < previous) {
                    lowest = Some(key);
                }
            }
            targets = lowest.into_iter().map(|(_, _, index)| index).collect();
        }
        Ok(targets.into_iter().map(|index| index as u8).collect())
    }

    fn resume_ipi_delivery(&mut self) -> Result<()> {
        let Some(mut delivery) = self.coordinator.pending_ipi.take() else {
            return Ok(());
        };
        let result = self.apply_ipi_delivery(&mut delivery);
        if result.is_err()
            && delivery
                .remaining
                .as_ref()
                .is_none_or(|targets| !targets.is_empty())
        {
            self.coordinator.pending_ipi = Some(delivery);
        }
        result
    }

    fn apply_ipi_delivery(&mut self, delivery: &mut PendingIpiDelivery) -> Result<()> {
        if delivery.remaining.is_none() {
            delivery.remaining =
                Some(self.resolve_ipi_targets(usize::from(delivery.source), &delivery.request)?);
        }
        let remaining = delivery.remaining.as_mut().unwrap();
        while let Some(index) = remaining.front().copied().map(usize::from) {
            match &delivery.request {
                IpiRequest::Fixed { vector, .. } | IpiRequest::LowestPriority { vector, .. } => {
                    self.local_apics[index]
                        .lock()
                        .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                        .receive_fixed_interrupt(*vector);
                }
                IpiRequest::Nmi { .. } => {
                    self.local_apics[index]
                        .lock()
                        .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                        .set_pending_nmi();
                }
                IpiRequest::Init { .. } => self.initialize_x86_cpu(index)?,
                IpiRequest::Sipi { vector, .. } => self.start_x86_cpu(index, *vector)?,
                IpiRequest::Smi { .. } => {
                    // Unsupported delivery is terminal, as it was before retries.
                    remaining.clear();
                    return Err(Error::Emulator(
                        "interprocessor SMI requires an implemented SMM entry contract".into(),
                    ));
                }
            }
            remaining.pop_front();
        }
        Ok(())
    }

    fn initialize_x86_cpu(&mut self, index: usize) -> Result<()> {
        // INIT does not repeat BSP selection: the current writable flag decides
        // whether this CPU resumes boot execution or waits for a SIPI.
        let bootstrap = self.vcpus[index].is_bootstrap_processor()?;
        self.vcpus[index].deliver_init()?;
        self.local_apics[index]
            .lock()
            .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
            .reset_for_init();
        self.coordinator.online[index] = bootstrap;
        Ok(())
    }

    fn start_x86_cpu(&mut self, index: usize, vector: u8) -> Result<()> {
        if self.coordinator.online[index] {
            // Running APs ignore duplicate SIPIs; do not restart their code.
            return Ok(());
        }
        let mut state = self.vcpus[index].get_state()?;
        let CpuState::X86_64(state) = &mut state else {
            return Err(Error::Emulator("SIPI target is not x86".into()));
        };
        state.regs.rip = 0;
        state.sregs.cs.selector = u16::from(vector) << 8;
        state.sregs.cs.base = u64::from(vector) << 12;
        self.vcpus[index].set_state(&CpuState::X86_64(state.clone()))?;
        self.vcpus[index].wake();
        self.coordinator.online[index] = true;
        Ok(())
    }
}
