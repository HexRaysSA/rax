//! Single-owner CPU selection and architectural x86 secondary startup.
use super::*;
use crate::vm::vcpu::{DEFAULT_RETIREMENT_QUANTUM, RetirementStop};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExecutionCoordinator {
    pub(super) cursor: usize,
    pub(super) retired: u64,
    pub(super) online: Vec<bool>,
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
    pub(super) fn capture_execution_state(&self) -> Result<crate::vm::snapshot::ExecutionSnapshot> {
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
            online: self.coordinator.online.clone(),
            local_apics,
            pl011: self
                .pl011
                .as_ref()
                .map(|uart| {
                    uart.lock()
                        .map_err(|_| Error::Emulator("PL011 lock poisoned".into()))?
                        .checkpoint()
                })
                .transpose()?,
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
        let _timing = self.timing_context.enter();
        self.route_interprocessor_requests()?;
        let Some(index) = self.coordinator.next() else {
            return Ok(None);
        };
        if !self.vcpus[index].supports_stepping() {
            // Native scheduling is being connected to each backend's bounded
            // entry contract separately; do not claim instruction retirement.
            let exit = self.vcpus[index].run()?;
            self.route_interprocessor_requests()?;
            if !self.coordinator.online[index] {
                return Ok(None);
            }
            return Ok(Some(ExecutionTurn {
                cpu_index: index,
                exit,
                #[cfg(feature = "debug")]
                debug_step_completed: false,
            }));
        }
        for _ in 0..DEFAULT_RETIREMENT_QUANTUM {
            let result = self.vcpus[index].run_retirement_budget(1)?;
            self.coordinator.retired = self.coordinator.retired.wrapping_add(result.retired);
            self.route_interprocessor_requests()?;
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
        for source in 0..self.local_apics.len() {
            loop {
                let request = self.local_apics[source]
                    .lock()
                    .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                    .take_pending_ipi();
                let Some(request) = request else {
                    break;
                };
                self.deliver_interprocessor_request(source, request)?;
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

    fn deliver_interprocessor_request(&mut self, source: usize, request: IpiRequest) -> Result<()> {
        let target = match &request {
            IpiRequest::Fixed { target, .. }
            | IpiRequest::LowestPriority { target, .. }
            | IpiRequest::Nmi { target }
            | IpiRequest::Smi { target }
            | IpiRequest::Init { target }
            | IpiRequest::Sipi { target, .. } => target,
        };
        let mut targets = self.ipi_targets(source, target)?;
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
        for index in targets {
            match &request {
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
                    return Err(Error::Emulator(
                        "interprocessor SMI requires an implemented SMM entry contract".into(),
                    ));
                }
            }
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
