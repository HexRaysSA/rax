//! Synchronous vCPU interface with a permanent native SDK owner.
//!
//! Only the worker creates, accesses, runs and destroys its native vCPU.
//! Callers may move the front end without moving that ownership.
use super::*;
use std::sync::mpsc;

type Operation = Box<dyn FnOnce(&mut HvfArm64Core) + Send + 'static>;

/// ARM64 HVF vCPU whose native handle remains on its creating thread.
pub struct HvfArm64Vcpu {
    id: u32,
    sender: Option<mpsc::Sender<Operation>>,
    worker: Option<std::thread::JoinHandle<()>>,
    lifetime: Arc<NativeVmLifetime>,
}

impl HvfArm64Vcpu {
    pub(super) fn new(
        id: u32,
        memory: Arc<GuestMemoryMmap>,
        lifetime: Arc<NativeVmLifetime>,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<Operation>();
        let frontend_lifetime = lifetime.clone();
        let (ready, created) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name(format!("rax-hvf-arm64-{id}"))
            .spawn(move || {
                let mut core = match HvfArm64Core::new(id, memory, lifetime) {
                    Ok(core) => core,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                for operation in receiver {
                    operation(&mut core);
                }
                // Core destruction, including the kick-thread join, runs here.
            })
            .map_err(|error| Error::Emulator(format!("ARM64 HVF owner spawn failed: {error}")))?;
        match created.recv() {
            Ok(Ok(())) => Ok(Self {
                id,
                sender: Some(sender),
                worker: Some(worker),
                lifetime: frontend_lifetime,
            }),
            result => {
                drop(sender);
                let _ = worker.join();
                match result {
                    Ok(Err(error)) => Err(error),
                    _ => Err(Error::Emulator(
                        "ARM64 HVF owner stopped during creation".into(),
                    )),
                }
            }
        }
    }

    fn request<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut HvfArm64Core) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let _boundary = self
            .lifetime
            .quiescence
            .read()
            .map_err(|_| Error::Emulator("native exclusion lock poisoned".into()))?;
        self.request_stopped(operation)
    }

    fn request_stopped<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut HvfArm64Core) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.lifetime.ensure_live()?;
        let (reply, result) = mpsc::sync_channel(1);
        let error = || Error::Emulator(format!("ARM64 HVF vCPU {} owner stopped", self.id));
        let sender = self.sender.as_ref().ok_or_else(error)?;
        let timing = crate::vm::timing::TimingContext::current();
        sender
            .send(Box::new(move |core| {
                let _timing = timing.as_ref().map(|clock| clock.enter());
                let _ = reply.send(operation(core));
            }))
            .map_err(|_| error())?;
        result.recv().map_err(|_| error())?
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;
    use crate::vm::timing::{self, ClockMode, TimingContext};

    #[test]
    #[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
    fn native_instruction_frontier_advance_wraps_the_sdk_pc_at_64_bits() {
        let backend = HvfArm64Backend::new().unwrap();
        let vm = backend.create_vm().unwrap();
        let native = vm.as_any().downcast_ref::<HvfArm64Vm>().unwrap();
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
        let cpu = HvfArm64Vcpu::new(0, memory, native.lifetime.clone()).unwrap();
        let pc = cpu
            .request(|core| {
                core.write_gpr(HV_REG_PC, u64::MAX - 3)?;
                core.advance_pc(4)?;
                core.read_gpr(HV_REG_PC)
            })
            .unwrap();
        assert_eq!(pc, 0);
    }

    #[test]
    #[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
    fn native_owner_requests_preserve_nested_caller_clocks_without_leaking_bindings() {
        let backend = HvfArm64Backend::new().unwrap();
        let vm = backend.create_vm().unwrap();
        let native = vm.as_any().downcast_ref::<HvfArm64Vm>().unwrap();
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
        let cpu = HvfArm64Vcpu::new(0, memory, native.lifetime.clone()).unwrap();
        let first = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let second = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        {
            let _first = first.enter();
            cpu.request(|_| {
                timing::record_retirement(3);
                Ok(())
            })
            .unwrap();
            assert_eq!(first.retirement_count(), Some(3));
            assert_eq!(first.elapsed_nanos(), 1);
            {
                let _second = second.enter();
                cpu.request(|_| {
                    timing::record_retirement(2);
                    Ok(())
                })
                .unwrap();
            }
            cpu.request(|_| {
                timing::record_retirement(1);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(
            cpu.request(|_| Ok(timing::retired_counter())).unwrap(),
            None
        );
        assert_eq!(first.retirement_count(), Some(4));
        assert_eq!(second.retirement_count(), Some(2));
    }
}

impl VCpu for HvfArm64Vcpu {
    fn start_aarch64_cpu(&mut self, entry: u64, context: u64, pstate: u64) -> Result<()> {
        self.request(move |core| core.start_cpu(entry, context, pstate))
    }
    fn validate_checkpoint_state(
        &self,
        _state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
    ) -> Result<()> {
        Err(Error::InvalidConfig(
            "native checkpoint restore requires the complete CPU/backend/VM graph".into(),
        ))
    }

    fn validate_checkpoint_context(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        let (state, emulator, context) = (state.clone(), emulator.clone(), context.cloned());
        self.request(move |core| {
            core.admit_native_context(&state, &emulator, context.as_ref())
                .map(|_| ())
        })
    }

    fn restore_checkpoint_record(
        &mut self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        boundary.require_owner(self.lifetime.identity())?;
        let (state, emulator, context) = (state.clone(), emulator.clone(), context.cloned());
        self.request_stopped(move |core| {
            let context = core.admit_native_context(&state, &emulator, context.as_ref())?;
            core.apply_native_context(&context)
        })
    }

    fn restore_checkpoint_context(
        &mut self,
        _state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
        _context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        Err(Error::InvalidConfig(
            "native backend context requires coordinated VM restoration".into(),
        ))
    }

    fn finish_checkpoint_restore(
        &mut self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        boundary.require_owner(self.lifetime.identity())?;
        let context = context.cloned();
        self.request_stopped(move |core| {
            let record = context
                .as_ref()
                .ok_or_else(|| Error::InvalidConfig("native finalization record absent".into()))?;
            let context = crate::backend::arm64_hvf_context::Context::decode(&record.data)?;
            core.finish_native_context(&context)
        })
    }

    fn capture_backend_context(&self) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.request(|core| {
            let context = core.capture_native_context()?;
            Ok(Some(crate::vm::snapshot::BackendContext {
                kind: crate::vm::snapshot::HVF_AARCH64_CONTEXT,
                data: context.encode()?,
            }))
        })
    }

    fn capture_checkpoint_record(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        _scope: Option<&crate::vm::memory::checkpoint::CheckpointPublication<'_>>,
    ) -> Result<(
        crate::vm::snapshot::CpuSnapshot,
        Option<crate::vm::snapshot::BackendContext>,
    )> {
        boundary.require_owner(self.lifetime.identity())?;
        self.request_stopped(|core| {
            let context = core.capture_native_context()?;
            let public = crate::vm::snapshot::CpuSnapshot {
                state: CpuState::Aarch64(context.public.clone()),
                emulator: crate::vm::snapshot::EmulatorState::default(),
            };
            Ok((
                public,
                Some(crate::vm::snapshot::BackendContext {
                    kind: crate::vm::snapshot::HVF_AARCH64_CONTEXT,
                    data: context.encode()?,
                }),
            ))
        })
    }

    fn run(&mut self) -> Result<VcpuExit> {
        loop {
            if let Some(exit) = self.run_host_slice(crate::vm::vcpu::DEFAULT_HOST_SLICE)? {
                return Ok(exit);
            }
        }
    }
    fn supports_host_slices(&self) -> bool {
        true
    }
    fn run_host_slice(&mut self, limit: std::time::Duration) -> Result<Option<VcpuExit>> {
        self.request(move |core| core.run_host_slice(limit))
    }

    fn get_state(&self) -> Result<CpuState> {
        self.request(|core| core.get_state())
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = state.clone();
        self.request(move |core| core.set_state(&state))
    }

    fn update_state(&mut self, state: &CpuState) -> Result<()> {
        let state = state.clone();
        // A register overlay retains in-flight I/O. Explicit state replacement
        // uses set_state, whose successful completion cancels the transaction.
        self.request(move |core| {
            if let CpuState::Aarch64(overlay) = &state {
                core.validate_pending_pc_overlay(overlay.regs.pc)?;
            }
            core.restore_native_state(&state)
        })
    }

    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        self.request(move |core| {
            core.validate_pending_pc_overlay(pc)?;
            core.write_gpr(HV_REG_PC, pc)
        })
    }

    fn wake(&mut self) {
        let _ = self.request(|core| {
            core.shutdown = false;
            core.clear_system_shutdown()?;
            Ok(())
        });
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        // Native scalar MMIO consumes at most eight bytes of the reply.
        let mut reply = [0; 8];
        let length = data.len().min(reply.len());
        reply[..length].copy_from_slice(&data[..length]);
        let _ = self.request(move |core| {
            core.complete_io_in(&reply[..length]);
            Ok(())
        });
    }

    fn io_completion_result(&self) -> Result<()> {
        self.request(|core| {
            if let Some(error) = &core.io_completion_error {
                return Err(match error {
                    Error::Emulator(message) => Error::Emulator(message.clone()),
                    other => Error::Emulator(other.to_string()),
                });
            }
            if core.pending_mmio_read.is_some() {
                Err(Error::Emulator(
                    "native MMIO read awaits a complete reply".into(),
                ))
            } else if core.pending_mmio_write.is_some() {
                Err(Error::Emulator(
                    "native MMIO store awaits successful caller dispatch".into(),
                ))
            } else {
                Ok(())
            }
        })
    }

    fn complete_io_out(&mut self) -> Result<()> {
        self.request(|core| core.complete_io_out())
    }

    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        self.request(move |core| core.inject_interrupt(vector))
    }

    fn can_inject_interrupt(&self) -> bool {
        false
    }

    fn inject_nmi(&mut self) -> Result<bool> {
        self.request(HvfArm64Core::inject_nmi)
    }

    #[cfg(feature = "debug")]
    fn set_single_step(&mut self, enabled: bool) {
        let _ = self.request(move |core| {
            core.set_single_step(enabled);
            Ok(())
        });
    }

    #[cfg(feature = "debug")]
    fn is_single_step(&self) -> bool {
        false
    }

    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, _addr: u64) {}

    fn id(&self) -> u32 {
        self.id
    }
    fn instruction_count(&self) -> u64 {
        0
    }
}

impl Drop for HvfArm64Vcpu {
    fn drop(&mut self) {
        let _boundary = self
            .lifetime
            .quiescence
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Disconnect after every preceding synchronous operation has completed.
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                self.lifetime
                    .owner_teardown_failed
                    .store(true, Ordering::Release);
                warn!(id = self.id, "ARM64 HVF owner panicked");
            }
        }
        // Successful per-CPU destruction leaves peers usable and releases this
        // logical identity. The final lifetime Arc owns whole-VM destruction.
        match self.lifetime.topology.lock() {
            Ok(mut topology) => {
                topology.created.remove(&self.id);
            }
            Err(_) => {
                self.lifetime
                    .owner_teardown_failed
                    .store(true, Ordering::Release);
                warn!(
                    id = self.id,
                    "ARM64 HVF topology lock poisoned during teardown"
                );
            }
        }
    }
}
