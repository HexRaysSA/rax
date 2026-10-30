//! Movable public interface; every SDK operation stays on its permanent owner.
use super::intel_owner::{Owner, StartError};
use super::intel_vm::Lifetime;
use super::*;

pub struct HvfVcpu {
    id: u32,
    owner: Owner<HvfCore>,
    lifetime: Arc<Lifetime>,
}

impl HvfVcpu {
    pub(super) fn new(
        id: u32,
        memory: Arc<GuestMemoryMmap>,
        cpuid: CpuidConfig,
        lifetime: Arc<Lifetime>,
    ) -> Result<Self> {
        let boundary = lifetime
            .quiescence
            .read()
            .map_err(|_| Error::Emulator("Intel HVF exclusion lock poisoned".into()))?;
        lifetime.ready()?;
        if !lifetime
            .cpus
            .lock()
            .map_err(|_| Error::Emulator("Intel HVF topology lock poisoned".into()))?
            .insert(id)
        {
            return Err(Error::InvalidConfig(format!(
                "Intel HVF CPU {id} already exists"
            )));
        }
        let core_lifetime = lifetime.clone();
        let failure_lifetime = lifetime.clone();
        let owner = Owner::spawn(
            format!("rax-hvf-intel-{id}"),
            move || HvfCore::create(id, memory, cpuid, core_lifetime),
            Arc::new(move |error| failure_lifetime.poison(error)),
        );
        match owner {
            Ok(owner) => {
                drop(boundary);
                Ok(Self {
                    id,
                    owner,
                    lifetime,
                })
            }
            Err(error) => {
                if lifetime.ready().is_ok() {
                    if let Ok(mut cpus) = lifetime.cpus.lock() {
                        cpus.remove(&id);
                    } else {
                        lifetime.poison("topology lock poisoned after creation failure".into());
                    }
                }
                drop(boundary);
                Err(match error {
                    StartError::Create(error) => error,
                    StartError::Spawn(error) => {
                        Error::Emulator(format!("Intel HVF owner spawn failed: {error}"))
                    }
                    StartError::Owner(error) => Error::Emulator(error),
                })
            }
        }
    }

    fn request<R: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut HvfCore) -> Result<R> + Send + 'static,
    ) -> Result<R> {
        let _boundary = self
            .lifetime
            .quiescence
            .read()
            .map_err(|_| Error::Emulator("Intel HVF exclusion lock poisoned".into()))?;
        self.request_stopped(operation)
    }

    fn request_stopped<R: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut HvfCore) -> Result<R> + Send + 'static,
    ) -> Result<R> {
        self.lifetime.ready()?;
        let lifetime = self.lifetime.clone();
        let timing = crate::vm::timing::TimingContext::current();
        self.owner
            .call(move |core| {
                let _timing = timing.as_ref().map(|clock| clock.enter());
                lifetime.ready()?;
                operation(core)
            })
            .map_err(Error::Emulator)?
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        let _boundary = self
            .lifetime
            .quiescence
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = self.owner.close();
        if self.lifetime.ready().is_ok() {
            if let Ok(mut cpus) = self.lifetime.cpus.lock() {
                cpus.remove(&self.id);
            } else {
                self.lifetime
                    .poison("topology lock poisoned during owner teardown".into());
            }
        }
    }
}

impl VCpu for HvfVcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        self.request(HvfCore::run)
    }
    fn get_state(&self) -> Result<CpuState> {
        self.request(|core| core.get_state())
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = state.clone();
        self.request(move |core| core.set_state(&state))
    }
    fn wake(&mut self) {
        let _ = self.request(|core| {
            core.wake();
            Ok(())
        });
    }
    fn complete_io_in(&mut self, data: &[u8]) {
        // Preserve invalid lengths too: completion diagnostics report the
        // original received length, rather than a truncated channel payload.
        let reply = data.to_vec();
        let _ = self.request(move |core| {
            core.complete_io_in(&reply);
            Ok(())
        });
    }
    fn complete_io_out(&mut self) -> Result<()> {
        self.request(HvfCore::complete_io_out)
    }
    fn io_completion_result(&self) -> Result<()> {
        self.request(|core| core.io_completion_result())
    }
    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        self.request(move |core| core.inject_interrupt(vector))
    }
    fn inject_nmi(&mut self) -> Result<bool> {
        self.request(HvfCore::inject_nmi)
    }
    fn can_inject_interrupt(&self) -> bool {
        self.request(|core| Ok(core.can_inject_interrupt()))
            .unwrap_or(false)
    }
    fn attach_local_apic(&mut self, lapic: Arc<Mutex<crate::devices::lapic::LocalApic>>) {
        let _ = self.request(move |core| {
            core.attach_local_apic(lapic);
            Ok(())
        });
    }
    fn is_bootstrap_processor(&self) -> Result<bool> {
        self.request(|core| core.is_bootstrap_processor())
    }
    fn id(&self) -> u32 {
        self.id
    }
    fn instruction_count(&self) -> u64 {
        0
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
        self.request(|core| Ok(core.is_single_step()))
            .unwrap_or(false)
    }
    #[cfg(feature = "debug")]
    fn debug_address_space(&self) -> Result<crate::vm::vcpu::DebugAddressSpace> {
        self.request(|core| core.debug_address_space())
    }
    #[cfg(feature = "debug")]
    fn debug_memory_changed(&mut self, _pages: &[u64]) -> Result<()> {
        // The SDK invalidates the entire TLB; there is no per-page selector.
        self.request(|core| core.debug_memory_changed(&[]))
    }
    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, address: u64) {
        let _ = self.request(move |core| {
            core.invalidate_code_cache(address);
            Ok(())
        });
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
        // Preserve the existing architectural projection without recursively
        // acquiring the VM lease. Complete native private capture is separate.
        self.request_stopped(|core| {
            Ok((
                crate::vm::snapshot::CpuSnapshot {
                    state: core.get_state()?,
                    emulator: crate::vm::snapshot::EmulatorState::default(),
                },
                None,
            ))
        })
    }
    fn restore_checkpoint_record(
        &mut self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        boundary.require_owner(self.lifetime.identity())?;
        let state = state.clone();
        let context = context.cloned();
        self.request_stopped(move |core| {
            if std::mem::discriminant(&state) != std::mem::discriminant(&core.get_state()?) {
                return Err(Error::InvalidConfig(
                    "checkpoint CPU kind does not match target vCPU".into(),
                ));
            }
            if context.is_some() {
                return Err(Error::InvalidConfig(
                    "checkpoint context producer differs from target backend".into(),
                ));
            }
            core.set_state(&state)
        })
    }
}
