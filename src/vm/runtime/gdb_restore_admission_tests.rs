//! Guest import must preserve the current controller or reject before publication.
use super::*;
use crate::debug::gdb::{Resume, ResumeAction, ThreadId};
use crate::vm::snapshot::{BackendContext, EmulatorState, PreparedResources};
use crate::vm::vcpu::DebuggerControls;

fn cpu_records(vm: &Vmm) -> Vec<(Vec<u8>, Option<BackendContext>)> {
    vm.vcpus
        .iter()
        .map(|cpu| {
            (
                crate::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
                cpu.capture_backend_context().unwrap(),
            )
        })
        .collect()
}

#[test]
fn detached_target_does_not_inherit_a_saved_frontends_cpu_controls() {
    let mut source = super::super::execution_tests::Fixture::new(2);
    source.write(super::super::execution_tests::BSP, &[0x40, 0xf4]);
    for cpu in &mut source.vm.vcpus {
        cpu.set_debugger_active(true);
        cpu.set_single_step(true);
        cpu.set_debug_breakpoint(super::super::execution_tests::BSP)
            .unwrap();
    }
    let saved = source.vm.take_snapshot_bundle(0).unwrap();
    let mut target = super::super::execution_tests::Fixture::new(2);
    let controls: Vec<_> = target
        .vm
        .vcpus
        .iter()
        .map(|cpu| cpu.debugger_controls())
        .collect();
    target.vm.restore_snapshot_bundle(&saved).unwrap();
    assert!(target.vm.gdb_channels.is_none());
    assert!(target.vm.gdb_breakpoints.is_empty());
    assert_eq!(
        target
            .vm
            .vcpus
            .iter()
            .map(|cpu| cpu.debugger_controls())
            .collect::<Vec<_>>(),
        controls
    );
    let turn = target.vm.execute_turn().unwrap().unwrap();
    assert!(matches!(turn.exit, VcpuExit::Hlt));
    assert!(!turn.debug_step_completed);
    let CpuState::X86_64(state) = target.vm.vcpus[0].get_state().unwrap() else {
        panic!("x86 fixture");
    };
    assert_eq!(state.regs.rax, 1);
}

#[test]
fn restore_rejects_before_publication_if_it_would_offline_the_current_step_target() {
    let source = super::super::execution_tests::Fixture::new(2);
    let saved = source.vm.take_snapshot_bundle(0).unwrap();
    assert_eq!(saved.execution().unwrap().online(), [true, false]);
    let mut target = super::super::execution_tests::Fixture::new(2);
    let vm = &mut target.vm;
    vm.coordinator.online[1] = true;
    assert_eq!(
        vm.resume_debugger(&[Resume {
            action: ResumeAction::Step,
            thread: ThreadId::Id(2),
        }])
        .unwrap(),
        Some(true)
    );
    target.write(0x7000, b"live");
    let vm = &mut target.vm;
    let before = cpu_records(vm);
    let memory = vm.guest_mem.try_read_all().unwrap();
    let coordinator = vm.coordinator.clone();
    let session = format!("{:?}", vm.debugger);
    let error = vm.restore_snapshot_bundle(&saved).unwrap_err();
    assert!(error.to_string().contains("debugger resume"), "{error}");
    assert_eq!(cpu_records(vm), before);
    assert_eq!(vm.guest_mem.try_read_all().unwrap(), memory);
    assert_eq!(vm.coordinator, coordinator);
    assert_eq!(format!("{:?}", vm.debugger), session);
    assert!(vm.debugger.failure.is_none());
}

/// Delegate real admission/preparation, then fail after changing only a candidate.
struct RejectBinding {
    inner: Box<dyn VCpu>,
    calls: Arc<AtomicU64>,
}

impl VCpu for RejectBinding {
    fn id(&self) -> u32 {
        self.inner.id()
    }
    fn run(&mut self) -> Result<VcpuExit> {
        panic!("binding rejection must precede entry")
    }
    fn get_state(&self) -> Result<CpuState> {
        self.inner.get_state()
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.inner.set_state(state)
    }
    fn complete_io_in(&mut self, _data: &[u8]) {}
    fn capture_backend_context(&self) -> Result<Option<BackendContext>> {
        self.inner.capture_backend_context()
    }
    fn debugger_controls(&self) -> Option<DebuggerControls> {
        self.inner.debugger_controls()
    }
    fn validate_checkpoint_for_machine(
        &self,
        config: &crate::config::CheckpointConfig,
        state: &CpuState,
        emulator: &EmulatorState,
        context: Option<&BackendContext>,
    ) -> Result<()> {
        self.inner
            .validate_checkpoint_for_machine(config, state, emulator, context)
    }
    fn checkpoint_resource_references(
        &self,
        context: Option<&BackendContext>,
    ) -> Result<Vec<crate::vm::snapshot::ResourceKey>> {
        self.inner.checkpoint_resource_references(context)
    }
    fn prepare_checkpoint_replacement(
        &self,
        state: &CpuState,
        emulator: &EmulatorState,
        context: Option<&BackendContext>,
        resources: &PreparedResources,
    ) -> Result<Option<Box<dyn VCpu>>> {
        let candidate = self
            .inner
            .prepare_checkpoint_replacement(state, emulator, context, resources)?
            .expect("software x86 prepares an offside replacement");
        Ok(Some(Box::new(Self {
            inner: candidate,
            calls: self.calls.clone(),
        })))
    }
    fn bind_debugger_controls(&mut self, controls: &DebuggerControls) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.bind_debugger_controls(controls)?;
        let CpuState::X86_64(mut state) = self.inner.get_state()? else {
            panic!("x86 candidate");
        };
        state.regs.rax = 0xdead_beef;
        self.inner.update_state(&CpuState::X86_64(state))?;
        Err(Error::Emulator("scripted candidate binding failure".into()))
    }
}

#[test]
fn first_and_last_candidate_binding_failures_leave_the_live_vm_unchanged() {
    let source = super::super::execution_tests::Fixture::new(2);
    let saved = source.vm.take_snapshot_bundle(0).unwrap();
    for failure_index in 0..2 {
        let mut target = super::super::execution_tests::Fixture::new(2);
        target.write(0x7000, b"live");
        let vm = &mut target.vm;
        let calls = Arc::new(AtomicU64::new(0));
        let inner = vm.vcpus.remove(failure_index);
        vm.vcpus.insert(
            failure_index,
            Box::new(RejectBinding {
                inner,
                calls: calls.clone(),
            }),
        );
        let before = cpu_records(vm);
        let memory = vm.guest_mem.try_read_all().unwrap();
        let coordinator = vm.coordinator.clone();
        let session = format!("{:?}", vm.debugger);
        let devices = crate::codec::serialize(&(
            vm.pic.lock().unwrap().clone(),
            vm.pit.lock().unwrap().clone(),
            vm.serial.lock().unwrap().clone(),
        ))
        .unwrap();
        let error = vm.restore_snapshot_bundle(&saved).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("scripted candidate binding failure"),
            "{error}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cpu_records(vm), before);
        assert_eq!(vm.guest_mem.try_read_all().unwrap(), memory);
        assert_eq!(vm.coordinator, coordinator);
        assert_eq!(format!("{:?}", vm.debugger), session);
        assert_eq!(
            crate::codec::serialize(&(
                vm.pic.lock().unwrap().clone(),
                vm.pit.lock().unwrap().clone(),
                vm.serial.lock().unwrap().clone(),
            ))
            .unwrap(),
            devices
        );
        assert!(vm.debugger.failure.is_none());
    }
}
