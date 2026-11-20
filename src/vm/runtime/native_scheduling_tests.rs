//! Actual coordinator selection with an explicitly bounded native-style CPU.
//! Native-style faults are injected through a model that makes no SDK calls.
use super::execution_tests::Fixture;
use super::*;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
struct Calls {
    bounded: Vec<(u32, Duration)>,
    event_windows: Vec<(u32, bool, bool)>,
    accept_bsp_entry_events: bool,
    bsp_entry_event: Option<u8>,
    unbounded: Vec<u32>,
    outgoing: Option<Arc<Mutex<LocalApic>>>,
    init_attempts: Vec<u32>,
    reject_init_once: Option<u32>,
    posted: Vec<u32>,
    collected: Vec<u32>,
    reject_post: Option<u32>,
}

struct Native {
    id: u32,
    state: CpuState,
    calls: Arc<Mutex<Calls>>,
    prepared_input: bool,
}

impl VCpu for Native {
    fn run(&mut self) -> Result<VcpuExit> {
        self.calls.lock().unwrap().unbounded.push(self.id);
        Err(Error::Emulator(format!(
            "native CPU {} used unbounded entry instead of its host-slice contract",
            self.id
        )))
    }

    fn supports_host_slices(&self) -> bool {
        true
    }

    fn run_host_slice(&mut self, limit: Duration) -> Result<Option<VcpuExit>> {
        assert!(!limit.is_zero() && limit <= Duration::from_millis(10));
        let outgoing = {
            let mut calls = self.calls.lock().unwrap();
            calls.bounded.push((self.id, limit));
            calls.outgoing.take()
        };
        if let Some(apic) = outgoing {
            // Model a fixed all-excluding-self IPI produced during native entry.
            apic.lock().unwrap().write_register(0x300, 0x000c_0041);
        }
        Ok(self.prepared_input.then_some(VcpuExit::IoIn {
            port: 0x3f8 + self.id as u16,
            size: 1,
        }))
    }

    fn post_host_slice(&mut self, limit: Duration) -> Result<()> {
        assert!(!limit.is_zero() && limit <= Duration::from_millis(1));
        let mut calls = self.calls.lock().unwrap();
        if calls.reject_post == Some(self.id) {
            return Err(Error::Emulator("test host entry post failed".into()));
        }
        assert!(
            calls.collected.is_empty(),
            "collected a CPU before posting all eligible entries"
        );
        calls.posted.push(self.id);
        Ok(())
    }

    fn collect_host_slice(&mut self) -> Result<Option<VcpuExit>> {
        let mut calls = self.calls.lock().unwrap();
        assert!(calls.posted.contains(&self.id));
        assert!(!calls.collected.contains(&self.id));
        calls.collected.push(self.id);
        Ok(self.prepared_input.then_some(VcpuExit::IoIn {
            port: 0x3f8 + self.id as u16,
            size: 1,
        }))
    }

    fn run_coordinated_host_slice_with_events(
        &mut self,
        limit: Duration,
        pending_maskable_irq: bool,
        pending_nmi: bool,
    ) -> Result<Option<VcpuExit>> {
        self.calls
            .lock()
            .unwrap()
            .event_windows
            .push((self.id, pending_maskable_irq, pending_nmi));
        self.run_host_slice(limit)
    }

    fn can_inject_interrupt(&self) -> bool {
        let calls = self.calls.lock().unwrap();
        self.id == 0 && calls.accept_bsp_entry_events && calls.bsp_entry_event.is_none()
    }

    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        let mut calls = self.calls.lock().unwrap();
        if self.id == 0 && calls.accept_bsp_entry_events && calls.bsp_entry_event.is_none() {
            calls.bsp_entry_event = Some(vector);
            return Ok(true);
        }
        Ok(false)
    }

    fn inject_nmi(&mut self) -> Result<bool> {
        self.inject_interrupt(2)
    }

    fn get_state(&self) -> Result<CpuState> {
        Ok(self.state.clone())
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.state = state.clone();
        Ok(())
    }

    fn deliver_init(&mut self) -> Result<()> {
        let mut calls = self.calls.lock().unwrap();
        calls.init_attempts.push(self.id);
        if calls.reject_init_once == Some(self.id) {
            calls.reject_init_once = None;
            return Err(Error::Emulator("test CPU rejected INIT".into()));
        }
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {
        self.prepared_input = false;
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        u64::MAX - u64::from(self.id)
    }
}

fn fixture(count: u8, prepared_input: bool) -> (Fixture, Arc<Mutex<Calls>>) {
    let mut fixture = Fixture::new(count);
    let calls = Arc::new(Mutex::new(Calls::default()));
    fixture.vm.vcpus = (0..u32::from(count))
        .map(|id| {
            let mut state = CpuState::x86_64(Default::default(), Default::default());
            let CpuState::X86_64(cpu) = &mut state else {
                unreachable!()
            };
            cpu.regs.rip = 0x8000 + 0x100 * u64::from(id);
            cpu.regs.rax = u64::from(id);
            Box::new(Native {
                id,
                state,
                calls: calls.clone(),
                prepared_input,
            }) as Box<dyn VCpu>
        })
        .collect();
    // Prepared online CPUs qualify selection, not firmware startup.
    fixture.vm.coordinator.online.fill(true);
    fixture.vm.coordinator.retired = 17;
    (fixture, calls)
}

fn public_states(vm: &Vmm) -> Vec<Vec<u8>> {
    vm.vcpus
        .iter()
        .map(|cpu| crate::codec::serialize(&cpu.get_state().unwrap()).unwrap())
        .collect()
}

#[test]
fn native_round_posts_every_online_cpu_before_collecting_owned_exits() {
    let (mut fixture, calls) = fixture(4, true);
    let vm = &mut fixture.vm;
    vm.coordinator.cursor = 2;
    vm.coordinator.online[1] = false;
    let mut turns = Vec::new();
    let mut pending = Vec::new();
    vm.execute_native_round(&mut turns, &mut pending).unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.posted, [2, 3, 0]);
    assert_eq!(calls.collected, [2, 3, 0]);
    assert!(pending.is_empty());
    assert_eq!(vm.coordinator.retired, 17);
    assert_eq!(vm.coordinator.cursor, 3);
    for (turn, id) in turns.iter().zip([2, 3, 0]) {
        assert_eq!(turn.cpu_index, id);
        assert!(matches!(
            turn.exit,
            VcpuExit::IoIn { port, size: 1 } if port == 0x3f8 + id as u16
        ));
    }
    assert_eq!(turns.len(), 3);
}

#[test]
fn native_round_joins_partial_dispatch_before_returning_a_post_error() {
    let (mut fixture, calls) = fixture(4, true);
    let vm = &mut fixture.vm;
    calls.lock().unwrap().reject_post = Some(2);
    let mut turns = Vec::new();
    let mut pending = Vec::new();
    let error = vm
        .execute_native_round(&mut turns, &mut pending)
        .unwrap_err();
    assert!(error.to_string().contains("test host entry post failed"));
    let calls = calls.lock().unwrap();
    assert_eq!(calls.posted, [0, 1]);
    assert_eq!(calls.collected, [0, 1]);
    assert!(pending.is_empty());
    assert_eq!(turns.len(), 2);
}

#[test]
fn host_yields_visit_every_online_cpu_without_guest_exits_or_retirement() {
    for count in [2, 4] {
        let (mut fixture, calls) = fixture(count, false);
        let before = public_states(&fixture.vm);
        for _ in 0..8 * usize::from(count) {
            let turn = fixture.vm.execute_turn().unwrap();
            assert!(turn.is_none(), "host yield became a guest exit: {turn:?}");
        }
        let calls = calls.lock().unwrap();
        assert!(calls.unbounded.is_empty());
        assert_eq!(
            calls.bounded.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            (0..u32::from(count))
                .cycle()
                .take(8 * usize::from(count))
                .collect::<Vec<_>>()
        );
        assert_eq!(fixture.vm.coordinator.retired, 17);
        assert_eq!(public_states(&fixture.vm), before);
    }
}

#[test]
fn event_window_requests_follow_the_selected_cpu_and_controller_priority() {
    let (mut fixture, calls) = fixture(4, false);
    let vm = &mut fixture.vm;
    vm.backend_kind = BackendKind::Hvf;
    {
        // The PIC belongs to the BSP. Only CPU 1 has an eligible LAPIC IRQ.
        MasterPicDevice::new(vm.pic.clone()).write(0x21, !(1 << 4));
        vm.pic.lock().unwrap().pulse_irq(4);
        for (index, apic) in vm.local_apics.iter().enumerate().skip(1) {
            let mut apic = apic.lock().unwrap();
            if index == 3 {
                apic.write_register(0xf0, 0xff);
            }
            if index == 2 {
                apic.write_register(0x80, 0x50);
                apic.set_pending_nmi();
            }
            apic.set_irr(0x51);
        }
    }
    for _ in 0..4 {
        assert!(vm.execute_turn().unwrap().is_none());
    }
    assert_eq!(
        calls.lock().unwrap().event_windows,
        [
            (0, true, false),
            (1, true, false),
            (2, false, true),
            (3, false, false)
        ]
    );
    assert!(vm.pic.lock().unwrap().has_pending());
    for apic in vm.local_apics.iter().skip(1) {
        assert_eq!(apic.lock().unwrap().get_pending_vector(), Some(0x51));
    }
    assert!(vm.local_apics[2].lock().unwrap().has_pending_nmi());
    assert_eq!(vm.coordinator.retired, 17);
}

#[test]
fn native_bsp_gives_the_entry_slot_to_nmi_before_legacy_pic() {
    let (mut fixture, calls) = fixture(2, false);
    let vm = &mut fixture.vm;
    vm.backend_kind = BackendKind::Hvf;
    calls.lock().unwrap().accept_bsp_entry_events = true;
    for (port, byte) in [(0x20, 0x13), (0x21, 0x40), (0x21, 0x01), (0x21, 0xfe)] {
        vm.io_bus.write(port, &[byte]).unwrap();
    }
    vm.pic.lock().unwrap().pulse_irq(0);
    vm.local_apics[0].lock().unwrap().set_pending_nmi();
    assert!(vm.poll_bsp_interrupts().unwrap());
    assert_eq!(calls.lock().unwrap().bsp_entry_event.take(), Some(2));
    assert!(vm.pic.lock().unwrap().has_pending());
    assert!(!vm.local_apics[0].lock().unwrap().has_pending_nmi());
    assert!(vm.poll_bsp_interrupts().unwrap());
    assert_eq!(calls.lock().unwrap().bsp_entry_event, Some(0x40));
    assert!(!vm.pic.lock().unwrap().has_pending());
}

#[test]
fn bounded_native_guest_exits_keep_the_selected_origin_and_cpu_frontier() {
    for count in [2, 4] {
        let (mut fixture, calls) = fixture(count, true);
        let before = public_states(&fixture.vm);
        for id in 0..usize::from(count) {
            let turn = fixture.vm.execute_turn().unwrap().unwrap();
            assert_eq!(turn.cpu_index, id);
            assert!(matches!(
                turn.exit,
                VcpuExit::IoIn { port, size: 1 } if port == 0x3f8 + id as u16
            ));
            #[cfg(feature = "debug")]
            assert!(!turn.debug_step_completed);
        }
        let calls = calls.lock().unwrap();
        assert!(calls.unbounded.is_empty());
        assert_eq!(calls.bounded.len(), usize::from(count));
        assert_eq!(fixture.vm.coordinator.retired, 17);
        assert_eq!(public_states(&fixture.vm), before);
    }
}

struct Legacy {
    state: CpuState,
    calls: Arc<Mutex<Calls>>,
}

impl VCpu for Legacy {
    fn run(&mut self) -> Result<VcpuExit> {
        self.calls.lock().unwrap().unbounded.push(0);
        Ok(VcpuExit::Hlt)
    }
    fn get_state(&self) -> Result<CpuState> {
        Ok(self.state.clone())
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.state = state.clone();
        Ok(())
    }
    fn complete_io_in(&mut self, _data: &[u8]) {
        panic!("the legacy HLT fixture cannot issue input");
    }
    fn id(&self) -> u32 {
        0
    }
}

#[test]
fn default_host_contract_rejects_without_entry_and_coordinator_keeps_legacy_dispatch() {
    let (mut fixture, calls) = fixture(1, false);
    let mut cpu = Legacy {
        state: fixture.vm.vcpus[0].get_state().unwrap(),
        calls: calls.clone(),
    };
    assert!(!cpu.supports_host_slices());
    for interval in [Duration::ZERO, Duration::from_millis(10), Duration::MAX] {
        assert!(matches!(
            cpu.run_host_slice(interval),
            Err(Error::InvalidConfig(_))
        ));
    }
    assert!(calls.lock().unwrap().unbounded.is_empty());
    fixture.vm.vcpus[0] = Box::new(cpu);
    let turn = fixture.vm.execute_turn().unwrap().unwrap();
    assert_eq!(turn.cpu_index, 0);
    assert!(matches!(turn.exit, VcpuExit::Hlt));
    assert_eq!(calls.lock().unwrap().unbounded, [0]);
    assert!(calls.lock().unwrap().bounded.is_empty());
    assert_eq!(fixture.vm.coordinator.retired, 17);
}

#[test]
fn actual_coordinator_routes_ipis_queued_during_a_host_yield() {
    for count in [2, 4] {
        let (mut fixture, calls) = fixture(count, false);
        for apic in &fixture.vm.local_apics {
            assert_eq!(apic.lock().unwrap().read_register(0x220) & 2, 0);
        }
        calls.lock().unwrap().outgoing = Some(fixture.vm.local_apics[0].clone());
        assert!(fixture.vm.execute_turn().unwrap().is_none());
        assert!(!fixture.vm.local_apics[0].lock().unwrap().has_pending_ipi());
        for (index, apic) in fixture.vm.local_apics.iter().enumerate() {
            assert_eq!(
                apic.lock().unwrap().read_register(0x220) & 2 != 0,
                index != 0
            );
        }
        assert_eq!(fixture.vm.coordinator.retired, 17);
    }
}

#[test]
fn broadcast_init_keeps_undelivered_targets_ahead_of_a_queued_sipi() {
    let (mut fixture, calls) = fixture(4, false);
    calls.lock().unwrap().reject_init_once = Some(2);
    {
        let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
        bsp.write_register(0x300, 0x000c_4500); // INIT, level assert, all excluding self.
        bsp.write_register(0x300, 0x000c_0609); // SIPI vector 9, all excluding self.
    }

    let error = fixture.vm.route_interprocessor_requests().unwrap_err();
    assert!(error.to_string().contains("test CPU rejected INIT"));
    assert_eq!(calls.lock().unwrap().init_attempts, [1, 2]);
    assert_eq!(fixture.vm.coordinator.online, [true, false, true, true]);

    fixture.vm.route_interprocessor_requests().unwrap();
    assert_eq!(calls.lock().unwrap().init_attempts, [1, 2, 2, 3]);
    assert_eq!(fixture.vm.coordinator.online, [true, true, true, true]);
    for cpu in &fixture.vm.vcpus[1..] {
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            panic!("expected a software-controlled x86 vCPU");
        };
        assert_eq!(
            (state.sregs.cs.selector, state.sregs.cs.base, state.regs.rip),
            (0x900, 0x9000, 0)
        );
    }
}

#[test]
fn checkpoint_resumes_only_the_unacknowledged_targets_of_a_logical_init() {
    use crate::vm::snapshot::SnapshotBundle;

    let mut fixture = Fixture::with_memory(4, 128 * 1024 * 1024);
    let vm = &mut fixture.vm;
    vm.coordinator.online.fill(true);
    let calls = Arc::new(Mutex::new(Calls {
        reject_init_once: Some(2),
        ..Default::default()
    }));
    let state = vm.vcpus[2].get_state().unwrap();
    let real_cpu = std::mem::replace(
        &mut vm.vcpus[2],
        Box::new(Native {
            id: 2,
            state,
            calls: calls.clone(),
            prepared_input: false,
        }),
    );
    for target in &vm.local_apics[1..] {
        target.lock().unwrap().write_register(0xd0, 0x100_0000);
    }
    {
        let mut bsp = vm.local_apics[0].lock().unwrap();
        bsp.write_register(0x310, 0x100_0000);
        bsp.write_register(0x300, 0x4d00); // INIT, level assert, logical destination 1.
        bsp.write_register(0x300, 0x000c_0609); // SIPI vector 9, all excluding self.
    }
    let error = vm.route_interprocessor_requests().unwrap_err();
    assert!(error.to_string().contains("test CPU rejected INIT"));
    assert_eq!(calls.lock().unwrap().init_attempts, [2]);
    vm.vcpus[2] = real_cpu;
    assert_eq!(vm.coordinator.online, [true, false, true, true]);
    assert!(vm.take_snapshot(53).is_err());

    // CPU 1 gains a pending interrupt after successful INIT. CPU 3 also
    // changes its logical ID, after it was selected but before it gets INIT.
    // These witnesses detect both duplicate INIT and destination re-resolution.
    vm.local_apics[1]
        .lock()
        .unwrap()
        .receive_fixed_interrupt(0x4a);
    vm.local_apics[3].lock().unwrap().write_register(0xd0, 0);
    let path = fixture.kernel.with_extension("rxc");
    vm.take_snapshot_bundle(53).unwrap().save(&path).unwrap();
    let restored = SnapshotBundle::load(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let execution = restored.execution().unwrap();
    let pending = execution.pending_ipi.as_ref().unwrap();
    assert_eq!(pending.source, 0);
    assert_eq!(
        pending.remaining,
        Some(std::collections::VecDeque::from([2, 3]))
    );
    assert_eq!(execution.local_apics[0].queued.len(), 1);
    let config = VmConfig::from_checkpoint_bundle(&restored, Default::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &restored).unwrap();

    for vm in [vm, &mut resumed] {
        vm.route_interprocessor_requests().unwrap();
        assert_eq!(vm.coordinator.online, [true; 4]);
        assert!(vm.coordinator.pending_ipi.is_none());
        assert!(!vm.local_apics[0].lock().unwrap().has_pending_ipi());
        assert_eq!(
            vm.local_apics[1].lock().unwrap().read_register(0x220),
            1 << 10
        );
        for cpu in &vm.vcpus[1..] {
            let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                panic!("expected x86 state");
            };
            assert_eq!(
                (state.sregs.cs.selector, state.sregs.cs.base, state.regs.rip),
                (0x900, 0x9000, 0)
            );
        }
    }
}
