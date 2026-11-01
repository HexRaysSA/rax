//! Actual coordinator selection with an explicitly bounded native-style CPU.
//! This model executes no SDK call or guest instruction.
use super::execution_tests::Fixture;
use super::*;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
struct Calls {
    bounded: Vec<(u32, Duration)>,
    unbounded: Vec<u32>,
    outgoing: Option<Arc<Mutex<LocalApic>>>,
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

    fn get_state(&self) -> Result<CpuState> {
        Ok(self.state.clone())
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.state = state.clone();
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
