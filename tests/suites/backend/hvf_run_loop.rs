//! Execute the actual shared VM-exit driver using deterministic host-call traces.
#[path = "../../../src/backend/hvf/run_loop.rs"]
mod run_loop;
use run_loop::{ExitHandler, run};
use std::collections::VecDeque;

const INTERNAL: [u32; 7] = [10, 31, 32, 1, 7, 28, 55];
struct Host {
    reasons: VecDeque<u32>,
    trace: Vec<&'static str>,
    fail: Option<&'static str>,
    msr_exit: bool,
    prepared_exit: bool,
    stream: usize,
    entries: usize,
    preparations: usize,
    record: bool,
}
impl Host {
    fn new(reasons: impl IntoIterator<Item = u32>) -> Self {
        Self {
            reasons: reasons.into_iter().collect(),
            trace: vec![],
            fail: None,
            msr_exit: false,
            prepared_exit: false,
            stream: 0,
            entries: 0,
            preparations: 0,
            record: true,
        }
    }
    fn call(&mut self, name: &'static str) -> Result<(), &'static str> {
        if self.record {
            self.trace.push(name);
        }
        if self.fail == Some(name) {
            Err(name)
        } else {
            Ok(())
        }
    }
}
impl ExitHandler for Host {
    type Exit = u32;
    type Error = &'static str;
    fn prepare(&mut self) -> Result<Option<u32>, Self::Error> {
        self.call("prepare")?;
        self.preparations += 1;
        Ok(self.prepared_exit.then_some(100))
    }
    fn next_reason(&mut self) -> Result<u32, Self::Error> {
        self.call("enter")?;
        self.entries += 1;
        if self.stream > 0 {
            self.stream -= 1;
            Ok(INTERNAL[self.stream % INTERNAL.len()])
        } else {
            Ok(self.reasons.pop_front().expect("unexpected extra VM entry"))
        }
    }
    fn halt(&mut self) -> Result<u32, Self::Error> {
        self.call("halt")?;
        Ok(12)
    }
    fn port_io(&mut self) -> Result<u32, Self::Error> {
        self.call("io")?;
        Ok(30)
    }
    fn mmio(&mut self) -> Result<u32, Self::Error> {
        self.call("mmio")?;
        Ok(48)
    }
    fn cpuid(&mut self) -> Result<(), Self::Error> {
        self.call("cpuid")
    }
    fn rdmsr(&mut self) -> Result<Option<u32>, Self::Error> {
        self.call("rdmsr")?;
        Ok(self.msr_exit.then_some(31))
    }
    fn wrmsr(&mut self) -> Result<Option<u32>, Self::Error> {
        self.call("wrmsr")?;
        Ok(self.msr_exit.then_some(32))
    }
    fn shutdown(&mut self) -> Result<u32, Self::Error> {
        self.call("shutdown")?;
        Ok(2)
    }
    fn exception(&mut self) -> Result<u32, Self::Error> {
        self.call("exception")?;
        Ok(0)
    }
    fn monitor_trap(&mut self) -> Result<u32, Self::Error> {
        self.call("monitor-trap")?;
        Ok(37)
    }
    fn interrupt_window(&mut self) -> Result<(), Self::Error> {
        self.call("window")
    }
    fn control_register(&mut self) -> Result<(), Self::Error> {
        self.call("control")
    }
    fn xsetbv(&mut self) -> Result<(), Self::Error> {
        self.call("xsetbv")
    }
    fn fail_entry(&mut self, reason: u32) -> Result<u32, Self::Error> {
        self.call("fail-entry")?;
        Ok(reason)
    }
    fn unknown(&mut self, reason: u32) -> Result<u32, Self::Error> {
        self.call("unknown")?;
        Ok(reason)
    }
}

#[test]
fn each_public_exit_returns_once_without_reentry() {
    for (reason, call) in [
        (12, "halt"),
        (30, "io"),
        (48, "mmio"),
        (2, "shutdown"),
        (0, "exception"),
        (37, "monitor-trap"),
        (0xffff, "unknown"),
    ] {
        let mut host = Host::new([reason]);
        assert_eq!(run(&mut host), Ok(reason));
        assert_eq!(host.trace, ["prepare", "enter", call]);
        assert_eq!((host.entries, host.preparations), (1, 1));
    }
}

#[test]
fn monitor_trap_has_a_distinct_host_debug_route() {
    let mut host = Host::new([37]);
    assert_eq!(run(&mut host), Ok(37));
    assert_eq!(host.trace, ["prepare", "enter", "monitor-trap"]);
    assert_eq!(host.entries, 1);
}

#[test]
fn every_internal_exit_resumes_after_its_own_effect() {
    let mut host = Host::new(INTERNAL.into_iter().chain([12]));
    assert_eq!(run(&mut host), Ok(12));
    assert_eq!(
        host.trace,
        [
            "prepare", "enter", "cpuid", "prepare", "enter", "rdmsr", "prepare", "enter", "wrmsr",
            "prepare", "enter", "prepare", "enter", "window", "prepare", "enter", "control",
            "prepare", "enter", "xsetbv", "prepare", "enter", "halt"
        ]
    );
    assert_eq!((host.entries, host.preparations), (8, 8));
}

#[test]
fn msr_handlers_may_return_a_public_exit_instead_of_resuming() {
    for (reason, call) in [(31, "rdmsr"), (32, "wrmsr")] {
        let mut host = Host::new([reason, 12]);
        host.msr_exit = true;
        assert_eq!(run(&mut host), Ok(reason));
        assert_eq!(host.trace, ["prepare", "enter", call]);
        assert_eq!(host.reasons.len(), 1);
    }
}

#[test]
fn prepare_can_halt_before_entering_the_host() {
    let mut host = Host::new([12]);
    host.prepared_exit = true;
    assert_eq!(run(&mut host), Ok(100));
    assert_eq!(host.trace, ["prepare"]);
    assert_eq!(host.entries, 0);
    assert_eq!(host.reasons.len(), 1);
}

#[test]
fn every_host_phase_propagates_errors_without_a_later_effect() {
    for (reason, call) in [
        (12, "halt"),
        (30, "io"),
        (48, "mmio"),
        (2, "shutdown"),
        (0, "exception"),
        (37, "monitor-trap"),
        (10, "cpuid"),
        (31, "rdmsr"),
        (32, "wrmsr"),
        (7, "window"),
        (28, "control"),
        (55, "xsetbv"),
        (0xffff, "unknown"),
        (0x8000_0002, "fail-entry"),
    ] {
        let mut host = Host::new([reason, 12]);
        host.fail = Some(call);
        assert_eq!(run(&mut host), Err(call));
        assert_eq!(host.trace.last(), Some(&call));
        assert_eq!(host.entries, 1);
        assert_eq!(host.reasons.len(), 1);
    }
    for call in ["prepare", "enter"] {
        let mut host = Host::new([12]);
        host.fail = Some(call);
        assert_eq!(run(&mut host), Err(call));
        assert_eq!(host.trace.last(), Some(&call));
        assert_eq!(host.reasons.len(), 1);
    }
}

#[test]
fn entry_failure_is_never_dispatched_as_an_ordinary_basic_reason() {
    for basic in 0..=0xffff {
        let raw = 0x8000_0000 | basic;
        let mut host = Host::new([raw]);
        assert_eq!(run(&mut host), Ok(raw));
        assert_eq!(host.trace, ["prepare", "enter", "fail-entry"]);
    }
}

#[test]
fn all_basic_reasons_and_non_failure_flags_have_defined_routes() {
    for reason in 0..=0xffff {
        for flags in [0, 1 << 28, 1 << 29, 1 << 30] {
            let internal = INTERNAL.contains(&reason);
            let mut host = Host::new([reason | flags, 12]);
            host.record = false;
            let want = if internal { 12 } else { reason };
            assert_eq!(run(&mut host), Ok(want));
            assert_eq!(host.entries, if internal { 2 } else { 1 });
        }
    }
}

#[test]
fn a_million_internal_exits_use_a_small_fixed_host_stack() {
    let thread = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| {
            let mut host = Host::new([12]);
            host.record = false;
            host.stream = 1_000_000;
            assert_eq!(run(&mut host), Ok(12));
            assert_eq!(host.entries, 1_000_001);
            assert_eq!(host.preparations, 1_000_001);
            assert!(host.trace.is_empty());
        })
        .unwrap();
    thread.join().unwrap();
}
