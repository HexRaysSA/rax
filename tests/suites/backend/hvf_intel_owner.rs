//! Public Intel backend with SDK symbols supplied by this executable.
//! No Hypervisor VM or guest instruction executes. Intel binaries can run
//! through Rosetta on Apple Silicon; the SDK ownership contract is simulated.
#![cfg(all(target_os = "macos", target_arch = "x86_64", feature = "hvf"))]

use rax::backend::Backend;
use rax::backend::hvf::{HvfBackend, HvfVm};
use rax::vm::memory::GuestMemoryWrapper;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};

static SERIAL: Mutex<()> = Mutex::new(());
static SDK: Mutex<Sdk> = Mutex::new(Sdk::new());

struct Cpu {
    owner: ThreadId,
    registers: BTreeMap<u32, u64>,
    vmcs: BTreeMap<u32, u64>,
}

struct Sdk {
    live: bool,
    next_id: u32,
    cpus: BTreeMap<u32, Cpu>,
    trace: Vec<String>,
    wrong_owner: usize,
    premature_vm_destroy: usize,
    fail_capability: bool,
    fail_cpu_destroy: bool,
    clock_history: Vec<u64>,
}

impl Sdk {
    const fn new() -> Self {
        Self {
            live: false,
            next_id: 0,
            cpus: BTreeMap::new(),
            trace: Vec::new(),
            wrong_owner: 0,
            premature_vm_destroy: 0,
            fail_capability: false,
            fail_cpu_destroy: false,
            clock_history: Vec::new(),
        }
    }
    fn cpu(&mut self, id: u32, operation: &str) -> Result<&mut Cpu, i32> {
        let current = thread::current().id();
        let Some(cpu) = self.cpus.get(&id) else {
            return Err(-1);
        };
        if cpu.owner != current {
            self.wrong_owner += 1;
            self.trace.push(format!("wrong-owner:{id}:{operation}"));
            return Err(-1);
        }
        self.trace.push(format!("{operation}:{id}"));
        self.clock_history
            .push(rax::vm::timing::instruction_count());
        self.cpus.get_mut(&id).ok_or(-1)
    }
}

fn access(id: u32, operation: &str, action: impl FnOnce(&mut Cpu)) -> i32 {
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    match sdk.cpu(id, operation) {
        Ok(cpu) => {
            action(cpu);
            0
        }
        Err(error) => error,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vm_create(_: u64) -> i32 {
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    if sdk.live {
        return -1;
    }
    sdk.live = true;
    sdk.trace.push("vm-create".into());
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vm_destroy() -> i32 {
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    if !sdk.cpus.is_empty() {
        sdk.premature_vm_destroy += 1;
        sdk.trace.push("vm-destroy-before-cpus".into());
        return -1;
    }
    sdk.live = false;
    sdk.trace.push("vm-destroy".into());
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hv_vcpu_create(output: *mut u32, _: u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    if !sdk.live {
        return -1;
    }
    let id = sdk.next_id;
    sdk.next_id += 1;
    sdk.cpus.insert(
        id,
        Cpu {
            owner: thread::current().id(),
            registers: BTreeMap::new(),
            vmcs: BTreeMap::new(),
        },
    );
    sdk.trace.push(format!("cpu-create:{id}"));
    // SAFETY: the product supplied one live SDK output word; no pointer escapes.
    unsafe { output.write(id) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_destroy(id: u32) -> i32 {
    let Ok(mut sdk) = SDK.lock() else { return -1 };
    if sdk.cpu(id, "cpu-destroy").is_err() {
        return -1;
    }
    if sdk.fail_cpu_destroy {
        return -1;
    }
    sdk.cpus.remove(&id);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vm_map(_: *mut c_void, _: u64, _: usize, _: u64) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vm_unmap(_: u64, _: usize) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vm_protect(_: u64, _: usize, _: u64) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vm_sync_tsc(_: u64) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_flush(id: u32) -> i32 {
    access(id, "flush", |_| {})
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_invalidate_tlb(id: u32) -> i32 {
    access(id, "invalidate", |_| {})
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hv_vcpu_interrupt(_: *mut u32, _: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hv_vmx_read_capability(field: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    if SDK.lock().map_or(true, |sdk| sdk.fail_capability) {
        return -1;
    }
    let value = if field == 10 {
        1 << 6
    } else {
        u64::from(u32::MAX) << 32
    };
    // SAFETY: checked live SDK output pointer, synchronous exclusive write.
    unsafe { output.write(value) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hv_vcpu_read_register(id: u32, register: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    access(id, "read-register", |cpu| {
        let value = cpu
            .registers
            .get(&register)
            .copied()
            .unwrap_or(if register == 17 { 2 } else { 0 });
        // SAFETY: checked SDK output word; access returns before its lifetime ends.
        unsafe { output.write(value) };
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_write_register(id: u32, register: u32, value: u64) -> i32 {
    access(id, "write-register", |cpu| {
        cpu.registers.insert(register, value);
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hv_vmx_vcpu_read_vmcs(id: u32, field: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    access(id, "read-vmcs", |cpu| {
        let value = cpu.vmcs.get(&field).copied().unwrap_or(match field {
            0x2806 => 1 << 10,
            0x4816 => 0x209b,
            0x440c => 1,
            _ => 0,
        });
        // SAFETY: checked SDK output word; the substitute retains no pointer.
        unsafe { output.write(value) };
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vmx_vcpu_write_vmcs(id: u32, field: u32, value: u64) -> i32 {
    access(id, "write-vmcs", |cpu| {
        cpu.vmcs.insert(field, value);
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_run(id: u32) -> i32 {
    access(id, "run", |cpu| {
        cpu.vmcs.insert(0x4402, 12);
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_run_until(id: u32, _: u64) -> i32 {
    hv_vcpu_run(id)
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_read_fpstate(id: u32, _: *mut c_void, _: usize) -> i32 {
    access(id, "fp-read", |_| {})
}
#[unsafe(no_mangle)]
pub extern "C" fn hv_vcpu_write_fpstate(id: u32, _: *mut c_void, _: usize) -> i32 {
    access(id, "fp-write", |_| {})
}

fn fixture() -> (Box<dyn rax::backend::Vm>, GuestMemoryWrapper) {
    *SDK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Sdk::new();
    SDK.clear_poison();
    let backend = HvfBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    let memory = GuestMemoryWrapper::new(0x4000).unwrap();
    vm.as_any()
        .downcast_ref::<HvfVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    (vm, memory)
}

#[test]
fn moving_public_vcpu_between_callers_preserves_sdk_thread_ownership() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let cpu = thread::spawn(move || {
        let state = cpu.get_state();
        assert!(state.is_ok(), "moved vCPU SDK access: {state:?}");
        cpu
    })
    .join()
    .unwrap();
    thread::spawn(move || drop(cpu)).join().unwrap();
    let (wrong_owner, empty) = {
        let sdk = SDK.lock().unwrap();
        (sdk.wrong_owner, sdk.cpus.is_empty())
    };
    assert_eq!(wrong_owner, 0);
    assert!(empty);
    drop(vm);
}

#[test]
fn dropping_vm_wrapper_retains_native_vm_until_all_cpu_owners_finish() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    drop(vm);
    let (premature, live) = {
        let sdk = SDK.lock().unwrap();
        (sdk.premature_vm_destroy, sdk.live)
    };
    assert_eq!(premature, 0);
    assert!(live);
    drop(cpu);
    let sdk = SDK.lock().unwrap();
    assert!(sdk.cpus.is_empty());
    assert!(!sdk.live);
    assert_eq!(sdk.trace.last().unwrap(), "vm-destroy");
}

#[test]
fn multiple_cpu_owners_execute_and_destroy_independently() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpus = Vec::new();
    for id in 0..4 {
        let mut cpu = vm
            .create_vcpu(id, Arc::new(memory.memory().clone()))
            .unwrap();
        assert_eq!(cpu.id(), id);
        let mut state = cpu.get_state().unwrap();
        if let rax::vm::vcpu::CpuState::X86_64(state) = &mut state {
            state.regs.rax = 0x100 + u64::from(id);
        }
        cpu.set_state(&state).unwrap();
        cpus.push(cpu);
    }
    let owners: Vec<_> = SDK
        .lock()
        .unwrap()
        .cpus
        .values()
        .map(|cpu| cpu.owner)
        .collect();
    for (index, owner) in owners.iter().enumerate() {
        assert!(!owners[..index].contains(owner));
    }
    drop(vm);
    for mut cpu in cpus {
        thread::spawn(move || {
            assert!(matches!(cpu.run().unwrap(), rax::vm::vcpu::VcpuExit::Hlt));
            let rax::vm::vcpu::CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                panic!("wrong native architecture");
            };
            assert_eq!(state.regs.rax, 0x100 + u64::from(cpu.id()));
        })
        .join()
        .unwrap();
    }
    let sdk = SDK.lock().unwrap();
    assert!(sdk.cpus.is_empty());
    assert_eq!(sdk.wrong_owner, 0);
    assert_eq!(sdk.premature_vm_destroy, 0);
    assert!(!sdk.live);
}

#[test]
fn duplicate_id_rejects_before_sdk_creation_and_released_id_can_be_reused() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(7, Arc::new(memory.memory().clone()))
        .unwrap();
    let before = SDK.lock().unwrap().next_id;
    assert!(
        vm.create_vcpu(7, Arc::new(memory.memory().clone()))
            .is_err()
    );
    let after = SDK.lock().unwrap().next_id;
    assert_eq!(before, after);
    drop(cpu);
    let cpu = vm
        .create_vcpu(7, Arc::new(memory.memory().clone()))
        .unwrap();
    assert_eq!(cpu.id(), 7);
    drop(cpu);
    drop(vm);
}

#[test]
fn failed_initialization_destroys_the_handle_on_owner_and_releases_the_slot() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    SDK.lock().unwrap().fail_capability = true;
    assert!(
        vm.create_vcpu(3, Arc::new(memory.memory().clone()))
            .is_err()
    );
    let empty = SDK.lock().unwrap().cpus.is_empty();
    assert!(empty);
    SDK.lock().unwrap().fail_capability = false;
    let cpu = vm
        .create_vcpu(3, Arc::new(memory.memory().clone()))
        .unwrap();
    drop(cpu);
    drop(vm);
    let sdk = SDK.lock().unwrap();
    assert_eq!(sdk.wrong_owner, 0);
    assert!(!sdk.live);
}

#[test]
fn failed_owner_teardown_fences_peer_execution_and_new_creation() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let mut peer = vm
        .create_vcpu(1, Arc::new(memory.memory().clone()))
        .unwrap();
    SDK.lock().unwrap().fail_cpu_destroy = true;
    drop(cpu);
    SDK.lock().unwrap().fail_cpu_destroy = false;
    let calls = SDK.lock().unwrap().trace.len();
    assert!(peer.run().is_err());
    assert!(peer.get_state().is_err());
    assert!(
        vm.create_vcpu(2, Arc::new(memory.memory().clone()))
            .is_err()
    );
    let after = SDK.lock().unwrap().trace.len();
    assert_eq!(calls, after);
    drop(peer);
    drop(vm);
}

#[test]
fn owner_requests_bind_each_callers_clock_and_restore_unbound_state() {
    use rax::vm::timing::{ClockMode, TimingContext};
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    let first = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let second = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let observe = |expected: u64| {
        SDK.lock().unwrap().clock_history.clear();
        cpu.get_state().unwrap();
        let history = SDK.lock().unwrap().clock_history.clone();
        assert!(!history.is_empty());
        assert!(
            history.iter().all(|&actual| actual == expected),
            "{history:?}"
        );
    };
    {
        let _first = first.enter();
        for _ in 0..3 {
            rax::vm::timing::tick();
        }
        observe(3);
        {
            let _second = second.enter();
            for _ in 0..7 {
                rax::vm::timing::tick();
            }
            observe(7);
        }
        observe(3);
    }
    observe(rax::vm::timing::instruction_count());
    drop(cpu);
    drop(vm);
}

#[test]
fn held_checkpoint_boundary_captures_and_restores_without_recursive_locking() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const CHILD: &str = "RAX_HVF_OWNER_BOUNDARY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let (vm, memory) = fixture();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let mut initial = cpu.get_state().unwrap();
        if let rax::vm::vcpu::CpuState::X86_64(state) = &mut initial {
            state.regs.rax = 42;
        }
        cpu.set_state(&initial).unwrap();
        let boundary = vm.checkpoint_boundary().unwrap();
        let (saved, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        let calls = SDK.lock().unwrap().trace.len();
        assert!(
            cpu.capture_checkpoint_record(&rax::backend::CheckpointBoundary::empty(), None)
                .is_err()
        );
        assert_eq!(SDK.lock().unwrap().trace.len(), calls);
        drop(boundary);
        if let rax::vm::vcpu::CpuState::X86_64(state) = &mut initial {
            state.regs.rax = 99;
        }
        cpu.set_state(&initial).unwrap();
        let boundary = vm.checkpoint_boundary().unwrap();
        cpu.restore_checkpoint_record(&boundary, &saved.state, &saved.emulator, context.as_ref())
            .unwrap();
        let (restored, _) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        let rax::vm::vcpu::CpuState::X86_64(state) = restored.state else {
            panic!("wrong architecture")
        };
        assert_eq!(state.regs.rax, 42);
        drop(boundary);
        drop(cpu);
        drop(vm);
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "held_checkpoint_boundary_captures_and_restores_without_recursive_locking",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut expired = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            // This is only the explicitly spawned test child, never a guest
            // or an unrelated compiler/runtime process.
            child.kill().unwrap();
            expired = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        !expired && output.status.success(),
        "checkpoint child: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
