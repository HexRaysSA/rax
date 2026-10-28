//! Real software adapters: PSCI, shared MMIO, per-PE ICC and IRQ conservation.
use rax::backend::{Vm, emulator::EmulatorVm};
use rax::config::ArchKind;
use rax::isa::arm::aarch64::gic::{Gic, GicConfig};
use rax::vm::vcpu::{CpuPowerRequest, CpuState, RetirementStop, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const CODE: u64 = 0x1000;
const HVC: u32 = 0xd400_0002;
const READ_PMR: u32 = 0xd538_4600;
const WRITE_PMR: u32 = 0xd518_4600;

struct Fixture {
    vm: EmulatorVm,
    mem: Arc<GuestMemoryMmap>,
    cpus: Vec<Box<dyn VCpu>>,
}

impl Fixture {
    fn new(count: u8) -> Self {
        let vm = EmulatorVm::new(
            ArchKind::Aarch64,
            Default::default(),
            Default::default(),
            None,
        );
        vm.configure_cpu_topology(count, 0x4000).unwrap();
        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
        let cpus = (0..count)
            .map(|id| vm.create_vcpu(u32::from(id), mem.clone()).unwrap())
            .collect();
        Self { vm, mem, cpus }
    }

    fn instruction(&mut self, id: usize, word: u32, x0: u64, x1: u64) -> u64 {
        self.mem
            .write_slice(&word.to_le_bytes(), GuestAddress(CODE))
            .unwrap();
        let CpuState::Aarch64(mut state) = self.cpus[id].get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.x[0] = x0;
        state.regs.x[1] = x1;
        self.cpus[id]
            .update_state(&CpuState::Aarch64(state))
            .unwrap();
        let result = self.cpus[id].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1, "id={id}, word={word:#x}: {result:?}");
        let CpuState::Aarch64(state) = self.cpus[id].get_state().unwrap() else {
            panic!()
        };
        state.regs.x[0]
    }

    fn psci(&mut self, id: usize, function: u32, args: [u64; 3]) -> i32 {
        let CpuState::Aarch64(mut state) = self.cpus[id].get_state().unwrap() else {
            panic!()
        };
        state.regs.x[2] = args[1];
        state.regs.x[3] = args[2];
        self.cpus[id]
            .update_state(&CpuState::Aarch64(state))
            .unwrap();
        self.instruction(id, HVC, u64::from(function), args[0]) as i32
    }

    fn drain(&mut self) {
        for request in self.vm.take_cpu_power_requests().unwrap() {
            match request {
                CpuPowerRequest::Start {
                    cpu_id,
                    entry,
                    context,
                    pstate,
                } => {
                    self.cpus[cpu_id as usize]
                        .start_aarch64_cpu(entry, context, pstate)
                        .unwrap();
                    self.vm.complete_cpu_start(cpu_id).unwrap();
                }
                CpuPowerRequest::Off { .. } => {}
            }
        }
    }

    fn start(&mut self, id: usize, context: u64) {
        assert_eq!(self.psci(0, 0xc400_0003, [id as u64, CODE, context]), 0);
        self.drain();
    }

    fn read(&mut self, id: usize, address: u64) -> u32 {
        self.instruction(id, 0xb940_0020, 0, address) as u32
    }

    fn write(&mut self, id: usize, address: u64, value: u32) {
        self.instruction(id, 0xb900_0020, u64::from(value), address);
    }
}

#[test]
fn startup_is_pending_until_entry_install_and_preserves_context() {
    let mut f = Fixture::new(2);
    assert_eq!(f.psci(0, 0xc400_0004, [1, 0, 0]), 1);
    assert_eq!(
        f.psci(0, 0xc400_0003, [1, 0x1080, 0x8877_6655_4433_2211]),
        0
    );
    assert_eq!(f.psci(0, 0xc400_0004, [1, 0, 0]), 2);
    assert_eq!(f.psci(0, 0xc400_0003, [1, CODE, 0]), -5);
    assert_eq!(f.cpus[1].run_retirement_budget(1).unwrap().retired, 0);
    f.drain();
    let CpuState::Aarch64(s) = f.cpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(
        (s.regs.pc, s.regs.x[0], s.regs.pstate),
        (0x1080, 0x8877_6655_4433_2211, 0x3c5)
    );
    assert_eq!(f.psci(0, 0xc400_0004, [1, 0, 0]), 0);
    assert_eq!(f.psci(0, 0xc400_0003, [1, CODE, 0]), -4);
}

#[test]
fn invalid_affinity_and_entry_do_not_publish_power_requests() {
    let mut f = Fixture::new(2);
    for target in [2, 255, 256, 1 << 24, 1 << 32, u64::MAX] {
        assert_eq!(f.psci(0, 0xc400_0003, [target, CODE, 0]), -2);
    }
    for entry in [CODE + 1, CODE + 2, 0x4000, u64::MAX - 3] {
        assert_eq!(f.psci(0, 0xc400_0003, [1, entry, 0]), -9);
    }
    assert!(f.vm.take_cpu_power_requests().unwrap().is_empty());
}

#[test]
fn smc32_parameters_are_truncated_for_an_aarch64_caller() {
    let mut f = Fixture::new(2);
    assert_eq!(
        f.psci(
            0,
            0x8400_0003,
            [(1 << 32) | 1, (1 << 32) | CODE, 0x1234_5678_89ab_cdef]
        ),
        0
    );
    f.drain();
    let CpuState::Aarch64(s) = f.cpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!((s.regs.pc, s.regs.x[0]), (CODE, 0x89ab_cdef));
}

#[test]
fn secondary_reset_preserves_shared_distributor_and_other_priority_masks() {
    let mut f = Fixture::new(4);
    f.write(0, 0x0800_0000, 3);
    f.instruction(0, WRITE_PMR, 0x80, 0);
    for id in 1..4 {
        f.start(id, id as u64);
        assert_eq!(f.read(id, 0x0800_0000) & 3, 3);
        f.instruction(id, WRITE_PMR, 0x80 + (id as u64) * 16, 0);
    }
    for id in 0..4 {
        assert_eq!(f.instruction(id, READ_PMR, 0, 0), 0x80 + id as u64 * 16);
    }
    let replacement = f.cpus[2].get_state().unwrap();
    f.cpus[2].set_state(&replacement).unwrap();
    assert_eq!(f.read(0, 0x0800_0000) & 3, 3);
    assert_eq!(f.instruction(0, READ_PMR, 0, 0), 0x80);
}

#[test]
fn each_redistributor_has_its_own_private_enable_and_affinity() {
    let mut f = Fixture::new(4);
    for id in 0..4 {
        let base = 0x080a_0000 + id as u64 * 0x2_0000;
        f.write(0, base + 0x10100, 1 << (id + 4));
        assert_eq!(f.read(0, base + 0xc), id as u32);
        assert_eq!(f.read(0, base + 8) & 16, if id == 3 { 16 } else { 0 });
    }
    for id in 0..4 {
        assert_eq!(
            f.read(0, 0x080a_0000 + id as u64 * 0x2_0000 + 0x10100),
            1 << (id + 4)
        );
    }
}

#[test]
fn cpu_off_parks_until_a_later_cpu_on_even_after_host_wake() {
    let mut f = Fixture::new(2);
    f.start(1, 11);
    assert_eq!(f.psci(1, 0x8400_0002, [0; 3]), 0x8400_0002u32 as i32);
    f.drain();
    f.cpus[1].wake();
    let result = f.cpus[1].run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 0);
    assert!(matches!(
        result.stop,
        RetirementStop::Exit(rax::vm::vcpu::VcpuExit::Hlt)
    ));
    assert_eq!(f.psci(0, 0xc400_0004, [1, 0, 0]), 1);
    f.start(1, 22);
    let CpuState::Aarch64(s) = f.cpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(s.regs.x[0], 22);
    assert_eq!(s.regs.x[1], 0);
}

#[test]
fn a_shared_active_spi_cannot_be_acknowledged_twice_before_deactivation() {
    let mut g = Gic::new(GicConfig {
        num_cpus: 2,
        ..Default::default()
    });
    g.write_dist(0, 3);
    g.set_group_enable(0, true, true);
    g.set_group_enable(1, true, true);
    g.write_dist(0x6000 + 42 * 8, 1 << 31);
    g.set_enabled(42, true);
    g.set_pending(42);
    assert_eq!(g.acknowledge(0), 42);
    assert_eq!(g.acknowledge(1), 1023);
    g.end_of_interrupt(0, 42);
    assert_eq!(g.acknowledge(1), 42);
}

#[test]
fn sgi_broadcast_excludes_the_sender_and_range_selectors_reach_high_affinities() {
    let mut g = Gic::new(GicConfig {
        num_cpus: 255,
        ..Default::default()
    });
    for id in [0, 1, 15, 16, 123, 254] {
        g.set_group_enable(id, true, true);
        g.write_redist(id, 0x10100, 1 << 7);
    }
    g.raise_sgi((7 << 24) | (1 << 40));
    assert_eq!(g.acknowledge(0), 1023);
    for id in [1, 15, 16, 123, 254] {
        assert_eq!(g.acknowledge(id), 7);
        g.end_of_interrupt(id, 7);
    }
    g.raise_sgi((7 << 24) | (15 << 44) | (1 << 14));
    assert_eq!(g.acknowledge(254), 7);
    assert_eq!(g.acknowledge(16), 1023);
}

#[test]
fn masked_wfi_wakes_on_its_own_pending_irq_without_taking_an_exception() {
    let mut f = Fixture::new(2);
    f.start(1, 0);
    f.write(0, 0x080c_0000 + 0x10100, 1 << 7);
    f.instruction(1, 0xd518_cce0, 1, 0); // MSR ICC_IGRPEN1_EL1, X0
    f.mem
        .write_slice(
            &[0x7f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5],
            GuestAddress(CODE + 8),
        )
        .unwrap();
    f.cpus[1].set_current_pc(CODE + 8).unwrap();
    assert_eq!(f.cpus[1].run_retirement_budget(1).unwrap().retired, 1);
    f.instruction(0, 0xd518_cba0, (7 << 24) | 2, 0);
    let result = f.cpus[1].run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 1);
    assert_eq!(f.cpus[1].current_pc(), CODE + 16);
}

#[test]
fn physical_timer_pending_bit_is_private_to_the_timer_owner() {
    let mut f = Fixture::new(2);
    f.start(1, 0);
    let CpuState::Aarch64(mut state) = f.cpus[1].get_state().unwrap() else {
        panic!()
    };
    state.sregs.cntp_ctl_el0 = 1;
    state.sregs.cntp_cval_el0 = 32;
    f.cpus[1].update_state(&CpuState::Aarch64(state)).unwrap();
    for _ in 0..2 {
        f.instruction(1, 0xd503_201f, 0, 0);
    }
    assert_eq!(f.read(0, 0x080a_0000 + 0x10200) & (1 << 30), 0);
    assert_ne!(f.read(0, 0x080c_0000 + 0x10200) & (1 << 30), 0);
}

#[test]
fn aarch32_cpu_on32_installs_thumb_entry_context_and_execution_controls() {
    let mut f = Fixture::new(2);
    let CpuState::Aarch64(mut state) = f.cpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CODE;
    state.regs.pstate = 0x1d3;
    state.regs.x[..4].copy_from_slice(&[0x8400_0003, 1, CODE | 1, 0x7654_3210]);
    state.sregs.execution.as_mut().unwrap().sysregs.hcr_el2 &= !(1 << 31);
    f.cpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
    f.mem
        .write_slice(&0xe140_0070u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    let result = f.cpus[0].run_retirement_budget(1).unwrap();
    let CpuState::Aarch64(after) = f.cpus[0].get_state().unwrap() else {
        panic!()
    };
    let system = &after.sregs.execution.as_ref().unwrap().sysregs;
    assert_eq!(
        result.retired,
        1,
        "{result:?} pc={:#x} pstate={:#x} ESR1={:#x} ESR2={:#x} SCR={:#x} HCR={:#x}",
        after.regs.pc,
        after.regs.pstate,
        after.sregs.esr_el1,
        system.el2.esr,
        system.scr_el3,
        system.hcr_el2
    );
    f.drain();
    let CpuState::Aarch64(state) = f.cpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!(
        (state.regs.pc, state.regs.x[0], state.regs.pstate & 0x3f),
        (CODE, 0x7654_3210, 0x33)
    );
    f.mem
        .write_slice(&0x2407u16.to_le_bytes(), GuestAddress(CODE))
        .unwrap();
    assert_eq!(f.cpus[1].run_retirement_budget(1).unwrap().retired, 1);
    let CpuState::Aarch64(state) = f.cpus[1].get_state().unwrap() else {
        panic!()
    };
    assert_eq!((state.regs.x[4], state.regs.pc), (7, CODE + 2));
}

#[test]
fn thumb_hvc_and_disabled_arm_hvc_have_distinct_retirement_boundaries() {
    for thumb in [false, true] {
        for enabled in [false, true] {
            let mut f = Fixture::new(2);
            let CpuState::Aarch64(mut state) = f.cpus[0].get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = CODE;
            state.regs.pstate = 0x1d3 | if thumb { 0x20 } else { 0 };
            state.regs.x[..4].copy_from_slice(&[0x8400_0003, 1, CODE, 99]);
            let system = &mut state.sregs.execution.as_mut().unwrap().sysregs;
            system.hcr_el2 &= !(1 << 31);
            if !enabled {
                system.scr_el3 &= !(1 << 8);
            }
            f.cpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
            let bytes = if thumb {
                [0xe0, 0xf7, 0x00, 0x80]
            } else {
                HVC_ARM.to_le_bytes()
            };
            f.mem.write_slice(&bytes, GuestAddress(CODE)).unwrap();
            let result = f.cpus[0].run_retirement_budget(1).unwrap();
            assert_eq!(
                result.retired,
                u64::from(enabled),
                "thumb={thumb} enabled={enabled}: {result:?}"
            );
            let requests = f.vm.take_cpu_power_requests().unwrap();
            assert_eq!(requests.len(), usize::from(enabled));
        }
    }
}

const HVC_ARM: u32 = 0xe140_0070;

#[test]
fn nonzero_firmware_immediates_do_not_dispatch_psci_requests() {
    let mut f = Fixture::new(2);
    f.mem
        .write_slice(&0xd400_0022u32.to_le_bytes(), GuestAddress(CODE))
        .unwrap(); // HVC #1
    let CpuState::Aarch64(mut state) = f.cpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.pc = CODE;
    state.regs.x[..4].copy_from_slice(&[0xc400_0003, 1, CODE, 99]);
    f.cpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
    let result = f.cpus[0].run_retirement_budget(1).unwrap();
    assert_eq!(result.retired, 1);
    assert!(matches!(
        result.stop,
        RetirementStop::Exit(rax::vm::vcpu::VcpuExit::Unknown(_))
    ));
    assert!(f.vm.take_cpu_power_requests().unwrap().is_empty());
}

#[test]
fn topology_cannot_change_after_creation_or_duplicate_a_bound_cpu_id() {
    let vm = EmulatorVm::new(
        ArchKind::Aarch64,
        Default::default(),
        Default::default(),
        None,
    );
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let _cpu = vm.create_vcpu(0, memory).unwrap();
    assert!(vm.configure_cpu_topology(2, 0x4000).is_err());
    let f = Fixture::new(2);
    assert!(f.vm.create_vcpu(0, f.mem.clone()).is_err());
    assert!(f.vm.create_vcpu(2, f.mem.clone()).is_err());
}

#[test]
fn redistributor_windows_reach_high_ids_without_aliasing_uart_or_large_ram() {
    let mut f = Fixture::new(255);
    for id in [0, 15, 16, 122, 123, 254] {
        let base = if id < 123 {
            0x080a_0000 + id as u64 * 0x2_0000
        } else {
            0x40_0000_0000 + (id - 123) as u64 * 0x2_0000
        };
        assert_eq!(f.read(0, base + 0xc), id as u32);
        assert_eq!(
            f.read(0, base + 8) & 16,
            if id == 122 || id == 254 { 16 } else { 0 }
        );
    }
    let vm = EmulatorVm::new(
        ArchKind::Aarch64,
        Default::default(),
        Default::default(),
        None,
    );
    vm.configure_cpu_topology(255, 0x80_0001_0001).unwrap();
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let cpu = vm.create_vcpu(0, memory.clone()).unwrap();
    let mut high = Fixture {
        vm,
        mem: memory,
        cpus: vec![cpu],
    };
    assert_eq!(high.read(0, 0x80_0002_0000 + 0xc), 123);
}

/// Read DTB structure/property tokens independently of FdtBuilder.
fn fdt_properties(blob: &[u8]) -> Vec<(String, String, Vec<u8>)> {
    fn word(blob: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes(blob[offset..offset + 4].try_into().unwrap())
    }
    fn text(blob: &[u8], offset: usize) -> (&str, usize) {
        let end = offset + blob[offset..].iter().position(|b| *b == 0).unwrap();
        (std::str::from_utf8(&blob[offset..end]).unwrap(), end + 1)
    }
    assert_eq!(word(blob, 0), 0xd00d_feed);
    let mut cursor = word(blob, 8) as usize;
    let strings = word(blob, 12) as usize;
    let mut path = Vec::new();
    let mut result = Vec::new();
    loop {
        let token = word(blob, cursor);
        cursor += 4;
        match token {
            1 => {
                let (name, end) = text(blob, cursor);
                path.push(name.to_string());
                cursor = (end + 3) & !3;
            }
            2 => {
                path.pop().unwrap();
            }
            3 => {
                let len = word(blob, cursor) as usize;
                let name = word(blob, cursor + 4) as usize;
                cursor += 8;
                result.push((
                    path.join("/"),
                    text(blob, strings + name).0.to_string(),
                    blob[cursor..cursor + len].to_vec(),
                ));
                cursor = (cursor + len + 3) & !3;
            }
            4 => {}
            9 => break,
            _ => panic!("invalid DTB token {token}"),
        }
    }
    result
}

#[test]
fn machine_dtb_enumerates_all_affinities_and_exact_redistributor_regions() {
    use rax::config::{CliConfig, MemorySize, VmConfig};
    use rax::machine::{Machine, arm_virt::Aarch64VirtMachine};
    use std::io::Write;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct OwnedKernel(std::path::PathBuf);
    impl Drop for OwnedKernel {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "rax-arm-fdt-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    let kernel = OwnedKernel(path);
    file.write_all(&0xd503_201fu32.to_le_bytes()).unwrap();
    drop(file);
    for count in [1, 2, 4, 16, 123, 124, 255] {
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::Aarch64),
                vcpus: Some(count),
                kernel: Some(kernel.0.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(4 * 1024 * 1024);
        let memory =
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x4000_0000), 4 * 1024 * 1024)])
                .unwrap();
        let boot = Aarch64VirtMachine::new()
            .load_kernel(&memory, &config)
            .unwrap();
        let address = boot.as_arm().unwrap().dtb_addr.unwrap();
        let mut header = [0; 40];
        memory
            .read_slice(&mut header, GuestAddress(address))
            .unwrap();
        let length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        let mut blob = vec![0; length];
        memory.read_slice(&mut blob, GuestAddress(address)).unwrap();
        let properties = fdt_properties(&blob);
        for id in 0..count {
            let path = format!("/cpus/cpu@{id:x}");
            let reg = properties
                .iter()
                .find(|(p, name, _)| *p == path && name == "reg")
                .unwrap();
            assert_eq!(reg.2, u32::from(id).to_be_bytes());
            let method = properties
                .iter()
                .find(|(p, name, _)| *p == path && name == "enable-method")
                .unwrap();
            assert_eq!(method.2, b"psci\0");
        }
        let reg = &properties
            .iter()
            .find(|(p, name, _)| p == "/intc@8000000" && name == "reg")
            .unwrap()
            .2;
        assert_eq!(reg.len(), if count <= 123 { 32 } else { 48 });
        assert_eq!(
            u64::from_be_bytes(reg[16..24].try_into().unwrap()),
            0x080a_0000
        );
        assert_eq!(
            u64::from_be_bytes(reg[24..32].try_into().unwrap()),
            u64::from(count.min(123)) * 0x2_0000
        );
        if count > 123 {
            assert_eq!(
                u64::from_be_bytes(reg[32..40].try_into().unwrap()),
                0x40_0000_0000
            );
            assert_eq!(
                u64::from_be_bytes(reg[40..48].try_into().unwrap()),
                u64::from(count - 123) * 0x2_0000
            );
        }
    }
}

#[test]
fn aarch32_callers_cannot_use_any_smc64_psci_function() {
    for thumb in [false, true] {
        for function in [0xc400_0003, 0xc400_0004] {
            let mut f = Fixture::new(2);
            let CpuState::Aarch64(mut state) = f.cpus[0].get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = CODE;
            state.regs.pstate = 0x1d3 | if thumb { 0x20 } else { 0 };
            state.regs.x[..4].copy_from_slice(&[function, 1, 0, 99]);
            state.sregs.execution.as_mut().unwrap().sysregs.hcr_el2 &= !(1 << 31);
            f.cpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
            let bytes = if thumb {
                [0xe0, 0xf7, 0x00, 0x80]
            } else {
                HVC_ARM.to_le_bytes()
            };
            f.mem.write_slice(&bytes, GuestAddress(CODE)).unwrap();
            assert_eq!(f.cpus[0].run_retirement_budget(1).unwrap().retired, 1);
            let CpuState::Aarch64(after) = f.cpus[0].get_state().unwrap() else {
                panic!()
            };
            assert_eq!(
                after.regs.x[0] as u32,
                u32::MAX,
                "thumb={thumb} function={function:#x}"
            );
            assert!(f.vm.take_cpu_power_requests().unwrap().is_empty());
        }
    }
}

#[test]
fn constrained_or_unprivileged_hvc_forms_take_undefined_without_retirement() {
    // A1 conditional HVC, T1 HVC in IT, and unprivileged HVC all select UNDEF.
    for (pstate, bytes) in [
        (0x1d3, 0x1140_0070u32.to_le_bytes()),
        (0x4000_01d3, 0x1140_0070u32.to_le_bytes()),
        (0x9f3, [0xe0, 0xf7, 0x00, 0x80]),
        (0x4000_09f3, [0xe0, 0xf7, 0x00, 0x80]),
        (0x1d0, HVC_ARM.to_le_bytes()),
        (0x1f0, [0xe0, 0xf7, 0x00, 0x80]),
    ] {
        let mut f = Fixture::new(2);
        let CpuState::Aarch64(mut state) = f.cpus[0].get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.pstate = pstate;
        state.regs.x[..4].copy_from_slice(&[0x8400_0003, 1, CODE, 99]);
        state.sregs.execution.as_mut().unwrap().sysregs.hcr_el2 &= !(1 << 31);
        f.cpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
        f.mem.write_slice(&bytes, GuestAddress(CODE)).unwrap();
        let result = f.cpus[0].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 0, "pstate={pstate:#x}: {result:?}");
        let CpuState::Aarch64(after) = f.cpus[0].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(after.regs.pc, 4, "pstate={pstate:#x}: {result:?}");
        assert_eq!(
            after.regs.pstate & 31,
            0x1b,
            "pstate={pstate:#x}: {result:?}"
        );
        assert!(f.vm.take_cpu_power_requests().unwrap().is_empty());
    }
}
