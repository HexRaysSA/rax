//! Guest observations of counters and timer interrupts across native file restoration.
use super::*;
use crate::backend::intel_hvf_deadline::mach;
use crate::isa::arm::Aarch64SysReg;
use std::time::Duration;

fn guest_mmio_boundary(
    cpu: &mut dyn crate::vm::vcpu::VCpu,
    reply: u64,
) -> crate::vm::vcpu::Aarch64CpuState {
    for _ in 0..50 {
        match cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
            Some(VcpuExit::MmioRead {
                addr: UART,
                size: 8,
            }) => {
                let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
                    unreachable!();
                };
                cpu.complete_io_in(&reply.to_le_bytes());
                cpu.io_completion_result().unwrap();
                return state;
            }
            None => (),
            exit => panic!("unexpected clock probe exit: {exit:?}"),
        }
    }
    panic!("clock probe did not reach MMIO");
}

fn read_guest_counter(cpu: &mut dyn crate::vm::vcpu::VCpu) -> (u64, u64) {
    let state = guest_mmio_boundary(cpu, 0);
    (state.regs.x[20], state.regs.x[21])
}

fn capture_shared_clock(vm: &Vmm) -> crate::backend::arm64_hvf_context::VtimerSnapshot {
    let boundary = vm.vm.checkpoint_boundary().unwrap();
    let shared = vm
        .vm
        .capture_checkpoint_vm_context(&boundary)
        .unwrap()
        .unwrap();
    GlobalContext::decode(&shared.data).unwrap().vtimer.unwrap()
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_virtual_counter_file_excludes_detached_and_first_entry_delay() {
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(2)).unwrap();
    psci::boot_native_secondaries(&mut source);
    // MRS X20,CNTVCT_EL0; MRS X21,CNTFRQ_EL0; LDR X0,[X7]; B back.
    let program = [0xd53b_e054u32, 0xd53b_e015, 0xf940_00e0, 0x17ff_fffd];
    for (index, word) in program.into_iter().enumerate() {
        source
            .guest_mem
            .memory()
            .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
            .unwrap();
    }
    publish_native_code(&source.guest_mem, CODE, program.len() * 4);
    let rates: Vec<_> = source
        .vcpus
        .iter_mut()
        .map(|cpu| {
            let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
                unreachable!();
            };
            state.regs.pc = CODE;
            state.regs.pstate = 0x3c5;
            state.regs.x[7] = UART;
            cpu.set_state(&CpuState::Aarch64(state)).unwrap();
            read_guest_counter(&mut **cpu).1
        })
        .collect();
    assert!(rates[0] > 0);
    assert_eq!(rates[0], rates[1]);

    let capture_start = mach::now();
    let saved = source.take_snapshot_bundle(0).unwrap();
    let capture_end = mach::now();
    let offsets: Vec<_> = saved
        .backend_contexts()
        .unwrap()
        .entries()
        .iter()
        .map(|record| {
            Context::decode(&record.as_ref().unwrap().data)
                .unwrap()
                .controls
                .vtimer_offset
        })
        .collect();
    saved.save(&fixture.checkpoint).unwrap();
    drop(saved);
    drop(source);
    std::thread::sleep(Duration::from_millis(250));

    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    let clock = GlobalContext::decode(&loaded.vm_context().unwrap().data)
        .unwrap()
        .vtimer
        .unwrap();
    assert!(!clock.waiting_for_entry);
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    std::thread::sleep(Duration::from_millis(250));
    let waiting = capture_shared_clock(&target);
    assert!(waiting.waiting_for_entry);
    assert_eq!(waiting.tick, clock.tick);
    assert_eq!(waiting.timebase, clock.timebase);

    let first_start = mach::now();
    let first = read_guest_counter(&mut *target.vcpus[0]);
    let first_end = mach::now();
    // A late peer still shares the first owner's resume anchor.
    std::thread::sleep(Duration::from_millis(100));
    let second_start = mach::now();
    let second = read_guest_counter(&mut *target.vcpus[1]);
    let second_end = mach::now();
    let normalized_first = first.0.wrapping_add(offsets[0]);
    let normalized_second = second.0.wrapping_add(offsets[1]);
    let peer_elapsed = normalized_second.wrapping_sub(normalized_first);
    assert!((second_start - first_end..=second_end - first_start).contains(&peer_elapsed));
    let resumed = capture_shared_clock(&target);
    assert!(!resumed.waiting_for_entry);
    assert!(resumed.tick >= normalized_second);
    for (id, ((count, rate), entry_start, entry_end)) in [
        (first, first_start, first_end),
        (second, second_start, second_end),
    ]
    .into_iter()
    .enumerate()
    {
        let earliest = capture_start
            .wrapping_sub(offsets[id])
            .wrapping_add(entry_start.saturating_sub(first_end));
        let latest = capture_end
            .wrapping_sub(offsets[id])
            .wrapping_add(entry_end - first_start);
        assert_eq!(rate, rates[id]);
        assert!(
            count.wrapping_sub(earliest) <= latest.wrapping_sub(earliest),
            "CPU {id} counter {count} outside resumed interval {earliest}..={latest} ticks"
        );
        eprintln!("CPU {id} counter {count} within {earliest}..={latest} ticks at {rate} Hz");
    }
}

const VECTOR_BASE: u64 = CODE + 0x800;
const IRQ_VECTOR: u64 = VECTOR_BASE + 0x280; // Current EL, SP_EL1, IRQ.
#[derive(Clone, Copy, Debug)]
enum Timer {
    Virtual,
    Physical,
}

impl Timer {
    fn ppi(self) -> u64 {
        match self {
            Self::Virtual => 27,
            Self::Physical => 30,
        }
    }

    fn registers(self) -> (Aarch64SysReg, Aarch64SysReg, Aarch64SysReg) {
        use Aarch64SysReg::*;
        match self {
            Self::Virtual => (CNTVCT_EL0, CNTV_CVAL_EL0, CNTV_CTL_EL0),
            Self::Physical => (CNTPCT_EL0, CNTP_CVAL_EL0, CNTP_CTL_EL0),
        }
    }

    fn saved_deadline_and_control(self, context: &Context) -> (u64, u64) {
        let sregs = &context.public.sregs;
        match self {
            Self::Virtual => (sregs.cntv_cval_el0, sregs.cntv_ctl_el0),
            Self::Physical => (sregs.cntp_cval_el0, sregs.cntp_ctl_el0),
        }
    }
}

fn install_timer_guest(vm: &Vmm, timer: Timer) {
    let (counter, compare, control) = timer.registers();
    let mrs_counter = 0xd520_0000 | counter.encoding().msr_encoding();
    let msr_compare = 0xd500_0000 | compare.encoding().msr_encoding();
    let msr_control = 0xd500_0000 | control.encoding().msr_encoding();
    // Program setup, then yield once with IRQ masked. After unmasking, the
    // probe loop records the count and yields. A nonzero reply rearms
    // the timer at that count.
    let main = [
        0xb900_014b,      // STR W11,[X10]  GICD_CTLR
        0xb900_01ac,      // STR W12,[X13]  GICR_IGROUPR0
        0xb900_01cc,      // STR W12,[X14]  GICR_ISENABLER0
        0xd518_460f,      // MSR ICC_PMR_EL1,X15
        0xd518_ccf0,      // MSR ICC_IGRPEN1_EL1,X16
        0xd53b_e018,      // MRS X24,CNTFRQ_EL0
        0x9b18_7cc6,      // MUL X6,X6,X24
        mrs_counter | 20, // MRS X20, counter
        0x8b06_0294,      // ADD X20,X20,X6
        msr_compare | 20, // MSR compare,X20
        msr_control | 16, // MSR control,X16
        0xd503_3fdf,      // ISB
        0xf940_00e0,      // LDR X0,[X7]
        0xd503_42ff,      // MSR DAIFClr,#2
        0xd503_3fdf,      // ISB
        mrs_counter | 25, // MRS X25, counter
        0xf940_00e0,      // LDR X0,[X7]
        0xb4ff_ffc0,      // CBZ X0, count sample
        msr_compare | 25, // MSR compare,X25
        msr_control | 16, // MSR control,X16
        0xd503_3fdf,      // ISB
        0x17ff_fffa,      // B count sample
    ];
    // Yield after acknowledge and before disabling the timer or ending the
    // interrupt. X23 counts actual vector entries.
    let irq = [
        0xd538_cc15,      // MRS X21,ICC_IAR1_EL1
        mrs_counter | 22, // MRS X22, counter
        0x9100_06f7,      // ADD X23,X23,#1
        0xf940_00e0,      // LDR X0,[X7]
        msr_control | 31, // MSR control,XZR
        0xd518_cc35,      // MSR ICC_EOIR1_EL1,X21
        0xd503_3fdf,      // ISB
        0xd69f_03e0,      // ERET
    ];
    for (address, words) in [(CODE, &main[..]), (IRQ_VECTOR, &irq[..])] {
        for (index, &word) in words.iter().enumerate() {
            vm.guest_mem
                .memory()
                .write_obj(u32::to_le(word), GuestAddress(address + index as u64 * 4))
                .unwrap();
        }
        publish_native_code(&vm.guest_mem, address, words.len() * 4);
    }
}

fn configure_timer_guest(vm: &mut Vmm, id: usize, delay_seconds: u64, ppi: u64) {
    use crate::machine::arm_virt::{AARCH64_GICD_BASE, AARCH64_GICR_BASE};
    let cpu = &mut vm.vcpus[id];
    let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
        unreachable!();
    };
    let redist = AARCH64_GICR_BASE + id as u64 * 0x2_0000;
    state.regs.pc = CODE;
    state.regs.pstate = 0x3c5;
    state.sregs.vbar_el1 = VECTOR_BASE;
    state.regs.x[6] = delay_seconds;
    state.regs.x[7] = UART;
    state.regs.x[10] = AARCH64_GICD_BASE;
    state.regs.x[11] = 2;
    state.regs.x[12] = 1 << ppi;
    state.regs.x[13] = redist + 0x10080;
    state.regs.x[14] = redist + 0x10100;
    state.regs.x[15] = 0xff;
    state.regs.x[16] = 1;
    cpu.set_state(&CpuState::Aarch64(state)).unwrap();
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_virtual_timer_file_keeps_armed_and_active_interrupts_on_their_cpus() {
    check_native_timer_file(Timer::Virtual);
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_physical_timer_file_keeps_armed_and_active_interrupts_on_their_cpus() {
    check_native_timer_file(Timer::Physical);
}

fn check_native_timer_file(timer: Timer) {
    const DELAY_SECONDS: u64 = 2;
    let ppi = timer.ppi();
    let fixture = Fixture::new();
    let mut source = Vmm::new_resume(fixture.config(2)).unwrap();
    psci::boot_native_secondaries(&mut source);
    install_timer_guest(&source, timer);
    configure_timer_guest(&mut source, 0, DELAY_SECONDS, ppi);
    configure_timer_guest(&mut source, 1, 0, ppi);

    let secondary = &mut *source.vcpus[1];
    assert_eq!(guest_mmio_boundary(secondary, 0).regs.x[23], 0);
    let active = guest_mmio_boundary(secondary, 0);
    assert_eq!(active.regs.pc, IRQ_VECTOR + 12);
    assert_eq!(active.regs.x[21], ppi);
    assert_eq!(active.regs.x[23], 1);

    let entry_start = mach::now();
    let armed = guest_mmio_boundary(&mut *source.vcpus[0], 0);
    let entry_end = mach::now();
    let deadline = armed.regs.x[20];
    let rate = armed.regs.x[24];
    assert!(rate > 0);
    assert_eq!(armed.regs.pc, CODE + 12 * 4);
    assert_eq!(armed.regs.x[23], 0);
    let contexts = private_states(&source);
    let offset = contexts[0].controls.vtimer_offset;
    let sample = deadline.wrapping_sub(DELAY_SECONDS * rate);
    let normalized = sample.wrapping_add(offset);
    assert!(
        (entry_start..=entry_end).contains(&normalized),
        "{timer:?} counter {sample} (offset {offset}) outside source interval {entry_start}..={entry_end} ticks"
    );
    let saved = source.take_snapshot_bundle(0).unwrap();
    assert_eq!(contexts[0].running_priority, 0xff);
    assert!(contexts[1].running_priority < 0xff);
    let (saved_deadline, saved_control) = timer.saved_deadline_and_control(&contexts[0]);
    assert_eq!(saved_deadline, deadline);
    assert_eq!(saved_control & 3, 1);
    saved.save(&fixture.checkpoint).unwrap();
    drop(saved);
    drop(source);
    std::fs::remove_file(&fixture.kernel).unwrap();
    std::thread::sleep(Duration::from_secs(DELAY_SECONDS));

    let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    let clock = GlobalContext::decode(&loaded.vm_context().unwrap().data)
        .unwrap()
        .vtimer
        .unwrap();
    assert!(deadline > clock.tick.wrapping_sub(contexts[0].controls.vtimer_offset));
    let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
    let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
    assert!(mach::now() - clock.tick > DELAY_SECONDS * rate);
    let restored = private_states(&target);
    assert_eq!(restored[0].running_priority, contexts[0].running_priority);
    assert_eq!(restored[1].running_priority, contexts[1].running_priority);

    let before = guest_mmio_boundary(&mut *target.vcpus[0], 0);
    assert_eq!(before.regs.x[23], 0, "detached time expired the BSP timer");
    assert!(before.regs.x[25] < deadline);
    let secondary = &mut *target.vcpus[1];
    let after_eoi = guest_mmio_boundary(secondary, 1);
    assert_eq!(after_eoi.regs.pc, CODE + 16 * 4);
    assert_eq!(
        after_eoi.regs.x[23], 1,
        "the active IRQ was delivered again"
    );
    let rearmed = (0..50)
        .map(|_| guest_mmio_boundary(secondary, 0))
        .find(|state| state.regs.x[23] == 2)
        .expect("the secondary timer did not deliver after rearming");
    assert_eq!(rearmed.regs.pc, IRQ_VECTOR + 12);
    assert_eq!(rearmed.regs.x[21], ppi);

    let remaining_ns =
        (u128::from(deadline - before.regs.x[25]) * 1_000_000_000).div_ceil(u128::from(rate));
    std::thread::sleep(Duration::from_nanos(u64::try_from(remaining_ns).unwrap()));
    let fired = (0..50)
        .map(|_| guest_mmio_boundary(&mut *target.vcpus[0], 0))
        .find(|state| state.regs.x[23] == 1)
        .expect("the restored BSP timer did not deliver");
    assert_eq!(fired.regs.pc, IRQ_VECTOR + 12);
    assert_eq!(fired.regs.x[21], ppi);
    assert!(fired.regs.x[22] >= deadline);
    let after_eoi = guest_mmio_boundary(&mut *target.vcpus[0], 0);
    assert_eq!(after_eoi.regs.pc, CODE + 16 * 4);
    assert_eq!(after_eoi.regs.x[23], 1);
}
