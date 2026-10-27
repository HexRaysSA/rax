//! Exercise the actual VMM run loop with an xAPIC INIT/SIPI guest.
#[cfg(feature = "debug")]
use super::coordinator::ExecutionTurn;
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::vcpu::Segment;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use vm_memory::GuestAddress;

static NEXT: AtomicU64 = AtomicU64::new(0);
const BSP: u64 = 0x8000;
const AP: u64 = 0x9000;
const FLAGS: u64 = 0x7000;

struct Fixture {
    kernel: PathBuf,
    vm: Vmm,
}

impl Fixture {
    fn new(count: u8) -> Self {
        Self::with_memory(count, 65536)
    }

    fn with_memory(count: u8, bytes: u64) -> Self {
        let kernel = std::env::temp_dir().join(format!(
            "rax-coordinator-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&kernel, [0; 64]).unwrap();
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Emulator),
                vcpus: Some(count),
                kernel: Some(kernel.clone()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(bytes);
        let mut vm = Vmm::new_resume(config).unwrap();
        let mut state = vm.vcpus[0].get_state().unwrap();
        let CpuState::X86_64(s) = &mut state else {
            unreachable!()
        };
        s.regs.rip = BSP;
        s.regs.rsp = 0xe000;
        s.regs.rflags = 2;
        s.sregs.cr0 = 0x11;
        s.sregs.cr3 = 0;
        s.sregs.cr4 = 0;
        s.sregs.efer = 0;
        s.sregs.cs = Segment {
            selector: 8,
            limit: u32::MAX,
            type_: 11,
            present: true,
            s: true,
            db: true,
            g: true,
            ..Default::default()
        };
        let data = Segment {
            selector: 16,
            limit: u32::MAX,
            type_: 3,
            present: true,
            s: true,
            db: true,
            g: true,
            ..Default::default()
        };
        s.sregs.ds = data.clone();
        s.sregs.es = data.clone();
        s.sregs.ss = data;
        vm.vcpus[0].set_state(&state).unwrap();
        let fixture = Self { kernel, vm };
        fixture.write(0x7200, &[23, 0, 0, 0x73, 0, 0]);
        let gdt: Vec<u8> = [0u64, 0x00cf_9a00_0000_ffff, 0x00cf_9200_0000_ffff]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        fixture.write(0x7300, &gdt);
        fixture
    }

    fn write(&self, address: u64, bytes: &[u8]) {
        self.vm
            .guest_mem
            .memory()
            .write_slice(bytes, GuestAddress(address))
            .unwrap();
    }

    fn flag(&self, index: usize) -> u32 {
        let mut value = [0; 4];
        self.vm
            .guest_mem
            .memory()
            .read_slice(&mut value, GuestAddress(FLAGS + 4 * index as u64))
            .unwrap();
        u32::from_le_bytes(value)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_file(&self.kernel).unwrap();
        }
    }
}

fn store32(code: &mut Vec<u8>, address: u32, value: u32) {
    code.extend_from_slice(&[0xc7, 0x05]);
    code.extend_from_slice(&address.to_le_bytes());
    code.extend_from_slice(&value.to_le_bytes());
}

fn bsp_program() -> Vec<u8> {
    let mut code = Vec::new();
    store32(&mut code, FLAGS as u32, 1);
    // INIT, level assert, all excluding self; then SIPI vector 9.
    store32(&mut code, (LAPIC_BASE + 0x300) as u32, 0x000c_4500);
    store32(&mut code, (LAPIC_BASE + 0x300) as u32, 0x000c_0609);
    // Bound the guest itself: a CPU0-only VMM reaches shutdown and fails the
    // memory assertions instead of hanging the host test indefinitely.
    code.extend_from_slice(&[0xb9, 0x00, 0x80, 0x00, 0x00]);
    code.extend_from_slice(&[0x49, 0x75, 0xfd]);
    code.extend_from_slice(&[0x66, 0xba, 0x04, 0x06]); // DX = ACPI control port
    code.extend_from_slice(&[0x66, 0xb8, 0x00, 0x20]); // AX = S5 power-off
    code.extend_from_slice(&[0x66, 0xef]);
    code
}

fn ap_program() -> Vec<u8> {
    // Frozen LLVM23/QEMU witness: LGDT, CR0.PE, far jump, flat data
    // segments, then read this AP's xAPIC ID and publish its RAM flag.
    vec![
        0x0f, 0x01, 0x16, 0x00, 0x72, 0x0f, 0x20, 0xc0, 0x66, 0x83, 0xc8, 0x01, 0x0f, 0x22, 0xc0,
        0x66, 0xea, 0x17, 0x90, 0x00, 0x00, 0x08, 0x00, 0x66, 0xb8, 0x10, 0x00, 0x8e, 0xd8, 0x8e,
        0xc0, 0x8e, 0xd0, 0xa1, 0x20, 0x00, 0xe0, 0xfe, 0xc1, 0xe8, 0x18, 0xba, 0x00, 0x70, 0x00,
        0x00, 0xc7, 0x04, 0x82, 0x01, 0x00, 0x00, 0x00, 0xf4, 0xeb, 0xfd,
    ]
}

fn run_startup(count: u8) {
    let mut fixture = Fixture::new(count);
    fixture.write(BSP, &bsp_program());
    fixture.write(AP, &ap_program());
    fixture.vm.run().unwrap();
    for index in 0..usize::from(count) {
        assert_eq!(fixture.flag(index), 1, "CPU {index} of {count} executed");
    }
    for index in usize::from(count)..4 {
        assert_eq!(fixture.flag(index), 0, "no phantom CPU {index}");
    }
}

#[test]
fn actual_vmm_run_executes_one_cpu() {
    run_startup(1);
}

#[test]
fn actual_vmm_run_executes_two_cpus_after_init_sipi() {
    run_startup(2);
}

#[test]
fn actual_vmm_run_executes_four_cpus_after_init_sipi() {
    run_startup(4);
}

#[test]
fn actual_saved_two_and_four_cpu_guests_resume_the_same_interleaving() {
    for count in [2, 4] {
        let mut fixture = Fixture::with_memory(count, 128 * 1024 * 1024);
        fixture.write(BSP, &bsp_program());
        let mut program = ap_program();
        // Replace the final store/halt with a counter loop. APs must execute
        // after resume; retaining an old flag alone cannot satisfy this test.
        program.truncate(46);
        program.extend_from_slice(&[0xff, 0x04, 0x82, 0xeb, 0xfb]);
        fixture.write(AP, &program);
        for _ in 0..usize::from(count) + 1 {
            fixture.vm.execute_turn().unwrap();
        }
        let before: Vec<_> = (1..usize::from(count))
            .map(|index| fixture.flag(index))
            .collect();
        assert!(before.iter().all(|value| *value > 0));
        let saved = fixture.vm.take_snapshot_bundle(53).unwrap();
        assert!(
            saved
                .execution()
                .unwrap()
                .online()
                .iter()
                .all(|online| *online)
        );
        assert_ne!(saved.execution().unwrap().cursor(), 0);
        let path = fixture.kernel.with_extension("rxc");
        saved.save(&path).unwrap();
        let saved = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
        let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
        fixture.vm.run().unwrap();
        resumed.run().unwrap();
        assert_eq!(
            fixture.vm.guest_mem.try_read_all().unwrap(),
            resumed.guest_mem.try_read_all().unwrap(),
            "complete RAM after actual run-loop resume with {count} CPUs"
        );
        assert_eq!(fixture.vm.coordinator, resumed.coordinator);
        for (index, prior) in (1..usize::from(count)).zip(before) {
            assert!(
                fixture.flag(index) > prior,
                "AP {index} continued after checkpoint"
            );
        }
        for (left, right) in fixture.vm.vcpus.iter().zip(&resumed.vcpus) {
            assert_eq!(
                bincode::serialize(&(left.get_state().unwrap(), left.get_emulator_state()))
                    .unwrap(),
                bincode::serialize(&(right.get_state().unwrap(), right.get_emulator_state()))
                    .unwrap()
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn checkpoint_keeps_an_unprocessed_init_sipi_and_fixed_ipi_fifo() {
    let mut fixture = Fixture::with_memory(2, 128 * 1024 * 1024);
    {
        let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
        bsp.write_register(0x310, 1 << 24);
        for value in [0x4500, 0x0609, 0x41, 0x42] {
            bsp.write_register(0x300, value);
        }
    }
    let saved = fixture.vm.take_snapshot_bundle(53).unwrap();
    let state = saved.execution().unwrap();
    assert_eq!(state.local_apics[0].queued.len(), 4);
    let path = fixture.kernel.with_extension("rxc");
    saved.save(&path).unwrap();
    let saved = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    assert_eq!(saved.execution().unwrap().local_apics[0].queued.len(), 4);
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
    for vm in [&mut fixture.vm, &mut resumed] {
        vm.route_interprocessor_requests().unwrap();
        assert!(vm.coordinator.online[1]);
        let state = vm.vcpus[1].get_state().unwrap();
        let CpuState::X86_64(state) = state else {
            unreachable!()
        };
        assert_eq!(state.regs.rip, 0);
        assert_eq!(state.sregs.cs.base, AP);
        let apic = vm.local_apics[1].lock().unwrap();
        assert_eq!(apic.read_register(0x220), (1 << 1) | (1 << 2));
    }
    std::fs::remove_file(path).unwrap();
}

fn delay_and_shutdown(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0xb9, 0x00, 0x80, 0x00, 0x00, 0x49, 0x75, 0xfd]);
    code.extend_from_slice(&[0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef]);
}

#[test]
fn actual_vmm_fixed_ipi_wakes_halted_aps_and_eoi_clears_each_controller() {
    for count in [1, 2, 4] {
        let mut fixture = Fixture::new(count);
        let mut bsp = bsp_program();
        bsp.truncate(bsp.len() - 10);
        store32(&mut bsp, (LAPIC_BASE + 0x300) as u32, 0x000c_0041);
        delay_and_shutdown(&mut bsp);
        fixture.write(BSP, &bsp);

        let mut ap = ap_program();
        ap.truncate(53); // Flat protected mode, AP ID read, initial flag stored.
        ap.extend_from_slice(&[
            0x89, 0xc4, 0xc1, 0xe4, 0x0a, // ESP = AP ID << 10
            0x81, 0xc4, 0x00, 0xb0, 0x00, 0x00, // distinct stack per AP
        ]);
        store32(&mut ap, (LAPIC_BASE + 0xf0) as u32, 0x1ff);
        ap.extend_from_slice(&[0xfb, 0xf4, 0xeb, 0xfd]); // STI; HLT; repeat HLT
        fixture.write(AP, &ap);
        // 32-bit interrupt gate 0x41 -> 0008:a000; all APs use this IDT.
        fixture.write(0x41 * 8, &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00]);
        let mut handler = vec![0xff, 0x04, 0x82]; // flags[AP ID]++
        store32(&mut handler, (LAPIC_BASE + 0xb0) as u32, 0); // EOI
        handler.push(0xcf); // IRETD
        fixture.write(0xa000, &handler);
        fixture.vm.run().unwrap();
        assert_eq!(fixture.flag(0), 1);
        for index in 1..usize::from(count) {
            assert_eq!(
                fixture.flag(index),
                2,
                "AP {index} woke and handled its IPI"
            );
            let apic = fixture.vm.local_apics[index].lock().unwrap();
            assert_eq!(apic.read_register(0x120), 0, "ISR cleared by guest EOI");
            assert_eq!(apic.read_register(0x220), 0, "IRR transferred exactly once");
            drop(apic);
            assert!(fixture.vm.vcpus[index].get_emulator_state().unwrap().halted);
        }
    }
}

#[test]
fn ap_startup_wait_prevents_execution_before_any_sipi() {
    let mut fixture = Fixture::new(4);
    let mut bsp = Vec::new();
    store32(&mut bsp, FLAGS as u32, 1);
    delay_and_shutdown(&mut bsp);
    fixture.write(BSP, &bsp);
    fixture.vm.run().unwrap();
    for index in 1..4 {
        assert_eq!(fixture.vm.vcpus[index].instruction_count(), 0);
        assert_eq!(fixture.flag(index), 0);
        assert!(!fixture.vm.coordinator.online[index]);
    }
}

#[test]
fn second_sipi_does_not_restart_an_online_application_cpu() {
    let mut fixture = Fixture::new(2);
    fixture.write(BSP, &bsp_program());
    fixture.write(AP, &ap_program());
    fixture.vm.execute_turn().unwrap();
    fixture.vm.execute_turn().unwrap();
    let before = bincode::serialize(&fixture.vm.vcpus[1].get_state().unwrap()).unwrap();
    {
        let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
        bsp.write_register(0x310, 1 << 24);
        bsp.write_register(0x300, 0x060a); // different vector while AP is online
    }
    fixture.vm.route_interprocessor_requests().unwrap();
    assert_eq!(
        bincode::serialize(&fixture.vm.vcpus[1].get_state().unwrap()).unwrap(),
        before
    );
}

#[test]
fn physical_flat_cluster_and_broadcast_ipis_select_the_expected_controllers() {
    // (destination format, logical IDs, ICR high, ICR low, expected recipients)
    for (format, logical, high, low, expected) in [
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            2 << 24,
            0x41,
            [false, false, true, false],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            3 << 24,
            0x0841,
            [true, true, false, false],
        ),
        (
            0x0fff_ffff,
            [0x11, 0x12, 0x21, 0x22],
            0x21 << 24,
            0x0841,
            [false, false, true, false],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            0xff << 24,
            0x41,
            [true, true, true, true],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            0,
            0x000c_0041,
            [false, true, true, true],
        ),
        (
            0xffff_ffff,
            [1, 2, 4, 8],
            0,
            0x0008_0041,
            [true, true, true, true],
        ),
    ] {
        let mut fixture = Fixture::new(4);
        for (apic, id) in fixture.vm.local_apics.iter().zip(logical) {
            let mut apic = apic.lock().unwrap();
            apic.write_register(0xe0, format);
            apic.write_register(0xd0, id << 24);
        }
        {
            let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
            bsp.write_register(0x310, high);
            bsp.write_register(0x300, low);
        }
        fixture.vm.route_interprocessor_requests().unwrap();
        for (index, wanted) in expected.into_iter().enumerate() {
            let apic = fixture.vm.local_apics[index].lock().unwrap();
            assert_eq!(
                apic.read_register(0x220) & 2 != 0,
                wanted,
                "CPU {index},ICR {high:x}:{low:x}"
            );
        }
    }
}

#[test]
fn lowest_priority_ipi_selects_one_online_enabled_target() {
    let mut fixture = Fixture::new(4);
    fixture.vm.coordinator.online.fill(true);
    for (index, priority) in [0x70, 0x20, 0x20, 0x10].into_iter().enumerate() {
        fixture.vm.local_apics[index]
            .lock()
            .unwrap()
            .write_register(0x80, priority);
    }
    fixture.vm.coordinator.online[3] = false;
    fixture.vm.local_apics[0]
        .lock()
        .unwrap()
        .write_register(0x300, 0x0008_0141);
    fixture.vm.route_interprocessor_requests().unwrap();
    for index in 0..4 {
        assert_eq!(
            fixture.vm.local_apics[index]
                .lock()
                .unwrap()
                .read_register(0x220)
                & 2
                != 0,
            index == 1
        );
    }
}

#[test]
fn illegal_fixed_ipi_vectors_set_sender_error_without_queueing_an_interrupt() {
    for vector in 0..16 {
        let mut fixture = Fixture::new(2);
        {
            let mut bsp = fixture.vm.local_apics[0].lock().unwrap();
            bsp.write_register(0x300, 0x000c_0000 | vector);
        }
        fixture.vm.route_interprocessor_requests().unwrap();
        assert_eq!(
            fixture.vm.local_apics[0]
                .lock()
                .unwrap()
                .read_register(0x280)
                & 0x20,
            0x20,
            "sender rejected vector {vector}"
        );
        for apic in &fixture.vm.local_apics {
            assert_eq!(
                apic.lock().unwrap().read_register(0x200) & 0xffff,
                0,
                "reserved vectors never enter IRR"
            );
        }
    }
}

#[cfg(feature = "debug")]
#[test]
fn gdb_single_step_reports_one_bsp_instruction_with_other_cpus_online() {
    let mut fixture = Fixture::new(4);
    fixture.write(BSP, &[0x90, 0x90, 0xf4]);
    fixture.vm.coordinator.online.fill(true);
    fixture.vm.coordinator.cursor = 2;
    fixture.vm.gdb_single_step = true;
    fixture.vm.vcpus[0].set_single_step(true);
    // GDB all-stop permits other threads to run while the selected thread
    // steps. Require the selected CPU's one-instruction stop within a round.
    let mut stopped = None;
    for _ in 0..4 {
        let turn = fixture.vm.execute_turn().unwrap();
        if matches!(
            turn,
            Some(ExecutionTurn {
                cpu_index: 0,
                exit: VcpuExit::GdbStep,
                ..
            })
        ) {
            stopped = turn;
            break;
        }
    }
    assert!(
        matches!(
            stopped,
            Some(ExecutionTurn {
                cpu_index: 0,
                exit: VcpuExit::GdbStep,
                ..
            })
        ),
        "selected BSP must report its single-instruction stop"
    );
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP + 1);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_breakpoint_stops_before_the_instruction_has_any_effect() {
    let mut fixture = Fixture::new(1);
    fixture.write(BSP, &[0xb8, 0x34, 0x12, 0x00, 0x00, 0xf4]);
    fixture.vm.vcpus[0].set_debug_breakpoint(BSP).unwrap();
    let turn = fixture.vm.execute_turn().unwrap();
    assert!(matches!(
        turn,
        Some(ExecutionTurn {
            cpu_index: 0,
            exit: VcpuExit::GdbBreakpoint { addr: BSP },
            ..
        })
    ));
    assert_eq!(fixture.vm.vcpus[0].current_pc(), BSP);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 0);
    let CpuState::X86_64(state) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    assert_eq!(state.regs.rax, 0);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_io_single_step_completes_input_and_stops_before_the_next_instruction() {
    use crate::debug::gdb::{GdbCommand, GdbResponse};
    let (client, channels) = crate::debug::gdb::create_channels();
    let worker = std::thread::spawn(move || {
        let mut fixture = Fixture::new(1);
        let mut code = vec![0xe4, 0x80]; // IN AL,80h; an unregistered port readsFF.
        store32(&mut code, FLAGS as u32, 0xdead_beef);
        delay_and_shutdown(&mut code);
        fixture.write(BSP, &code);
        fixture.vm.gdb_channels = Some(channels);
        fixture.vm.gdb_stopped = true;
        let outcome = fixture.vm.run().map_err(|error| error.to_string());
        let CpuState::X86_64(state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        (
            outcome,
            state.regs.rip,
            state.regs.rax & 0xff,
            fixture.flag(0),
            fixture.vm.vcpus[0].instruction_count(),
        )
    });
    client.cmd_tx.send(GdbCommand::Step).unwrap();
    let reply = client
        .resp_rx
        .recv_timeout(std::time::Duration::from_secs(30));
    // Always release the worker, including a failed stop expectation.
    let _ = client.cmd_tx.send(GdbCommand::Kill);
    let (outcome, pc, value, marker, retired) = worker.join().unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(matches!(reply, Ok(GdbResponse::StopReply(5))), "{reply:?}");
    assert_eq!(pc, BSP + 2);
    assert_eq!(value, 0xff, "I/O completion precedes the debug stop");
    assert_eq!(marker, 0, "the following store did not execute");
    assert_eq!(retired, 1);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_single_step_stops_after_output_or_halt_before_the_following_store() {
    use crate::debug::gdb::{GdbCommand, GdbResponse};
    for instruction in [vec![0xe6, 0x80], vec![0xf4]] {
        let length = instruction.len() as u64;
        let (client, channels) = crate::debug::gdb::create_channels();
        let worker = std::thread::spawn(move || {
            let mut fixture = Fixture::new(1);
            let mut code = instruction;
            store32(&mut code, FLAGS as u32, 0xdead_beef);
            delay_and_shutdown(&mut code);
            fixture.write(BSP, &code);
            fixture.vm.gdb_channels = Some(channels);
            fixture.vm.gdb_stopped = true;
            let outcome = fixture.vm.run().map_err(|error| error.to_string());
            (
                outcome,
                fixture.vm.vcpus[0].current_pc(),
                fixture.flag(0),
                fixture.vm.vcpus[0].instruction_count(),
            )
        });
        client.cmd_tx.send(GdbCommand::Step).unwrap();
        let reply = client
            .resp_rx
            .recv_timeout(std::time::Duration::from_secs(30));
        let _ = client.cmd_tx.send(GdbCommand::Kill);
        let (outcome, pc, marker, retired) = worker.join().unwrap();
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(matches!(reply, Ok(GdbResponse::StopReply(5))), "{reply:?}");
        assert_eq!(pc, BSP + length);
        assert_eq!(
            marker, 0,
            "the instruction following the step did not execute"
        );
        assert_eq!(retired, 1);
    }
}

#[cfg(feature = "debug")]
#[test]
fn gdb_single_step_waits_for_retirement_after_a_delivered_fault() {
    let mut fixture = Fixture::new(1);
    fixture.write(BSP, &[0x8e, 0xd8]); // MOV DS,AX: selector18h exceeds GDT.
    fixture.write(0xa000, &[0x90, 0xf4]);
    fixture.write(13 * 8, &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00]);
    let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
        unreachable!()
    };
    state.regs.rax = 0x18;
    state.sregs.gdt.base = 0x7300;
    state.sregs.gdt.limit = 23;
    state.sregs.idt.base = 0;
    state.sregs.idt.limit = 2047;
    fixture.vm.vcpus[0]
        .set_state(&CpuState::X86_64(state))
        .unwrap();
    fixture.vm.vcpus[0].set_single_step(true);
    assert!(fixture.vm.execute_turn().unwrap().is_none());
    assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa000);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 0);
    assert!(matches!(
        fixture.vm.execute_turn().unwrap(),
        Some(ExecutionTurn {
            cpu_index: 0,
            exit: VcpuExit::GdbStep,
            ..
        })
    ));
    assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa001);
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
}

#[test]
fn automatic_checkpoint_after_input_contains_the_completed_value_and_resumes_it() {
    let mut fixture = Fixture::with_memory(1, 128 * 1024 * 1024);
    let directory = fixture.kernel.with_extension("automatic");
    std::fs::create_dir(&directory).unwrap();
    fixture.vm.snapshot_config = Some(SnapshotConfig {
        interval: 0,
        at_instructions: vec![1],
        output_dir: directory.to_string_lossy().into_owned(),
        prefix: "completion".into(),
    });
    let mut code = vec![0xe4, 0x80, 0xa3]; // IN AL,80h; MOV [FLAGS],EAX
    code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    delay_and_shutdown(&mut code);
    fixture.write(BSP, &code);
    fixture.vm.run().unwrap();
    assert_eq!(fixture.flag(0), 0xff);
    let path = directory.join("completion_000000000001.rxc");
    let saved = crate::vm::snapshot::SnapshotBundle::load(&path).unwrap();
    let CpuState::X86_64(state) = &saved.base().cpu_state else {
        unreachable!()
    };
    assert_eq!(saved.base().instruction_count, 1);
    assert_eq!(state.regs.rip, BSP + 2);
    assert_eq!(
        state.regs.rax & 0xff,
        0xff,
        "snapshot follows I/O completion"
    );
    let config = VmConfig::from_checkpoint_bundle(&saved, CliConfig::default()).unwrap();
    let mut resumed = Vmm::new_resume_bundle(config, &saved).unwrap();
    resumed.run().unwrap();
    assert_eq!(
        resumed.guest_mem.try_read_all().unwrap(),
        fixture.vm.guest_mem.try_read_all().unwrap()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "debug")]
#[test]
fn gdb_boundary_halted_cpu_does_not_hit_the_following_breakpoint_until_woken() {
    let mut fixture = Fixture::new(1);
    fixture.write(BSP, &[0xf4, 0x90]);
    assert!(matches!(
        fixture.vm.execute_turn().unwrap(),
        Some(ExecutionTurn {
            cpu_index: 0,
            exit: VcpuExit::Hlt,
            ..
        })
    ));
    fixture.vm.vcpus[0].set_debug_breakpoint(BSP + 1).unwrap();
    assert!(
        matches!(
            fixture.vm.execute_turn().unwrap(),
            Some(ExecutionTurn {
                cpu_index: 0,
                exit: VcpuExit::Hlt,
                ..
            })
        ),
        "halted CPUs do not attempt the instruction at their next RIP"
    );
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
    fixture.vm.vcpus[0].wake();
    assert!(
        matches!(fixture.vm.execute_turn().unwrap(), Some(ExecutionTurn {
        cpu_index: 0,
        exit: VcpuExit::GdbBreakpoint { addr },
        ..
    }) if addr == BSP + 1)
    );
    assert_eq!(fixture.vm.vcpus[0].instruction_count(), 1);
}

#[cfg(feature = "debug")]
#[test]
fn gdb_boundary_stopped_cpu_retains_registers_stack_and_pending_interrupt() {
    use crate::debug::gdb::{GdbCommand, GdbResponse};
    let (client, channels) = crate::debug::gdb::create_channels();
    let worker = std::thread::spawn(move || {
        let mut fixture = Fixture::new(1);
        fixture.write(BSP, &[0x90, 0xf4]);
        fixture.write(0xa000, &[0x90, 0xf4]);
        fixture.write(0x41 * 8, &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00]);
        let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rflags = 0x202;
        state.sregs.gdt.base = 0x7300;
        state.sregs.gdt.limit = 23;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 2047;
        fixture.vm.vcpus[0]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
        {
            let mut apic = fixture.vm.local_apics[0].lock().unwrap();
            apic.write_register(0xf0, 0x1ff);
            apic.receive_fixed_interrupt(0x41);
        }
        fixture.vm.gdb_channels = Some(channels);
        fixture.vm.gdb_stopped = true;
        let outcome = fixture.vm.run().map_err(|error| error.to_string());
        let CpuState::X86_64(state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        let mut stack = [0; 16];
        fixture
            .vm
            .guest_mem
            .memory()
            .read_slice(&mut stack, GuestAddress(0xdff0))
            .unwrap();
        let apic = fixture.vm.local_apics[0].lock().unwrap();
        (
            outcome,
            state.regs.rip,
            state.regs.rsp,
            stack,
            apic.read_register(0x220),
            apic.read_register(0x120),
        )
    });
    client.cmd_tx.send(GdbCommand::ReadRegisters).unwrap();
    let reply = client
        .resp_rx
        .recv_timeout(std::time::Duration::from_secs(30));
    let _ = client.cmd_tx.send(GdbCommand::Kill);
    let (outcome, pc, sp, stack, irr, isr) = worker.join().unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(matches!(reply, Ok(GdbResponse::Registers(_))), "{reply:?}");
    assert_eq!(
        pc, BSP,
        "debugger inspection cannot deliver a guest interrupt"
    );
    assert_eq!(sp, 0xe000);
    assert_eq!(stack, [0; 16]);
    assert_eq!(irr & 2, 2);
    assert_eq!(isr & 2, 0);
}

#[test]
fn retirement_distinguishes_inline_faults_debug_traps_and_faulted_software_interrupts() {
    use crate::vm::vcpu::RetirementStop;
    for (name, code, vector, retired, debug_general_detect, nested_software_fault) in [
        ("segment selector GP", vec![0x8e, 0xd8], 13, 0, false, false),
        ("UD2", vec![0x0f, 0x0b], 6, 0, false, false),
        ("unknown RDMSR", vec![0x0f, 0x32], 13, 0, false, false),
        (
            "debug-register GD fault",
            vec![0x0f, 0x21, 0xc0],
            1,
            0,
            true,
            false,
        ),
        ("ICEBP trap", vec![0xf1], 1, 1, false, false),
        ("INT3 trap", vec![0xcc], 3, 1, false, false),
        ("faulted INT80 gate", vec![0xcd, 0x80], 13, 0, false, true),
    ] {
        let mut fixture = Fixture::new(1);
        fixture.write(BSP, &code);
        fixture.write(0xa000, &[0x90, 0xf4]);
        fixture.write(
            vector * 8,
            &[0x00, 0xa0, 0x08, 0x00, 0x00, 0x8e, 0x00, 0x00],
        );
        if nested_software_fault {
            fixture.write(0x80 * 8, &[0x00, 0xa0, 0x18, 0x00, 0x00, 0x8e, 0x00, 0x00]);
        }
        let CpuState::X86_64(mut state) = fixture.vm.vcpus[0].get_state().unwrap() else {
            unreachable!()
        };
        state.regs.rax = 0x18;
        state.regs.rcx = u64::from(u32::MAX);
        state.sregs.gdt.base = 0x7300;
        state.sregs.gdt.limit = 23;
        state.sregs.idt.base = 0;
        state.sregs.idt.limit = 2047;
        if debug_general_detect {
            state.sregs.dr7 |= 1 << 13;
        }
        fixture.vm.vcpus[0]
            .set_state(&CpuState::X86_64(state))
            .unwrap();
        let result = fixture.vm.vcpus[0].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, retired, "{name}: {result:?}");
        if retired == 0 {
            assert!(
                matches!(result.stop, RetirementStop::StateChange),
                "{name}: {result:?}"
            );
        } else {
            assert!(
                matches!(result.stop, RetirementStop::BudgetExhausted),
                "{name}: {result:?}"
            );
        }
        assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa000, "{name}");
        assert_eq!(fixture.vm.vcpus[0].instruction_count(), retired, "{name}");
        // The first handler instruction must retire independently, with no
        // stale event classification inherited from the interrupted attempt.
        let result = fixture.vm.vcpus[0].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 1, "{name}: handler NOP");
        assert_eq!(fixture.vm.vcpus[0].current_pc(), 0xa001, "{name}");
    }
}
