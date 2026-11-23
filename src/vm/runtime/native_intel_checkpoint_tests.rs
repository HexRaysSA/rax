//! Signed Intel HVF integration tests for state captured before device dispatch.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::devices::bus::MmioDevice;
use crate::vm::snapshot::{HVF_INTEL_CONTEXT, SnapshotBundle};
use crate::vm::vcpu::{Segment, X86_64CpuState};
use std::path::PathBuf;
use std::sync::Mutex;
use vm_memory::{Bytes, GuestAddress};

const RAM: u64 = 16 << 20;
const CODE: u64 = 0x10_0000;
const MMIO: u64 = 0x4000_0103;
const LOW: u64 = 0x1122_3344_5566_7788;
const HIGH: u64 = 0xa1b2_c3d4_e5f6_0718;
const REPLY: u64 = 0x7e2d_b864_11db_feb0;

struct Paths(PathBuf);

impl Paths {
    fn new(count: u8) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rax-intel-vmm-pending-xmm-{}-{count}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let paths = Self(directory);
        std::fs::write(paths.0.join("kernel"), [0; 64]).unwrap();
        paths
    }

    fn config(&self, count: u8) -> VmConfig {
        let mut config = VmConfig::from_sources(
            CliConfig {
                arch: Some(ArchKind::X86_64),
                backend: Some(BackendKind::Hvf),
                kernel: Some(self.0.join("kernel")),
                vcpus: Some(count),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        config.memory = MemorySize(RAM);
        config
    }
}

impl Drop for Paths {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Access {
    Read(u64, usize),
    Write(u64, Vec<u8>),
}

struct Device(Arc<Mutex<Vec<Access>>>);

impl MmioDevice for Device {
    fn read(&mut self, address: u64, bytes: &mut [u8]) {
        self.0
            .lock()
            .unwrap()
            .push(Access::Read(address, bytes.len()));
        bytes.copy_from_slice(&REPLY.to_le_bytes());
    }

    fn write(&mut self, address: u64, bytes: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push(Access::Write(address, bytes.to_vec()));
    }
}

fn attach(vm: &mut Vmm, accesses: &Arc<Mutex<Vec<Access>>>) {
    vm.mmio_bus
        .register(
            MmioRange { base: MMIO, len: 8 },
            Box::new(Device(accesses.clone())),
        )
        .unwrap();
}

fn install_program(vm: &mut Vmm, ap: usize, read: bool) {
    let memory = vm.guest_mem.memory();
    for (address, word) in [
        (0x1000, 0x2003u64),             // PML4 to PDPT.
        (0x2000, 0x3003),                // PD for RAM.
        (0x2008, 0x4003),                // PD for the device.
        (0x3000, 0x0083),                // Identity-map the first 2 MiB.
        (0x4000, 0x4000_009b),           // Identity-map the MMIO region uncached.
        (0x9008, 0x00af_9b00_0000_ffff), // 64-bit code descriptor.
        (0x9010, 0x00cf_9300_0000_ffff), // Data descriptor.
        (0x9018, 0x0000_8b00_8000_0067), // Busy 64-bit TSS descriptor.
        (0x8004, 0x1f_0000),             // RSP0.
    ] {
        memory
            .write_slice(&word.to_le_bytes(), GuestAddress(address))
            .unwrap();
    }
    memory
        .write_slice(&0x68u16.to_le_bytes(), GuestAddress(0x8066))
        .unwrap();

    // The first instruction is MOVLPD (load) or MOVHPD (store) at [RDI+3].
    // MOV DX,0x604; MOV AX,0x2000; OUT DX,AX shuts down the VMM after retirement.
    let opcode = if read { 0x12 } else { 0x17 };
    let program = [
        0x66, 0x44, 0x0f, opcode, 0x7f, 3, 0x66, 0xba, 4, 6, 0x66, 0xb8, 0, 0x20, 0x66, 0xef, 0xf4,
    ];
    memory.write_slice(&program, GuestAddress(CODE)).unwrap();
    memory
        .write_slice(&[0xf4, 0xeb, 0xfd], GuestAddress(CODE + 0x100))
        .unwrap();

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
    let mut state = X86_64CpuState::default();
    state.regs.rip = CODE + 0x100;
    state.regs.rsp = 0x1f_0000;
    state.regs.rflags = 2;
    state.sregs.cs = Segment {
        selector: 8,
        limit: u32::MAX,
        type_: 11,
        present: true,
        s: true,
        l: true,
        g: true,
        ..Default::default()
    };
    state.sregs.ds = data.clone();
    state.sregs.es = data.clone();
    state.sregs.ss = data.clone();
    state.sregs.fs = data.clone();
    state.sregs.gs = data;
    state.sregs.tr = Segment {
        selector: 24,
        base: 0x8000,
        limit: 0x67,
        type_: 11,
        present: true,
        ..Default::default()
    };
    state.sregs.ldt.unusable = true;
    state.sregs.gdt.base = 0x9000;
    state.sregs.gdt.limit = 47;
    state.sregs.cr0 = 0x8001_0033;
    state.sregs.cr3 = 0x1000;
    state.sregs.cr4 = 0x220;
    state.sregs.efer = 0x500;
    state.sregs.dr6 = 0xffff_0ff0;
    state.sregs.dr7 = 0x400;
    vm.vcpus[0]
        .set_state(&CpuState::X86_64(state.clone()))
        .unwrap();
    state.regs.rip = CODE;
    state.regs.rdi = MMIO - 3;
    state.regs.xmm[15] = [LOW, HIGH];
    vm.vcpus[ap].set_state(&CpuState::X86_64(state)).unwrap();
    vm.coordinator.online[ap] = true;
    vm.coordinator.cursor = ap;
}

#[test]
#[ignore = "requires Intel macOS and com.apple.security.hypervisor entitlement"]
fn pending_xmm_lane_on_secondary_survives_file_and_dispatches_once() {
    for (count, read) in [(2, true), (4, false)] {
        let ap = usize::from(count - 1);
        let paths = Paths::new(count);
        let accesses = Arc::new(Mutex::new(Vec::new()));
        let mut source = Vmm::new_resume(paths.config(count)).unwrap();
        attach(&mut source, &accesses);
        install_program(&mut source, ap, read);

        let turn = (0..32)
            .filter_map(|_| source.execute_turn().unwrap())
            .find(|turn| turn.cpu_index == ap)
            .expect("native AP did not reach its MMIO instruction");
        assert_eq!(turn.cpu_index, ap);
        if read {
            assert!(matches!(
                turn.exit,
                VcpuExit::MmioRead {
                    addr: MMIO,
                    size: 8
                }
            ));
        } else {
            assert!(
                matches!(turn.exit, VcpuExit::MmioWrite { addr: MMIO, data } if data == HIGH.to_le_bytes())
            );
        }
        assert!(source.vcpus[ap].io_completion_result().is_err());
        assert!(accesses.lock().unwrap().is_empty());

        // Replace the stopped instruction with UD2. A target that discards its
        // pending transaction cannot reproduce the transfer by re-executing it.
        source
            .guest_mem
            .memory()
            .write_slice(&[0x0f, 0x0b], GuestAddress(CODE))
            .unwrap();
        let checkpoint = paths.0.join("pending.rxc");
        source
            .take_snapshot_bundle(0)
            .unwrap()
            .save(&checkpoint)
            .unwrap();
        if let Some(out) = std::env::var_os("RAX_NATIVE_CHECKPOINT_EVIDENCE") {
            let out = PathBuf::from(out);
            std::fs::create_dir_all(&out).unwrap();
            std::fs::copy(
                &checkpoint,
                out.join(format!("pending-xmm-ap{ap}-{count}cpus.rxc")),
            )
            .unwrap();
        }
        drop(source);
        std::fs::remove_file(paths.0.join("kernel")).unwrap();
        let loaded = SnapshotBundle::load(&checkpoint).unwrap();
        assert_eq!(loaded.cpus().unwrap().entries()[ap].state.pc(), CODE);
        let private = loaded.backend_contexts().unwrap().entries();
        assert_eq!(private.len(), usize::from(count));
        assert!(
            private
                .iter()
                .all(|cpu| cpu.as_ref().unwrap().kind == HVF_INTEL_CONTEXT)
        );
        assert!(loaded.execution().unwrap().online()[ap]);

        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
        attach(&mut target, &accesses);
        // The public live-state accessor is fenced while I/O is pending.
        // Inspect the stopped CPU through the checkpoint interface.
        {
            let boundary = target.vm.checkpoint_boundary().unwrap();
            let (saved, private) = target.vcpus[ap]
                .capture_checkpoint_record(&boundary, None)
                .unwrap();
            assert_eq!(saved.state.pc(), CODE);
            assert_eq!(private.unwrap().kind, HVF_INTEL_CONTEXT);
        }
        assert!(target.vcpus[ap].io_completion_result().is_err());
        assert!(accesses.lock().unwrap().is_empty());
        target.run().unwrap();

        let expected = if read {
            Access::Read(MMIO, 8)
        } else {
            Access::Write(MMIO, HIGH.to_le_bytes().to_vec())
        };
        assert_eq!(*accesses.lock().unwrap(), [expected]);
        let CpuState::X86_64(after) = target.vcpus[ap].get_state().unwrap() else {
            panic!("expected x86 vCPU")
        };
        assert_eq!(after.regs.rip, CODE + 16);
        assert_eq!(after.regs.xmm[15], [if read { REPLY } else { LOW }, HIGH]);
        target.vcpus[ap].io_completion_result().unwrap();
        assert!(target.vcpus[ap].complete_io_out().is_err());

        println!("native pending XMM passed count={count} ap={ap} read={read}");
    }
}
