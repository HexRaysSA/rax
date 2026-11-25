//! Guest trap return and cross-process restoration of the virt firmware profile.
use super::*;
use crate::config::{CliConfig, MemorySize};
use crate::vm::snapshot::SnapshotBundle;
use crate::vm::timing::ClockMode;
use crate::vm::vcpu::RiscVRegisters;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../../../tests/support/riscv_startup.rs"]
mod image;

const BASE: u64 = 0x1000;
const MTVEC: u64 = BASE + 0x40;
const STVEC: u64 = BASE + 0x60;
const ECALL: u32 = 0x0000_0073;
const EBREAK: u32 = 0x0010_0073;
const ILLEGAL: u32 = u32::MAX;
const TOPOLOGIES: [u8; 3] = [1, 2, 4];
const ROOT: &str = "RAX_TEST_VIRT_TRAP_ROOT";
const PHASE: &str = "RAX_TEST_VIRT_TRAP_PHASE";

struct Fault {
    word: u32,
    mode: u8,
    cause: u64,
    value: Option<u64>,
    delegates: bool,
}

const FAULTS: [Fault; 4] = [
    Fault {
        word: ECALL,
        mode: 1,
        cause: 9,
        value: Some(0),
        delegates: false,
    },
    Fault {
        word: ILLEGAL,
        mode: 1,
        cause: 2,
        value: Some(u32::MAX as u64),
        delegates: true,
    },
    Fault {
        word: EBREAK,
        mode: 0,
        cause: 3,
        value: None,
        delegates: true,
    },
    Fault {
        word: ECALL,
        mode: 0,
        cause: 8,
        value: Some(0),
        delegates: true,
    },
];

fn registers(cpu: &dyn VCpu) -> RiscVRegisters {
    let CpuState::RiscV(state) = cpu.get_state().unwrap() else {
        panic!("expected a RISC-V hart");
    };
    state.regs
}

fn csr(regs: &RiscVRegisters, number: u16) -> u64 {
    regs.csrs.iter().find(|&&(csr, _)| csr == number).unwrap().1
}

fn entry(index: usize) -> u64 {
    BASE + index as u64 * 16
}

fn program() -> Vec<u8> {
    let mut code = Vec::new();
    for fault in &FAULTS {
        code.extend([fault.word, 0x02b0_0393, ECALL, 0x0000_006f]); // addi t2,zero,43; ecall; j .
    }
    code.extend([
        0x3410_2373u32,
        0x0043_0313,
        0x3413_1073,
        0x02a0_0293,
        0x3020_0073, // MRET
        0,
        0,
        0,
        0x1410_2373,
        0x0043_0313,
        0x1413_1073,
        0x02a0_0293,
        0x1020_0073, // SRET
    ]);
    let bytes: Vec<_> = code.into_iter().flat_map(u32::to_le_bytes).collect();
    image::elf(&bytes, BASE, BASE)
}

fn assert_frame(cpu: &dyn VCpu, supervisor: bool, epc: u64, cause: u64, tval: u64) {
    let regs = registers(cpu);
    let (vector, mode, epc_csr, cause_csr, tval_csr) = if supervisor {
        (STVEC, 1, 0x141, 0x142, 0x143)
    } else {
        (MTVEC, 3, 0x341, 0x342, 0x343)
    };
    assert_eq!(regs.privilege, Some(mode));
    assert_eq!(regs.pc, vector);
    assert_eq!(csr(&regs, epc_csr), epc);
    assert_eq!(csr(&regs, cause_csr), cause);
    assert_eq!(csr(&regs, tval_csr), tval);
}

fn capture(root: &Path, count: u8) {
    let kernel = root.join(format!("guest-{count}.elf"));
    std::fs::write(&kernel, program()).unwrap();
    let config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::Riscv64),
            backend: Some(BackendKind::Emulator),
            kernel: Some(kernel.clone()),
            vcpus: Some(count),
            memory: Some(MemorySize(128 << 20)),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let mut vm = Vmm::new_with_clock(config, ClockMode::Retired).unwrap();
    for (index, cpu) in vm.vcpus.iter_mut().enumerate() {
        let mut regs = registers(cpu.as_ref());
        assert_eq!(csr(&regs, 0x301) & (1 << 7), 0, "hart {index} misa.H");
        let fault = &FAULTS[index];
        regs.pc = entry(index);
        regs.privilege = Some(fault.mode);
        regs.x[17] = 93;
        regs.csrs = vec![
            (0x302, (1 << 2) | (1 << 3) | (1 << 8)),
            (0x305, MTVEC | 1),
            (0x105, STVEC | 1),
        ];
        cpu.set_state(&CpuState::riscv(regs)).unwrap();
    }
    for (index, fault) in FAULTS.iter().take(usize::from(count)).enumerate() {
        let exit = vm.execute_turn().unwrap();
        assert!(
            exit.is_none(),
            "hart {index} exited at trap entry: {exit:?}"
        );
        let cpu = vm.vcpus[index].as_ref();
        assert_eq!(cpu.instruction_count(), 0);
        let pc = entry(index);
        assert_frame(
            cpu,
            fault.delegates,
            pc,
            fault.cause,
            fault.value.unwrap_or(pc),
        );
    }
    assert_eq!(vm.coordinator.retired, 0);
    let mut bundle = vm.take_snapshot_bundle(0).unwrap();
    let original = bundle.take_backend_contexts().unwrap();
    let mut harts = original.entries().to_vec();
    for hart in harts.iter().flatten() {
        assert_eq!(&hart.data[..9], b"RAXRV007\x07");
    }
    let last_hart = harts.last_mut().unwrap().as_mut().unwrap();
    last_hart.data[..9].copy_from_slice(b"RAXRV005\x03");
    let mismatch = bundle.with_backend_contexts(harts).unwrap();
    assert!(
        mismatch
            .validate_riscv_platform_graph()
            .unwrap_err()
            .to_string()
            .contains("Sv39 checkpoint requires matching private hart profiles")
    );
    mismatch
        .with_backend_contexts(original.entries().to_vec())
        .unwrap()
        .save(&kernel.with_extension("rxc"))
        .unwrap();
    std::fs::remove_file(kernel).unwrap();
}

fn restore(root: &Path, count: u8) {
    let file = root.join(format!("guest-{count}.rxc"));
    assert!(!file.with_extension("elf").exists());
    let bundle = SnapshotBundle::load(&file).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&bundle, CliConfig::default()).unwrap();
    let mut vm = Vmm::new_resume_bundle(config, &bundle).unwrap();
    for (index, fault) in FAULTS.iter().take(usize::from(count)).enumerate() {
        let cpu = vm.vcpus[index].as_ref();
        assert_eq!(
            csr(&registers(cpu), 0x301) & (1 << 7),
            0,
            "hart {index} restored misa.H"
        );
        let pc = entry(index);
        assert_frame(
            cpu,
            fault.delegates,
            pc,
            fault.cause,
            fault.value.unwrap_or(pc),
        );
        let exit = vm.execute_turn().unwrap();
        assert!(
            exit.is_none(),
            "hart {index} had a host exit after return: {exit:?}"
        );
        let cpu = vm.vcpus[index].as_ref();
        let user_call = fault.mode == 0;
        assert_frame(cpu, user_call, pc + 8, if user_call { 8 } else { 9 }, 0);
        assert_eq!(cpu.instruction_count(), 6);
        let regs = registers(cpu);
        assert_eq!((regs.x[5], regs.x[7]), (42, 43));
    }
    assert_eq!(vm.coordinator.retired, 6 * u64::from(count));
}

#[test]
fn firmware_traps_resume_every_hart_from_a_source_free_file() {
    if let Some(root) = std::env::var_os(ROOT) {
        let root = PathBuf::from(root);
        let phase = std::env::var(PHASE).unwrap();
        for count in TOPOLOGIES {
            match phase.as_str() {
                "capture" => capture(&root, count),
                "restore" => restore(&root, count),
                _ => panic!("unexpected trap test phase {phase}"),
            }
        }
        return;
    }

    let root = std::env::temp_dir().join(format!("rax-virt-traps-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let runs = ["capture", "restore"].map(|phase| {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "vm::runtime::riscv_trap_tests::firmware_traps_resume_every_hart_from_a_source_free_file",
            "--exact",
            "--nocapture",
        ])
        .env(ROOT, &root)
        .env(PHASE, phase)
        .env_remove("RAX_MACHINE");
        if phase == "capture" {
            cmd.env("RAX_MACHINE", "riscv-virt");
        }
        (phase, cmd.output().unwrap())
    });
    std::fs::remove_dir_all(root).unwrap();
    for (phase, out) in runs {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("1 passed; 0 failed"),
            "{phase}: {stdout}\n{stderr}"
        );
    }
}
