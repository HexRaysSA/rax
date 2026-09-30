//! Closed ELF interpreter loading through all guest ABIs, without host paths.
use super::harness::{ARM_EABI5_HARD_FLOAT, CODE};
use super::loader::{Seg, image, image32};
use crate::user::image::elf::{
    EM_386, EM_AARCH64, EM_ARM, EM_RISCV, EM_X86_64, ET_DYN, ET_EXEC, PF_R, PF_X, PT_INTERP,
};
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::loader::{ImageFile, LoadError};
use crate::user::linux::sched::RunStatus;
use crate::user::linux::{ExitStatus, LinuxConfig, LinuxProcess, SpawnError};
use crate::user::supplied_fs::Files;
use std::collections::BTreeMap;
use std::sync::{Arc, atomic::AtomicBool};

const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];
const INTERPRETER: &str = "/supplied/ld.so";

fn executable(abi: LinuxAbi, dynamic: bool, interpreter: bool, status: u8) -> Vec<u8> {
    let machine = match abi {
        LinuxAbi::X86_64 => EM_X86_64,
        LinuxAbi::I386 => EM_386,
        LinuxAbi::Aarch64 => EM_AARCH64,
        LinuxAbi::Arm => EM_ARM,
        LinuxAbi::Riscv64 => EM_RISCV,
    };
    let base = if dynamic { 0 } else { CODE };
    let kind = if dynamic { ET_DYN } else { ET_EXEC };
    let segment = Seg::load(base, 0, 0x2000, 0x2000, PF_R | PF_X);
    let mut bytes = if abi.is_compat() {
        let mut segments = vec![segment];
        if interpreter {
            segments.push(Seg {
                p_type: PT_INTERP,
                vaddr: 0,
                offset: 0x200,
                filesz: INTERPRETER.len() as u64 + 1,
                memsz: INTERPRETER.len() as u64 + 1,
                flags: PF_R,
                align: 1,
            });
        }
        let mut bytes = image32(machine, kind, (base + 0x1000) as u32, &segments);
        if interpreter {
            bytes[0x200..0x200 + INTERPRETER.len()].copy_from_slice(INTERPRETER.as_bytes());
            bytes[0x200 + INTERPRETER.len()] = 0;
        }
        if abi == LinuxAbi::Arm {
            bytes[36..40].copy_from_slice(&ARM_EABI5_HARD_FLOAT.to_le_bytes());
        }
        bytes
    } else {
        image(
            machine,
            kind,
            base + 0x1000,
            &[segment],
            interpreter.then_some(INTERPRETER),
        )
    };
    let words = |code: &[u32]| {
        code.iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let status32 = u32::from(status);
    let code = match abi {
        LinuxAbi::X86_64 => vec![0xb8, 60, 0, 0, 0, 0xbf, status, 0, 0, 0, 0x0f, 0x05],
        LinuxAbi::I386 => vec![0xb8, 1, 0, 0, 0, 0xbb, status, 0, 0, 0, 0xcd, 0x80],
        LinuxAbi::Aarch64 => words(&[0xd280_0ba8, 0xd280_0000 | status32 << 5, 0xd400_0001]),
        LinuxAbi::Arm => words(&[0xe3a0_7001, 0xe3a0_0000 | status32, 0xef00_0000]),
        LinuxAbi::Riscv64 => words(&[0x05d0_0893, status32 << 20 | 0x513, 0x0000_0073]),
    };
    bytes[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    bytes
}

#[test]
fn closed_linux_supplied_interpreter_executes_and_missing_dependency_fails_all_abis() {
    for abi in ABIS {
        let main = executable(abi, false, true, 9);
        let interpreter = executable(abi, true, false, 37);
        let mut config =
            LinuxConfig::embedded("/program", vec![b"program".to_vec()], vec![], vec![], 1024)
                .unwrap();
        let missing = LinuxProcess::spawn(config.clone(), ImageFile::new(main.clone(), "/program"));
        assert!(
            matches!(
                missing,
                Err(SpawnError::Load(LoadError::Interpreter { .. }))
            ),
            "{abi:?}"
        );
        config.supplied_files = Some(
            Files::new(BTreeMap::from([(
                INTERPRETER.into(),
                Arc::from(interpreter),
            )]))
            .unwrap(),
        );
        let mut process = LinuxProcess::spawn(config, ImageFile::new(main, "/program")).unwrap();
        assert!(process.state.exe_host_path.is_none());
        assert!(process.state.mm.program.interp_base > 0);
        assert_eq!(
            process.threads[0].cpu.pc(),
            process.state.mm.program.interp_base + 0x1000
        );
        let cancelled = AtomicBool::new(false);
        let expected = RunStatus::Complete(ExitStatus::Exited(37));
        assert_eq!(process.run_slice(8, &cancelled), expected, "{abi:?}");
        assert_eq!(process.run_slice(1, &cancelled), expected, "{abi:?}");
    }
}
