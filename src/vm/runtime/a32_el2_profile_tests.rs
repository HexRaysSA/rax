//! FP-related EL2 capability and stopped trap state through the standalone VMM.
use super::*;
use crate::config::Aarch32Isa;
use crate::vm::vcpu::state::Aarch32Registers;

const ID_PFR1: u32 = 0xee10_2f31;
const CPACR: u32 = 0xee11_2f50;
const HSR_READ: u32 = 0xee95_2f12;
const HSTR_WRITE: u32 = 0xee81_0f71;
const HSTR_READ: u32 = 0xee91_2f71;
const HCPTR_READ: u32 = 0xee91_2f51;
const HYP: u32 = 0x1a;
const SVC: u32 = 0x13;
const UNDEFINED: u32 = 0x1b;
const FRAME: u64 = CODE + 0x100;

fn registers(vm: &Vmm) -> Aarch32Registers {
    let CpuState::Aarch32(state) = vm.vcpus[0].get_state().unwrap() else {
        panic!("expected AArch32 state");
    };
    state.regs
}

fn set_mode(vm: &mut Vmm, mode: u32) -> Result<()> {
    let cpu = &mut vm.vcpus[0];
    let CpuState::Aarch32(mut state) = cpu.get_state()? else {
        panic!("expected AArch32 state");
    };
    state.regs.cpsr = 0xc0 | mode;
    cpu.set_state(&CpuState::Aarch32(state))
}

fn step(vm: &mut Vmm, raw: u32, thumb: bool, retired: bool) -> Aarch32Registers {
    step_at(vm, CODE, raw, thumb, retired)
}

fn step_at(vm: &mut Vmm, address: u64, raw: u32, thumb: bool, retired: bool) -> Aarch32Registers {
    let word = if thumb { raw.rotate_left(16) } else { raw };
    vm.guest_mem
        .memory()
        .write_slice(&word.to_le_bytes(), GuestAddress(address))
        .unwrap();
    let cpu = &mut vm.vcpus[0];
    let CpuState::Aarch32(mut state) = cpu.get_state().unwrap() else {
        panic!("expected AArch32 state");
    };
    state.regs.pc = address as u32;
    state.regs.cpsr = (state.regs.cpsr & !32) | (u32::from(thumb) << 5);
    state.regs.r[0] = 1 << 1;
    state.regs.r[2] = u32::MAX;
    state.regs.r[3] = HYP;
    state.regs.r[4] = FRAME as u32;
    cpu.set_state(&CpuState::Aarch32(state)).unwrap();
    let count = cpu.instruction_count();
    assert!(cpu.step_insn().unwrap().is_none());
    assert_eq!(
        cpu.instruction_count(),
        count + u64::from(retired),
        "{raw:#010x} Thumb={thumb}"
    );
    registers(vm)
}

#[test]
fn configured_armv7_a_disables_el2_fp_controls_and_hyp_admission() {
    let fixture = Fixture::new();
    let mut vm = Vmm::new_resume(fixture.config(1)).unwrap();
    for thumb in [false, true] {
        set_mode(&mut vm, SVC).unwrap();
        assert_eq!(step(&mut vm, ID_PFR1, thumb, true).r[2] & 0xf000, 0);
        for raw in [HSTR_READ, HCPTR_READ] {
            set_mode(&mut vm, SVC).unwrap();
            let state = step(&mut vm, raw, thumb, false);
            assert_eq!(state.cpsr & 0x1f, UNDEFINED);
            assert_eq!(state.pc, 4);
            assert_eq!(state.r[2], u32::MAX);
        }
        let mode_writes = if thumb {
            [0xf3af_811a, 0xf383_8100] // CPS #Hyp; MSR CPSR_c,R3
        } else {
            [0xf102_001a, 0xe121_f003]
        };
        for raw in mode_writes {
            set_mode(&mut vm, SVC).unwrap();
            assert_eq!(step(&mut vm, raw, thumb, false).cpsr & 0x1f, UNDEFINED);
        }
    }
    assert!(set_mode(&mut vm, HYP).is_err());
    assert_eq!(registers(&vm).cpsr & 0x1f, UNDEFINED);
    let mem = vm.guest_mem.memory();
    mem.write_slice(&(CODE as u32).to_le_bytes(), GuestAddress(FRAME))
        .unwrap();
    mem.write_slice(&HYP.to_le_bytes(), GuestAddress(FRAME + 4))
        .unwrap();
    set_mode(&mut vm, SVC).unwrap();
    let state = step(&mut vm, 0xf8b4_0a00, false, false); // RFEIA R4!
    assert_eq!(state.cpsr & 0x1f, UNDEFINED);
    assert_eq!(state.r[4], FRAME as u32);

    // The old default profile put a read-only EL2 bit in every private CPU
    // record. It is importable only when no live Hyp state would be hidden.
    let public = vm.vcpus[0].get_state().unwrap();
    let mut old = contexts(&vm).remove(0).unwrap();
    let (id, mut saved, end) = profile_cpu(&old);
    saved.cp15.id_pfr1 |= 1 << 12;
    old.data
        .splice(8..end, crate::codec::serialize(&(id, &saved)).unwrap());
    vm.vcpus[0]
        .restore_checkpoint_context(&public, &Default::default(), Some(&old))
        .unwrap();
    assert_eq!(
        profile_cpu(&contexts(&vm)[0].clone().unwrap())
            .1
            .cp15
            .id_pfr1
            & 0xf000,
        0
    );
    let before = contexts(&vm);
    saved.cp15.hcr = 1 << 27;
    old.data
        .splice(8..end, crate::codec::serialize(&(id, &saved)).unwrap());
    assert!(
        vm.vcpus[0]
            .restore_checkpoint_context(&public, &Default::default(), Some(&old))
            .is_err()
    );
    assert_eq!(contexts(&vm), before);
}

#[test]
fn configured_hstr_trap_survives_warm_and_source_free_cold_restore() {
    let fixture = Fixture::new();
    for isa in [Aarch32Isa::V7ALpae, Aarch32Isa::V8A32] {
        let mut config = fixture.config(1);
        config.aarch32_isa = isa;
        let mut vm = Vmm::new_resume(config).unwrap();
        set_mode(&mut vm, HYP).unwrap();
        assert_eq!(step(&mut vm, ID_PFR1, false, true).r[2] & 0xf000, 0x1000);
        for raw in [HSTR_READ, HCPTR_READ] {
            assert_eq!(step(&mut vm, raw, true, true).cpsr & 0x1f, HYP);
        }
    }
    check_hstr(&fixture, CODE);
}

fn check_hstr(fixture: &Fixture, address: u64) {
    let mut config = fixture.config(1);
    config.aarch32_isa = Aarch32Isa::V7AVirt;
    let mut vm = Vmm::new_resume(config).unwrap();
    set_mode(&mut vm, HYP).unwrap();
    assert_eq!(
        step_at(&mut vm, address, ID_PFR1, false, true).r[2] & 0xf000,
        0x1000
    );
    let idle = (address == CODE).then(|| {
        let public = vm.vcpus[0].get_state().unwrap();
        let context = contexts(&vm).remove(0).unwrap();
        assert!(context.data.starts_with(b"RAXS3C02"));
        (public, context)
    });
    step_at(&mut vm, address, HSTR_WRITE, false, true);
    assert_eq!(
        step_at(&mut vm, address, HSTR_READ, true, true).r[2],
        1 << 1
    );
    if let Some((public, idle_context)) = idle {
        let before = contexts(&vm);
        let mut malformed = before[0].clone().unwrap();
        let field = malformed.data.len() - 4;
        malformed.data[field..].copy_from_slice(&(1u32 << 4).to_le_bytes());
        let armed_state = vm.vcpus[0].get_state().unwrap();
        assert!(
            vm.vcpus[0]
                .restore_checkpoint_context(&armed_state, &Default::default(), Some(&malformed))
                .is_err()
        );
        assert_eq!(contexts(&vm), before);
        vm.vcpus[0]
            .restore_checkpoint_context(&public, &Default::default(), Some(&idle_context))
            .unwrap();
        assert_eq!(step_at(&mut vm, address, HSTR_READ, false, true).r[2], 0);
        step_at(&mut vm, address, HSTR_WRITE, false, true);
    }
    set_mode(&mut vm, SVC).unwrap();
    let bundle = vm
        .take_snapshot_bundle(vm.vcpus[0].instruction_count())
        .unwrap();
    bundle.save(&fixture.checkpoint).unwrap();
    let assert_trap = |vm: &mut Vmm, thumb: bool| {
        let trapped = step_at(vm, address, CPACR, thumb, false);
        assert_eq!(trapped.pc, 0x14);
        assert_eq!(trapped.cpsr & 0x1f, HYP);
        assert_eq!(trapped.r[2], u32::MAX);
        if address == CODE {
            let context = contexts(vm).remove(0).unwrap();
            assert!(context.data.starts_with(b"RAXS3C03"));
            assert_eq!(&context.data[context.data.len() - 4..], &2u32.to_le_bytes());
            let (_, cpu, _) = profile_cpu(&context);
            assert_eq!(cpu.cp15.elr_hyp, address as u32);
        }
        assert_eq!(
            step_at(vm, address, HSR_READ, false, true).r[2],
            0x0fe4_0441
        );
    };
    assert_trap(&mut vm, false);
    vm.restore_snapshot_bundle(&bundle).unwrap();
    assert_trap(&mut vm, true);
    drop(vm);
    std::fs::remove_file(&fixture.kernel).unwrap();
    let file = SnapshotBundle::load(&fixture.checkpoint).unwrap();
    let config = VmConfig::from_checkpoint_bundle(&file, CliConfig::default()).unwrap();
    let mut restored = Vmm::new_resume_bundle(config, &file).unwrap();
    assert_trap(&mut restored, false);
}

#[test]
fn s5l8900_hstr_trap_survives_warm_and_source_free_cold_restore() {
    const CHILD: &str = "RAX_EL2_PROFILE_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        check_hstr(&Fixture::new(), 0x1000);
        return;
    }
    let mut run = std::process::Command::new(std::env::current_exe().unwrap());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("RAX_") {
            run.env_remove(key);
        }
    }
    let output = run
        .args([
            "--exact",
            "vm::runtime::backend_context_tests::el2_profile::s5l8900_hstr_trap_survives_warm_and_source_free_cold_restore",
            "--nocapture",
        ])
        .env("RAX_MACHINE", "s5l8900")
        .env("RAX_S5L_NO_SECURITY_SEED", "1")
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}
