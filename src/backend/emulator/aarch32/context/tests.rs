use super::*;
use crate::isa::arm::Psr;
use crate::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const CODE: u32 = 0x100;
const DATA: u32 = 0x2000;
const VADD: u32 = 0xee31_0a02;

fn fixture(words: &[u32]) -> (Aarch32Vcpu, Arc<GuestMemoryMmap>) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    for (index, word) in words.iter().enumerate() {
        memory
            .write_slice(
                &word.to_le_bytes(),
                GuestAddress(u64::from(CODE) + 4 * index as u64),
            )
            .unwrap();
    }
    let mut cpu = Aarch32Vcpu::new(0, memory.clone());
    cpu.cpu.regs[15] = CODE;
    (cpu, memory)
}

fn state(cpu: &Aarch32Vcpu) -> Vec<u8> {
    cpu.save_context().unwrap()
}

#[test]
fn backend_context_trait_retains_controls_and_rejects_a_conflicting_projection() {
    let (mut source, memory) = fixture(&[]);
    source.cpu.cp15.cpacr = crate::isa::arm::cp15::Cpacr::from_bits(0x0050_0000);
    source.cpu.vfp.fpexc = 0;
    source.cpu.regs_irq = [0xaabb_ccdd, 0x1122_3344];
    source.excl.address = Some(DATA);
    source.excl.size = 4;
    let context = source.capture_backend_context().unwrap().unwrap();
    let public = source.get_state().unwrap();
    let legacy = crate::vm::snapshot::EmulatorState::default();
    let mut restored = Aarch32Vcpu::new(0, memory);
    restored
        .restore_checkpoint_context(&public, &legacy, Some(&context))
        .unwrap();
    assert_eq!(state(&restored), state(&source));
    let before = state(&restored);
    let mut conflict = public;
    let CpuState::Aarch32(ref mut conflict) = conflict else {
        panic!()
    };
    conflict.regs.r[0] ^= 1;
    let conflict = CpuState::Aarch32(conflict.clone());
    assert!(
        restored
            .restore_checkpoint_context(&conflict, &legacy, Some(&context))
            .is_err()
    );
    assert_eq!(state(&restored), before);
}

#[test]
fn guest_written_cpacr_and_fpexc_survive_context_restore_and_still_fault() {
    // These are the unchanged guest transfers in the two retained predecessor
    // get_state/set_state failures. Capture occurs after the control write.
    for control in [0xee01_0f50, 0xeee8_0a10] {
        let (mut live, memory) = fixture(&[control, VADD]);
        live.cpu.vfp.write_s_bits(0, 0x1234_5678);
        live.cpu.vfp.write_s_bits(2, 0x3f80_0000);
        live.cpu.vfp.write_s_bits(4, 0x3f80_0000);
        assert!(live.step_insn().unwrap().is_none());
        assert_eq!(live.instruction_count(), 1);
        let mut resumed = Aarch32Vcpu::new(0, memory);
        resumed.restore_context(&state(&live)).unwrap();
        assert!(live.step_insn().unwrap().is_none());
        assert!(resumed.step_insn().unwrap().is_none());
        assert_eq!(live.current_pc(), 4);
        assert_eq!(live.instruction_count(), 1);
        assert_eq!(live.cpu.vfp.read_s_bits(0), 0x1234_5678);
        assert_eq!(state(&live), state(&resumed), "control {control:#010x}");
    }
}

#[test]
fn all_represented_cpu_fields_and_banked_modes_roundtrip() {
    let (mut live, memory) = fixture(&[]);
    // Populate every CP15 field, including arrays, raw control bits, timer and
    // ID registers. Bounded u32 values also fit the represented u64 registers.
    fn fill(value: &mut serde_json::Value, seed: &mut u32) {
        match value {
            serde_json::Value::Object(fields) => {
                for value in fields.values_mut() {
                    fill(value, seed);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    fill(value, seed);
                }
            }
            serde_json::Value::Number(_) => {
                *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *value = (*seed).into();
            }
            _ => panic!("unexpected CP15 state field"),
        }
    }
    let mut cp15 = serde_json::to_value(&live.cpu.cp15).unwrap();
    fill(&mut cp15, &mut 0x1234_5678);
    live.cpu.cp15 = serde_json::from_value(cp15).unwrap();
    live.cpu.cp15.ttbr0 = 0xfedc_ba98_7654_3210;
    live.cpu.cp15.cntpct = u64::MAX - 19;
    live.cpu.regs = std::array::from_fn(|i| 0x1000_0000 + i as u32);
    live.cpu.regs_usr = [0x11, 0x12];
    live.cpu.regs_usr_high = [0x18, 0x19, 0x1a, 0x1b, 0x1c];
    live.cpu.regs_fiq = [0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e];
    live.cpu.regs_irq = [0x31, 0x32];
    live.cpu.regs_svc = [0x41, 0x42];
    live.cpu.regs_mon = [0x51, 0x52];
    live.cpu.regs_abt = [0x61, 0x62];
    live.cpu.regs_und = [0x71, 0x72];
    live.cpu.sp_hyp = 0x81;
    for (index, psr) in [
        &mut live.cpu.spsr_fiq,
        &mut live.cpu.spsr_irq,
        &mut live.cpu.spsr_svc,
        &mut live.cpu.spsr_mon,
        &mut live.cpu.spsr_abt,
        &mut live.cpu.spsr_und,
        &mut live.cpu.spsr_hyp,
    ]
    .into_iter()
    .enumerate()
    {
        *psr = Psr::from_u32(0xf80f_01d0 ^ ((index as u32) << 28));
    }
    live.cpu.vfp.dregs = std::array::from_fn(|i| 0x1234_5678_abcd_0000 + i as u64);
    live.cpu.vfp.fpscr = crate::isa::arm::vfp::Fpscr::from_bits(0xf7c8_009f);
    live.cpu.vfp.fpexc = 0x700;
    live.cpu.vfp.fpsid = 0x1234_5678;
    live.cpu.vfp.mvfr0 = 0x1357_9bdf;
    live.cpu.vfp.mvfr1 = 0x2468_ace0;
    live.cpu.vfp.mvfr2 = 0x5566_7788;
    live.cpu.nonsecure = true;
    live.cpu.carry_out = true;
    live.cpu.overflow = true;
    live.cpu.branch_to = Some(0x8000);
    live.insn_count = u64::MAX - 1;
    let saved = state(&live);
    let mut resumed = Aarch32Vcpu::new(0, memory);
    resumed.restore_context(&saved).unwrap();
    assert_eq!(state(&resumed), saved);
    for mode in [
        ProcessorMode::User,
        ProcessorMode::Fiq,
        ProcessorMode::Irq,
        ProcessorMode::Supervisor,
        ProcessorMode::Monitor,
        ProcessorMode::Abort,
        ProcessorMode::Undefined,
        ProcessorMode::Hyp,
        ProcessorMode::System,
    ] {
        live.cpu.change_mode(mode);
        resumed.cpu.change_mode(mode);
        assert_eq!(state(&live), state(&resumed), "mode {mode:?}");
    }
}

#[test]
fn exclusive_load_store_continuation_keeps_the_reservation() {
    // LLVM MC encoding is retained under docs/development/a32-context/.
    let (mut live, memory) = fixture(&[0xe192_1f9f, 0xe182_3f91]);
    live.cpu.regs[2] = DATA;
    memory
        .write_obj(0x1234_5678u32.to_le(), GuestAddress(u64::from(DATA)))
        .unwrap();
    assert!(live.step_insn().unwrap().is_none());
    let saved = state(&live);
    let (mut resumed, restored_memory) = fixture(&[0xe192_1f9f, 0xe182_3f91]);
    restored_memory
        .write_obj(0x1234_5678u32.to_le(), GuestAddress(u64::from(DATA)))
        .unwrap();
    resumed.restore_context(&saved).unwrap();
    assert!(live.step_insn().unwrap().is_none());
    assert!(resumed.step_insn().unwrap().is_none());
    assert_eq!(
        live.cpu.regs[3], 0,
        "STREX must succeed after restored LDREX"
    );
    assert_eq!(state(&live), state(&resumed));
    let a: u32 = memory.read_obj(GuestAddress(u64::from(DATA))).unwrap();
    let b: u32 = restored_memory
        .read_obj(GuestAddress(u64::from(DATA)))
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn halted_context_keeps_pc_and_count_until_explicit_wake() {
    let (mut live, memory) = fixture(&[0xe320_f003, 0xe320_f000]);
    assert!(matches!(live.step_insn().unwrap(), Some(VcpuExit::Hlt)));
    let mut resumed = Aarch32Vcpu::new(0, memory);
    resumed.restore_context(&state(&live)).unwrap();
    assert!(matches!(resumed.step_insn().unwrap(), Some(VcpuExit::Hlt)));
    assert_eq!(resumed.current_pc(), u64::from(CODE + 4));
    assert_eq!(resumed.instruction_count(), 1);
    live.wake();
    resumed.wake();
    assert!(live.step_insn().unwrap().is_none());
    assert!(resumed.step_insn().unwrap().is_none());
    assert_eq!(state(&live), state(&resumed));
}

#[test]
fn malformed_context_never_partially_changes_the_target() {
    let (live, _) = fixture(&[]);
    let saved = state(&live);
    let (mut target, _) = fixture(&[]);
    target.cpu.regs[0] = 0xdead_beef;
    let before = state(&target);
    for end in 0..saved.len() {
        assert!(
            target.restore_context(&saved[..end]).is_err(),
            "prefix {end}"
        );
        assert_eq!(state(&target), before);
    }
    for mutation in 0..5 {
        let mut context: Context = crate::codec::deserialize_strict(&saved[8..]).unwrap();
        match mutation {
            0 => context.id = 1,
            1 => context.cpu.cpsr.mode = 0,
            2 => context.cpu.spsr_irq.ge = 16,
            3 => context.cpu.instruction_size = 3,
            4 => {
                context.exclusive_address = Some(DATA);
                context.exclusive_size = 3;
            }
            _ => unreachable!(),
        }
        let mut raw = TAG.to_vec();
        raw.extend(crate::codec::serialize(&context).unwrap());
        assert!(target.restore_context(&raw).is_err(), "mutation {mutation}");
        assert_eq!(state(&target), before);
    }
    let mut trailing = saved.clone();
    trailing.push(0);
    assert!(target.restore_context(&trailing).is_err());
    assert!(target.restore_context(&vec![0; MAX_PAYLOAD + 9]).is_err());
    let unknown = !crate::isa::arm::common::features::ArmFeatures::all().bits();
    assert_ne!(unknown, 0);
    let mut unknown_features = saved.clone();
    // Tag, ID, then the first Armv7Cpu field: the u64 feature mask.
    unknown_features[12..20].copy_from_slice(&unknown.to_le_bytes());
    assert!(target.restore_context(&unknown_features).is_err());
    assert_eq!(state(&target), before);
}

#[test]
fn restored_mmu_controls_replace_the_targets_cached_flat_view() {
    let (mut live, memory) = fixture(&[0xe320_f000]);
    let virtual_code = 0x0010_0000 + CODE;
    // Short-descriptor section mapping VA 0x00100000 -> PA 0, domain0,
    // privileged/user RW. The table is at PA0; its index1 entry is PA4.
    memory
        .write_obj(0x0000_0c02u32.to_le(), GuestAddress(4))
        .unwrap();
    live.cpu.cp15.ttbr0 = 0;
    live.cpu.cp15.ttbcr = 0;
    live.cpu.cp15.dacr = 3;
    live.cpu.cp15.sctlr = crate::isa::arm::cp15::Sctlr::from_bits(live.cpu.cp15.sctlr.bits() | 1);
    live.cpu.regs[15] = virtual_code;
    let saved = state(&live);
    let mut resumed = Aarch32Vcpu::new(0, memory);
    assert_eq!(
        resumed
            .translate_addr(u64::from(virtual_code), crate::vm::vcpu::MemAccess::Exec)
            .unwrap(),
        u64::from(virtual_code)
    );
    resumed.restore_context(&saved).unwrap();
    assert_eq!(
        resumed
            .translate_addr(u64::from(virtual_code), crate::vm::vcpu::MemAccess::Exec)
            .unwrap(),
        u64::from(CODE)
    );
    assert!(live.step_insn().unwrap().is_none());
    assert!(resumed.step_insn().unwrap().is_none());
    assert_eq!(resumed.current_pc(), u64::from(virtual_code + 4));
    assert_eq!(state(&live), state(&resumed));
}

#[test]
fn projected_enclosing_pe_context_is_rejected_before_mutation() {
    let (mut live, _) = fixture(&[]);
    let saved = state(&live);
    let mut context: Context = crate::codec::deserialize_strict(&saved[8..]).unwrap();
    context.cpu.fp_access_context = Some(crate::isa::arm::aarch32::fp_controls::FpAccessContext {
        current_el: 0,
        secure: false,
        have_el2: true,
        have_el3: true,
        el1_aarch64: true,
        el2_aarch64: true,
        el3_aarch64: true,
        el2_enabled: true,
        vhe: false,
        cpacr: 3 << 20,
        fpexc: 1 << 30,
        nsacr: 0xc00,
        hcptr: 0,
        hcr: 0,
        cptr_el2: 0,
        cptr_el3: 0,
    });
    let mut raw = TAG.to_vec();
    raw.extend(crate::codec::serialize(&context).unwrap());
    assert!(live.restore_context(&raw).is_err());
    assert_eq!(state(&live), saved);
    live.cpu.fp_access_context = context.cpu.fp_access_context;
    assert!(live.save_context().is_err());
}

#[test]
fn thumb_it_state_and_decoder_mode_survive_the_boundary() {
    let (mut live, memory) = fixture(&[]);
    for (index, halfword) in [0xbf08u16, 0x2001, 0x2102].into_iter().enumerate() {
        memory
            .write_obj(
                halfword.to_le(),
                GuestAddress(u64::from(CODE) + 2 * index as u64),
            )
            .unwrap();
    }
    live.cpu.cpsr.t = true;
    live.cpu.cpsr.z = true;
    assert!(live.step_insn().unwrap().is_none());
    assert_ne!(live.cpu.cpsr.it_state, 0);
    let mut resumed = Aarch32Vcpu::new(0, memory);
    resumed.restore_context(&state(&live)).unwrap();
    for _ in 0..2 {
        assert!(live.step_insn().unwrap().is_none());
        assert!(resumed.step_insn().unwrap().is_none());
        assert_eq!(state(&live), state(&resumed));
    }
    let CpuState::Aarch32(final_state) = resumed.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(&final_state.regs.r[..2], &[1, 2]);
}
