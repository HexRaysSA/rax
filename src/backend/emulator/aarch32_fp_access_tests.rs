//! Architectural Undefined entry through the actual vCPU fetch/step path.
use super::*;
use crate::isa::arm::cp15::{Cpacr, Sctlr};

fn fp_vcpu(thumb: bool) -> Aarch32Vcpu {
    let raw = 0xee30_0a20u32;
    if thumb {
        let hi = ((raw >> 16) as u16).to_le_bytes();
        let lo = (raw as u16).to_le_bytes();
        thumb_vcpu(&[hi[0], hi[1], lo[0], lo[1]]).0
    } else {
        new_vcpu(&[raw]).0
    }
}

#[test]
fn fp_permission_and_enable_faults_enter_guest_undefined_without_retirement() {
    let mut count = 0;
    for thumb in [false, true] {
        for user in [false, true] {
            for permission in [0, 1, 3] {
                for enabled in [false, true] {
                    let mut vcpu = fp_vcpu(thumb);
                    vcpu.cpu.cpsr.mode = if user { USER_MODE } else { SVC_MODE } as u8;
                    vcpu.cpu.cp15.cpacr = Cpacr::from_bits(permission << 20 | permission << 22);
                    vcpu.cpu.vfp.fpexc = if enabled { 0x4000_0700 } else { 0x700 };
                    let old = vcpu.cpu.cpsr.to_u32();
                    assert!(vcpu.step_insn().unwrap().is_none());
                    let allowed = enabled && (permission == 3 || (permission == 1 && !user));
                    if allowed {
                        assert_eq!(vcpu.current_pc(), CODE + 4);
                        assert_eq!(vcpu.instruction_count(), 1);
                    } else {
                        assert_eq!(vcpu.current_pc(), 4);
                        assert_eq!(vcpu.cpu.cpsr.mode, ProcessorMode::Undefined as u8);
                        assert_eq!(vcpu.cpu.regs[14], CODE as u32 + if thumb { 2 } else { 4 });
                        assert_eq!(vcpu.cpu.spsr_und.to_u32(), old);
                        assert_eq!(vcpu.instruction_count(), 0);
                    }
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn fp_undefined_frame_saves_old_state_and_applies_handler_te_ee_and_it_reset() {
    let mut count = 0;
    for thumb in [false, true] {
        for it in [false, true] {
            if it && !thumb {
                continue;
            }
            for user in [false, true] {
                for high in [false, true] {
                    for handler_thumb in [false, true] {
                        for handler_big in [false, true] {
                            let mut vcpu = fp_vcpu(thumb);
                            vcpu.cpu.cpsr.mode = if user { USER_MODE } else { SVC_MODE } as u8;
                            vcpu.cpu.cpsr.n = true;
                            vcpu.cpu.cpsr.z = true;
                            vcpu.cpu.cpsr.c = false;
                            vcpu.cpu.cpsr.v = true;
                            vcpu.cpu.cpsr.q = true;
                            vcpu.cpu.cpsr.e = !handler_big;
                            if it {
                                vcpu.cpu.cpsr.set_it_state(0, 8);
                            }
                            vcpu.cpu.cp15.cpacr = Cpacr::from_bits(0);
                            vcpu.cpu.cp15.sctlr = Sctlr::from_bits(
                                u32::from(high) << 13
                                    | u32::from(handler_thumb) << 30
                                    | u32::from(handler_big) << 25,
                            );
                            vcpu.cpu.regs[14] = 0x1234_5678;
                            vcpu.cpu.vfp.dregs.fill(0x7ff1_2345_89ab_cdef);
                            let regs = vcpu.cpu.regs;
                            let old = vcpu.cpu.cpsr.to_u32();
                            let dregs = vcpu.cpu.vfp.dregs;
                            let fpscr = vcpu.cpu.vfp.fpscr.bits();
                            assert!(vcpu.step_insn().unwrap().is_none());
                            assert_eq!(vcpu.current_pc(), if high { 0xffff_0004 } else { 4 });
                            assert_eq!(vcpu.cpu.cpsr.mode, ProcessorMode::Undefined as u8);
                            assert_eq!(vcpu.cpu.regs[14], CODE as u32 + if thumb { 2 } else { 4 });
                            assert_eq!(vcpu.cpu.spsr_und.to_u32(), old);
                            assert_eq!(vcpu.cpu.cpsr.it_state, 0);
                            assert_eq!(vcpu.cpu.cpsr.t, handler_thumb);
                            assert_eq!(vcpu.cpu.cpsr.e, handler_big);
                            assert!(vcpu.cpu.cpsr.i);
                            assert_eq!(vcpu.cpu.regs[..13], regs[..13]);
                            assert_eq!(
                                if user {
                                    vcpu.cpu.regs_usr[1]
                                } else {
                                    vcpu.cpu.regs_svc[1]
                                },
                                0x1234_5678
                            );
                            assert_eq!(vcpu.cpu.vfp.dregs, dregs);
                            assert_eq!(vcpu.cpu.vfp.fpscr.bits(), fpscr);
                            assert_eq!(vcpu.instruction_count(), 0);
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(count, 48);
}

#[test]
fn unsupported_decoded_instruction_retains_host_error_and_no_retirement() {
    // Reserved VSEL size0 remains unsupported by the decoder/executor API.
    let (mut vcpu, _) = new_vcpu(&[0xfe00_0800]);
    assert!(matches!(
        vcpu.step_insn(),
        Err(Error::InvalidInstruction { pc: CODE, .. })
    ));
    assert_eq!(vcpu.current_pc(), CODE);
    assert_eq!(vcpu.instruction_count(), 0);
}

#[test]
fn standalone_hstr_controls_cp15_after_detached_restore() {
    const HSTR_WRITE: u32 = 0xee81_0f71; // MCR p15, 4, R0, c1, c1, 3
    const HSTR_READ: u32 = 0xee91_2f71; // MRC p15, 4, R2, c1, c1, 3
    const CP15_WFI: u32 = 0xee07_0f90;
    const HVBAR: u32 = 0x3000;
    for thumb in [false, true] {
        for hstr in [0, 1 << 7, 1 << 2, u32::MAX] {
            let words = [HSTR_WRITE, HSTR_READ, CP15_WFI];
            let fixture = || {
                if thumb {
                    let bytes = words.map(|instruction| instruction.rotate_left(16).to_le_bytes());
                    thumb_vcpu(bytes.as_flattened()).0
                } else {
                    new_vcpu(&words).0
                }
            };
            let mut source = fixture();
            source.cpu.change_mode(ProcessorMode::Hyp);
            source.cpu.cp15.hvbar = HVBAR;
            source.cpu.regs[0] = hstr;
            assert!(source.step_insn().unwrap().is_none());
            assert!(source.step_insn().unwrap().is_none());
            assert_eq!(source.cpu.regs[2], hstr & 0xbfef, "guest HSTR readback");
            source.cpu.change_mode(ProcessorMode::Supervisor);
            source.cpu.set_nonsecure(true);
            source.excl.address = Some(DATA as u32);
            source.excl.size = 4;
            let saved_status = source.cpu.cpsr.to_u32();
            let checkpoint = source.save_context().unwrap();
            drop(source);
            let mut target = fixture();
            target.restore_context(&checkpoint).unwrap();
            let exit = target.step_insn().unwrap();
            if hstr & (1 << 7) != 0 {
                assert!(exit.is_none());
                assert_eq!(target.current_pc(), u64::from(HVBAR + 0x14));
                assert_eq!(target.cpu.cpsr.mode, ProcessorMode::Hyp as u8);
                assert_eq!(target.cpu.cp15.hsr, 0x0fe8_1c00);
                assert_eq!(target.cpu.cp15.elr_hyp, CODE as u32 + 8);
                assert_eq!(target.cpu.spsr_hyp.to_u32(), saved_status);
                assert_eq!(target.instruction_count(), 2);
                assert_eq!(target.excl.address, None);
                assert!(!target.cpu.is_halted, "trap must precede WFI");
            } else {
                assert!(matches!(exit, Some(VcpuExit::Hlt)));
                assert_eq!(target.current_pc(), CODE + 12);
                assert_eq!(target.instruction_count(), 3);
            }
        }
    }
}

#[test]
fn standalone_hstr_checkpoint_rejects_invalid_bits_and_imports_idle_v2() {
    let words = [0xee81_0f71, 0xee91_2f71];
    let (mut vcpu, _) = new_vcpu(&words);
    vcpu.cpu.change_mode(ProcessorMode::Hyp);
    let idle = vcpu.save_context().unwrap();
    assert!(idle.starts_with(b"RAXA3202"));
    vcpu.cpu.regs[0] = 1 << 7;
    assert!(vcpu.step_insn().unwrap().is_none());

    let armed = vcpu.save_context().unwrap();
    assert!(armed.starts_with(b"RAXA3203"));
    assert_eq!(armed.len(), idle.len() + 4);
    assert_eq!(&armed[armed.len() - 4..], &(1u32 << 7).to_le_bytes());
    let mut corrupt = armed.clone();
    let end = corrupt.len();
    corrupt[end - 4..].copy_from_slice(&(1u32 << 14).to_le_bytes());
    assert!(vcpu.restore_context(&corrupt).is_err());
    assert_eq!(vcpu.save_context().unwrap(), armed);

    vcpu.restore_context(&idle).unwrap();
    assert_eq!(vcpu.save_context().unwrap(), idle);
    vcpu.set_current_pc(CODE + 4).unwrap();
    vcpu.cpu.regs[2] = u32::MAX;
    assert!(vcpu.step_insn().unwrap().is_none());
    assert_eq!(vcpu.cpu.regs[2], 0);
}

#[test]
fn standalone_hstr_direct_access_obeys_mode_and_feature() {
    const HSTR_READ: u32 = 0xee91_2f71;
    for (mode, el2, scr_ns, admitted, own_hyp) in [
        (ProcessorMode::Hyp, true, false, true, false),
        (ProcessorMode::Hyp, false, false, false, true),
        (ProcessorMode::Monitor, true, true, true, false),
        (ProcessorMode::Monitor, false, true, true, false),
        (ProcessorMode::Monitor, true, false, false, false),
        (ProcessorMode::Supervisor, true, true, false, false),
        (ProcessorMode::User, true, true, false, false),
    ] {
        let (mut vcpu, _) = new_vcpu(&[HSTR_READ]);
        vcpu.cpu.change_mode(mode);
        vcpu.cpu.cp15.scr = u32::from(scr_ns);
        if !el2 {
            vcpu.cpu.cp15.id_pfr1 &= !(15 << 12);
        }
        vcpu.cpu.regs[2] = u32::MAX;
        assert!(vcpu.step_insn().unwrap().is_none());
        assert_eq!(vcpu.instruction_count(), u64::from(admitted));
        assert_eq!(vcpu.cpu.regs[2], if admitted { 0 } else { u32::MAX });
        assert_eq!(
            vcpu.current_pc(),
            if admitted { CODE + 4 } else { 4 },
            "{mode:?}, EL2={el2}, SCR.NS={scr_ns}"
        );
        assert_eq!(
            vcpu.cpu.cpsr.mode,
            if admitted || own_hyp {
                mode
            } else {
                ProcessorMode::Undefined
            } as u8
        );
        if own_hyp {
            assert_eq!(vcpu.cpu.cp15.hsr, 1 << 25);
            assert_eq!(vcpu.cpu.cp15.elr_hyp, CODE as u32);
        }
    }
}
