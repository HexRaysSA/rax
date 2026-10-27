//! AArch64 format-4 contexts, frozen legacy inputs, and key continuity.

use super::*;
use crate::context::{rax_context_restore, rax_context_save};
use rax_engine::isa::arm::aarch64::pauth::{PauthAlgorithm, PauthConfig, PauthProfile};
use rax_engine::isa::arm::common::features::ArmFeatures;
use rax_engine::vm::vcpu::{Aarch64Registers, CpuState};

fn small_arm64() -> *mut Engine {
    small_arm64_mode(RAX_MODE_64)
}

fn small_arm64_mode(mode: u32) -> *mut Engine {
    let config = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Arm64 as i32,
        mode,
        backend: crate::arch::RAX_BACKEND_DEFAULT,
        mem_base: 0,
        mem_size: 0x4000,
        mem_perms: RAX_PROT_ALL,
        flags: 0,
        riscv_ext: 0,
    };
    let mut engine = ptr::null_mut();
    assert_eq!(rax_engine_open_config(&config, &mut engine), RaxStatus::Ok);
    engine
}

fn save(engine: *mut Engine) -> Vec<u8> {
    let mut length = 0;
    assert_eq!(
        rax_context_save(engine, ptr::null_mut(), 0, &mut length),
        RaxStatus::Ok
    );
    let mut bytes = vec![0; length];
    assert_eq!(
        rax_context_save(engine, bytes.as_mut_ptr(), length, &mut length),
        RaxStatus::Ok
    );
    bytes
}

fn replace_cpu(blob: &[u8], version: u32, cpu: &[u8]) -> Vec<u8> {
    let old_length = u64::from_le_bytes(blob[20..28].try_into().unwrap()) as usize;
    let mut result = blob[..20].to_vec();
    result[4..8].copy_from_slice(&version.to_le_bytes());
    result.extend_from_slice(&(cpu.len() as u64).to_le_bytes());
    result.extend_from_slice(cpu);
    result.extend_from_slice(&blob[28 + old_length..]);
    result
}

// ABI <= 1.14: frozen variant 2, 31 X registers, SP/PC/PSTATE, 32 vectors,
// FPCR/FPSR, then exactly nineteen u64 system-register fields. No key storage.
fn legacy_cpu(sctlr: u64) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0; 31 * 8]);
    bytes.extend_from_slice(&0x3000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x3c5u64.to_le_bytes());
    bytes.extend_from_slice(&[0; 32 * 16 + 8]);
    bytes.extend_from_slice(&sctlr.to_le_bytes());
    bytes.extend_from_slice(&[0; 18 * 8]);
    assert_eq!(bytes.len(), 948);
    bytes
}

#[test]
fn pauth_context_roundtrip_preserves_keys_configuration_and_full_pstate() {
    let engine = small_arm64();
    unsafe {
        write(engine, 0x1000, &0xdac1_0020u32.to_le_bytes()); // PACIA X0,X1
        write(engine, 0x1004, &0xdac1_1020u32.to_le_bytes()); // AUTIA X0,X1
        let mut state = (*engine).vcpu.get_state().unwrap();
        let CpuState::Aarch64(arm) = &mut state else {
            panic!("wrong architecture")
        };
        arm.regs.x[1] = 1;
        arm.regs.pstate =
            0x3c5 | Aarch64Registers::PSTATE_PAN | Aarch64Registers::PSTATE_BTYPE_MASK;
        arm.sregs.sctlr_el1 = 1 << 31;
        arm.sregs.tcr_el1 = 16 | (16 << 16);
        let extension = arm.sregs.execution.as_mut().unwrap();
        extension.features |= (ArmFeatures::PACA | ArmFeatures::PACG).bits();
        extension.pauth = PauthConfig {
            algorithm: PauthAlgorithm::Qarma5,
            profile: PauthProfile::FpacCombine,
        };
        extension.sysregs.apiakeylo_el1 = u64::MAX;
        extension.sysregs.apiakeyhi_el1 = 0x0123_4567_89ab_cdef;
        extension.sysregs.hcr_el2 = (1 << 40) | (1 << 41);
        extension.sysregs.scr_el3 = 1 | (1 << 16) | (1 << 17);
        extension.sysregs.el2.elr = 0x2340;
        extension.sysregs.el3.spsr = 0x3c9;
        extension.sp_el2 = 0x3000;
        extension.sp_el3 = 0x4000;
        let expected_pstate = arm.regs.pstate;
        (*engine).vcpu.set_state(&state).unwrap();
        // An ordinary register write must not discard PAN/BTYPE or key state.
        assert_eq!(rax_reg_write_u64(engine, ARM64_X0, 0), RaxStatus::Ok);
        let preserved = (*engine).vcpu.get_state().unwrap();
        assert_eq!(preserved.as_aarch64().unwrap().regs.pstate, expected_pstate);
        assert_eq!(
            rax_emu_start(engine, 0x1000, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        assert_eq!(rd_u64(engine, ARM64_X0), 0xf916_0000_0000_0000);
        let saved_state = (*engine).vcpu.get_state().unwrap();
        let blob = save(engine);
        assert_eq!(&blob[4..8], &4u32.to_le_bytes());
        assert_eq!(rax_engine_reset(engine), RaxStatus::Ok);
        assert_eq!(
            rax_context_restore(engine, blob.as_ptr(), blob.len()),
            RaxStatus::Ok
        );
        let restored = (*engine).vcpu.get_state().unwrap();
        assert_eq!(
            rax_engine::codec::serialize(&restored).unwrap(),
            rax_engine::codec::serialize(&saved_state).unwrap()
        );
        assert_eq!(
            rax_emu_start(engine, 0x1004, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        assert_eq!(rd_u64(engine, ARM64_X0), 0);
    }
    rax_engine_close(engine);
}

#[test]
fn pauth_context_aarch32_width_roundtrip_keeps_physical_aliases_and_executes_thumb() {
    let engine = small_arm64_mode(RAX_MODE_64 | crate::arch::RAX_MODE_USER);
    unsafe {
        write(engine, 0x1000, &0x4608u16.to_le_bytes()); // MOV R0,R1
        write(engine, 0x1002, &0xdf42u16.to_le_bytes()); // SVC #0x42
        write(engine, 0x1004, &0xbe07u16.to_le_bytes()); // BKPT #7
        let mut state = (*engine).vcpu.get_state().unwrap();
        let CpuState::Aarch64(arm) = &mut state else {
            panic!("architecture");
        };
        arm.regs.pstate = 0xa805_0030; // AArch32 User, Thumb, NZCV/Q/GE.
        arm.regs.pc = 0x1000;
        arm.regs.sp = 0x3000;
        arm.regs.x[0] = 0x1234_5678_0000_0000;
        arm.regs.x[1] = 0x8765_4321_0000_0042;
        arm.regs.x[13] = 0x0102_0304_0000_3000;
        (*engine).vcpu.set_state(&state).unwrap();
        let blob = save(engine);
        assert_eq!(rax_engine_reset(engine), RaxStatus::Ok);
        assert_eq!(
            rax_context_restore(engine, blob.as_ptr(), blob.len()),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_engine::codec::serialize(&(*engine).vcpu.get_state().unwrap()).unwrap(),
            rax_engine::codec::serialize(&state).unwrap()
        );
        assert_eq!(
            rax_emu_start(engine, 0x1000, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        let after = (*engine).vcpu.get_state().unwrap();
        let arm = after.as_aarch64().unwrap();
        assert_eq!(arm.regs.x[0], 0x1234_5678_0000_0042);
        assert_eq!(arm.regs.pc, 0x1002);
        assert_eq!(arm.regs.pstate, 0xa805_0030);
        assert_eq!(arm.regs.x[13], 0x0102_0304_0000_3000);
        let mut corrupt = state.clone();
        let CpuState::Aarch64(arm) = &mut corrupt else {
            unreachable!();
        };
        arm.sregs
            .execution
            .as_mut()
            .unwrap()
            .sysregs
            .id_aa64pfr0_el1 = 0x1111;
        let invalid = replace_cpu(&blob, 4, &rax_engine::codec::serialize(&corrupt).unwrap());
        assert_eq!(
            rax_context_restore(engine, invalid.as_ptr(), invalid.len()),
            RaxStatus::Format
        );
        assert_eq!(
            rax_engine::codec::serialize(&(*engine).vcpu.get_state().unwrap()).unwrap(),
            rax_engine::codec::serialize(&after).unwrap()
        );
        assert_eq!(
            rax_emu_start(engine, 0x1002, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        let mut call = crate::user::RaxSyscallInfo::default();
        assert_eq!(
            crate::user::rax_emu_last_syscall(engine, &mut call),
            RaxStatus::Ok
        );
        assert_eq!(
            (call.pc, call.resume_pc, call.size, call.immediate),
            (0x1002, 0x1004, 2, 0x42)
        );
        assert_eq!(
            rax_emu_start(engine, 0x1004, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        let mut exception = crate::user::RaxExceptionInfo::default();
        assert_eq!(
            crate::user::rax_emu_last_exception(engine, &mut exception),
            RaxStatus::Ok
        );
        assert_eq!(
            (
                exception.vector,
                exception.pc,
                exception.return_pc,
                exception.syndrome
            ),
            (0x38, 0x1004, 0x1004, 7)
        );
        assert_ne!(exception.flags & crate::user::RAX_EXCEPTION_SOFTWARE, 0);
    }
    rax_engine_close(engine);
}

#[test]
fn pauth_context_legacy_decoding_is_exact_and_rejects_missing_enabled_keys() {
    let engine = small_arm64();
    let blob = save(engine);
    for version in [1, 2] {
        let legacy = replace_cpu(&blob, version, &legacy_cpu(0));
        assert_eq!(
            rax_context_restore(engine, legacy.as_ptr(), legacy.len()),
            RaxStatus::Ok
        );
        for bit in [31, 30, 27, 13] {
            let invalid = replace_cpu(&blob, version, &legacy_cpu(1 << bit));
            assert_eq!(
                rax_context_restore(engine, invalid.as_ptr(), invalid.len()),
                RaxStatus::Format
            );
        }
        let mut trailing = legacy_cpu(0);
        trailing.push(0);
        let invalid = replace_cpu(&blob, version, &trailing);
        assert_eq!(
            rax_context_restore(engine, invalid.as_ptr(), invalid.len()),
            RaxStatus::Format
        );
    }
    rax_engine_close(engine);
}

#[test]
fn pauth_context_rejects_missing_extension_unknown_algorithm_and_trailing_data() {
    let engine = small_arm64();
    let blob = save(engine);
    let state = unsafe { (*engine).vcpu.get_state().unwrap() };
    let mut no_extension = state.clone();
    let CpuState::Aarch64(arm) = &mut no_extension else {
        panic!("wrong architecture")
    };
    arm.sregs.execution = None;
    let absent = replace_cpu(
        &blob,
        4,
        &rax_engine::codec::serialize(&no_extension).unwrap(),
    );
    assert_eq!(
        rax_context_restore(engine, absent.as_ptr(), absent.len()),
        RaxStatus::Format
    );
    let mut cpu = rax_engine::codec::serialize(&state).unwrap();
    // Frozen old fields (948 bytes), Option::Some tag (1), features (8),
    // then algorithm u32. An unknown algorithm must not select a default.
    cpu[957..961].copy_from_slice(&2u32.to_le_bytes());
    let unknown = replace_cpu(&blob, 4, &cpu);
    assert_eq!(
        rax_context_restore(engine, unknown.as_ptr(), unknown.len()),
        RaxStatus::Format
    );
    let mut trailing = blob.clone();
    trailing.push(0);
    assert_eq!(
        rax_context_restore(engine, trailing.as_ptr(), trailing.len()),
        RaxStatus::Format
    );
    rax_engine_close(engine);
}

#[test]
fn pauth_configuration_api_validates_and_survives_reset_and_mapping_changes() {
    use crate::pauth::{
        RaxArm64PauthConfig, rax_arm64_pauth_configure, rax_arm64_pauth_get_config,
    };
    let engine = small_arm64();
    let mut config = RaxArm64PauthConfig {
        size: 32,
        features: 3,
        algorithm: 0,
        profile: 0,
        reserved: [0; 4],
    };
    assert_eq!(rax_arm64_pauth_configure(engine, &config), RaxStatus::Ok);
    assert_eq!(
        rax_arm64_pauth_get_config(engine, &mut config),
        RaxStatus::Ok
    );
    assert_eq!(
        (config.features, config.algorithm, config.profile),
        (3, 2, 4)
    );
    for algorithm in [1, 2] {
        for profile in 1..=4 {
            config.algorithm = algorithm;
            config.profile = profile;
            assert_eq!(rax_arm64_pauth_configure(engine, &config), RaxStatus::Ok);
            unsafe {
                assert_eq!(rax_reg_write_u64(engine, 0x0413, 0x1234), RaxStatus::Ok);
                assert_eq!(rax_reg_write_u64(engine, 0x041d, 1 << 41), RaxStatus::Ok);
                assert_eq!(rax_reg_write_u64(engine, 0x041f, 0x3000), RaxStatus::Ok);
                assert_eq!(
                    rax_mem_map(engine, 0x8000, 0x1000, RAX_PROT_ALL),
                    RaxStatus::Ok
                );
                assert_eq!(rd_u64(engine, 0x0413), 0x1234);
                assert_eq!(rd_u64(engine, 0x041d), 1 << 41);
                assert_eq!(rd_u64(engine, 0x041f), 0x3000);
                assert_eq!(rax_mem_unmap(engine, 0x8000, 0x1000), RaxStatus::Ok);
            }
            assert_eq!(rax_engine_reset(engine), RaxStatus::Ok);
            let mut got = config;
            assert_eq!(rax_arm64_pauth_get_config(engine, &mut got), RaxStatus::Ok);
            assert_eq!(
                (got.features, got.algorithm, got.profile),
                (3, algorithm, profile)
            );
            unsafe {
                assert_eq!(rd_u64(engine, 0x0413), 0);
            }
        }
    }
    let before = save(engine);
    for invalid in [
        RaxArm64PauthConfig { size: 31, ..config },
        RaxArm64PauthConfig {
            features: 4,
            ..config
        },
        RaxArm64PauthConfig {
            algorithm: 3,
            ..config
        },
        RaxArm64PauthConfig {
            profile: 5,
            ..config
        },
        RaxArm64PauthConfig {
            reserved: [0, 0, 1, 0],
            ..config
        },
    ] {
        assert_eq!(rax_arm64_pauth_configure(engine, &invalid), RaxStatus::Arg);
        assert_eq!(save(engine), before);
    }
    for id in 0x0413..=0x0433 {
        assert_eq!(rax_reg_size(RaxArch::Arm64 as i32, id), 8);
        unsafe {
            let value = 0x1234_5678_abcd_0000 | id as u64;
            assert_eq!(rax_reg_write_u64(engine, id, value), RaxStatus::Ok);
            assert_eq!(rd_u64(engine, id), value);
        }
    }
    // Current-SP coherence extends to EL2h and EL3h, including PSTATE writes.
    unsafe {
        assert_eq!(rax_reg_write_u64(engine, 0x0012, 0x3c9), RaxStatus::Ok);
        assert_eq!(rd_u64(engine, 0x0010), rd_u64(engine, 0x041f));
        assert_eq!(rax_reg_write_u64(engine, 0x041f, 0x7770), RaxStatus::Ok);
        assert_eq!(rd_u64(engine, 0x0010), 0x7770);
        assert_eq!(rax_reg_write_u64(engine, 0x0012, 0x3cd), RaxStatus::Ok);
        assert_eq!(rd_u64(engine, 0x0010), rd_u64(engine, 0x0420));
    }
    rax_engine_close(engine);
}

#[test]
fn pauth_user_fpac_reports_exact_fault_pc_iss_and_no_retirement() {
    use crate::pauth::{RaxArm64PauthConfig, rax_arm64_pauth_configure};
    use crate::user::{
        RAX_EXCEPTION_SYNDROME, RAX_EXCEPTION_VALID, RaxExceptionInfo, rax_emu_last_exception,
    };
    for key in 0..4u32 {
        let engine = small_arm64_mode(RAX_MODE_64 | crate::arch::RAX_MODE_USER);
        let config = RaxArm64PauthConfig {
            size: 32,
            features: 3,
            algorithm: 2,
            profile: 4,
            reserved: [0; 4],
        };
        assert_eq!(rax_arm64_pauth_configure(engine, &config), RaxStatus::Ok);
        unsafe {
            for register in [0x0413, 0x0415, 0x0417, 0x0419] {
                assert_eq!(rax_reg_write_u64(engine, register, u64::MAX), RaxStatus::Ok);
                assert_eq!(
                    rax_reg_write_u64(engine, register + 1, 0x0123_4567_89ab_cdef),
                    RaxStatus::Ok
                );
            }
            assert_eq!(
                rax_reg_write_u64(
                    engine,
                    0x040a,
                    (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13)
                ),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_reg_write_u64(engine, 0x040b, 16 | (16 << 16)),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_reg_write_u64(engine, 0x041d, (1 << 40) | (1 << 41)),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_reg_write_u64(engine, 0x041e, 1 | (1 << 16) | (1 << 17)),
                RaxStatus::Ok
            );
            assert_eq!(rax_reg_write_u64(engine, ARM64_X0, 0x1230), RaxStatus::Ok);
            assert_eq!(
                rax_reg_write_u64(engine, ARM64_X0 + 1, 0x4567),
                RaxStatus::Ok
            );
            let word = 0xdac1_0000 | ((key | 4) << 10) | (1 << 5);
            write(engine, 0x1000, &word.to_le_bytes());
            assert_eq!(
                rax_emu_start(engine, 0x1000, RAX_NO_ADDR, 0, 1),
                RaxStatus::Ok
            );
            let mut exception = RaxExceptionInfo::default();
            assert_eq!(
                rax_emu_last_exception(engine, &mut exception),
                RaxStatus::Ok
            );
            assert_eq!(
                (exception.vector, exception.syndrome),
                (0x1c, u64::from(key))
            );
            assert_eq!((exception.pc, exception.return_pc), (0x1000, 0x1000));
            assert_eq!(
                exception.flags,
                RAX_EXCEPTION_VALID | RAX_EXCEPTION_SYNDROME
            );
            assert_eq!(rd_u64(engine, 0x0011), 0x1000);
            assert_eq!(rd_u64(engine, ARM64_X0), 0x1230);
            assert_eq!(rd_u64(engine, ARM64_X0 + 1), 0x4567);
            assert_eq!(rax_emu_icount(engine), 0);
        }
        rax_engine_close(engine);
    }
}

#[cfg(all(feature = "jit", target_arch = "aarch64"))]
#[test]
fn pauth_c_api_native_loop_reports_precise_fpac_after_actual_native_entries() {
    use crate::pauth::{RaxArm64PauthConfig, rax_arm64_pauth_configure};
    use crate::user::{RaxExceptionInfo, rax_emu_last_exception};
    let mut cases = 0;
    for (algorithm, signed) in [(1, 0xa02d_0000_0000_0000u64), (2, 0xf916_0000_0000_0000)] {
        for key in 0..4u32 {
            let engine = small_arm64_mode(RAX_MODE_64 | crate::arch::RAX_MODE_USER);
            let config = RaxArm64PauthConfig {
                size: 32,
                features: 3,
                algorithm,
                profile: 4,
                reserved: [0; 4],
            };
            assert_eq!(rax_arm64_pauth_configure(engine, &config), RaxStatus::Ok);
            unsafe {
                for register in [0x0413, 0x0415, 0x0417, 0x0419] {
                    assert_eq!(rax_reg_write_u64(engine, register, u64::MAX), RaxStatus::Ok);
                    assert_eq!(
                        rax_reg_write_u64(engine, register + 1, 0x0123_4567_89ab_cdef),
                        RaxStatus::Ok
                    );
                }
                for (register, value) in [
                    (0x040a, (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13)),
                    (0x040b, 16 | (16 << 16)),
                    (0x041d, (1 << 40) | (1 << 41)),
                    (0x041e, 1 | (1 << 16) | (1 << 17)),
                    (ARM64_X0, signed),
                    (ARM64_X0 + 1, 1),
                    (ARM64_X0 + 2, 128),
                    (ARM64_X0 + 3, signed),
                    (ARM64_X0 + 4, signed ^ (1 << 48)),
                    (ARM64_X0 + 11, 0x1122_3344_5566_7788),
                ] {
                    assert_eq!(rax_reg_write_u64(engine, register, value), RaxStatus::Ok);
                }
                // AUT* X0,X1; SUBS X2,X2,#1; CSEL X0,X3,X4,NE; B head.
                // The first 128 AUTs succeed. The next visit faults on the same
                // already-promoted instruction without a host register write.
                let words = [
                    0xdac1_0020 | ((key | 4) << 10),
                    0xf100_0442,
                    0x9a84_1060,
                    0x17ff_fffd,
                ];
                let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
                write(engine, 0x1000, &bytes);
                let mut expected_state = (*engine).vcpu.get_state().unwrap();
                let CpuState::Aarch64(expected) = &mut expected_state else {
                    panic!("arm64 state required")
                };
                expected.regs.x[0] = signed ^ (1 << 48);
                expected.regs.x[2] = 0;
                expected.regs.pc = 0x1000;
                // SUBS 1-1 establishes N=0,Z=1,C=1,V=0; AUT/CSEL/B preserve it.
                expected.regs.pstate = (expected.regs.pstate & !0xf000_0000) | 0x6000_0000;
                assert_eq!(
                    rax_emu_start(engine, 0x1000, RAX_NO_ADDR, 0, 520),
                    RaxStatus::Ok
                );
                let crate::vcpu::Vcpu::Arm64User(vcpu) = &(*engine).vcpu else {
                    panic!("EL0 arm64 adapter required")
                };
                assert_eq!(
                    vcpu.native_pauth_entry_count(),
                    65,
                    "algorithm={algorithm} key={key}"
                );
                let mut exception = RaxExceptionInfo::default();
                assert_eq!(
                    rax_emu_last_exception(engine, &mut exception),
                    RaxStatus::Ok
                );
                assert_eq!(
                    (exception.vector, exception.syndrome),
                    (0x1c, u64::from(key))
                );
                assert_eq!((exception.pc, exception.return_pc), (0x1000, 0x1000));
                assert_eq!(rd_u64(engine, ARM64_X0), signed ^ (1 << 48));
                assert_eq!(rd_u64(engine, ARM64_X0 + 11), 0x1122_3344_5566_7788);
                assert_eq!(
                    rax_emu_icount(engine),
                    512,
                    "failed native AUT does not retire"
                );
                assert_eq!(rd_u64(engine, 0x0011), 0x1000);
                assert_eq!(
                    rax_engine::codec::serialize(&(*engine).vcpu.get_state().unwrap()).unwrap(),
                    rax_engine::codec::serialize(&expected_state).unwrap(),
                    "complete register/key/control state: algorithm={algorithm} key={key}"
                );
            }
            rax_engine_close(engine);
            cases += 1;
        }
    }
    assert_eq!(cases, 8);
}
