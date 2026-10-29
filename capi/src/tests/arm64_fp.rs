//! Public FP/SIMD configuration, including real guest admission and reset/restore.
use super::*;
use crate::arm64_fp::*;

const PC: i32 = 0x0011;
const X0: i32 = 0x0100;

struct OwnedEngine(*mut Engine);
impl Drop for OwnedEngine {
    fn drop(&mut self) {
        rax_engine_close(self.0);
    }
}

fn open(user: bool) -> OwnedEngine {
    let config = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Arm64 as i32,
        mode: RAX_MODE_64 | if user { crate::arch::RAX_MODE_USER } else { 0 },
        backend: crate::arch::RAX_BACKEND_DEFAULT,
        mem_base: 0,
        mem_size: 0x4000,
        mem_perms: RAX_PROT_ALL,
        flags: 0,
        riscv_ext: 0,
    };
    let mut engine = ptr::null_mut();
    assert_eq!(rax_engine_open_config(&config, &mut engine), RaxStatus::Ok);
    OwnedEngine(engine)
}

fn selection(features: u32) -> RaxArm64FpConfig {
    RaxArm64FpConfig {
        size: 32,
        features,
        reserved: [0; 6],
    }
}

fn profile(engine: *const Engine) -> RaxArm64FpConfig {
    let mut result = selection(0);
    assert_eq!(rax_arm64_fp_get_config(engine, &mut result), RaxStatus::Ok);
    assert_eq!((result.size, result.reserved), (32, [0; 6]));
    result
}

fn select(engine: *mut Engine, features: u32) {
    assert_eq!(
        rax_arm64_fp_configure(engine, &selection(features)),
        RaxStatus::Ok
    );
    assert_eq!(profile(engine).features, features);
}

fn register(engine: *mut Engine, id: i32) -> u64 {
    let mut value = 0;
    assert_eq!(rax_reg_read_u64(engine, id, &mut value), RaxStatus::Ok);
    value
}

fn instruction(engine: *mut Engine, word: u32) {
    let bytes = word.to_le_bytes();
    assert_eq!(
        rax_mem_write(engine, 0x100, bytes.as_ptr(), bytes.len()),
        RaxStatus::Ok
    );
    assert_eq!(rax_reg_write_u64(engine, PC, 0x100), RaxStatus::Ok);
}

fn read_id(engine: *mut Engine, word: u32) -> u64 {
    instruction(engine, word);
    let mut retired = 0;
    assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Ok);
    assert_eq!(retired, 1);
    register(engine, X0)
}

#[test]
fn public_fp_configuration_covers_all_selections_and_guest_id_fields() {
    let owner = open(false);
    let engine = owner.0;
    assert_eq!(profile(engine).features, 0);
    for bits in 0..=RAX_ARM64_FP_FEATURES_SUPPORTED {
        let before = (
            profile(engine).features,
            register(engine, PC),
            rax_emu_icount(engine),
        );
        let result = rax_arm64_fp_configure(engine, &selection(bits));
        if bits & RAX_ARM64_FEATURE_FHM != 0 && bits & RAX_ARM64_FEATURE_FP16 == 0 {
            assert_eq!(result, RaxStatus::Arg);
            assert_eq!(
                (
                    profile(engine).features,
                    register(engine, PC),
                    rax_emu_icount(engine)
                ),
                before
            );
            continue;
        }
        assert_eq!(result, RaxStatus::Ok);
        assert_eq!(profile(engine).features, bits);
        assert_eq!(
            (register(engine, PC), rax_emu_icount(engine)),
            (before.1, before.2)
        );
        // LLVM MRS encodings; ID fields follow Arm DDI0616 B.a E3.2.11
        // and the primary local ID_AA64ISAR0_EL1 register declaration.
        let isar0 = read_id(engine, 0xd538_0600);
        let isar1 = read_id(engine, 0xd538_0620);
        let pfr0 = read_id(engine, 0xd538_0400);
        for (flag, value, shift) in [
            (RAX_ARM64_FEATURE_JSCVT, isar1, 12),
            (RAX_ARM64_FEATURE_FCMA, isar1, 16),
            (RAX_ARM64_FEATURE_FRINTTS, isar1, 32),
            (RAX_ARM64_FEATURE_BF16, isar1, 44),
            (RAX_ARM64_FEATURE_I8MM, isar1, 52),
            (RAX_ARM64_FEATURE_DOTPROD, isar0, 44),
            (RAX_ARM64_FEATURE_FHM, isar0, 48),
            (RAX_ARM64_FEATURE_FP16, pfr0, 16),
            (RAX_ARM64_FEATURE_FP16, pfr0, 20),
        ] {
            assert_eq!(
                (value >> shift) & 15,
                u64::from(bits & flag != 0),
                "flags={bits:02x}"
            );
        }
    }
}

#[test]
fn public_fp_configuration_retries_disabled_instructions_in_both_engine_modes() {
    for user in [false, true] {
        for (flags, word) in [
            (RAX_ARM64_FEATURE_FP16, 0x1ee2_2820u32),
            (RAX_ARM64_FEATURE_FP16 | RAX_ARM64_FEATURE_FHM, 0x0e22_ec20),
            (RAX_ARM64_FEATURE_JSCVT, 0x1e7e_0020),
            (RAX_ARM64_FEATURE_FCMA, 0x6e82_e420),
            (RAX_ARM64_FEATURE_FRINTTS, 0x1e28_4020),
            (RAX_ARM64_FEATURE_BF16, 0x1e63_4020),
            (RAX_ARM64_FEATURE_I8MM, 0x4e82_a420),
            (RAX_ARM64_FEATURE_DOTPROD, 0x4e82_9420),
        ] {
            let owner = open(user);
            let engine = owner.0;
            instruction(engine, word);
            let mut retired = u64::MAX;
            let status = rax_emu_step(engine, 1, &mut retired);
            if user {
                assert_eq!(status, RaxStatus::Ok);
                let mut exit = ExitInfo::none();
                assert_eq!(rax_emu_last_exit(engine, &mut exit), RaxStatus::Ok);
                assert_eq!(
                    (exit.reason, exit.intno),
                    (crate::run::RAX_STOP_EXCEPTION, 0)
                );
            } else {
                assert_ne!(status, RaxStatus::Ok);
            }
            assert_eq!(
                (retired, rax_emu_icount(engine), register(engine, PC)),
                (0, 0, 0x100)
            );
            select(engine, flags);
            assert_eq!((rax_emu_icount(engine), register(engine, PC)), (0, 0x100));
            assert_eq!(
                rax_emu_step(engine, 1, &mut retired),
                RaxStatus::Ok,
                "{word:08x}"
            );
            assert_eq!(
                (retired, rax_emu_icount(engine), register(engine, PC)),
                (1, 1, 0x104)
            );
        }
    }
}

#[test]
fn public_fp_configuration_survives_context_reset_and_memory_reconstruction() {
    for user in [false, true] {
        let owner = open(user);
        let engine = owner.0;
        select(engine, RAX_ARM64_FP_FEATURES_SUPPORTED);
        instruction(engine, 0x9100_0694); // ADD X20,X20,#1
        let mut retired = 0;
        assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Ok);
        assert_eq!(retired, 1);
        let mut length = 0;
        assert_eq!(
            crate::context::rax_context_save(engine, ptr::null_mut(), 0, &mut length),
            RaxStatus::Ok
        );
        let mut bytes = vec![0; length];
        assert_eq!(
            crate::context::rax_context_save(engine, bytes.as_mut_ptr(), length, &mut length),
            RaxStatus::Ok
        );
        select(engine, 0);
        assert_eq!(rax_emu_icount(engine), 1);
        assert_eq!(
            crate::context::rax_context_restore(engine, bytes.as_ptr(), length),
            RaxStatus::Ok
        );
        assert_eq!(profile(engine).features, RAX_ARM64_FP_FEATURES_SUPPORTED);
        assert_eq!(
            (register(engine, PC), register(engine, X0 + 20)),
            (0x104, 1)
        );
        assert_eq!(
            rax_mem_map(engine, 0x8000, 0x1000, RAX_PROT_ALL),
            RaxStatus::Ok
        );
        assert_eq!(profile(engine).features, RAX_ARM64_FP_FEATURES_SUPPORTED);
        assert_eq!(
            (register(engine, PC), register(engine, X0 + 20)),
            (0x104, 1)
        );
        assert_eq!(rax_engine_reset(engine), RaxStatus::Ok);
        assert_eq!(profile(engine).features, RAX_ARM64_FP_FEATURES_SUPPORTED);
        assert_eq!(
            (
                register(engine, PC),
                register(engine, X0 + 20),
                rax_emu_icount(engine)
            ),
            (0, 0, 0)
        );
    }
}

#[test]
fn public_fp_configuration_rejects_invalid_prefix_flags_and_reserved_fields() {
    let owner = open(false);
    let engine = owner.0;
    select(engine, RAX_ARM64_FEATURE_BF16);
    instruction(engine, 0x9100_0694);
    let mut retired = 0;
    assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Ok);
    let before = (
        profile(engine).features,
        register(engine, PC),
        register(engine, X0 + 20),
        rax_emu_icount(engine),
    );
    assert_eq!(
        rax_arm64_fp_configure(ptr::null_mut(), ptr::null()),
        RaxStatus::Handle
    );
    assert_eq!(
        rax_arm64_fp_get_config(ptr::null(), ptr::null_mut()),
        RaxStatus::Handle
    );
    assert_eq!(rax_arm64_fp_configure(engine, ptr::null()), RaxStatus::Arg);
    assert_eq!(
        rax_arm64_fp_get_config(engine, ptr::null_mut()),
        RaxStatus::Arg
    );
    for size in 0..32u32 {
        assert_eq!(
            rax_arm64_fp_configure(engine, (&size as *const u32).cast()),
            RaxStatus::Arg
        );
        let mut prefix = size;
        assert_eq!(
            rax_arm64_fp_get_config(engine, (&mut prefix as *mut u32).cast()),
            RaxStatus::Arg
        );
        assert_eq!(prefix, size);
    }
    for bit in 8..32 {
        assert_eq!(
            rax_arm64_fp_configure(engine, &selection(1 << bit)),
            RaxStatus::Arg
        );
    }
    for index in 0..6 {
        let mut bad = selection(0);
        bad.reserved[index] = 1;
        assert_eq!(rax_arm64_fp_configure(engine, &bad), RaxStatus::Arg);
    }
    assert_eq!(
        rax_arm64_fp_configure(engine, &selection(RAX_ARM64_FEATURE_FHM)),
        RaxStatus::Arg
    );
    assert_eq!(
        (
            profile(engine).features,
            register(engine, PC),
            register(engine, X0 + 20),
            rax_emu_icount(engine)
        ),
        before
    );
    let mut x86 = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::X86 as i32, RAX_MODE_64, &mut x86),
        RaxStatus::Ok
    );
    let x86 = OwnedEngine(x86);
    assert_eq!(
        rax_arm64_fp_configure(x86.0, &selection(0)),
        RaxStatus::Arch
    );
    assert_eq!(
        rax_arm64_fp_get_config(x86.0, &mut selection(0)),
        RaxStatus::Arch
    );
}

#[test]
fn public_fp_configuration_accepts_unaligned_extensible_prefixes_without_tail_writes() {
    let owner = open(false);
    let mut bytes = [0xa5u8; 65];
    let config = RaxArm64FpConfig {
        size: 64,
        ..selection(RAX_ARM64_FEATURE_FP16)
    };
    let pointer = bytes[1..].as_mut_ptr().cast::<RaxArm64FpConfig>();
    // SAFETY: this owned byte array exposes a complete writable 64-byte buffer;
    // unaligned copies avoid creating references to an unaligned struct.
    unsafe {
        std::ptr::write_unaligned(pointer, config);
    }
    assert_eq!(rax_arm64_fp_configure(owner.0, pointer), RaxStatus::Ok);
    assert_eq!(rax_arm64_fp_get_config(owner.0, pointer), RaxStatus::Ok);
    // SAFETY: the same complete byte prefix remains initialized and readable.
    let result = unsafe { std::ptr::read_unaligned(pointer) };
    assert_eq!(
        (result.size, result.features, result.reserved),
        (64, RAX_ARM64_FEATURE_FP16, [0; 6])
    );
    assert_eq!(bytes[0], 0xa5);
    assert!(bytes[33..].iter().all(|b| *b == 0xa5));
}

#[test]
fn public_fp_configuration_is_rejected_during_an_actual_execution_callback() {
    #[derive(Default)]
    struct CallbackResult {
        configure: Option<RaxStatus>,
        query: Option<RaxStatus>,
    }
    extern "C" fn callback(engine: *mut Engine, _pc: u64, _size: u32, data: *mut c_void) {
        // SAFETY: this synchronous hook receives the live boxed result passed
        // below; the test keeps it exclusively owned through emulation.
        let result = unsafe { &mut *data.cast::<CallbackResult>() };
        result.configure = Some(rax_arm64_fp_configure(
            engine,
            &selection(RAX_ARM64_FEATURE_FP16),
        ));
        result.query = Some(rax_arm64_fp_get_config(engine, &mut selection(0)));
    }
    let owner = open(false);
    instruction(owner.0, 0x9100_0694);
    let mut results = Box::new(CallbackResult::default());
    let mut hook = 0;
    assert_eq!(
        rax_hook_add_code(
            owner.0,
            1,
            0,
            Some(callback),
            (&mut *results as *mut CallbackResult).cast(),
            &mut hook
        ),
        RaxStatus::Ok
    );
    let mut retired = 0;
    assert_eq!(rax_emu_step(owner.0, 1, &mut retired), RaxStatus::Ok);
    assert_eq!(
        (results.configure, results.query),
        (Some(RaxStatus::State), Some(RaxStatus::State))
    );
    assert_eq!((retired, profile(owner.0).features), (1, 0));
}

#[test]
fn public_fp_configuration_preserves_independently_selected_pauth_and_keys() {
    use crate::pauth::{
        RaxArm64PauthConfig, rax_arm64_pauth_configure, rax_arm64_pauth_get_config,
    };
    for user in [false, true] {
        let owner = open(user);
        let mut pauth = RaxArm64PauthConfig {
            size: 32,
            features: 3,
            algorithm: 2,
            profile: 4,
            reserved: [0; 4],
        };
        assert_eq!(rax_arm64_pauth_configure(owner.0, &pauth), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(owner.0, 0x0413, 0x1234), RaxStatus::Ok);
        select(owner.0, RAX_ARM64_FEATURE_BF16 | RAX_ARM64_FEATURE_I8MM);
        assert_eq!(
            rax_arm64_pauth_get_config(owner.0, &mut pauth),
            RaxStatus::Ok
        );
        assert_eq!((pauth.features, pauth.algorithm, pauth.profile), (3, 2, 4));
        assert_eq!(register(owner.0, 0x0413), 0x1234);
        assert_eq!(rax_engine_reset(owner.0), RaxStatus::Ok);
        assert_eq!(
            profile(owner.0).features,
            RAX_ARM64_FEATURE_BF16 | RAX_ARM64_FEATURE_I8MM
        );
        assert_eq!(
            rax_arm64_pauth_get_config(owner.0, &mut pauth),
            RaxStatus::Ok
        );
        assert_eq!((pauth.features, pauth.algorithm, pauth.profile), (3, 2, 4));
        assert_eq!(register(owner.0, 0x0413), 0);
    }
}
