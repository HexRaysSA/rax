//! Public instruction budgets and contexts at a precise Undefined frontier.
use super::*;
use crate::arm64_fp::{RAX_ARM64_FP_FEATURES_SUPPORTED, RaxArm64FpConfig, rax_arm64_fp_configure};

struct OwnedEngine(*mut Engine);
impl Drop for OwnedEngine {
    fn drop(&mut self) {
        rax_engine_close(self.0);
    }
}

fn register(engine: *mut Engine, id: i32) -> u64 {
    let mut value = 0;
    assert_eq!(rax_reg_read_u64(engine, id, &mut value), RaxStatus::Ok);
    value
}

fn write_word(engine: *mut Engine, pc: u64, word: u32) {
    let bytes = word.to_le_bytes();
    assert_eq!(
        rax_mem_write(engine, pc, bytes.as_ptr(), bytes.len()),
        RaxStatus::Ok
    );
}

#[test]
fn arm64_undefined_budgets_and_public_contexts_preserve_the_retired_prefix() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/development/a64-undefined-retirement/corpus.json"
    )))
    .unwrap();
    for user in [false, true] {
        for record in corpus["records"].as_array().unwrap() {
            let word = record["word"].as_u64().unwrap() as u32;
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
            let _owner = OwnedEngine(engine);
            let profile = RaxArm64FpConfig {
                size: 32,
                features: RAX_ARM64_FP_FEATURES_SUPPORTED,
                reserved: [0; 6],
            };
            assert_eq!(rax_arm64_fp_configure(engine, &profile), RaxStatus::Ok);
            write_word(engine, 0x100, 0x9100_0694); // ADD X20,X20,#1
            write_word(engine, 0x104, word);
            write_word(engine, 0x108, 0x9100_054a); // ADD X10,X10,#1
            assert_eq!(rax_reg_write_u64(engine, 0x0011, 0x100), RaxStatus::Ok);
            let mut retired = u64::MAX;
            let status = rax_emu_step(engine, 1000, &mut retired);
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
            assert_eq!((retired, rax_emu_icount(engine)), (1, 1), "{word:08x}");
            assert_eq!(
                (register(engine, 0x0011), register(engine, 0x0114)),
                (0x104, 1)
            );
            assert_eq!((register(engine, 0x0109), register(engine, 0x010a)), (0, 0));
            let mut length = 0;
            assert_eq!(
                crate::context::rax_context_save(engine, ptr::null_mut(), 0, &mut length),
                RaxStatus::Ok
            );
            let mut context = vec![0; length];
            assert_eq!(
                crate::context::rax_context_save(engine, context.as_mut_ptr(), length, &mut length),
                RaxStatus::Ok
            );
            write_word(engine, 0x104, 0x9100_0529); // ADD X9,X9,#1
            assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Ok);
            assert_eq!(
                (retired, rax_emu_icount(engine), register(engine, 0x0109)),
                (1, 2, 1)
            );
            assert_eq!(
                crate::context::rax_context_restore(engine, context.as_ptr(), length),
                RaxStatus::Ok
            );
            // Restoration retains the backend history and restarts the C API's
            // documented observation counter at zero.
            assert_eq!(
                (
                    rax_emu_icount(engine),
                    register(engine, 0x0011),
                    register(engine, 0x0109)
                ),
                (0, 0x104, 0)
            );
            write_word(engine, 0x104, 0x9100_0529);
            assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Ok);
            assert_eq!(
                (retired, rax_emu_icount(engine), register(engine, 0x0011)),
                (1, 1, 0x108)
            );
            assert_eq!((register(engine, 0x0109), register(engine, 0x010a)), (1, 0));
        }
    }
}
