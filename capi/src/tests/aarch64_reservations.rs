//! Host memory writes participate in the AArch64 physical reservation domain.
use super::*;

#[test]
fn complete_context_restores_ram_before_reinstating_exclusive_rights() {
    use crate::context::{rax_context_restore, rax_context_save};
    for user in [false, true] {
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
        let mut source = ptr::null_mut();
        let mut target = ptr::null_mut();
        assert_eq!(rax_engine_open_config(&config, &mut source), RaxStatus::Ok);
        assert_eq!(rax_engine_open_config(&config, &mut target), RaxStatus::Ok);
        unsafe {
            write(source, 0x1000, &0x885f_7c20u32.to_le_bytes());
            write(source, 0x1004, &0x8802_7c20u32.to_le_bytes());
            write(source, 0x2000, &0x1234_5678u32.to_le_bytes());
            assert_eq!(rax_reg_write_u64(source, 0x0101, 0x2000), RaxStatus::Ok);
            assert_eq!(rax_reg_write_u64(source, 0x0011, 0x1000), RaxStatus::Ok);
            let mut executed = 0;
            assert_eq!(rax_emu_step(source, 1, &mut executed), RaxStatus::Ok);
            assert_eq!(executed, 1);
            let mut size = 0;
            assert_eq!(
                rax_context_save(source, ptr::null_mut(), 0, &mut size),
                RaxStatus::Ok
            );
            let mut bytes = vec![0; size];
            assert_eq!(
                rax_context_save(source, bytes.as_mut_ptr(), size, &mut size),
                RaxStatus::Ok
            );
            assert_eq!(&bytes[4..8], &8u32.to_le_bytes());
            write(target, 0x2000, &[0xff; 4]);
            assert_eq!(
                rax_context_restore(target, bytes.as_ptr(), size),
                RaxStatus::Ok
            );
            assert_eq!(rax_emu_step(target, 1, &mut executed), RaxStatus::Ok);
            assert_eq!(executed, 1);
            assert_eq!(rd_u64(target, 0x0102), 0, "user={user}");
            rax_engine_close(source);
            rax_engine_close(target);
        }
    }
}

#[test]
fn identical_aba_and_nonoverlapping_c_api_stores_have_distinct_effects() {
    for values in [&[0][..], &[99, 0][..], &[][..]] {
        let config = RaxEngineConfig {
            size: std::mem::size_of::<RaxEngineConfig>() as u32,
            arch: RaxArch::Arm64 as i32,
            mode: RAX_MODE_64,
            backend: crate::arch::RAX_BACKEND_DEFAULT,
            mem_base: 0,
            mem_size: 0x4000,
            mem_perms: RAX_PROT_ALL,
            flags: 0,
            riscv_ext: 0,
        };
        let mut engine = ptr::null_mut();
        assert_eq!(rax_engine_open_config(&config, &mut engine), RaxStatus::Ok);
        unsafe {
            write(engine, 0x1000, &0x885f_7c20u32.to_le_bytes());
            write(engine, 0x1004, &0x8802_7c20u32.to_le_bytes());
            assert_eq!(rax_reg_write_u64(engine, 0x0101, 0x2000), RaxStatus::Ok);
            assert_eq!(rax_reg_write_u64(engine, 0x0011, 0x1000), RaxStatus::Ok);
            let mut executed = u64::MAX;
            assert_eq!(rax_emu_step(engine, 1, &mut executed), RaxStatus::Ok);
            assert_eq!(executed, 1);
            for &value in values {
                write(engine, 0x2000, &[value]);
            }
            // The next reservation granule is independent even when written
            // through the same exported API and backing-memory handle.
            write(engine, 0x2040, &[7]);
            let mut executed = u64::MAX;
            assert_eq!(rax_emu_step(engine, 1, &mut executed), RaxStatus::Ok);
            assert_eq!(executed, 1);
            assert_eq!(rd_u64(engine, 0x0102), u64::from(!values.is_empty()));
            rax_engine_close(engine);
        }
    }
}
