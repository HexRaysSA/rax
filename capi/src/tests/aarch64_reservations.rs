//! Host memory writes participate in the AArch64 physical reservation domain.
use super::*;

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
