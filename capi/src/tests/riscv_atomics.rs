//! Exported user-engine CAS permission and precise fault witnesses.
use super::*;
use crate::arch::RAX_MODE_USER;
use crate::fault::{
    RAX_FAULT_ACCESS_WRITE, RAX_FAULT_PERMISSION, RaxFaultInfo, rax_emu_last_fault,
};

fn open() -> *mut Engine {
    let config = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Riscv64 as i32,
        mode: RAX_MODE_USER,
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

#[test]
fn comparison_miss_needs_write_permission_and_preserves_precise_state() {
    for (width, size) in [(2, 4), (3, 8), (4, 16)] {
        let engine = open();
        // SAFETY: this test exclusively owns a live engine; every pointer names
        // a stack buffer of the size passed to the synchronous exported API.
        unsafe {
            let word: u32 = (5 << 27) | (8 << 20) | (10 << 15) | (width << 12) | (6 << 7) | 0x2f;
            write(engine, 0x100, &word.to_le_bytes());
            for (reg, value) in [(6, 1), (7, 2), (8, 3), (9, 4), (10, 0x2000)] {
                assert_eq!(
                    rax_reg_write_u64(engine, RISCV_X0 + reg, value),
                    RaxStatus::Ok
                );
            }
            assert_eq!(
                rax_mem_protect(engine, 0x2000, 4096, RAX_PROT_READ),
                RaxStatus::Ok
            );
            assert_eq!(rax_reg_write_u64(engine, RISCV_PC, 0x100), RaxStatus::Ok);
            let mut retired = u64::MAX;
            assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Fault);
            assert_eq!((retired, rax_emu_icount(engine)), (0, 0));
            assert_eq!(
                (
                    rd_u64(engine, RISCV_PC),
                    rd_u64(engine, RISCV_X0 + 6),
                    rd_u64(engine, RISCV_X0 + 7)
                ),
                (0x100, 1, 2)
            );
            let mut fault = RaxFaultInfo::default();
            assert_eq!(rax_emu_last_fault(engine, &mut fault), RaxStatus::Ok);
            assert_eq!(
                (
                    fault.kind,
                    fault.access,
                    fault.address,
                    fault.size,
                    fault.pc
                ),
                (
                    RAX_FAULT_PERMISSION,
                    RAX_FAULT_ACCESS_WRITE,
                    0x2000,
                    size,
                    0x100
                )
            );
            // Granting access makes the same comparison miss retire and return
            // zero without changing RAM. A retry must not retain the old fault.
            assert_eq!(
                rax_mem_protect(engine, 0x2000, 4096, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Ok);
            assert_eq!(
                (
                    retired,
                    rax_emu_icount(engine),
                    rd_u64(engine, RISCV_X0 + 6)
                ),
                (1, 1, 0)
            );
            assert_eq!(rd_u64(engine, RISCV_X0 + 7), if size == 16 { 0 } else { 2 });
            let mut bytes = [0xff; 16];
            assert_eq!(
                rax_mem_read(engine, 0x2000, bytes.as_mut_ptr(), size as usize),
                RaxStatus::Ok
            );
            assert!(bytes[..size as usize].iter().all(|b| *b == 0));
        }
        rax_engine_close(engine);
    }
}
