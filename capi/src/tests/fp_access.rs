//! Public stepping must expose denied FP without consuming its instruction limit.
use super::*;
use rax_engine::vm::vcpu::CpuState;

#[test]
fn arm64_fp_denial_preserves_pc_count_and_context_before_successful_retry() {
    for user in [false, true] {
        for instruction in [
            0x1e22_2820u32,
            0xd53b_4400,
            0xd53b_4420,
            0xd51b_4400,
            0xd51b_4420,
        ] {
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
            let code = instruction.to_le_bytes();
            assert_eq!(
                rax_mem_write(engine, 0x100, code.as_ptr(), code.len()),
                RaxStatus::Ok
            );
            // SAFETY: open_config returned this live engine; no concurrent calls or
            // callback borrows exist. The borrow ends before every C API call.
            unsafe {
                let CpuState::Aarch64(mut state) = (*engine).vcpu.get_state().unwrap() else {
                    panic!()
                };
                state.regs.pc = 0x100;
                state.sregs.execution.as_mut().unwrap().sysregs.el1.cpacr = 0;
                (*engine).vcpu.set_state(&CpuState::Aarch64(state)).unwrap();
            }
            let mut retired = u64::MAX;
            let status = rax_emu_step(engine, 1, &mut retired);
            if user {
                // User exceptions are successful stops with an exception descriptor.
                assert_eq!(status, RaxStatus::Ok);
                let mut exit = ExitInfo::none();
                assert_eq!(rax_emu_last_exit(engine, &mut exit), RaxStatus::Ok);
                assert_eq!(exit.reason, crate::run::RAX_STOP_EXCEPTION);
                assert_eq!(exit.intno, 7);
            } else {
                assert_ne!(status, RaxStatus::Ok);
            }
            assert_eq!(retired, 0);
            assert_eq!(rax_emu_icount(engine), 0);
            let mut pc = 0;
            assert_eq!(rax_reg_read_u64(engine, 0x0011, &mut pc), RaxStatus::Ok);
            assert_eq!(pc, 0x100);
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
            assert_eq!(
                crate::context::rax_context_restore(engine, context.as_ptr(), length),
                RaxStatus::Ok
            );
            // SAFETY: the same engine remains live, exclusively owned and idle.
            unsafe {
                let CpuState::Aarch64(mut state) = (*engine).vcpu.get_state().unwrap() else {
                    panic!()
                };
                state.sregs.execution.as_mut().unwrap().sysregs.el1.cpacr = 3 << 20;
                (*engine).vcpu.set_state(&CpuState::Aarch64(state)).unwrap();
            }
            assert_eq!(rax_emu_step(engine, 1, &mut retired), RaxStatus::Ok);
            assert_eq!(retired, 1);
            assert_eq!(rax_emu_icount(engine), 1);
            assert_eq!(rax_reg_read_u64(engine, 0x0011, &mut pc), RaxStatus::Ok);
            assert_eq!(pc, 0x104);
            rax_engine_close(engine);
        }
    }
}
