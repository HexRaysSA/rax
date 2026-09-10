//! C API micro-emulation must expose a recoverable fault at its exact PC.
use super::*;
use crate::engine::rax_engine_errmsg;

#[test]
fn arm64_unmapped_global_load_retries_at_faulting_instruction() {
    // A64 LDR X0,[X1]; ADD X0,X0,#7; RET. The stop address is before RET.
    let code = [
        0x20, 0x00, 0x40, 0xf9, 0x00, 0x1c, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    for single_step in [false, true] {
        let cfg = RaxEngineConfig {
            size: std::mem::size_of::<RaxEngineConfig>() as u32,
            arch: RaxArch::Arm64 as i32,
            mode: 0,
            backend: crate::arch::RAX_BACKEND_DEFAULT,
            mem_base: 0x1000,
            mem_size: 0x1000,
            mem_perms: RAX_PROT_ALL,
            flags: 0,
            riscv_ext: 0,
        };
        let mut e = ptr::null_mut();
        assert_eq!(rax_engine_open_config(&cfg, &mut e), RaxStatus::Ok);
        assert_eq!(
            rax_mem_write(e, 0x1000, code.as_ptr(), code.len()),
            RaxStatus::Ok
        );
        assert_eq!(rax_reg_write_u64(e, 0x0101, 0x200_0000), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, ARM64_X0, 0x55), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, 0x0011, 0x1000), RaxStatus::Ok);
        let mut executed = 0;
        let status = if single_step {
            rax_emu_step(e, 1, &mut executed)
        } else {
            rax_emu_start(e, 0x1000, 0x1008, 1_000_000, 8)
        };
        let mut pc = 0;
        assert_eq!(rax_reg_read_u64(e, 0x0011, &mut pc), RaxStatus::Ok);
        assert_ne!(
            status,
            RaxStatus::Ok,
            "unmapped load reported success at PC {pc:#x}"
        );
        assert_eq!(pc, 0x1000, "fault must preserve the retry PC");
        assert_eq!(unsafe { rd_u64(e, ARM64_X0) }, 0x55);
        assert_eq!(
            rax_mem_map(e, 0x200_0000, 0x1000, RAX_PROT_ALL),
            RaxStatus::Ok
        );
        let global = 0x1234_5678_u64.to_le_bytes();
        assert_eq!(
            rax_mem_write(e, 0x200_0000, global.as_ptr(), global.len()),
            RaxStatus::Ok
        );
        assert_eq!(rax_emu_start(e, pc, 0x1008, 1_000_000, 8), RaxStatus::Ok);
        assert_eq!(unsafe { rd_u64(e, ARM64_X0) }, 0x1234_567f);
        assert_eq!(unsafe { rd_u64(e, 0x0011) }, 0x1008);
        rax_engine_close(e);
    }
}

#[test]
fn arm64_read_write_and_fetch_faults_are_reported_before_retry() {
    for (instruction, address, writing) in [
        (0xf940_0020_u32, 0_u64, false),
        (0xf940_0020, 0x200_0ffc, false),
        // Instruction embedders own addresses that happen to match VMM devices.
        (0xf940_0020, 0x900_0000, false),
        (0xf940_0020, 0x800_0000, false),
        (0xf900_0020, 0x200_0000, true),
    ] {
        let cfg = RaxEngineConfig {
            size: std::mem::size_of::<RaxEngineConfig>() as u32,
            arch: RaxArch::Arm64 as i32,
            mode: 0,
            backend: crate::arch::RAX_BACKEND_DEFAULT,
            mem_base: 0x1000,
            mem_size: 0x1000,
            mem_perms: RAX_PROT_ALL,
            flags: 0,
            riscv_ext: 0,
        };
        let mut e = ptr::null_mut();
        assert_eq!(rax_engine_open_config(&cfg, &mut e), RaxStatus::Ok);
        let code = instruction.to_le_bytes();
        assert_eq!(rax_mem_write(e, 0x1000, code.as_ptr(), 4), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, 0x0101, address), RaxStatus::Ok);
        assert_eq!(
            rax_reg_write_u64(e, ARM64_X0, 0x8877_6655_4433_2211),
            RaxStatus::Ok
        );
        if address & 0xfff > 0xff8 {
            assert_eq!(
                rax_mem_map(e, address & !0xfff, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
        }
        assert_ne!(
            rax_emu_start(e, 0x1000, 0x1004, 1_000_000, 1),
            RaxStatus::Ok
        );
        let page = (address & !0xfff) + if address & 0xfff > 0xff8 { 0x1000 } else { 0 };
        let mut message = [0 as std::ffi::c_char; 256];
        assert!(rax_engine_errmsg(e, message.as_mut_ptr(), message.len()) > 0);
        let message = unsafe { std::ffi::CStr::from_ptr(message.as_ptr()) }.to_string_lossy();
        assert!(message.contains(&format!("at {page:#x}")), "{message}");
        assert_eq!(unsafe { rd_u64(e, 0x0011) }, 0x1000);
        assert_eq!(rax_mem_map(e, page, 0x1000, RAX_PROT_ALL), RaxStatus::Ok);
        let data = 0x1234_5678_u64.to_le_bytes();
        if !writing {
            assert_eq!(rax_mem_write(e, address, data.as_ptr(), 8), RaxStatus::Ok);
        }
        assert_eq!(
            rax_emu_start(e, 0x1000, 0x1004, 1_000_000, 1),
            RaxStatus::Ok
        );
        if writing {
            let mut output = [0_u8; 8];
            assert_eq!(
                rax_mem_read(e, address, output.as_mut_ptr(), 8),
                RaxStatus::Ok
            );
            assert_eq!(u64::from_le_bytes(output), 0x8877_6655_4433_2211);
        } else {
            assert_eq!(unsafe { rd_u64(e, ARM64_X0) }, 0x1234_5678);
        }
        // Fetching outside every mapping must also exit at the exact fault PC.
        assert_ne!(
            rax_emu_start(e, 0x400_0000, 0x400_0004, 1_000_000, 1),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(e, 0x0011) }, 0x400_0000);
        rax_engine_close(e);
    }
}
