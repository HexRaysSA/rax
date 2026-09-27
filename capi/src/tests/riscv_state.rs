//! RISC-V vector registers, CSRs by number, and the privilege level
//! (API 1.5). Encodings are from LLVM 23 `llvm-mc -triple=riscv64 -mattr=+v`.
use super::*;
use crate::arch::RAX_MODE_USER;
use crate::context::{rax_context_restore, rax_context_save};
use crate::run::RAX_STOP_SHUTDOWN;

const RV_V: i32 = 0x0300;
const RV_CSR: i32 = 0x1000;
const RV_PRIV: i32 = 0x0024;
const MSCRATCH: i32 = RV_CSR + 0x340;
const MTVEC: i32 = RV_CSR + 0x305;
const MISA: i32 = RV_CSR + 0x301;
const FRM: i32 = RV_CSR + 0x002;
const VL: i32 = RV_CSR + 0xC20;
const VTYPE: i32 = RV_CSR + 0xC21;
const VLENB: i32 = RV_CSR + 0xC22;
const A0: i32 = RISCV_X0 + 10;
const RISCV_FCSR: i32 = 0x0023;

fn words(code: &[u32]) -> Vec<u8> {
    code.iter().flat_map(|w| w.to_le_bytes()).collect()
}

unsafe fn write_v(e: *mut Engine, reg: i32, bytes: [u8; 16]) {
    assert_eq!(rax_reg_size(RaxArch::Riscv64 as i32, RV_V + reg), 16);
    assert_eq!(
        unsafe { rax_reg_write(e, RV_V + reg, bytes.as_ptr().cast()) },
        RaxStatus::Ok
    );
}

unsafe fn read_v(e: *mut Engine, reg: i32) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    assert_eq!(
        unsafe { rax_reg_read(e, RV_V + reg, bytes.as_mut_ptr().cast(), ptr::null_mut()) },
        RaxStatus::Ok
    );
    bytes
}

fn lanes(values: [u32; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, v) in values.iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    bytes
}

#[test]
fn vector_registers_feed_vector_instructions() {
    let e = open_riscv_with_ext(0);
    unsafe {
        // vsetivli zero,4,e32,m1,ta,ma ; vadd.vv v3,v1,v2 ; ecall
        write(e, 0x1000, &words(&[0xCD02_7057, 0x0211_01D7, 0x0000_0073]));
        write_v(e, 1, lanes([1, 2, 3, 0xFFFF_FFFF]));
        write_v(e, 2, lanes([10, 20, 30, 1]));
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        let mut exit = ExitInfo::none();
        assert_eq!(rax_emu_last_exit(e, &mut exit), RaxStatus::Ok);
        assert_eq!(exit.reason, RAX_STOP_SHUTDOWN);
        assert_eq!(read_v(e, 3), lanes([11, 22, 33, 0]));
        assert_eq!(rd_u64(e, VL), 4);
        // e32 (vsew 0b010), m1, tail and mask agnostic.
        assert_eq!(rd_u64(e, VTYPE), 0xD0);
        assert_eq!(rd_u64(e, VLENB), 16);
    }
    rax_engine_close(e);
}

#[test]
fn csrs_are_addressable_by_number() {
    let e = open_riscv_with_ext(0);
    unsafe {
        assert_eq!(rax_reg_write_u64(e, MSCRATCH, 0x1234), RaxStatus::Ok);
        assert_eq!(rd_u64(e, MSCRATCH), 0x1234);
        // The hart sees the value: csrr a0,mscratch ; ecall
        write(e, 0x1000, &words(&[0x3400_2573, 0x0000_0073]));
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        assert_eq!(rd_u64(e, A0), 0x1234);
        // mtvec is WARL: mode 3 is reserved.
        assert_eq!(rax_reg_write_u64(e, MTVEC, 0x8000_0003), RaxStatus::Ok);
        assert_ne!(rd_u64(e, MTVEC) & 3, 3);
        // misa reports RV64 (MXL 2) with V (bit 21).
        let misa = rd_u64(e, MISA);
        assert_eq!((misa >> 62, misa >> 21 & 1), (2, 1));
        // frm is a view of fcsr.
        assert_eq!(rax_reg_write_u64(e, FRM, 3), RaxStatus::Ok);
        assert_eq!(rd_u64(e, RISCV_FCSR) >> 5, 3);
        // An unimplemented CSR.
        let mut v = 0;
        assert_eq!(rax_reg_read_u64(e, RV_CSR + 0x7C0, &mut v), RaxStatus::Reg);
    }
    rax_engine_close(e);
}

#[test]
fn privilege_level_is_a_register() {
    let e = open_riscv_with_ext(0);
    unsafe {
        let mut level = [0u8; 1];
        assert_eq!(
            rax_reg_read(e, RV_PRIV, level.as_mut_ptr().cast(), ptr::null_mut()),
            RaxStatus::Ok
        );
        assert_eq!(level[0], 3, "a system-mode hart starts in M-mode");
        assert_eq!(
            rax_reg_write(e, RV_PRIV, [1u8].as_ptr().cast()),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_reg_read(e, RV_PRIV, level.as_mut_ptr().cast(), ptr::null_mut()),
            RaxStatus::Ok
        );
        assert_eq!(level[0], 1);
        assert_ne!(
            rax_reg_write(e, RV_PRIV, [2u8].as_ptr().cast()),
            RaxStatus::Ok
        );
    }
    rax_engine_close(e);

    let cfg = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Riscv64 as i32,
        mode: RAX_MODE_USER,
        backend: crate::arch::RAX_BACKEND_DEFAULT,
        mem_base: 0x1_0000,
        mem_size: 0x1_0000,
        mem_perms: RAX_PROT_ALL,
        flags: 0,
        riscv_ext: 0,
    };
    let mut e = ptr::null_mut();
    assert_eq!(rax_engine_open_config(&cfg, &mut e), RaxStatus::Ok);
    unsafe {
        let mut level = [9u8; 1];
        assert_eq!(
            rax_reg_write(e, RV_PRIV, [3u8].as_ptr().cast()),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_reg_read(e, RV_PRIV, level.as_mut_ptr().cast(), ptr::null_mut()),
            RaxStatus::Ok
        );
        assert_eq!(level[0], 0, "a user-mode hart stays in U-mode");
    }
    rax_engine_close(e);
}

#[test]
fn contexts_carry_vector_csr_and_privilege_state() {
    let e = open_riscv_with_ext(0);
    let save = |e: *mut Engine| {
        let mut len = 0;
        assert_eq!(
            rax_context_save(e, ptr::null_mut(), 0, &mut len),
            RaxStatus::Ok
        );
        let mut blob = vec![0u8; len];
        assert_eq!(
            rax_context_save(e, blob.as_mut_ptr(), len, &mut len),
            RaxStatus::Ok
        );
        blob
    };
    unsafe {
        write_v(e, 5, lanes([5, 6, 7, 8]));
        assert_eq!(rax_reg_write_u64(e, MSCRATCH, 0xAB), RaxStatus::Ok);
        assert_eq!(
            rax_reg_write(e, RV_PRIV, [1u8].as_ptr().cast()),
            RaxStatus::Ok
        );
        let blob = save(e);
        write_v(e, 5, [0; 16]);
        assert_eq!(rax_reg_write_u64(e, MSCRATCH, 0), RaxStatus::Ok);
        assert_eq!(
            rax_reg_write(e, RV_PRIV, [3u8].as_ptr().cast()),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_context_restore(e, blob.as_ptr(), blob.len()),
            RaxStatus::Ok
        );
        assert_eq!(read_v(e, 5), lanes([5, 6, 7, 8]));
        assert_eq!(rd_u64(e, MSCRATCH), 0xAB);
        let mut level = [0u8; 1];
        assert_eq!(
            rax_reg_read(e, RV_PRIV, level.as_mut_ptr().cast(), ptr::null_mut()),
            RaxStatus::Ok
        );
        assert_eq!(level[0], 1);
    }
    rax_engine_close(e);
}
