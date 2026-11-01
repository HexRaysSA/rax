//! Cortex-M continuation through exported context functions.
use super::*;
use crate::context::{rax_context_restore, rax_context_save};
const CODE: u64 = 0x1000;
fn open(code: &[u8]) -> *mut Engine {
    let config = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::CortexM as i32,
        mode: 0,
        backend: 0,
        mem_base: 0,
        mem_size: 0x4000,
        mem_perms: RAX_PROT_ALL,
        flags: 0,
        riscv_ext: 0,
    };
    let mut e = ptr::null_mut();
    assert_eq!(rax_engine_open_config(&config, &mut e), RaxStatus::Ok);
    unsafe {
        write(e, CODE, code);
    }
    e
}
fn save(e: *mut Engine) -> Vec<u8> {
    let mut size = 0;
    assert_eq!(
        rax_context_save(e, ptr::null_mut(), 0, &mut size),
        RaxStatus::Ok
    );
    let mut bytes = vec![0; size];
    assert_eq!(
        rax_context_save(e, bytes.as_mut_ptr(), size, &mut size),
        RaxStatus::Ok
    );
    bytes
}
fn step(e: *mut Engine) -> (u64, ExitInfo) {
    let mut count = 0;
    assert_eq!(rax_emu_step(e, 1, &mut count), RaxStatus::Ok);
    let mut exit = ExitInfo::none();
    assert_eq!(rax_emu_last_exit(e, &mut exit), RaxStatus::Ok);
    (count, exit)
}
#[test]
fn cortex_m_c_context_retains_the_backend_counter() {
    let source = open(&[0x00, 0xbf, 0x00, 0xbf]);
    let target = open(&[]);
    assert_eq!(
        rax_emu_start(source, CODE, RAX_NO_ADDR, 0, 1),
        RaxStatus::Ok
    );
    let raw = save(source);
    assert_eq!(
        rax_context_restore(target, raw.as_ptr(), raw.len()),
        RaxStatus::Ok
    );
    unsafe {
        assert_eq!(
            (*target).vcpu.instruction_count(),
            1,
            "C context lost the Cortex-M backend counter"
        );
    }
    assert_eq!(rax_emu_icount(target), 0);
    rax_engine_close(source);
    rax_engine_close(target);
}
#[test]
fn cortex_m_c_context_preserves_wfi_sleep_across_restore_and_mapping() {
    for remap in [false, true] {
        let source = open(&[0x30, 0xbf, 0x2a, 0x20]);
        let target = open(&[]);
        assert_eq!(
            rax_emu_start(source, CODE, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        if remap {
            assert_eq!(
                rax_mem_map(source, 0x8000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
        }
        let raw = save(source);
        assert_eq!(
            rax_context_restore(target, raw.as_ptr(), raw.len()),
            RaxStatus::Ok
        );
        let (count, exit) = step(target);
        assert_eq!(count, 0, "C restore executed a sleeping Cortex-M CPU");
        assert_eq!(exit.reason, RAX_STOP_HLT);
        assert_eq!(
            rax_emu_start(target, CODE + 2, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(target, 0x0100) }, 42);
        rax_engine_close(source);
        rax_engine_close(target);
    }
}
#[test]
fn cortex_m_c_context_preserves_the_sev_event() {
    let source = open(&[0x40, 0xbf, 0x20, 0xbf, 0x2a, 0x20]);
    let target = open(&[]);
    assert_eq!(
        rax_emu_start(source, CODE, RAX_NO_ADDR, 0, 1),
        RaxStatus::Ok
    );
    let raw = save(source);
    assert_eq!(
        rax_context_restore(target, raw.as_ptr(), raw.len()),
        RaxStatus::Ok
    );
    let (count, exit) = step(target);
    assert_eq!(count, 1);
    assert_ne!(
        exit.reason, RAX_STOP_HLT,
        "C restore lost the SEV event consumed by WFE"
    );
    assert_eq!(step(target).0, 1);
    assert_eq!(unsafe { rd_u64(target, 0x0100) }, 42);
    rax_engine_close(source);
    rax_engine_close(target);
}
fn size_at(bytes: &[u8], at: usize) -> usize {
    usize::try_from(u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())).unwrap()
}
fn backend_offset(bytes: &[u8]) -> usize {
    let at = 28 + size_at(bytes, 20);
    at + 8 + size_at(bytes, at)
}
#[test]
fn cortex_m_c_context_keeps_ldrex_rights_until_strex_consumes_them() {
    // LLVM 23 llvm-mc -triple=thumbv7em -show-encoding.
    let source = open(&[0x52, 0xe8, 0x00, 0x1f, 0x42, 0xe8, 0x00, 0x13]);
    let target = open(&[]);
    unsafe {
        write(source, 0x2000, &0x11223344u32.to_le_bytes());
    }
    assert_eq!(rax_reg_write_u64(source, 0x0102, 0x2000), RaxStatus::Ok);
    assert_eq!(
        rax_emu_start(source, CODE, RAX_NO_ADDR, 0, 1),
        RaxStatus::Ok
    );
    assert_eq!(rax_reg_write_u64(source, 0x0101, 0x55667788), RaxStatus::Ok);
    let raw = save(source);
    assert_eq!(
        rax_context_restore(target, raw.as_ptr(), raw.len()),
        RaxStatus::Ok
    );
    assert_eq!(step(target).0, 1);
    assert_eq!(unsafe { rd_u64(target, 0x0103) }, 0);
    let mut bytes = [0; 4];
    assert_eq!(
        rax_mem_read(target, 0x2000, bytes.as_mut_ptr(), 4),
        RaxStatus::Ok
    );
    assert_eq!(u32::from_le_bytes(bytes), 0x55667788);
    // A map replacement can discard local rights, and removing their range
    // must remain possible without resetting the core's retirement phase.
    assert_eq!(rax_mem_unmap(source, 0x2000, 0x1000), RaxStatus::Ok);
    assert_eq!(
        rax_mem_map(source, 0x2000, 0x1000, RAX_PROT_ALL),
        RaxStatus::Ok
    );
    assert_eq!(rax_emu_icount(source), 1);
    assert_eq!(step(source).0, 1);
    assert_eq!(unsafe { rd_u64(source, 0x0103) }, 1);
    // Retrying STREX without another LDREX fails: the monitor was consumed.
    assert_eq!(
        rax_emu_start(target, CODE + 4, RAX_NO_ADDR, 0, 1),
        RaxStatus::Ok
    );
    assert_eq!(unsafe { rd_u64(target, 0x0103) }, 1);
    rax_engine_close(source);
    rax_engine_close(target);
}
#[test]
fn cortex_m_c_context_reads_legacy_projection_formats() {
    let source = open(&[0x00, 0xbf]);
    assert_eq!(
        rax_emu_start(source, CODE, RAX_NO_ADDR, 0, 1),
        RaxStatus::Ok
    );
    let raw = save(source);
    assert_eq!(u32::from_le_bytes(raw[4..8].try_into().unwrap()), 9);
    let at = backend_offset(&raw);
    let end = at + 12 + size_at(&raw, at + 4);
    for version in [1u32, 2] {
        let target = open(&[]);
        let mut legacy = raw[..at].to_vec();
        legacy.extend_from_slice(&raw[end..]);
        legacy[4..8].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            rax_context_restore(target, legacy.as_ptr(), legacy.len()),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(target, 0x0011) }, CODE + 2);
        unsafe {
            assert_eq!((*target).vcpu.instruction_count(), 0);
        }
        rax_engine_close(target);
    }
    rax_engine_close(source);
}
#[test]
fn cortex_m_c_context_rejects_corruption_and_every_truncation_without_publication() {
    let source = open(&[0x00, 0xbf]);
    let target = open(&[]);
    assert_eq!(rax_reg_write_u64(target, 0x0100, 0xfeedbeef), RaxStatus::Ok);
    let raw = save(source);
    let before = save(target);
    let at = backend_offset(&raw);
    for mutation in 0..7 {
        let mut bad = raw.clone();
        match mutation {
            0 => bad[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes()),
            1 => bad[at + 4..at + 12].copy_from_slice(&u64::MAX.to_le_bytes()),
            2 => bad[at + 12] ^= 1,
            3 => bad.push(0),
            4 => bad[32] ^= 1, // public R0 disagrees with private image.
            5 => bad[16..20].copy_from_slice(&u32::MAX.to_le_bytes()),
            6 => bad[4..8].copy_from_slice(&8u32.to_le_bytes()), // another architecture's private format.
            _ => unreachable!(),
        }
        assert_eq!(
            rax_context_restore(target, bad.as_ptr(), bad.len()),
            RaxStatus::Format
        );
        assert_eq!(save(target), before);
    }
    for length in 1..raw.len() {
        assert_ne!(
            rax_context_restore(target, raw.as_ptr(), length),
            RaxStatus::Ok,
            "prefix {length}"
        );
    }
    assert_eq!(save(target), before);
    rax_engine_close(source);
    rax_engine_close(target);
}
