//! System AArch32 contexts retain backend state through the exported C ABI.
use super::*;
use crate::arch::RAX_MODE_ARM;
use crate::context::{rax_context_restore, rax_context_save};

const PC: i32 = 0x0011;
const PSTATE: i32 = 0x0012;
const S0: i32 = 0x0200;
const CODE: u64 = 0x100;

fn open() -> *mut Engine {
    let config = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Arm as i32,
        mode: RAX_MODE_ARM,
        backend: crate::arch::RAX_BACKEND_DEFAULT,
        mem_base: 0,
        mem_size: 0x1000,
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
fn word(bytes: &[u8], offset: usize) -> usize {
    usize::try_from(u64::from_le_bytes(
        bytes[offset..offset + 8].try_into().unwrap(),
    ))
    .unwrap()
}
fn backend_offset(bytes: &[u8]) -> usize {
    let emulator = 28 + word(bytes, 20);
    emulator + 8 + word(bytes, emulator)
}

#[test]
fn aarch32_c_context_keeps_guest_cpacr_and_fpexc_denials_and_retirement() {
    for control in [0xee01_0f50u32, 0xeee8_0a10] {
        for remap in [false, true] {
            let source = open();
            let restored = open();
            unsafe {
                let code: Vec<_> = [control, 0xee31_0a02]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                write(source, CODE, &code);
                for (reg, value) in [
                    (S0, 0x1234_5678),
                    (S0 + 2, 0x3f80_0000),
                    (S0 + 4, 0x3f80_0000),
                ] {
                    assert_eq!(rax_reg_write_u64(source, reg, value), RaxStatus::Ok);
                }
                assert_eq!(
                    rax_emu_start(source, CODE, RAX_NO_ADDR, 0, 1),
                    RaxStatus::Ok
                );
                if remap {
                    assert_eq!(
                        rax_mem_map(source, 0x8000, 0x1000, RAX_PROT_ALL),
                        RaxStatus::Ok
                    );
                    assert_eq!(rax_emu_icount(source), 1);
                }
                let context = save(source);
                assert_eq!(u32::from_le_bytes(context[4..8].try_into().unwrap()), 5);
                assert_eq!(
                    rax_context_restore(restored, context.as_ptr(), context.len()),
                    RaxStatus::Ok
                );
                assert_eq!(rax_emu_icount(source), 1);
                assert_eq!(rax_emu_icount(restored), 0);
                for engine in [source, restored] {
                    // Stop at the entered exception vector before its first handler
                    // instruction can obscure the nonretiring FP access fault.
                    assert_eq!(rax_emu_start(engine, CODE + 4, 4, 0, 1), RaxStatus::Ok);
                    assert_eq!(rd_u64(engine, PC), 4, "control {control:#x}");
                    assert_eq!(rd_u64(engine, S0), 0x1234_5678);
                    assert_eq!(rax_emu_icount(engine), if engine == source { 1 } else { 0 });
                }
                assert_eq!(rd_u64(restored, PSTATE), rd_u64(source, PSTATE));
            }
            rax_engine_close(source);
            rax_engine_close(restored);
        }
    }
}

#[test]
fn aarch32_c_context_and_mapping_rebuild_preserve_exclusive_state() {
    let source = open();
    let restored = open();
    unsafe {
        // LDREX r1,[r2]; STREX r3,r1,[r2].
        write(
            source,
            CODE,
            &[0x9f, 0x1f, 0x92, 0xe1, 0x91, 0x3f, 0x82, 0xe1],
        );
        write(source, 0x800, &0x1122_3344u32.to_le_bytes());
        assert_eq!(rax_reg_write_u64(source, 0x0102, 0x800), RaxStatus::Ok);
        assert_eq!(
            rax_emu_start(source, CODE, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_reg_write_u64(source, 0x0101, 0x5566_7788),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_mem_map(source, 0x8000, 0x1000, RAX_PROT_ALL),
            RaxStatus::Ok
        );
        assert_eq!(rax_emu_icount(source), 1);
        let context = save(source);
        assert_eq!(
            rax_context_restore(restored, context.as_ptr(), context.len()),
            RaxStatus::Ok
        );
        assert_eq!(rax_emu_icount(restored), 0);
        for engine in [source, restored] {
            let mut executed = 0;
            assert_eq!(rax_emu_step(engine, 1, &mut executed), RaxStatus::Ok);
            assert_eq!(executed, 1);
            assert_eq!(
                rd_u64(engine, 0x0103),
                0,
                "STREX must retain the LDREX reservation"
            );
            let mut bytes = [0; 4];
            assert_eq!(
                rax_mem_read(engine, 0x800, bytes.as_mut_ptr(), bytes.len()),
                RaxStatus::Ok
            );
            assert_eq!(u32::from_le_bytes(bytes), 0x5566_7788);
            assert_eq!(rax_emu_icount(engine), if engine == source { 2 } else { 1 });
        }
    }
    rax_engine_close(source);
    rax_engine_close(restored);
}

#[test]
fn aarch32_c_context_still_reads_legacy_projection_formats() {
    let source = open();
    assert_eq!(
        rax_reg_write_u64(source, 0x0103, 0x1234_5678),
        RaxStatus::Ok
    );
    let bytes = save(source);
    let offset = backend_offset(&bytes);
    let end = offset + 12 + word(&bytes, offset + 4);
    for version in [1u32, 2] {
        let target = open();
        let mut legacy = bytes[..offset].to_vec();
        legacy.extend_from_slice(&bytes[end..]);
        legacy[4..8].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            rax_context_restore(target, legacy.as_ptr(), legacy.len()),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(target, 0x0103) }, 0x1234_5678);
        rax_engine_close(target);
    }
    rax_engine_close(source);
}

#[test]
fn aarch32_c_context_rejects_corruption_and_every_truncation_without_publication() {
    let source = open();
    let target = open();
    assert_eq!(
        rax_reg_write_u64(target, 0x0103, 0xfeed_beef),
        RaxStatus::Ok
    );
    let bytes = save(source);
    let before = save(target);
    let offset = backend_offset(&bytes);
    let end = offset + 12 + word(&bytes, offset + 4);
    for mutation in 0..7 {
        let mut bad = bytes.clone();
        match mutation {
            0 => bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes()),
            1 => bad[offset + 4..offset + 12].copy_from_slice(&u64::MAX.to_le_bytes()),
            2 => bad[offset + 12] ^= 1,
            3 => bad[end..end + 8].copy_from_slice(&u64::MAX.to_le_bytes()),
            4 => bad.push(0),
            5 => bad[32] ^= 1,
            6 => bad[16..20].copy_from_slice(&u32::MAX.to_le_bytes()),
            _ => unreachable!(),
        }
        assert_eq!(
            rax_context_restore(target, bad.as_ptr(), bad.len()),
            RaxStatus::Format
        );
        assert_eq!(save(target), before);
    }
    for length in 1..bytes.len() {
        assert_ne!(
            rax_context_restore(target, bytes.as_ptr(), length),
            RaxStatus::Ok,
            "prefix {length}"
        );
    }
    assert_eq!(save(target), before);
    rax_engine_close(source);
    rax_engine_close(target);
}
