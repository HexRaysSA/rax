//! Complete RISC-V contexts through the exported C API.
use super::*;
use crate::arch::{RAX_MODE_USER, RAX_RISCV_EXT_ZCMT};
use crate::context::{rax_context_restore, rax_context_save};

fn open(mode: u32, extensions: u64) -> *mut Engine {
    let cfg = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Riscv64 as i32,
        mode,
        backend: crate::arch::RAX_BACKEND_DEFAULT,
        mem_base: 0,
        mem_size: 0x4000,
        mem_perms: RAX_PROT_ALL,
        flags: 0,
        riscv_ext: extensions,
    };
    let mut engine = ptr::null_mut();
    assert_eq!(rax_engine_open_config(&cfg, &mut engine), RaxStatus::Ok);
    engine
}
fn save(engine: *mut Engine) -> Vec<u8> {
    let mut len = 0;
    assert_eq!(
        rax_context_save(engine, ptr::null_mut(), 0, &mut len),
        RaxStatus::Ok
    );
    let mut raw = vec![0; len];
    assert_eq!(
        rax_context_save(engine, raw.as_mut_ptr(), len, &mut len),
        RaxStatus::Ok
    );
    raw
}
fn word(raw: &[u8], at: usize) -> usize {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap()) as usize
}
fn backend_offset(raw: &[u8]) -> usize {
    let emu = 28 + word(raw, 20);
    emu + 8 + word(raw, emu)
}

#[test]
fn riscv_c_context_retains_reservation_through_remaps_and_restore_in_both_modes() {
    for mode in [0, RAX_MODE_USER] {
        for remaps in 0..3 {
            let source = open(mode, 0);
            let restored = open(mode, 0);
            unsafe {
                write(
                    source,
                    0x100,
                    &[0xaf, 0x22, 0x05, 0x10, 0xaf, 0x25, 0x55, 0x18],
                );
                write(source, 0x800, &0x1234_5678u32.to_le_bytes());
                assert_eq!(
                    rax_reg_write_u64(source, RISCV_X0 + 10, 0x800),
                    RaxStatus::Ok
                );
                assert_eq!(
                    rax_emu_start(source, 0x100, RAX_NO_ADDR, 0, 1),
                    RaxStatus::Ok
                );
                if remaps > 0 {
                    assert_eq!(
                        rax_mem_map(source, 0x8000, 0x1000, RAX_PROT_ALL),
                        RaxStatus::Ok
                    );
                }
                if remaps > 1 {
                    assert_eq!(rax_mem_unmap(source, 0x8000, 0x1000), RaxStatus::Ok);
                }
                assert_eq!(rax_emu_icount(source), 1);
                let raw = save(source);
                assert_eq!(&raw[4..8], &6u32.to_le_bytes());
                assert_eq!(
                    rax_context_restore(restored, raw.as_ptr(), raw.len()),
                    RaxStatus::Ok
                );
                assert_eq!(rax_emu_icount(restored), 0);
                for engine in [source, restored] {
                    assert_eq!(
                        rax_emu_start(engine, 0x104, RAX_NO_ADDR, 0, 1),
                        RaxStatus::Ok
                    );
                    assert_eq!(rd_u64(engine, RISCV_X0 + 11), 0);
                    assert_eq!(rd_u64(engine, RISCV_PC), 0x108);
                }
                assert_eq!(rax_emu_icount(source), 2);
                assert_eq!(rax_emu_icount(restored), 1);
                assert_eq!(save(source), save(restored));
            }
            rax_engine_close(source);
            rax_engine_close(restored);
        }
    }
}

#[test]
fn riscv_profile_survives_context_restore_into_default_engine_and_map_rebuild() {
    const JVT: i32 = 0x1017;
    let source = open(0, RAX_RISCV_EXT_ZCMT);
    let target = open(0, 0);
    unsafe {
        assert_eq!(rax_reg_write_u64(source, JVT, 0x1234_5000), RaxStatus::Ok);
        let mut value = 0;
        assert_eq!(rax_reg_read_u64(target, JVT, &mut value), RaxStatus::Reg);
        let raw = save(source);
        assert_eq!(
            rax_context_restore(target, raw.as_ptr(), raw.len()),
            RaxStatus::Ok
        );
        assert_eq!(rax_reg_read_u64(target, JVT, &mut value), RaxStatus::Ok);
        assert_eq!(value, 0x1234_5000);
        assert_eq!(
            rax_mem_map(target, 0x8000, 0x1000, RAX_PROT_ALL),
            RaxStatus::Ok
        );
        assert_eq!(rax_reg_read_u64(target, JVT, &mut value), RaxStatus::Ok);
        assert_eq!(value, 0x1234_5000);
        assert_eq!(rax_engine_reset(target), RaxStatus::Ok);
        assert_eq!(rax_reg_read_u64(target, JVT, &mut value), RaxStatus::Ok);
        assert_eq!(value, 0);
    }
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn legacy_riscv_format_two_retains_its_projection_only_semantics() {
    let source = open(0, 0);
    let target = open(0, 0);
    unsafe {
        write(
            source,
            0x100,
            &[0xaf, 0x22, 0x05, 0x10, 0xaf, 0x25, 0x55, 0x18],
        );
        assert_eq!(
            rax_reg_write_u64(source, RISCV_X0 + 10, 0x800),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_emu_start(source, 0x100, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        let mut raw = save(source);
        let at = backend_offset(&raw);
        let end = at + 12 + word(&raw, at + 4);
        raw.drain(at..end);
        raw[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            rax_context_restore(target, raw.as_ptr(), raw.len()),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_emu_start(target, 0x104, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        assert_eq!(rd_u64(target, RISCV_X0 + 11), 1);
    }
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn riscv_context_rejects_truncation_corruption_and_public_private_disagreement() {
    let source = open(0, 0);
    let target = open(0, 0);
    unsafe {
        assert_eq!(
            rax_reg_write_u64(source, RISCV_X0 + 5, 0x1234),
            RaxStatus::Ok
        );
        let raw = save(source);
        let before = save(target);
        let at = backend_offset(&raw);
        for end in 0..raw.len() {
            assert_ne!(
                rax_context_restore(target, raw.as_ptr(), end),
                RaxStatus::Ok,
                "prefix {end}"
            );
        }
        for offset in [16, at, at + 4, at + 12, 28 + 4 + 5 * 8] {
            let mut bad = raw.clone();
            bad[offset] ^= 0x80;
            assert_ne!(
                rax_context_restore(target, bad.as_ptr(), bad.len()),
                RaxStatus::Ok,
                "offset {offset}"
            );
        }
        assert_eq!(save(target), before);
    }
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn riscv64_header_rejects_a_consistent_rv32_private_profile_without_publication() {
    use rax_engine::backend::emulator::riscv::RiscVVcpu;
    use rax_engine::cpu::VCpu;
    use rax_engine::isa::riscv::{Isa, RiscVConfig};
    use rax_engine::memory::vm::{GuestAddress, GuestMemoryMmap};
    use std::sync::Arc;
    let source = open(0, 0);
    let target = open(0, 0);
    let raw = save(source);
    let before = save(target);
    let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    let rv32 = RiscVVcpu::new_embedded(0, mem, RiscVConfig::rv32(Isa::rv64gc()));
    let cpu = rax_engine::codec::serialize(&rv32.get_state().unwrap()).unwrap();
    let backend = rv32.save_context().unwrap();
    let at = backend_offset(&raw);
    let regions = at + 12 + word(&raw, at + 4);
    let mut forged = raw[..20].to_vec(); // Riscv64 architecture, format6.
    forged.extend_from_slice(&(cpu.len() as u64).to_le_bytes());
    forged.extend_from_slice(&cpu);
    forged.extend_from_slice(&0u64.to_le_bytes());
    forged.extend_from_slice(&rax_engine::snapshot::RISCV_CONTEXT.to_le_bytes());
    forged.extend_from_slice(&(backend.len() as u64).to_le_bytes());
    forged.extend_from_slice(&backend);
    forged.extend_from_slice(&raw[regions..]);
    assert_eq!(
        unsafe { rax_context_restore(target, forged.as_ptr(), forged.len()) },
        RaxStatus::Format
    );
    assert_eq!(save(target), before);
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn riscv_register_updates_preserve_live_reservations_in_both_modes() {
    for mode in [0, RAX_MODE_USER] {
        let engine = open(mode, 0);
        unsafe {
            write(
                engine,
                0x100,
                &[0xaf, 0x22, 0x05, 0x10, 0xaf, 0x25, 0x55, 0x18],
            );
            assert_eq!(
                rax_reg_write_u64(engine, RISCV_X0 + 10, 0x800),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_emu_start(engine, 0x100, RAX_NO_ADDR, 0, 1),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_reg_write_u64(engine, RISCV_X0 + 13, 0x42),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_emu_start(engine, 0x104, RAX_NO_ADDR, 0, 1),
                RaxStatus::Ok
            );
            assert_eq!(rd_u64(engine, RISCV_X0 + 11), 0);
        }
        rax_engine_close(engine);
    }
}

#[test]
fn riscv_same_value_host_write_after_remap_stays_invalid_after_restore() {
    for mode in [0, RAX_MODE_USER] {
        let source = open(mode, 0);
        let restored = open(mode, 0);
        unsafe {
            write(
                source,
                0x100,
                &[0xaf, 0x22, 0x05, 0x10, 0xaf, 0x25, 0x55, 0x18],
            );
            write(source, 0x800, &0x1234_5678u32.to_le_bytes());
            assert_eq!(
                rax_reg_write_u64(source, RISCV_X0 + 10, 0x800),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_emu_start(source, 0x100, RAX_NO_ADDR, 0, 1),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_mem_map(source, 0x8000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            write(source, 0x800, &0x1234_5678u32.to_le_bytes());
            let raw = save(source);
            assert_eq!(
                rax_context_restore(restored, raw.as_ptr(), raw.len()),
                RaxStatus::Ok
            );
            for engine in [source, restored] {
                assert_eq!(
                    rax_emu_start(engine, 0x104, RAX_NO_ADDR, 0, 1),
                    RaxStatus::Ok
                );
                assert_eq!(rd_u64(engine, RISCV_X0 + 11), 1);
            }
        }
        rax_engine_close(source);
        rax_engine_close(restored);
    }
}

#[test]
fn riscv_unmapping_reserved_bytes_succeeds_without_regranting_rights() {
    for mode in [0, RAX_MODE_USER] {
        let engine = open(mode, 0);
        unsafe {
            write(
                engine,
                0x100,
                &[0xaf, 0x22, 0x05, 0x10, 0xaf, 0x25, 0x55, 0x18],
            );
            assert_eq!(
                rax_reg_write_u64(engine, RISCV_X0 + 10, 0x800),
                RaxStatus::Ok
            );
            assert_eq!(
                rax_emu_start(engine, 0x100, RAX_NO_ADDR, 0, 1),
                RaxStatus::Ok
            );
            assert_eq!(rax_mem_unmap(engine, 0, 0x1000), RaxStatus::Ok);
            assert_eq!(rax_mem_map(engine, 0, 0x1000, RAX_PROT_ALL), RaxStatus::Ok);
            write(engine, 0x104, &0x1855_25afu32.to_le_bytes());
            write(engine, 0x800, &0x9999_9999u32.to_le_bytes());
            assert_eq!(
                rax_emu_start(engine, 0x104, RAX_NO_ADDR, 0, 1),
                RaxStatus::Ok
            );
            assert_eq!(rd_u64(engine, RISCV_X0 + 11), 1);
            let mut bytes = [0; 4];
            assert_eq!(
                rax_mem_read(engine, 0x800, bytes.as_mut_ptr(), 4),
                RaxStatus::Ok
            );
            assert_eq!(u32::from_le_bytes(bytes), 0x9999_9999);
        }
        rax_engine_close(engine);
    }
}
