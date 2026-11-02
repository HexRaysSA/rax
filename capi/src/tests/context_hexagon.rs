//! Hexagon represented private state through exported C context functions.
use super::*;
use crate::context::{rax_context_restore, rax_context_save};
const CODE: u64 = 0x1000;
fn open(words: &[u32]) -> *mut Engine {
    let config = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Hexagon as i32,
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
    let code: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    unsafe {
        write(e, CODE, &code);
    }
    assert_eq!(rax_reg_write_u64(e, 0x0309, CODE), RaxStatus::Ok);
    e
}
fn save(e: *mut Engine) -> Vec<u8> {
    let mut n = 0;
    assert_eq!(
        rax_context_save(e, ptr::null_mut(), 0, &mut n),
        RaxStatus::Ok
    );
    let mut b = vec![0; n];
    assert_eq!(
        rax_context_save(e, b.as_mut_ptr(), n, &mut n),
        RaxStatus::Ok
    );
    b
}
fn step(e: *mut Engine) -> u64 {
    let mut n = 0;
    assert_eq!(rax_emu_step(e, 1, &mut n), RaxStatus::Ok);
    n
}
fn restored(source: *mut Engine, target: *mut Engine) {
    let b = save(source);
    assert_eq!(
        rax_context_restore(target, b.as_ptr(), b.len()),
        RaxStatus::Ok
    );
}
fn word(e: *mut Engine, at: u64) -> u32 {
    let mut b = [0; 4];
    assert_eq!(rax_mem_read(e, at, b.as_mut_ptr(), 4), RaxStatus::Ok);
    u32::from_le_bytes(b)
}
#[test]
fn hexagon_c_context_and_mapping_keep_raw_packet_counts_with_a_fresh_public_origin() {
    for remap in [false, true] {
        let source = open(&[0x7800_c540, 0x7800_c540]);
        let target = open(&[]);
        assert_eq!(step(source), 1);
        if remap {
            assert_eq!(
                rax_mem_map(source, 0x8000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
        }
        assert_eq!(rax_emu_icount(source), 1);
        restored(source, target);
        unsafe {
            assert_eq!((*target).vcpu.instruction_count(), 1);
        }
        assert_eq!(rax_emu_icount(target), 0);
        assert_eq!(step(target), 1);
        assert_eq!(rax_emu_icount(target), 1);
        rax_engine_close(source);
        rax_engine_close(target);
    }
}
#[test]
fn hexagon_c_context_keeps_local_ll_sc_but_mapping_may_invalidate_rights() {
    let source = open(&[0x9202_c001, 0xa0a2_c300]);
    let target = open(&[]);
    unsafe {
        write(source, 0x2000, &0x1122_3344u32.to_le_bytes());
    }
    assert_eq!(rax_reg_write_u64(source, 0x0102, 0x2000), RaxStatus::Ok);
    assert_eq!(
        rax_reg_write_u64(source, 0x0103, 0x5566_7788),
        RaxStatus::Ok
    );
    assert_eq!(step(source), 1);
    restored(source, target);
    assert_eq!(step(target), 1);
    assert_eq!(unsafe { rd_u64(target, 0x0400) }, 255);
    assert_eq!(word(target, 0x2000), 0x5566_7788);
    assert_eq!(rax_mem_unmap(source, 0x2000, 0x1000), RaxStatus::Ok);
    assert_eq!(
        rax_mem_map(source, 0x2000, 0x1000, RAX_PROT_ALL),
        RaxStatus::Ok
    );
    assert_eq!(step(source), 1);
    assert_eq!(unsafe { rd_u64(source, 0x0400) }, 0);
    rax_engine_close(source);
    rax_engine_close(target);
}
#[test]
fn hexagon_c_context_keeps_pending_input_and_buffered_registers() {
    let source = open(&[0x7800_4038, 0x9182_c001]);
    let target = open(&[]);
    assert_eq!(
        rax_reg_write_u64(source, 0x0102, 0xf000_0000),
        RaxStatus::Ok
    );
    unsafe {
        assert!(matches!(
            (*source).vcpu.step_insn().unwrap(),
            Some(rax_engine::cpu::VcpuExit::MmioRead { size: 4, .. })
        ));
    }
    assert_eq!(unsafe { rd_u64(source, 0x0118) }, 0);
    restored(source, target);
    for e in [source, target] {
        unsafe {
            (*e).vcpu.complete_io_in(&0x1122_3344u32.to_le_bytes());
        }
        assert_eq!(step(e), 1);
        assert_eq!(unsafe { rd_u64(e, 0x0118) }, 1);
        assert_eq!(unsafe { rd_u64(e, 0x0101) }, 0x1122_3344);
        rax_engine_close(e);
    }
}
#[test]
fn hexagon_c_context_keeps_deferred_ram_after_an_output_was_returned() {
    let source = open(&[0xa023_0045]);
    let target = open(&[]);
    for (r, v) in [
        (0x0102, 0x2000),
        (0x0103, 0x1122_3344),
        (0x0104, 0xf000_0004),
        (0x0105, 0x5566_7788),
    ] {
        assert_eq!(rax_reg_write_u64(source, r, v), RaxStatus::Ok);
    }
    unsafe {
        assert!(matches!(
            (*source).vcpu.step_insn().unwrap(),
            Some(rax_engine::cpu::VcpuExit::MmioWrite {
                addr: 0xf000_0004,
                ..
            })
        ));
    }
    assert_eq!(word(source, 0x2000), 0);
    restored(source, target);
    for e in [source, target] {
        assert_eq!(word(e, 0x2000), 0);
        assert_eq!(step(e), 1);
        assert_eq!(word(e, 0x2000), 0x1122_3344);
        rax_engine_close(e);
    }
}
fn size_at(b: &[u8], at: usize) -> usize {
    usize::try_from(u64::from_le_bytes(b[at..at + 8].try_into().unwrap())).unwrap()
}
fn backend_offset(b: &[u8]) -> usize {
    let at = 28 + size_at(b, 20);
    at + 8 + size_at(b, at)
}
#[test]
fn hexagon_c_context_retains_legacy_projection_versions() {
    let source = open(&[0x7800_c540]);
    assert_eq!(step(source), 1);
    let raw = save(source);
    assert_eq!(u32::from_le_bytes(raw[4..8].try_into().unwrap()), 10);
    let at = backend_offset(&raw);
    let end = at + 12 + size_at(&raw, at + 4);
    for version in [1u32, 2] {
        let target = open(&[]);
        let mut old = raw[..at].to_vec();
        old.extend_from_slice(&raw[end..]);
        old[4..8].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            rax_context_restore(target, old.as_ptr(), old.len()),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(target, 0x0100) }, 42);
        unsafe {
            assert_eq!((*target).vcpu.instruction_count(), 0);
        }
        rax_engine_close(target);
    }
    rax_engine_close(source);
}
#[test]
fn hexagon_c_context_rejects_corruption_and_every_truncation_without_publication() {
    let source = open(&[0x7800_c540]);
    let target = open(&[]);
    assert_eq!(
        rax_reg_write_u64(target, 0x0100, 0xfeed_beef),
        RaxStatus::Ok
    );
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
            4 => bad[32] ^= 1,
            5 => bad[16..20].copy_from_slice(&u32::MAX.to_le_bytes()),
            6 => bad[4..8].copy_from_slice(&9u32.to_le_bytes()),
            _ => unreachable!(),
        }
        assert_eq!(
            rax_context_restore(target, bad.as_ptr(), bad.len()),
            RaxStatus::Format
        );
        assert_eq!(save(target), before);
    }
    for n in 1..raw.len() {
        assert_ne!(
            rax_context_restore(target, raw.as_ptr(), n),
            RaxStatus::Ok,
            "prefix {n}"
        );
    }
    assert_eq!(save(target), before);
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn hexagon_c_context_same_pc_start_and_register_edits_keep_restored_rights() {
    let source = open(&[0x9202_c001, 0xa0a2_c300]);
    assert_eq!(rax_reg_write_u64(source, 0x0102, 0x2000), RaxStatus::Ok);
    assert_eq!(
        rax_reg_write_u64(source, 0x0103, 0x5566_7788),
        RaxStatus::Ok
    );
    assert_eq!(step(source), 1);
    let raw = save(source);
    for edit in [false, true] {
        let target = open(&[]);
        assert_eq!(
            rax_context_restore(target, raw.as_ptr(), raw.len()),
            RaxStatus::Ok
        );
        if edit {
            assert_eq!(rax_reg_write_u64(target, 0x010a, 7), RaxStatus::Ok);
        }
        assert_eq!(
            rax_emu_start(target, CODE + 4, RAX_NO_ADDR, 0, 1),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(target, 0x0400) }, 255);
        assert_eq!(word(target, 0x2000), 0x5566_7788);
        if edit {
            assert_eq!(unsafe { rd_u64(target, 0x010a) }, 7);
        }
        rax_engine_close(target);
    }
    rax_engine_close(source);
}
#[test]
fn hexagon_c_context_rejects_destructive_pending_edits_then_resumes_at_same_pc() {
    let source = open(&[0x7800_4038, 0x9182_c001]);
    let target = open(&[]);
    assert_eq!(
        rax_reg_write_u64(source, 0x0102, 0xf000_0000),
        RaxStatus::Ok
    );
    unsafe {
        assert!(matches!(
            (*source).vcpu.step_insn().unwrap(),
            Some(rax_engine::cpu::VcpuExit::MmioRead { .. })
        ));
    }
    restored(source, target);
    let before = save(target);
    assert_ne!(rax_reg_write_u64(target, 0x010a, 7), RaxStatus::Ok);
    assert_eq!(save(target), before);
    assert_ne!(
        rax_emu_start(target, CODE + 4, RAX_NO_ADDR, 0, 1),
        RaxStatus::Ok
    );
    assert_eq!(save(target), before);
    assert_eq!(rax_reg_write_u64(target, 0x0309, CODE), RaxStatus::Ok);
    assert_eq!(save(target), before);
    unsafe {
        (*target).vcpu.complete_io_in(&0x1122_3344u32.to_le_bytes());
    }
    assert_eq!(
        rax_emu_start(target, CODE, RAX_NO_ADDR, 0, 1),
        RaxStatus::Ok
    );
    assert_eq!(unsafe { rd_u64(target, 0x0118) }, 1);
    assert_eq!(unsafe { rd_u64(target, 0x0101) }, 0x1122_3344);
    assert_eq!(rax_emu_icount(target), 1);
    rax_engine_close(source);
    rax_engine_close(target);
}
