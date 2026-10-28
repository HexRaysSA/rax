//! Full x86 contexts through the exported C API and memory-map reconstruction.
use super::*;
use crate::arch::{RAX_MODE_16, RAX_MODE_32, RAX_MODE_USER};
use crate::context::{rax_context_restore, rax_context_save};
use rax_engine::cpu::CpuState;
use rax_engine::isa::x86_64::{X86_64Config, gdt_entry};
use std::sync::Arc;

fn open(mode: u32) -> *mut Engine {
    let config = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::X86 as i32,
        mode,
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
fn save(e: *mut Engine) -> Vec<u8> {
    let mut len = 0;
    assert_eq!(
        rax_context_save(e, ptr::null_mut(), 0, &mut len),
        RaxStatus::Ok
    );
    let mut raw = vec![0; len];
    assert_eq!(
        rax_context_save(e, raw.as_mut_ptr(), len, &mut len),
        RaxStatus::Ok
    );
    raw
}
fn restore(e: *mut Engine, raw: &[u8]) -> RaxStatus {
    rax_context_restore(e, raw.as_ptr(), raw.len())
}
fn step(e: *mut Engine) {
    let mut retired = 0;
    assert_eq!(rax_emu_step(e, 1, &mut retired), RaxStatus::Ok);
    assert_eq!(retired, 1);
}
fn word(raw: &[u8], at: usize) -> usize {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap()) as usize
}
fn backend_offset(raw: &[u8]) -> usize {
    let emu = 28 + word(raw, 20);
    emu + 8 + word(raw, emu)
}
fn resources_offset(raw: &[u8]) -> usize {
    let backend = backend_offset(raw);
    backend + 12 + word(raw, backend + 4)
}
fn regions_offset(raw: &[u8]) -> usize {
    let resources = resources_offset(raw);
    resources + 8 + word(raw, resources)
}
unsafe fn configure(e: *mut Engine, pc: u64, a: u64, c: u64, d: u64) {
    unsafe {
        let v = &mut (*e).vcpu;
        let CpuState::X86_64(mut state) = v.get_state().unwrap() else {
            panic!()
        };
        state.regs.rip = pc;
        state.regs.rax = a;
        state.regs.rcx = c;
        state.regs.rdx = d;
        state.regs.rsp = 0x3000;
        state.sregs.cr4 |= 1 << 18;
        v.set_state(&CpuState::X86_64(state)).unwrap();
    }
}

#[test]
fn xcr0_survives_context_restore_and_map_rebuilds_in_system_and_user_modes() {
    for mode in [RAX_MODE_32, RAX_MODE_64, RAX_MODE_64 | RAX_MODE_USER] {
        let source = open(mode);
        let target = open(RAX_MODE_64);
        unsafe {
            write(source, 0x1000, &[0x0f, 0x01, 0xd1, 0x0f, 0x01, 0xd0, 0xf4]);
            if let crate::vcpu::Vcpu::X86User(core) = &mut (*source).vcpu {
                core.set_xcr0(3).unwrap();
                configure(source, 0x1003, 0, 0, 0);
            } else {
                configure(source, 0x1000, 3, 0, 0);
                step(source);
            }
            let raw = save(source);
            assert_eq!(&raw[4..8], &7u32.to_le_bytes());
            assert_eq!(restore(target, &raw), RaxStatus::Ok);
            assert_eq!(rax_emu_icount(target), 0);
            assert_eq!(
                rax_mem_map(target, 0x8000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            assert_eq!(rax_mem_unmap(target, 0x8000, 0x1000), RaxStatus::Ok);
            step(source);
            step(target);
            let CpuState::X86_64(a) = (*source).vcpu.get_state().unwrap() else {
                panic!()
            };
            let CpuState::X86_64(b) = (*target).vcpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(a.regs.rax, 3);
            assert_eq!(b.regs.rax, 3);
            assert_eq!(
                (*source).vcpu.instruction_count(),
                (*target).vcpu.instruction_count()
            );
            assert_eq!(rax_emu_icount(target), 1);
        }
        rax_engine_close(source);
        rax_engine_close(target);
    }
}

#[test]
fn selected_capabilities_survive_restore_remap_and_architectural_reset() {
    for mode in [RAX_MODE_64, RAX_MODE_64 | RAX_MODE_USER] {
        let source = open(mode);
        let target = open(mode);
        unsafe {
            let config = X86_64Config {
                sse4a: true,
                ..Default::default()
            };
            (*source).vcpu.set_x86_configuration(config).unwrap();
            write(source, 0x1000, &[0x0f, 0xa2, 0xf4]);
            configure(source, 0x1000, 0x80000001, 0, 0);
            let raw = save(source);
            assert_eq!(restore(target, &raw), RaxStatus::Ok);
            assert_eq!((*target).vcpu.x86_configuration(), Some(config));
            assert_eq!(
                rax_mem_map(target, 0x8000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            for reset in [false, true] {
                if reset {
                    assert_eq!(rax_engine_reset(target), RaxStatus::Ok);
                }
                assert_eq!((*target).vcpu.x86_configuration(), Some(config));
                configure(target, 0x1000, 0x80000001, 0, 0);
                step(target);
                let CpuState::X86_64(state) = (*target).vcpu.get_state().unwrap() else {
                    panic!()
                };
                assert_ne!(
                    state.regs.rcx & (1 << 6),
                    0,
                    "SSE4A CPUID capability was lost"
                );
            }
        }
        rax_engine_close(source);
        rax_engine_close(target);
    }
}

#[test]
fn private_user_descriptors_survive_restore_and_memory_reconstruction() {
    let source = open(RAX_MODE_64 | RAX_MODE_USER);
    let target = open(RAX_MODE_64);
    unsafe {
        write(source, 0x1000, &[0x8e, 0xe0, 0xf4]);
        configure(source, 0x1000, 0x63, 0, 0);
        let crate::vcpu::Vcpu::X86User(core) = &mut (*source).vcpu else {
            panic!()
        };
        assert!(core.set_user_tls_entry(12, gdt_entry(0xc0f3, 0x12345000, 0xfffff)));
        assert_eq!(restore(target, &save(source)), RaxStatus::Ok);
        assert_eq!(
            rax_mem_map(target, 0x8000, 0x1000, RAX_PROT_ALL),
            RaxStatus::Ok
        );
        step(source);
        step(target);
        let CpuState::X86_64(a) = (*source).vcpu.get_state().unwrap() else {
            panic!()
        };
        let CpuState::X86_64(b) = (*target).vcpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(a.sregs.fs.base, 0x12345000);
        assert_eq!(b.sregs.fs.base, a.sregs.fs.base);
    }
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn complete_bios_media_and_memory_report_binding_survive_restore_remap_and_reset() {
    let source = open(RAX_MODE_16);
    let target = open(RAX_MODE_16);
    unsafe {
        write(source, 0x100, &[0xcd, 0x13, 0xcd, 0x15, 0xf4]);
        let mut dap = [0; 16];
        dap[0] = 16;
        dap[2] = 1;
        dap[5] = 0x10;
        write(source, 0x800, &dap);
        (*source)
            .vcpu
            .attach_x86_64_bios(Some(Arc::new(vec![0xa5; 2048])), 128 << 20);
        configure(source, 0x100, 0x4200, 0, 0xe0);
        let CpuState::X86_64(mut state) = (*source).vcpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.rsi = 0x800;
        (*source).vcpu.set_state(&CpuState::X86_64(state)).unwrap();
        let raw = save(source);
        assert!(word(&raw, resources_offset(&raw)) > 0);
        assert_eq!(restore(target, &raw), RaxStatus::Ok);
        for stage in 0..4 {
            if stage == 1 {
                assert_eq!(
                    rax_mem_map(target, 0x8000, 0x1000, RAX_PROT_ALL),
                    RaxStatus::Ok
                );
            }
            if stage == 2 {
                assert_eq!(rax_mem_unmap(target, 0x8000, 0x1000), RaxStatus::Ok);
            }
            if stage == 3 {
                assert_eq!(rax_engine_reset(target), RaxStatus::Ok);
            }
            let binding = (*target).vcpu.x86_bios_binding().unwrap();
            assert_eq!(binding.1, 128 << 20);
            assert_eq!(binding.0.unwrap().as_slice(), &[0xa5; 2048]);
            write(target, 0x1000, &[0; 2048]);
            configure(target, 0x100, 0x4200, 0, 0xe0);
            let CpuState::X86_64(mut state) = (*target).vcpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.rsi = 0x800;
            (*target).vcpu.set_state(&CpuState::X86_64(state)).unwrap();
            step(target);
            let mut bytes = [0u8; 2048];
            assert_eq!(
                rax_mem_read(target, 0x1000, bytes.as_mut_ptr().cast(), 2048),
                RaxStatus::Ok
            );
            assert_eq!(bytes, [0xa5; 2048], "stage{stage}");
            configure(target, 0x102, 0xe801, 0, 0);
            step(target);
            let CpuState::X86_64(state) = (*target).vcpu.get_state().unwrap() else {
                panic!()
            };
            // E801 reports 15 MiB in KiB, then 112 MiB in 64 KiB blocks.
            assert_eq!(state.regs.rax & 0xffff, 15360);
            assert_eq!(state.regs.rcx & 0xffff, 15360);
            assert_eq!(state.regs.rbx & 0xffff, 1792);
            assert_eq!(state.regs.rdx & 0xffff, 1792);
        }
    }
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn malformed_full_contexts_and_late_resource_failures_leave_cpu_and_ram_unchanged() {
    let source = open(RAX_MODE_64);
    let target = open(RAX_MODE_64);
    unsafe {
        write(source, 0x1000, &[0x90, 0xf4]);
        configure(source, 0x1000, 0x1234, 0, 0);
        write(target, 0x2000, &[0x55]);
    }
    let raw = save(source);
    let before = save(target);
    for end in 0..raw.len() {
        assert_ne!(restore(target, &raw[..end]), RaxStatus::Ok, "prefix{end}");
    }
    assert_eq!(save(target), before);
    let b = backend_offset(&raw);
    let r = resources_offset(&raw);
    let region = regions_offset(&raw);
    for mutation in 0..7 {
        let mut bad = raw.clone();
        match mutation {
            0 => bad[16..20].copy_from_slice(&0u32.to_le_bytes()),
            1 => bad[b..b + 4].copy_from_slice(&3u32.to_le_bytes()),
            2 => bad[b + 12] ^= 1,
            3 => bad[r..r + 8].copy_from_slice(&u64::MAX.to_le_bytes()),
            4 => bad[region + 8 + 20..region + 8 + 24].copy_from_slice(&1u32.to_le_bytes()),
            5 => {
                let mut state: CpuState =
                    rax_engine::codec::deserialize(&bad[28..28 + word(&bad, 20)]).unwrap();
                let CpuState::X86_64(s) = &mut state else {
                    panic!()
                };
                s.regs.rax ^= 1;
                let changed = rax_engine::codec::serialize(&state).unwrap();
                bad[28..28 + changed.len()].copy_from_slice(&changed);
            }
            6 => bad.push(0),
            _ => unreachable!(),
        }
        assert_ne!(restore(target, &bad), RaxStatus::Ok, "mutation{mutation}");
        assert_eq!(save(target), before);
    }
    unsafe {
        (*source)
            .vcpu
            .attach_x86_64_bios(Some(Arc::new(vec![7; 2048])), 128 << 20);
    }
    let medium = save(source);
    let offset = resources_offset(&medium);
    let length = word(&medium, offset);
    let mut corrupt = medium.clone();
    corrupt[offset + 8 + 24] ^= 1;
    assert_ne!(restore(target, &corrupt), RaxStatus::Ok);
    assert_eq!(save(target), before);
    let mut missing = medium[..offset].to_vec();
    missing.extend_from_slice(&0u64.to_le_bytes());
    missing.extend_from_slice(&medium[offset + 8 + length..]);
    assert_ne!(restore(target, &missing), RaxStatus::Ok);
    assert_eq!(save(target), before);
    rax_engine_close(source);
    rax_engine_close(target);
}

#[test]
fn legacy_x86_projection_stays_readable_with_its_original_xcr0_reset_semantics() {
    let source = open(RAX_MODE_64);
    let target = open(RAX_MODE_64);
    unsafe {
        write(source, 0x1000, &[0x0f, 0x01, 0xd1, 0x0f, 0x01, 0xd0]);
        configure(source, 0x1000, 3, 0, 0);
    }
    step(source);
    let raw = save(source);
    let mut legacy = raw[..backend_offset(&raw)].to_vec();
    legacy[4..8].copy_from_slice(&2u32.to_le_bytes());
    legacy.extend_from_slice(&raw[regions_offset(&raw)..]);
    assert_eq!(restore(target, &legacy), RaxStatus::Ok);
    step(target);
    unsafe {
        let CpuState::X86_64(state) = (*target).vcpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.rax, 1);
    }
    rax_engine_close(source);
    rax_engine_close(target);
}
