//! Public vectored-continue registration through KERNEL32 and KERNELBASE.

use super::super::BuiltinDll;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{Api, Arg, Conv, Ctx, Flow, Item, Value, args::stdcall_bytes};
use crate::user::windows::memory::Mem;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

const ADD_VCH: &str = "AddVectoredContinueHandler";
const REMOVE_VCH: &str = "RemoveVectoredContinueHandler";
const ADD_VEH: &str = "AddVectoredExceptionHandler";
const REMOVE_VEH: &str = "RemoveVectoredExceptionHandler";

fn export(dll: &str, name: &str, arch: WinArch) -> &'static Api {
    let module: &'static BuiltinDll = super::super::find(dll).unwrap();
    let item = module
        .exports
        .iter()
        .flat_map(|table| table.iter())
        .find(|export| export.name == name && export.archs.has(arch))
        .unwrap_or_else(|| panic!("{dll} lacks {name} on {arch}"));
    match &item.item {
        Item::Func(api) => api,
        _ => panic!("{dll}!{name} is not a function on {arch}"),
    }
}

fn with_context(arch: WinArch, test: impl FnOnce(&mut Ctx)) {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::new("vch-api-test.exe", vec![]);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let sp = thread.cpu.sp();
    let mut c = Ctx {
        p,
        t: &mut thread,
        api: export("kernel32.dll", ADD_VEH, arch),
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    };
    test(&mut c);
}

fn integer(c: &mut Ctx, dll: &str, name: &str, values: &[u64]) -> u64 {
    c.api = export(dll, name, c.arch());
    assert_eq!(values.len(), c.api.args.len(), "{dll}!{name} arity");
    for (index, &value) in values.iter().enumerate() {
        match c.arch() {
            // The return address occupies [ESP, ESP+4); stdcall arguments
            // begin at [ESP+4] and each of these parameters occupies 4 B.
            WinArch::X86 => c
                .mem()
                .w32(c.entry_sp + 4 + 4 * index as u64, value as u32)
                .unwrap(),
            WinArch::X64 => c.t.cpu.set_gpr([1, 2, 8, 9][index], value),
            WinArch::Arm64 => c.t.cpu.set_gpr(index, value),
        }
    }
    match (c.api.imp)(c).unwrap() {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("{dll}!{name} did not return an integer"),
    }
}

#[test]
fn both_public_hosts_expose_vch_with_exact_scalar_abi_on_all_architectures() {
    for arch in WinArch::ALL {
        for dll in ["kernel32.dll", "kernelbase.dll"] {
            let add = export(dll, ADD_VCH, arch);
            assert_eq!(add.conv, Conv::Stdcall, "{dll} {arch}");
            assert_eq!(add.args, &[Arg::I32, Arg::Ptr], "{dll} {arch}");
            let remove = export(dll, REMOVE_VCH, arch);
            assert_eq!(remove.conv, Conv::Stdcall, "{dll} {arch}");
            assert_eq!(remove.args, &[Arg::Ptr], "{dll} {arch}");
            if arch == WinArch::X86 {
                assert_eq!(stdcall_bytes(add.args), 8);
                assert_eq!(stdcall_bytes(remove.args), 4);
            }
        }
    }
}

#[test]
fn vch_first_prepends_zero_appends_and_duplicate_callbacks_have_distinct_handles() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let first = integer(c, "kernel32.dll", ADD_VCH, &[0, 0x1000]);
            let duplicate = integer(c, "kernelbase.dll", ADD_VCH, &[0, 0x1000]);
            let prepend = integer(c, "kernel32.dll", ADD_VCH, &[1, 0x2000]);
            let nonzero = integer(c, "kernelbase.dll", ADD_VCH, &[2, 0x3000]);
            assert_ne!(first, 0, "{arch}");
            assert_ne!(duplicate, 0, "{arch}");
            assert_ne!(first, duplicate, "{arch}: duplicate callback pointer");
            assert_eq!(
                c.p.seh.vch,
                vec![
                    (nonzero, 0x3000),
                    (prepend, 0x2000),
                    (first, 0x1000),
                    (duplicate, 0x1000),
                ],
                "{arch}"
            );
            assert!(c.p.seh.veh.is_empty(), "{arch}");
            if arch.is64() {
                let high_only = integer(c, "kernel32.dll", ADD_VCH, &[0x1_0000_0000, 0x4000]);
                assert_eq!(c.p.seh.vch.last(), Some(&(high_only, 0x4000)));
            }
        });
    }
}

#[test]
fn vch_and_veh_handles_are_disjoint_and_removal_is_family_specific() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let veh = integer(c, "kernel32.dll", ADD_VEH, &[0, 0x5000]);
            let vch = integer(c, "kernelbase.dll", ADD_VCH, &[0, 0x5000]);
            assert_ne!(veh, 0, "{arch}");
            assert_ne!(vch, 0, "{arch}");
            assert_ne!(veh, vch, "{arch}: shared allocator");
            let before_veh = c.p.seh.veh.clone();
            let before_vch = c.p.seh.vch.clone();
            assert_eq!(integer(c, "kernel32.dll", REMOVE_VCH, &[veh]), 0);
            assert_eq!(integer(c, "kernelbase.dll", REMOVE_VEH, &[vch]), 0);
            assert_eq!(integer(c, "kernel32.dll", REMOVE_VCH, &[0]), 0);
            assert_eq!(c.p.seh.veh, before_veh, "{arch}");
            assert_eq!(c.p.seh.vch, before_vch, "{arch}");
            assert_eq!(integer(c, "kernel32.dll", REMOVE_VCH, &[vch]), 1);
            assert!(c.p.seh.vch.is_empty(), "{arch}");
            assert_eq!(integer(c, "kernelbase.dll", REMOVE_VCH, &[vch]), 0);
            assert_eq!(c.p.seh.veh, before_veh, "{arch}");
            assert_eq!(integer(c, "kernelbase.dll", REMOVE_VEH, &[veh]), 1);
            assert!(c.p.seh.veh.is_empty(), "{arch}");
            assert_eq!(integer(c, "kernel32.dll", REMOVE_VEH, &[veh]), 0);
        });
    }
}

#[test]
fn x86_shared_handle_space_accepts_last_slot_then_exhausts_without_mutation() {
    with_context(WinArch::X86, |c| {
        c.p.seh.next_handle = 0xffff_fff8;
        let last = integer(c, "kernelbase.dll", ADD_VCH, &[0, 0x6000]);
        assert_eq!(last, 0xffff_fffc);
        assert_eq!(c.p.seh.next_handle, last);
        let before_vch = c.p.seh.vch.clone();
        let before_veh = c.p.seh.veh.clone();
        assert_eq!(integer(c, "kernel32.dll", ADD_VEH, &[1, 0x7000]), 0);
        assert_eq!(integer(c, "kernel32.dll", ADD_VCH, &[1, 0x8000]), 0);
        assert_eq!(c.p.seh.next_handle, last);
        assert_eq!(c.p.seh.vch, before_vch);
        assert_eq!(c.p.seh.veh, before_veh);
        assert_eq!(integer(c, "kernelbase.dll", REMOVE_VCH, &[last]), 1);
        assert_eq!(integer(c, "kernel32.dll", ADD_VCH, &[0, 0x9000]), 0);
        assert!(c.p.seh.vch.is_empty());
    });
}

#[test]
fn win64_shared_handle_space_accepts_last_slot_then_exhausts_without_mutation() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        with_context(arch, |c| {
            c.p.seh.next_handle = u64::MAX - 7;
            let last = integer(c, "kernelbase.dll", ADD_VCH, &[0, 0x6000]);
            assert_eq!(last, 0xffff_ffff_ffff_fffc, "{arch}");
            assert_eq!(c.p.seh.next_handle, last, "{arch}");
            let before_vch = c.p.seh.vch.clone();
            let before_veh = c.p.seh.veh.clone();
            assert_eq!(integer(c, "kernel32.dll", ADD_VCH, &[1, 0x7000]), 0);
            assert_eq!(integer(c, "kernel32.dll", ADD_VEH, &[1, 0x8000]), 0);
            assert_eq!(c.p.seh.next_handle, last, "{arch}");
            assert_eq!(c.p.seh.vch, before_vch, "{arch}");
            assert_eq!(c.p.seh.veh, before_veh, "{arch}");
        });
    }
}

#[test]
fn cross_family_handle_collision_fails_closed_without_mutation() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let veh = integer(c, "kernel32.dll", ADD_VEH, &[0, 0x5000]);
            assert_ne!(veh, 0, "{arch}");
            c.p.seh.next_handle = veh - 4;
            let before_veh = c.p.seh.veh.clone();
            let before_vch = c.p.seh.vch.clone();
            let before_next = c.p.seh.next_handle;
            assert_eq!(integer(c, "kernelbase.dll", ADD_VCH, &[0, 0x6000]), 0);
            assert_eq!(c.p.seh.veh, before_veh, "{arch}");
            assert_eq!(c.p.seh.vch, before_vch, "{arch}");
            assert_eq!(c.p.seh.next_handle, before_next, "{arch}");

            c.p.seh.next_handle = veh;
            let vch = integer(c, "kernelbase.dll", ADD_VCH, &[0, 0x7000]);
            assert_ne!(vch, 0, "{arch}");
            assert_ne!(vch, veh, "{arch}");
            c.p.seh.next_handle = vch - 4;
            let before_veh = c.p.seh.veh.clone();
            let before_vch = c.p.seh.vch.clone();
            let before_next = c.p.seh.next_handle;
            assert_eq!(integer(c, "kernel32.dll", ADD_VEH, &[0, 0x8000]), 0);
            assert_eq!(c.p.seh.veh, before_veh, "{arch}");
            assert_eq!(c.p.seh.vch, before_vch, "{arch}");
            assert_eq!(c.p.seh.next_handle, before_next, "{arch}");
        });
    }
}

#[test]
fn null_vectored_callback_is_rejected_without_consuming_a_registration_handle() {
    for arch in WinArch::ALL {
        with_context(arch, |c| {
            let before = c.p.seh.next_handle;
            assert_eq!(integer(c, "kernel32.dll", ADD_VCH, &[0, 0]), 0, "{arch}");
            assert_eq!(integer(c, "kernelbase.dll", ADD_VEH, &[1, 0]), 0, "{arch}");
            assert_eq!(c.p.seh.next_handle, before, "{arch}");
            assert!(c.p.seh.vch.is_empty(), "{arch}");
            assert!(c.p.seh.veh.is_empty(), "{arch}");
        });
    }
}
