//! Exhaustive independent scalar results through every Windows guest ABI.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt;

const SERVICE: u32 = 0xa0;
const LAST_ERROR: u32 = 0x1234_5678;

#[derive(serde::Deserialize)]
struct Capture {
    palette: Vec<Returned>,
    matrix_rows: Vec<String>,
    profiles: Vec<Profile>,
}
#[derive(serde::Deserialize)]
struct Returned {
    status: u32,
    dos_error: u32,
}
#[derive(serde::Deserialize)]
struct Profile {
    architecture: String,
    carrier_cases: Vec<(String, String, usize)>,
}

fn enter(p: &mut Proc, t: &mut Thread, args: [u64; 2]) -> Outcome {
    let last_error = t.teb + layout::offsets(p.arch).teb_last_error;
    p.space.w32(last_error, LAST_ERROR).unwrap();
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr([10, 2][index], value);
            }
        }
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (index, value) in args.into_iter().enumerate() {
                p.space
                    .w32(sp + 8 + index as u64 * 4, value as u32)
                    .unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(result, Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
    t.cpu.set_sp(sp);
    result
}

fn check(p: &mut Proc, t: &mut Thread, args: [u64; 2], expected: &Returned) {
    enter(p, t, args);
    assert_eq!(t.cpu.gpr(0) as u32, expected.status, "{} {args:x?}", p.arch);
    assert_eq!(nt::status_to_error(expected.status), expected.dos_error);
}

#[test]
fn native_compare_signing_levels_replays_all_byte_pairs_and_wide_abi_carriers() {
    let capture: Capture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-compare-signing-levels/observations-v1.json"
    )).unwrap();
    assert_eq!(
        capture
            .profiles
            .iter()
            .map(|p| p.architecture.as_str())
            .collect::<Vec<_>>(),
        ["arm64", "x64", "x86"]
    );
    assert_eq!(capture.matrix_rows.len(), 256);
    assert_eq!(capture.palette.len(), 2);
    assert_eq!(capture.palette[0].status, nt::status::STATUS_SUCCESS);
    assert_eq!(
        capture.palette[1].status,
        nt::status::STATUS_INVALID_IMAGE_HASH
    );
    let mut cases = 0;
    for profile in capture.profiles {
        let arch = match profile.architecture.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown native caller {other}"),
        };
        let (mut process, mut thread) = fixture(arch, "NtCompareSigningLevels", SERVICE);
        let p = process.state_mut();
        let page =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(page, &[0x5a; 4096]).unwrap();
        p.vm.protect(page, 4096, prot::READWRITE | prot::GUARD)
            .unwrap();
        let resources = (p.objects.handle_count(), p.objects.iter().count());
        let mut success = 0;
        for (first, row) in capture.matrix_rows.iter().enumerate() {
            assert_eq!(row.len(), 256);
            for (second, symbol) in row.bytes().enumerate() {
                let index = match symbol {
                    b'0' => 0,
                    b'1' => 1,
                    _ => panic!("invalid native matrix symbol"),
                };
                let expected = &capture.palette[index];
                check(p, &mut thread, [first as u64, second as u64], expected);
                success += usize::from(expected.status == 0);
                cases += 1;
            }
        }
        assert_eq!(success, 22016);
        assert_eq!(profile.carrier_cases.len(), 256);
        for (first, second, index) in profile.carrier_cases {
            let parse =
                |value: &str| u64::from_str_radix(value.strip_prefix("0x").unwrap(), 16).unwrap();
            check(
                p,
                &mut thread,
                [parse(&first), parse(&second)],
                &capture.palette[index],
            );
            cases += 1;
        }
        assert_eq!(p.vm.query(page).unwrap().protect & prot::GUARD, prot::GUARD);
        p.vm.protect(page, 4096, prot::READWRITE).unwrap();
        assert_eq!(p.space.bytes(page, 4096).unwrap(), [0x5a; 4096]);
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            resources
        );
    }
    assert_eq!(cases, 197376);
}

#[test]
fn native_compare_signing_levels_export_keeps_every_prior_ordinal_and_trap() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtCompareSigningLevels"))
        .unwrap();
    assert_eq!(current.exports[family].len(), 1);
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let through_compare = BuiltinDll {
        exports: &current.exports[..=family],
        ..previous
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(&through_compare, arch, 0, &[]);
        assert_eq!(before.ordinal_base, after.ordinal_base);
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(&after.symbols[..before.symbols.len()], before.symbols);
        assert!(dll::nt_service("NtCompareSigningLevels", arch).is_some());
    }
}

#[cfg(windows)]
#[test]
fn native_compare_signing_levels_matches_all_pairs_on_the_live_host_kernel() {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
    }
    let name: Vec<_> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: fixed module/export names and the byte-sized native declaration.
    let compare: unsafe extern "system" fn(u8, u8) -> i32 = unsafe {
        let module = GetModuleHandleW(name.as_ptr());
        assert!(!module.is_null(), "native NTDLL unavailable");
        let entry = GetProcAddress(module, b"NtCompareSigningLevels\0".as_ptr());
        assert!(!entry.is_null(), "native signing comparison unavailable");
        std::mem::transmute(entry)
    };
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let (mut process, mut thread) = fixture(arch, "NtCompareSigningLevels", SERVICE);
    let p = process.state_mut();
    for first in 0..=255u8 {
        for second in 0..=255u8 {
            // SAFETY: only two scalar levels; this query mutates no signing cache.
            let native = unsafe { compare(first, second) } as u32;
            enter(p, &mut thread, [first.into(), second.into()]);
            assert_eq!(thread.cpu.gpr(0) as u32, native, "{first:#x}, {second:#x}");
        }
    }
}
