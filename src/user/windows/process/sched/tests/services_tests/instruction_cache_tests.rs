//! Independent NT/Win32 controls replayed through the guest service boundary.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::mm::CodeChanges;
use crate::user::windows::arch::CpuStop;
use crate::user::windows::dll::{self, BuiltinDll};
use crate::user::windows::hle::{Api, Ctx, Flow, Item, Value};
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt;
use crate::user::windows::objects::Object;

const SERVICE: u32 = 0xf0;
const LAST_ERROR: u32 = 0x1234_5678;
const GUARDS: [u64; 3] = [12288, 24576, 28672];
const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

#[derive(serde::Deserialize)]
struct Capture {
    state: String,
    profiles: Vec<Profile>,
}
#[derive(serde::Deserialize)]
struct Profile {
    architecture: String,
    handles: Vec<Handle>,
    lengths_hex: Vec<String>,
    address_kinds: usize,
    palette: Vec<[u32; 8]>,
    matrix_rows: Vec<String>,
    native_calls: usize,
}
#[derive(serde::Deserialize)]
struct Handle {
    kind: String,
    granted: u32,
    tag: u32,
}

fn arguments(p: &Proc, t: &mut Thread, args: [u64; 3], native: bool) {
    let sp = t.cpu.sp();
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            if native {
                p.space.w32(sp + 4, 0x1234_0000).unwrap();
            }
            for (index, value) in args.into_iter().enumerate() {
                p.space
                    .w32(
                        sp + if native { 8 } else { 4 } + index as u64 * 4,
                        value as u32,
                    )
                    .unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu
                    .set_gpr([if native { 10 } else { 1 }, 2, 8][index], value);
            }
            if native {
                t.cpu.set_gpr(0, SERVICE.into());
                t.cpu.set_gpr(1, 0x1234_0004);
            }
        }
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
    }
}

fn native_call(p: &mut Proc, t: &mut Thread, args: [u64; 3]) -> Outcome {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    arguments(p, t, args, true);
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}

fn win32_api() -> &'static Api {
    dll::find("kernel32.dll")
        .unwrap()
        .exports
        .iter()
        .flat_map(|table| table.iter())
        .find_map(|export| match &export.item {
            Item::Func(api) if api.name == "FlushInstructionCache" => Some(api),
            _ => None,
        })
        .unwrap()
}

fn builtin_call(p: &mut Proc, t: &mut Thread, api: &'static Api, args: [u64; 3]) -> u32 {
    arguments(p, t, args, false);
    let sp = t.cpu.sp();
    let mut context = Ctx {
        p,
        t,
        api,
        entry_pc: 0x1234_0000,
        entry_sp: sp,
        ret_addr: 0x1234_0004,
        cursor: sp,
    };
    let Flow::Ret(Value::Int(value)) = (api.imp)(&mut context).unwrap() else {
        panic!("integer return")
    };
    value as u32
}

fn open(p: &mut Proc, object: Object, access: u32) -> u64 {
    let id = p.objects.create(object);
    p.objects.open_access(id, false, access).unwrap().into()
}

fn handles(p: &mut Proc, t: &Thread, descriptors: &[Handle]) -> Vec<u64> {
    let mut full = 0;
    descriptors
        .iter()
        .map(|h| match h.kind.as_str() {
            "pseudo_process" => p.arch.ptr(u64::MAX),
            "pseudo_thread" => p.arch.ptr(u64::MAX - 1),
            "null" => 0,
            "invalid" => 0x1000_0000,
            "process_high_carrier" => full | (1 << 32),
            "process" if h.tag != 0 => full | u64::from(h.tag),
            "process" => {
                let pid = p.pid;
                let handle = open(
                    p,
                    Object::Process {
                        pid,
                        exit_code: None,
                    },
                    h.granted,
                );
                if h.granted == 0x1f_ffff {
                    full = handle;
                }
                handle
            }
            "event" | "closed" => {
                let handle = open(
                    p,
                    Object::Event {
                        manual: true,
                        signaled: 0,
                    },
                    h.granted,
                );
                if h.kind == "closed" {
                    p.objects.close(handle).unwrap();
                }
                handle
            }
            "thread" => open(
                p,
                Object::Thread {
                    tid: t.tid,
                    exit_code: None,
                },
                h.granted,
            ),
            other => panic!("native handle kind {other}"),
        })
        .collect()
}

fn address(arch: WinArch, kind: usize, base: u64, reserved: u64, hole: u64) -> u64 {
    let probe = if arch == WinArch::X86 {
        0x7fff_0000
    } else {
        0x7fff_ffff_0000
    };
    match kind {
        0 => 0,
        1 => 1,
        2 => base + 128,
        3 => base + 8192,
        4 => hole,
        5 => reserved,
        6 => base + 12288,
        7 => base + 20480,
        8 => base + 16384,
        9 => base + 8191,
        10 => arch.ptr(u64::MAX),
        11 => probe,
        12 => {
            if arch == WinArch::X86 {
                0x8000_0000
            } else {
                0x8000_0000_0000
            }
        }
        13 => {
            if arch == WinArch::X86 {
                0xffff_0000
            } else {
                0x1_0000_0000_0000
            }
        }
        14 => {
            if arch == WinArch::X86 {
                0xffff_fffe
            } else {
                0xffff_8000_0000_0000
            }
        }
        15 => probe - 1,
        16 => probe - 2,
        17 => probe - 64,
        18 => probe - 4096,
        19 => base + 16383,
        20 => base + 24576,
        21 => base + 28672,
        22 => base + 12287,
        23 => base + 24575,
        other => panic!("native address kind {other}"),
    }
}

fn replay(capture: Capture) -> usize {
    assert_eq!(capture.state, "complete");
    assert!((2..=3).contains(&capture.profiles.len()));
    let mut count = 0;
    for profile in capture.profiles {
        let arch = match profile.architecture.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("native architecture {other}"),
        };
        assert_eq!(profile.address_kinds, 24);
        assert_eq!(profile.lengths_hex.len(), 15);
        assert_eq!(profile.matrix_rows.len(), profile.handles.len());
        let (mut process, mut t) = fixture(arch, "NtFlushInstructionCache", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 32768, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(base, &[0xa5; 32768]).unwrap();
        p.vm.protect(base + 8192, 4096, prot::NOACCESS).unwrap();
        p.vm.protect(base + 16384, 4096, prot::EXECUTE_READ)
            .unwrap();
        p.vm.protect(base + 20480, 4096, prot::READONLY).unwrap();
        let reserved =
            p.vm.allocate(None, 65536, mem::RESERVE, prot::NOACCESS)
                .unwrap()
                .0;
        let hole =
            p.vm.allocate(None, 65536, mem::RESERVE, prot::NOACCESS)
                .unwrap()
                .0;
        p.vm.release(hole).unwrap();
        let handles = handles(p, &t, &profile.handles);
        let resources = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        let last = t.teb + layout::offsets(arch).teb_last_error;
        let mut cases = 0;
        for (h, codes) in profile.matrix_rows.iter().enumerate() {
            assert_eq!(codes.len(), 24 * 15);
            for (position, symbol) in codes.bytes().enumerate() {
                let pair = profile.palette[ALPHABET.iter().position(|&c| c == symbol).unwrap()];
                let kind = position / 15;
                let length = u64::from_str_radix(
                    profile.lengths_hex[position % 15].trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                let args = [
                    handles[h],
                    address(arch, kind, base, reserved, hole),
                    length,
                ];
                for win32 in [false, true] {
                    for offset in GUARDS {
                        p.vm.protect(base + offset, 4096, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    p.space.w32(last, LAST_ERROR).unwrap();
                    let result = if win32 {
                        builtin_call(p, &mut t, win32_api(), args)
                    } else {
                        assert_eq!(
                            native_call(p, &mut t, args),
                            Outcome::Continue,
                            "{arch}/{h}/{kind}/{length:x}"
                        );
                        t.cpu.gpr(0) as u32
                    };
                    let offset = if win32 { 4 } else { 0 };
                    assert_eq!(result, pair[offset], "{arch}/{h}/{kind}/{length:x}/{win32}");
                    if !win32 {
                        assert_eq!(nt::status_to_error(result), pair[1]);
                    }
                    assert_eq!(p.space.u32(last).unwrap(), pair[offset + 2]);
                    let mask = GUARDS.iter().enumerate().fold(0, |mask, (index, offset)| {
                        mask | (u32::from(
                            p.vm.page_state(base + offset).unwrap().protect & prot::GUARD != 0,
                        ) << index)
                    });
                    assert_eq!(
                        mask,
                        pair[offset + 3],
                        "{arch}/{h}/{kind}/{length:x}/{win32}"
                    );
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, profile.native_calls);
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes()
            ),
            resources
        );
        p.vm.protect(base, 32768, prot::READWRITE).unwrap();
        assert_eq!(p.space.bytes(base, 32768).unwrap(), [0xa5; 32768]);
        count += cases;
    }
    count
}

#[test]
fn native_instruction_cache_replays_all_independent_nt_and_win32_cases() {
    let retained = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-instruction-cache/observations-v1.json"
    )))
    .unwrap();
    assert_eq!(replay(retained), 68400);
    if let Some(path) = std::env::var_os("RAX_INSTRUCTION_CACHE_CORPUS") {
        let fresh: Capture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let calls: usize = fresh
            .profiles
            .iter()
            .map(|profile| profile.native_calls)
            .sum();
        assert!(calls >= 45360);
        assert_eq!(replay(fresh), calls);
    }
}

#[test]
fn native_instruction_cache_export_preserves_earlier_ordinals_and_traps() {
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtFlushInstructionCache"))
        .unwrap();
    assert_eq!(current.exports[family].len(), 1);
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let updated = BuiltinDll {
        exports: &current.exports[..=family],
        ..previous
    };
    for arch in WinArch::ALL {
        let before = crate::user::windows::loader::builtin::build(&previous, arch, 0, &[]);
        let after = crate::user::windows::loader::builtin::build(&updated, arch, 0, &[]);
        assert_eq!(before.ordinal_base, after.ordinal_base);
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(&after.symbols[..before.symbols.len()], before.symbols);
        assert!(dll::nt_service("NtFlushInstructionCache", arch).is_some());
    }
}

#[test]
fn native_instruction_cache_synchronizes_raw_code_changes_in_both_thread_cpus() {
    for arch in WinArch::ALL {
        for whole in [false, true] {
            let (mut process, mut t) = fixture(arch, "NtFlushInstructionCache", SERVICE);
            let p = process.state_mut();
            let code =
                p.vm.allocate(
                    None,
                    4096,
                    mem::RESERVE | mem::COMMIT,
                    prot::EXECUTE_READWRITE,
                )
                .unwrap()
                .0;
            let encode = |n: u8| {
                if arch == WinArch::Arm64 {
                    (0xd280_0000u32 | (u32::from(n) << 5))
                        .to_le_bytes()
                        .to_vec()
                } else {
                    vec![0xb8, n, 0, 0, 0]
                }
            };
            p.space.wr(code, &encode(1)).unwrap();
            let mut peer = t.cpu.new_thread();
            for cpu in [&mut t.cpu, &mut peer] {
                cpu.set_pc(code);
                assert!(matches!(cpu.run(1), CpuStop::Yield));
                assert_eq!(cpu.gpr(0), 1);
            }
            let physical = p
                .space
                .translate(code, crate::error::MemoryAccessKind::Write)
                .unwrap();
            let epoch = p.space.code_epoch();
            p.space.store_phys(physical, &encode(2));
            assert_eq!(p.space.code_epoch(), epoch, "controlled untracked writer");
            let (base, size) = if whole { (0, u64::MAX) } else { (code, 5) };
            assert_eq!(
                native_call(p, &mut t, [arch.ptr(u64::MAX), base, size]),
                Outcome::Continue
            );
            assert_eq!(t.cpu.gpr(0), 0);
            assert!(matches!(
                p.space.code_changes_since(epoch).0,
                CodeChanges::Ranges(_)
            ));
            for cpu in [&mut t.cpu, &mut peer] {
                cpu.set_pc(code);
                assert!(matches!(cpu.run(1), CpuStop::Yield));
                assert_eq!(cpu.gpr(0), 2, "{arch}/{whole}");
            }
        }
    }
}

#[test]
fn native_instruction_cache_x86_ignores_inaccessible_argument_slots() {
    let (mut process, mut t) = fixture(WinArch::X86, "NtFlushInstructionCache", SERVICE);
    let p = process.state_mut();
    let base =
        p.vm.allocate(
            None,
            4096,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE | prot::GUARD,
        )
        .unwrap()
        .0;
    let epoch = p.space.code_epoch();
    let api = dll::nt_service("NtFlushInstructionCache", WinArch::X86).unwrap();
    let mut c = Ctx {
        p,
        t: &mut t,
        api,
        entry_pc: 0,
        entry_sp: base - 4,
        ret_addr: 0,
        cursor: base - 4,
    };
    assert!(matches!(
        (api.imp)(&mut c).unwrap(),
        Flow::Ret(Value::Int(0))
    ));
    assert_eq!(
        c.p.vm.page_state(base).unwrap().protect & prot::GUARD,
        prot::GUARD
    );
    assert!(c.p.space.code_epoch() > epoch);
}

#[test]
fn native_instruction_cache_other_process_is_explicit_and_failed_calls_preserve_state() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        let (mut process, mut t) = fixture(arch, "NtFlushInstructionCache", SERVICE);
        let p = process.state_mut();
        let pid = p.pid + 1;
        let handle = open(
            p,
            Object::Process {
                pid,
                exit_code: None,
            },
            0x20,
        );
        let epoch = p.space.code_epoch();
        assert!(
            matches!(native_call(p, &mut t, [handle, 0, 0]), Outcome::Fail(reason) if reason.contains("another guest process"))
        );
        assert_eq!(p.space.code_epoch(), epoch);
    }
}

#[test]
fn native_instruction_cache_sparse_ranges_use_actual_first_guard_and_preserve_later_guards() {
    for arch in [WinArch::X64, WinArch::Arm64] {
        let (mut process, mut t) = fixture(arch, "NtFlushInstructionCache", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.vm.protect(base + 4096, 4096, prot::READWRITE | prot::GUARD)
            .unwrap();
        p.vm.protect(base + 8192, 4096, prot::READWRITE | prot::GUARD)
            .unwrap();
        // A reported guard on an ordinary page must not hide a later actual
        // guard, even when that actual guard is reported without the flag.
        p.vm.set_reported(base, 4096, prot::READWRITE | prot::GUARD);
        p.vm.set_reported(base + 4096, 4096, prot::READWRITE);
        let epoch = p.space.code_epoch();
        let committed = p.vm.committed_bytes();
        assert_eq!(native_call(p, &mut t, [0, base, 1]), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(nt::status::STATUS_INVALID_HANDLE));
        assert_eq!(p.space.code_epoch(), epoch);
        assert_eq!(
            native_call(
                p,
                &mut t,
                [arch.ptr(u64::MAX), base, 0x7fff_ffff_0000 - base]
            ),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(p.vm.page_state(base).unwrap().protect & prot::GUARD, 0);
        assert_eq!(p.vm.query(base).unwrap().protect & prot::GUARD, prot::GUARD);
        assert_eq!(
            p.vm.page_state(base + 4096).unwrap().protect & prot::GUARD,
            0
        );
        assert_eq!(
            p.vm.page_state(base + 8192).unwrap().protect & prot::GUARD,
            prot::GUARD
        );
        assert_eq!(p.vm.committed_bytes(), committed);
        assert_eq!(
            native_call(p, &mut t, [arch.ptr(u64::MAX), 0, u64::MAX]),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(
            p.vm.page_state(base + 8192).unwrap().protect & prot::GUARD,
            prot::GUARD
        );
        assert_eq!(p.vm.committed_bytes(), committed);
    }
}
