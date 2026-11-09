//! Native buffer publication is distinct from modeled guest counter values.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::dll;
use crate::user::windows::hle::{Ctx, Flow, Value};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::{layout, nt};

const SERVICE: u32 = 0x36; // Fixture-owned identity, not a host table lookup.
const LAST_ERROR: u32 = 0x1234_5678;

#[derive(serde::Deserialize)]
struct Capture {
    palette: Vec<Returned>,
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
    pointer_bytes: usize,
    bytes_palette: Vec<String>,
    row_bytes_indices: Vec<usize>,
}

fn prepare(p: &Proc, t: &mut Thread, args: [u64; 4], native: bool) {
    let sp = t.cpu.sp();
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr([1, 2, 8, 9][index], value);
            }
            t.cpu.set_gpr(10, args[0]);
            t.cpu.set_gpr(0, SERVICE.into());
        }
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
    }
}

fn native_call(p: &mut Proc, t: &mut Thread, args: [u64; 4]) -> u32 {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    t.cpu.set_gpr(1, 0x1234_0004);
    prepare(p, t, args, true);
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(outcome, Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

fn decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len(), 128);
    (0..value.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&value[n..n + 2], 16).unwrap())
        .collect()
}

#[test]
fn memory_usage_replays_all_native_destinations_lengths_guards_and_aliases() {
    let capture: Capture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-memory-usage/observations-v1.json"
    ))
    .unwrap();
    let mut rows: Vec<[u32; 9]> = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-memory-usage/cases-0-v1.json"
    ))
    .unwrap();
    rows.extend(
        serde_json::from_str::<Vec<[u32; 9]>>(include_str!(
            "../../../../../../../docs/specifications/windows/native-memory-usage/cases-1-v1.json"
        ))
        .unwrap(),
    );
    assert_eq!(rows.len(), 2450);
    assert_eq!(capture.profiles.len(), 3);
    let mut count = 0;
    for profile in capture.profiles {
        let arch = match profile.architecture.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown capture architecture {other}"),
        };
        assert_eq!(
            profile.pointer_bytes,
            if arch == WinArch::X86 { 4 } else { 8 }
        );
        assert_eq!(profile.row_bytes_indices.len(), rows.len());
        let (mut process, mut thread) = fixture(arch, "NtQuerySystemInformation", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 32768, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let last_error = thread.teb + layout::offsets(arch).teb_last_error;
        let objects = (p.objects.handle_count(), p.objects.iter().count());
        for (index, row) in rows.iter().enumerate() {
            let [
                kind,
                bytes,
                offset,
                ret_kind,
                pattern,
                status_index,
                returned,
                buffer_guard,
                return_guard,
            ] = *row;
            p.vm.protect(base, 32768, prot::READWRITE).unwrap();
            p.space.wr(base, &[0xa5; 32768]).unwrap();
            let output = match kind {
                0 => 0,
                1 => 1,
                2 | 5 => base + 128 + u64::from(offset),
                3 => base + 8192 + u64::from(offset),
                4 => base + 12288 + u64::from(offset),
                6 | 7 => base + 4096 - u64::from(offset),
                _ => panic!("buffer kind {kind}"),
            };
            let observed = if kind <= 1 { base + 128 } else { output };
            p.space
                .wr(observed, &[if pattern == 0 { 0 } else { 0xa5 }; 64])
                .unwrap();
            let ret = match ret_kind {
                0 => 0,
                2 => 1,
                3 => base + 5 * 4096,
                4 => base + 6 * 4096,
                5 => base + 4 * 4096 + 129,
                6 => output,
                7 => output + profile.pointer_bytes as u64,
                9 => base + 5 * 4096 - 3,
                1 | 8 => base + 4 * 4096 + 128,
                _ => panic!("return kind {ret_kind}"),
            };
            let ret_observed = if ret_kind == 0 || ret_kind == 2 {
                base + 4 * 4096 + 128
            } else {
                ret
            };
            if ret_kind != 6 && ret_kind != 7 {
                p.space.w32(ret_observed, 0xaabb_ccdd).unwrap();
            }
            for (page, protection) in [
                (2, prot::READONLY),
                (3, prot::NOACCESS),
                (5, prot::READONLY),
                (6, prot::NOACCESS),
            ] {
                p.vm.protect(base + page * 4096, 4096, protection).unwrap();
            }
            if kind == 5 || kind == 7 {
                p.vm.protect(base, 4096, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            if kind == 6 {
                p.vm.protect(base + 4096, 4096, prot::NOACCESS).unwrap();
            }
            if ret_kind == 8 {
                p.vm.protect(base + 4 * 4096, 4096, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            let native = decode(&profile.bytes_palette[profile.row_bytes_indices[index]]);
            let mut provider: [u8; 56] = native[..56].try_into().unwrap();
            if ret_kind == 6 || ret_kind == 7 {
                let at = if ret_kind == 6 {
                    0
                } else {
                    profile.pointer_bytes
                };
                // Distinct pre-store bytes prove ReturnLength wins an alias.
                provider[at..at + 4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            }
            p.space.w32(last_error, LAST_ERROR).unwrap();
            prepare(p, &mut thread, [182, output, bytes.into(), ret], false);
            let sp = thread.cpu.sp();
            let mut context = Ctx {
                p,
                t: &mut thread,
                api: dll::nt_service("NtQuerySystemInformation", arch).unwrap(),
                entry_pc: 0x1234_0000,
                entry_sp: sp,
                ret_addr: 0x1234_0004,
                cursor: sp - 32,
            };
            let mut acquired = 0;
            let result = dll::memory_usage_replay(&mut context, |_| {
                acquired += 1;
                Ok(provider)
            })
            .unwrap();
            let Flow::Ret(Value::Int(status)) = result else {
                panic!("unexpected query result")
            };
            let expected = &capture.palette[status_index as usize];
            assert_eq!(status as u32, expected.status, "{arch} row{index}");
            assert_eq!(nt::status_to_error(status as u32), expected.dos_error);
            assert_eq!(
                acquired,
                usize::from(expected.status == 0),
                "{arch} row{index}"
            );
            assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
            assert_eq!(
                u32::from(p.vm.query(base).unwrap().protect & prot::GUARD != 0),
                buffer_guard,
                "{arch} row{index}"
            );
            assert_eq!(
                u32::from(p.vm.query(base + 4 * 4096).unwrap().protect & prot::GUARD != 0),
                return_guard,
                "{arch} row{index}"
            );
            p.vm.protect(base, 32768, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.u32(ret_observed).unwrap(),
                returned,
                "{arch} row{index}"
            );
            assert_eq!(
                p.space.bytes(observed, 64).unwrap(),
                native,
                "{arch} row{index}"
            );
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                objects
            );
            count += 1;
        }
    }
    assert_eq!(count, 7350);
}

#[test]
fn memory_usage_native_dispatch_tracks_guest_budget_basic_and_shared_data() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtQuerySystemInformation", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let initial = p.vm.memory_usage().unwrap();
        let extra =
            p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        for releasing in [false, true] {
            if releasing {
                p.vm.release(extra).unwrap();
            }
            let expected = p.vm.memory_usage().unwrap();
            let last_error = thread.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(last_error, LAST_ERROR).unwrap();
            p.space.wr(base, &[0xa5; 64]).unwrap();
            assert_eq!(native_call(p, &mut thread, [182, base, 56, base + 128]), 0);
            assert_eq!(p.space.bytes(base, 56).unwrap(), expected.to_bytes());
            assert_eq!(p.space.bytes(base + 56, 8).unwrap(), [0xa5; 8]);
            assert_eq!(p.space.u32(base + 128).unwrap(), 56);
            assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
            assert_eq!(
                expected.committed_bytes,
                initial.committed_bytes + if releasing { 0 } else { 8192 }
            );
            let basic_bytes = if arch == WinArch::X86 { 44 } else { 64 };
            assert_eq!(
                native_call(p, &mut thread, [0, base, basic_bytes, base + 128]),
                0
            );
            assert_eq!(
                u64::from(p.space.u32(base + 12).unwrap()) * 4096,
                expected.total_physical_bytes
            );
            assert_eq!(
                u64::from(
                    p.space
                        .u32(layout::KUSER_SHARED_DATA + layout::kuser::NUMBER_OF_PHYSICAL_PAGES)
                        .unwrap()
                ) * 4096,
                expected.total_physical_bytes
            );
        }
    }
}
