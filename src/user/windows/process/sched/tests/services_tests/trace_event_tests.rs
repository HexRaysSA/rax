//! Independent native status, RTL, span, alignment and guard observations.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt;

const SERVICE: u32 = 0x5e;
const LAST_ERROR: u32 = 0x1234_5678;
const PROVIDER: [u8; 16] = [
    0x12, 0xe6, 0xc4, 0xc5, 0xde, 0xd6, 0xac, 0x4c, 0xa4, 0xc1, 0x19, 0xcd, 0x76, 0x93, 0x72, 0x16,
];

#[derive(serde::Deserialize)]
struct Capture {
    profiles: Vec<Profile>,
}
#[derive(serde::Deserialize)]
struct Profile {
    architecture: String,
    cases: Vec<Case>,
}
#[derive(serde::Deserialize)]
struct Case {
    group: String,
    index: u64,
    phase: u8,
    flags: u32,
    length: u32,
    status: u32,
    dos_error: u32,
    remaining_guard: u32,
    unchanged: u32,
}

fn enter(p: &mut Proc, t: &mut Thread, args: [u64; 4]) -> Outcome {
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
                t.cpu.set_gpr([10, 2, 8, 9][index], value);
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
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
    t.cpu.set_sp(sp);
    result
}

fn allocate(p: &mut Proc, bytes: u64) -> u64 {
    p.vm.allocate(None, bytes, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

fn inputs(
    p: &mut Proc,
    row: &Case,
    pages: u64,
    fields: u64,
    payload: u64,
) -> ([u64; 4], Option<u64>) {
    let mut header = [0; 128];
    if row.group != "zero" {
        header[40] = 7;
        header[43] = 0x11;
        header[44] = 3;
        header[49] = 2;
        header[55] = 0x20;
        header[84] = 1;
        header[88..96].copy_from_slice(&payload.to_le_bytes());
    }
    if row.group == "nested-unavailable" {
        header[84..88].copy_from_slice(&u32::MAX.to_le_bytes());
        header[88..96].copy_from_slice(&u64::MAX.to_le_bytes());
    }
    p.space.wr(fields, &header).unwrap();
    let (mut provider, mut buffer, mut guard) = (pages, fields, None);
    let max = p.arch.ptr(u64::MAX);
    match row.group.as_str() {
        "zero" | "shape" | "flags" | "flag-bits" | "kind" | "max-size" | "nested-unavailable" => {}
        "provider" => {
            provider = [
                0,
                1,
                pages,
                pages + 1,
                pages + 4080,
                pages + 4081,
                pages + 4096,
                max,
            ][row.index as usize]
        }
        "fields" => {
            buffer = [
                0,
                1,
                fields,
                fields + 1,
                pages + 3976,
                pages + 3977,
                pages + 4096,
                max,
            ][row.index as usize]
        }
        "priority" => {
            provider = [pages, pages + 1, pages + 4096, 0][(row.index % 16 / 4) as usize];
            buffer = [fields, fields + 1, pages + 4096, 0][(row.index % 4) as usize];
        }
        "span" => buffer = pages + 4096 - row.index,
        "provider-span" => provider = pages + 4088,
        "guard" => {
            let page = if row.index < 2 { pages } else { pages + 8192 };
            p.vm.protect(page, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
            guard = Some(page);
            if row.index == 0 {
                buffer = 0;
            }
            if row.index >= 2 {
                buffer = pages + 8192;
            }
            if row.index == 3 {
                provider = 0;
            }
        }
        "provider-align" => provider = pages + row.index,
        "provider-align-null-fields" => {
            provider = pages + row.index;
            buffer = 0;
        }
        "fields-align" => buffer = fields + row.index,
        "null-provider-fields-align" => {
            provider = 0;
            buffer = fields + row.index;
        }
        "flag-bits-null" | "kind-null" => {
            provider = 0;
            buffer = 0;
        }
        other => panic!("unknown native trace-event case {other}"),
    }
    (
        [provider, row.flags.into(), row.length.into(), buffer],
        guard,
    )
}

#[test]
fn native_trace_event_replays_dormant_noreg_validation_and_native_rtl_results() {
    let capture: Capture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-trace-event/observations-v4.json"
    ))
    .unwrap();
    assert_eq!(capture.profiles.len(), 3);
    let (mut replayed, mut explicit_other_kinds) = (0, 0);
    for profile in capture.profiles {
        let arch = match profile.architecture.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown captured caller {other}"),
        };
        assert_eq!(profile.cases.len(), 2337);
        let (mut process, mut thread) = fixture(arch, "NtTraceEvent", SERVICE);
        let p = process.state_mut();
        let pages = allocate(p, 12288);
        let fields = allocate(p, 131072);
        let payload = allocate(p, 4096);
        p.space.wr(pages, &PROVIDER).unwrap();
        p.vm.protect(pages + 4096, 4096, prot::NOACCESS).unwrap();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let (mut phase, mut registration) = (0, None);
        for row in profile.cases {
            if row.phase != phase {
                assert_eq!(row.phase, phase + 1);
                phase = row.phase;
                if phase == 1 {
                    let mut request = Box::new([0; 160]);
                    request[..16].copy_from_slice(&PROVIDER);
                    registration = p.objects.register_etw_provider(request);
                    assert!(registration.is_some());
                } else {
                    p.objects
                        .close(registration.take().unwrap().into())
                        .unwrap();
                }
            }
            let (args, guard) = inputs(p, &row, pages, fields, payload);
            let bytes = p.space.bytes(fields, 128).unwrap();
            let resources = (p.objects.handle_count(), p.objects.iter().count());
            let result = enter(p, &mut thread, args);
            let kind = row.flags & 0xff00;
            if kind == 0x700 || kind == 0 || kind > 0x900 || (kind == 0x900 && arch == WinArch::X86)
            {
                assert_eq!(
                    result,
                    Outcome::Continue,
                    "{arch} {} {} phase{}",
                    row.group,
                    row.index,
                    phase
                );
                assert_eq!(
                    thread.cpu.gpr(0) as u32,
                    row.status,
                    "{arch} {} {} phase{} args={args:x?}",
                    row.group,
                    row.index,
                    phase
                );
                assert_eq!(nt::status_to_error(row.status), row.dos_error);
                replayed += 1;
            } else {
                assert!(
                    matches!(result, Outcome::Fail(ref text) if text.contains("NtTraceEvent flags"))
                );
                explicit_other_kinds += 1;
            }
            if let Some(page) = guard {
                assert_eq!(
                    u32::from(p.vm.query(page).unwrap().protect & prot::GUARD != 0),
                    row.remaining_guard
                );
                p.vm.protect(page, 4096, prot::READWRITE).unwrap();
            }
            assert_eq!(row.unchanged, 1);
            assert_eq!(p.space.bytes(fields, 128).unwrap(), bytes);
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                resources
            );
        }
        assert_eq!(phase, 2);
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            baseline
        );
    }
    assert_eq!(replayed + explicit_other_kinds, 7011);
    assert_eq!(replayed, 6849);
    assert_eq!(explicit_other_kinds, 162);
}

#[test]
fn native_trace_event_appends_one_export_without_changing_prior_ordinals_or_traps() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtTraceEvent"))
        .unwrap();
    assert_eq!(family + 1, current.exports.len());
    assert_eq!(current.exports[family].len(), 1);
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(current, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(&after.symbols[..before.symbols.len()], before.symbols);
        assert!(dll::nt_service("NtTraceEvent", arch).is_some());
    }
}
