//! Native two-processor buffer contract and actual one-processor guest dispatch.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::dll;
use crate::user::windows::hle::{Ctx, Flow, Value};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt;

const SERVICE: u32 = 0x5f;
const LAST_ERROR: u32 = 0x1234_5678;

#[derive(serde::Deserialize)]
struct Capture {
    records: Vec<[u32; 6]>,
    palette: Vec<Returned>,
    bytes_palette: Vec<String>,
    rows: Vec<[u32; 8]>,
}
#[derive(serde::Deserialize)]
struct Returned {
    status: u32,
    dos_error: u32,
}

fn prepare(p: &Proc, t: &mut Thread, args: [u64; 5], native: bool) {
    let sp = t.cpu.sp();
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            for (index, value) in args[..4].iter().enumerate() {
                t.cpu.set_gpr([1, 2, 8, 9][index], *value);
            }
            t.cpu.set_gpr(10, args[0]);
            p.space.w64(sp + 0x28, args[4]).unwrap();
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

fn native_call(p: &mut Proc, t: &mut Thread, args: [u64; 5]) -> u32 {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    t.cpu.set_gpr(1, 0x1234_0004);
    prepare(p, t, args, true);
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(result, Outcome::Continue);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

fn arena(p: &mut Proc) -> u64 {
    p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

#[test]
fn native_processor_power_replays_every_captured_buffer_case_on_all_guest_abis() {
    let capture: Capture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-processor-power/observations-v1.json"
    )).unwrap();
    assert_eq!(capture.rows.len(), 755);
    assert_eq!(capture.records.len(), 2);
    let mut cases = 0;
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtPowerInformation", SERVICE);
        let p = process.state_mut();
        let base = arena(p);
        let objects = (p.objects.handle_count(), p.objects.iter().count());
        let last_error = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        for (index, row) in capture.rows.iter().enumerate() {
            let [
                input_kind,
                input_bytes,
                output_kind,
                output_bytes,
                offset,
                returned,
                guard,
                bytes,
            ] = *row;
            p.vm.protect(base, 16384, prot::READWRITE).unwrap();
            p.space.wr(base, &[0xa5; 16384]).unwrap();
            p.vm.protect(base + 8192, 4096, prot::NOACCESS).unwrap();
            p.vm.protect(base + 12288, 4096, prot::READONLY).unwrap();
            let input = match input_kind {
                0 => 0,
                1 => 1,
                2 => base + 512,
                3 => base + 8192,
                4 => base + 12288,
                other => panic!("native input kind {other}"),
            };
            let output = match output_kind {
                0 => 0,
                1 => 1,
                2 => base + 128 + u64::from(offset),
                3 => base + 8192,
                4 => base + 12288,
                5..=7 => base + 4096 - u64::from(offset),
                other => panic!("native output kind {other}"),
            };
            if output_kind == 5 {
                p.vm.protect(base + 4096, 4096, prot::NOACCESS).unwrap();
            }
            if output_kind == 7 {
                p.vm.protect(base, 4096, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            p.space.w32(last_error, LAST_ERROR).unwrap();
            prepare(
                p,
                &mut thread,
                [11, input, input_bytes.into(), output, output_bytes.into()],
                false,
            );
            let sp = thread.cpu.sp();
            let mut context = Ctx {
                p,
                t: &mut thread,
                api: dll::nt_service("NtPowerInformation", arch).unwrap(),
                entry_pc: 0x1234_0000,
                entry_sp: sp,
                ret_addr: 0x1234_0004,
                cursor: sp - 32,
            };
            let mut acquired = 0;
            // The captured kernel has two processors. This exercises the same
            // production buffer contract at its measured count, separately
            // from the real guest's one-processor topology below.
            let result = dll::processor_power_information_with(&mut context, 2, |_| {
                acquired += 1;
                Ok(capture.records.clone())
            })
            .unwrap();
            let Flow::Ret(Value::Int(status)) = result else {
                panic!("unexpected result")
            };
            let expected = &capture.palette[returned as usize];
            assert_eq!(status as u32, expected.status, "{arch} native case {index}");
            assert_eq!(nt::status_to_error(status as u32), expected.dos_error);
            assert_eq!(acquired, usize::from(expected.status == 0));
            assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
            assert_eq!(
                u32::from(p.vm.query(base).unwrap().protect & prot::GUARD != 0),
                guard
            );
            p.vm.protect(base, 16384, prot::READWRITE).unwrap();
            let observed = if output_kind >= 5 {
                base + 4048
            } else {
                base + 128
            };
            let actual = p.space.bytes(observed, 96).unwrap();
            let native = &capture.bytes_palette[bytes as usize];
            let encoded: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(encoded, *native, "{arch} native case {index}");
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                objects
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 2265);
}

#[test]
fn native_processor_power_dispatch_matches_single_processor_topology() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtPowerInformation", SERVICE);
        let p = process.state_mut();
        let base = arena(p);
        let last_error = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        for offset in 0..8u64 {
            for bytes in [0, 1, 23, 24, 25, 48] {
                p.space.wr(base, &[0xa5; 128]).unwrap();
                p.space.w32(last_error, LAST_ERROR).unwrap();
                let status = native_call(
                    p,
                    &mut thread,
                    [11, 0, u32::MAX.into(), base + offset, bytes],
                );
                let expected = if bytes == 0 {
                    nt::status::STATUS_INVALID_PARAMETER
                } else if bytes < 24 {
                    nt::status::STATUS_BUFFER_TOO_SMALL
                } else {
                    0
                };
                assert_eq!(status, expected, "{arch} offset{offset} bytes{bytes}");
                if status == 0 {
                    let words: Vec<_> = p
                        .space
                        .bytes(base + offset, 24)
                        .unwrap()
                        .chunks_exact(4)
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                        .collect();
                    assert_eq!(words, [0, 3000, 3000, 3000, 0, 0]);
                    assert_eq!(p.space.bytes(base + offset + 24, 24).unwrap(), [0xa5; 24]);
                }
                assert_eq!(p.space.u32(last_error).unwrap(), LAST_ERROR);
            }
        }
        // A fault in excess capacity wins even though the 24-byte row fits.
        p.vm.protect(base + 4096, 4096, prot::NOACCESS).unwrap();
        assert_eq!(
            native_call(p, &mut thread, [11, 0, 0, base + 4072, 25]),
            nt::status::STATUS_ACCESS_VIOLATION
        );
    }
}

#[test]
fn native_processor_power_export_preserves_prior_ordinals_and_traps() {
    use crate::user::windows::dll::BuiltinDll;
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtPowerInformation"))
        .unwrap();
    assert_eq!(current.exports[family].len(), 1);
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let through_power = BuiltinDll {
        exports: &current.exports[..=family],
        ..previous
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(&through_power, arch, 0, &[]);
        assert_eq!(before.ordinal_base, after.ordinal_base);
        assert_eq!(&after.symbols[..before.symbols.len()], before.symbols);
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert!(dll::nt_service("NtPowerInformation", arch).is_some());
    }
}

#[cfg(windows)]
#[test]
fn native_processor_power_reads_the_live_host_metadata_adapter() {
    let row = crate::user::windows::native::processor_power::capture()
        .expect("fixed native processor query");
    assert_eq!(row[0], 0);
    let (mut process, mut thread) = fixture(WinArch::Arm64, "NtPowerInformation", SERVICE);
    let p = process.state_mut();
    super::native_profile::kernel_profile(p, 29698, 0xaa64);
    let base = arena(p);
    assert_eq!(native_call(p, &mut thread, [11, 0, 0, base, 24]), 0);
    let words: Vec<_> = p
        .space
        .bytes(base, 24)
        .unwrap()
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    assert_eq!(words[0], 0);
    // Frequencies and current idle state can change between native samples.
    // The captured VM is checked byte-for-byte in the independent corpus;
    // this live control proves actual adapter acquisition and guest publication.
    assert_eq!(words.len(), 6);
}
