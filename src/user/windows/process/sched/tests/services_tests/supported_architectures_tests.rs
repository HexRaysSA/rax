//! Replay original ARM64 Windows 29708 class 230 replies.
use super::*;
use crate::user::windows::native::{
    SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES2, SupportedArchitectures,
};
use serde_json::Value;

const LENGTHS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-supported-processor-architectures/native-lengths-29708.json"
));
const ORDER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-supported-processor-architectures/native-order-29708.json"
));
const UNCHANGED: u32 = 0xA5A5_A5A5;
const CLASS: u64 = SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES2 as u64;

fn decode(value: &Value) -> Vec<u8> {
    let value = value.as_str().unwrap();
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn measured() -> (Vec<Value>, SupportedArchitectures) {
    let rows: Vec<Value> = serde_json::from_str(LENGTHS).unwrap();
    assert_eq!(rows.len(), 48);
    let record = |subject: &str| {
        let row = rows
            .iter()
            .find(|row| row["subject"] == subject && row["capacity"] == 16)
            .unwrap();
        assert_eq!(row["status"], 0);
        assert_eq!(row["returned"], 16);
        decode(&row["observed"])[..16].try_into().unwrap()
    };
    let data = SupportedArchitectures {
        system: record("zero"),
        current_process: record("pseudo-current"),
    };
    (rows, data)
}

#[test]
fn supported_architectures_replays_length_probes_and_exact_bytes() {
    let (rows, snapshot) = measured();
    let (mut process, mut thread, scratch) = group_fixture(WinArch::Arm64);
    let p = process.state_mut();
    p.supported_architectures = Ok(snapshot);
    for row in rows {
        let (source, buffer, result) = (scratch, scratch + PAGE_SIZE, scratch + 2 * PAGE_SIZE);
        let input = match row["subject"].as_str().unwrap() {
            "missing" => 0,
            subject => {
                let handle = match subject {
                    "zero" => 0,
                    "pseudo-current" => u64::MAX,
                    "invalid-ordinary" => 0xF123_4560,
                    _ => unreachable!(),
                };
                p.space.w64(source, handle).unwrap();
                source + row["input_adjust"].as_u64().unwrap()
            }
        };
        let capacity = row["capacity"].as_u64().unwrap();
        let output = if capacity == 0 {
            0
        } else {
            buffer + row["output_adjust"].as_u64().unwrap()
        };
        let returned = if row["omit_return"].as_bool().unwrap() {
            0
        } else {
            result
        };
        p.space.wr(buffer, &[0xA5; 48]).unwrap();
        p.space.w32(result, UNCHANGED).unwrap();
        assert_eq!(
            group_call(
                p,
                &mut thread,
                [
                    CLASS,
                    input,
                    row["input_length"].as_u64().unwrap(),
                    output,
                    capacity,
                    returned
                ],
            ),
            Outcome::Continue,
            "{row}",
        );
        assert_eq!(thread.cpu.gpr(0), row["status"].as_u64().unwrap(), "{row}");
        assert_eq!(
            p.space.u32(result).unwrap(),
            row["returned"].as_u64().unwrap() as u32,
            "{row}"
        );
        assert_eq!(
            p.space.bytes(buffer, 48).unwrap(),
            decode(&row["observed"]),
            "{row}"
        );
    }
}

#[test]
fn supported_architectures_replays_capture_order_aliases_and_guest_handle_rights() {
    let (_, snapshot) = measured();
    let rows: Vec<Value> = serde_json::from_str(ORDER).unwrap();
    assert_eq!(rows.len(), 24);
    let (mut process, mut thread, scratch) = group_fixture(WinArch::Arm64);
    let p = process.state_mut();
    p.supported_architectures = Ok(snapshot);
    let (source, buffer, result, unmapped) = (
        scratch,
        scratch + PAGE_SIZE,
        scratch + 2 * PAGE_SIZE,
        scratch + 3 * PAGE_SIZE,
    );
    p.vm.protect(unmapped, PAGE_SIZE, prot::NOACCESS).unwrap();
    let process = p.objects.create(Object::Process {
        pid: p.pid,
        exit_code: None,
    });
    let wrong_type = p.objects.insert(Object::Event {
        manual: true,
        signaled: 0,
    });
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let handle = if let Some(granted) = name.strip_prefix("process-access-0x") {
            let granted = u32::from_str_radix(granted, 16).unwrap();
            u64::from(p.objects.open_access(process, false, granted).unwrap())
        } else if name == "wrong-type" {
            u64::from(wrong_type)
        } else if name.starts_with("invalid-handle-") {
            0xF123_4560
        } else if matches!(name, "output-alias-input" | "return-alias-input") {
            u64::MAX
        } else {
            0
        };
        p.space.wr(source, &[0; 48]).unwrap();
        p.space.w64(source, handle).unwrap();
        p.space.wr(buffer, &[0xA5; 48]).unwrap();
        p.space.w32(result, UNCHANGED).unwrap();
        let input = match row["input_kind"].as_str().unwrap() {
            "normal" => source,
            "misaligned" => source + 4,
            "unmapped" => unmapped,
            "null" => 0,
            _ => unreachable!(),
        };
        let output = match row["output_kind"].as_str().unwrap() {
            "normal" => buffer,
            "misaligned" => buffer + 1,
            "unmapped" => unmapped,
            "null" => 0,
            "input" => source,
            _ => unreachable!(),
        };
        let returned = match row["length_kind"].as_str().unwrap() {
            "normal" => result,
            "unmapped" => unmapped,
            "null" => 0,
            "output" => buffer,
            "end-output" => buffer + 16,
            "input" => source,
            _ => unreachable!(),
        };
        let input_bytes = if name.starts_with("short-input") {
            4
        } else {
            8
        };
        let capacity = row["capacity"].as_u64().unwrap();
        assert_eq!(
            group_call(
                p,
                &mut thread,
                [CLASS, input, input_bytes, output, capacity, returned]
            ),
            Outcome::Continue,
            "{row}",
        );
        assert_eq!(thread.cpu.gpr(0), row["status"].as_u64().unwrap(), "{row}");
        assert_eq!(
            p.space.u32(result).unwrap(),
            row["returned"].as_u64().unwrap() as u32,
            "{row}"
        );
        assert_eq!(
            p.space.bytes(buffer, 48).unwrap(),
            decode(&row["output"]),
            "{row}"
        );
        if input_bytes == 8 && (returned == source || output == source) {
            assert_eq!(
                p.space.bytes(source, 48).unwrap(),
                decode(&row["input"]),
                "{row}"
            );
        }
    }
}

#[test]
fn supported_architectures_requires_a_captured_profile() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, scratch) = group_fixture(arch);
        let p = process.state_mut();
        p.space.w64(scratch, 0).unwrap();
        let result = group_call(
            p,
            &mut thread,
            [CLASS, scratch, 8, 0, 0, scratch + PAGE_SIZE],
        );
        assert!(
            matches!(result, Outcome::Fail(ref message) if message.contains("supported processor architectures unavailable")),
            "{arch:?} {result:?}"
        );
        assert_eq!(p.space.u32(scratch + PAGE_SIZE).unwrap(), UNCHANGED);
    }
}

const THUNKS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-supported-processor-architectures/native-thunks-29708.json"
));
const THUNK_ORDER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-supported-processor-architectures/native-thunk-order-29708.json"
));

fn thunk_snapshot(arch: WinArch) -> SupportedArchitectures {
    let (_, native) = measured();
    let system = std::array::from_fn(|index| {
        let at = index * 4;
        u32::from_le_bytes(native.system[at..at + 4].try_into().unwrap())
    });
    SupportedArchitectures::for_guest(system, arch).unwrap()
}

#[test]
fn supported_architectures_replays_installed_thunk_records() {
    let evidence: Value = serde_json::from_str(THUNKS).unwrap();
    for (arch, key) in [(WinArch::X86, "x86"), (WinArch::X64, "x64")] {
        let (mut process, mut thread, scratch) = group_fixture(arch);
        let p = process.state_mut();
        p.supported_architectures = Ok(thunk_snapshot(arch));
        let output = scratch + PAGE_SIZE;
        let returned = scratch + 2 * PAGE_SIZE;
        let rows = evidence[key]["rows"].as_array().unwrap();
        assert_eq!(evidence[key]["exit"], 0);
        assert_eq!(rows.len(), 81);
        for row in rows {
            let handle = match row["subject"].as_str().unwrap() {
                "zero" => 0,
                "pseudo-current" => arch.ptr(u64::MAX),
                "invalid-ordinary" => 0xF123_4560,
                _ => unreachable!(),
            };
            p.space.wr(scratch, &[0; 32]).unwrap();
            p.space
                .wptr(scratch, arch.ptr_size() as u64, handle)
                .unwrap();
            p.space.wr(output, &[0xa5; 48]).unwrap();
            p.space.w32(returned, UNCHANGED).unwrap();
            let length = row["input_length"].as_u64().unwrap();
            let capacity = row["capacity"].as_u64().unwrap();
            let input = scratch + row["input_offset"].as_u64().unwrap();
            let destination = if capacity == 0 {
                0
            } else {
                output + row["output_offset"].as_u64().unwrap()
            };
            assert_eq!(
                group_call(
                    p,
                    &mut thread,
                    [CLASS, input, length, destination, capacity, returned],
                ),
                Outcome::Continue,
                "{key}/{row}",
            );
            assert_eq!(
                thread.cpu.gpr(0),
                row["status"].as_u64().unwrap(),
                "{key}/{row}"
            );
            assert_eq!(
                p.space.u32(returned).unwrap(),
                row["required"].as_u64().unwrap() as u32,
                "{key}/{row}"
            );
            assert_eq!(
                p.space.bytes(output, 48).unwrap(),
                decode(&row["output"]),
                "{key}/{row}"
            );
        }
    }
}

#[test]
fn supported_architectures_replays_installed_thunk_probe_order() {
    let evidence: Value = serde_json::from_str(THUNK_ORDER).unwrap();
    for (arch, key) in [(WinArch::X86, "x86"), (WinArch::X64, "x64")] {
        let (mut process, mut thread, scratch) = group_fixture(arch);
        let p = process.state_mut();
        p.supported_architectures = Ok(thunk_snapshot(arch));
        let output = scratch + PAGE_SIZE;
        let returned = scratch + 2 * PAGE_SIZE;
        let noaccess = scratch + 3 * PAGE_SIZE;
        p.vm.protect(noaccess, PAGE_SIZE, prot::NOACCESS).unwrap();
        let rows = evidence[key].as_array().unwrap();
        assert_eq!(rows.len(), 18);
        for row in rows {
            let mode = row["mode"].as_u64().unwrap();
            assert_eq!(row["exit"], 0);
            let handle = if mode >= 16 { 0xF123_4560 } else { 0 };
            p.space
                .wptr(scratch, arch.ptr_size() as u64, handle)
                .unwrap();
            p.space.wr(output, &[0xa5; 32]).unwrap();
            p.space.w32(returned, UNCHANGED).unwrap();
            let input = match mode {
                1 | 2 | 11 => 0,
                3 | 4 | 9 | 10 => noaccess,
                _ => scratch,
            };
            let length = match mode {
                2 | 4 => 0,
                13 | 14 => 4,
                15 => u32::MAX.into(),
                _ => arch.ptr_size() as u64,
            };
            let destination = match mode {
                5 | 6 | 13 => noaccess,
                9 | 11 | 17 => output + 1,
                _ => output,
            };
            let capacity = match mode {
                6 => 4,
                8 => 0,
                _ => 16,
            };
            let length_destination = match mode {
                7 | 8 | 10 | 14 | 16 => noaccess,
                12 => output,
                _ => returned,
            };
            assert_eq!(
                group_call(
                    p,
                    &mut thread,
                    [
                        CLASS,
                        input,
                        length,
                        destination,
                        capacity,
                        length_destination
                    ],
                ),
                Outcome::Continue,
                "{key}/{row}",
            );
            assert_eq!(
                thread.cpu.gpr(0),
                row["status"].as_u64().unwrap(),
                "{key}/{row}"
            );
            assert_eq!(
                p.space.u32(returned).unwrap(),
                row["returned"].as_u64().unwrap() as u32,
                "{key}/{row}"
            );
            assert_eq!(
                p.space.bytes(output, 32).unwrap(),
                decode(&row["output"]),
                "{key}/{row}"
            );
        }
    }
}
