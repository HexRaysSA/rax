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
        let (_, data) = measured();
        let (mut process, mut thread, scratch) = group_fixture(arch);
        let p = process.state_mut();
        if arch != WinArch::Arm64 {
            p.supported_architectures = Ok(data);
        }
        p.space.w64(scratch, 0).unwrap();
        let result = group_call(
            p,
            &mut thread,
            [CLASS, scratch, 8, 0, 0, scratch + PAGE_SIZE],
        );
        assert!(
            matches!(result, Outcome::Fail(ref message) if message.contains("class 230") || message.contains("supported processor architectures unavailable")),
            "{arch:?} {result:?}"
        );
        assert_eq!(p.space.u32(scratch + PAGE_SIZE).unwrap(), UNCHANGED);
    }
}
