//! Replays the native bcrypt SHA-256 provider calls through ARM64 service dispatch.

use super::file_open_tests::Harness;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS,
};
use crate::user::windows::object_namespace::security_device::SecurityDevice;
use crate::user::windows::objects::Object;
use serde_json::Value;

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn native_security_provider_replays_arm64_bcrypt_configuration() {
    let observation: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-ksecdd/bcrypt-sha256-arm64.json"
    )))
    .unwrap();
    let mut h = Harness::new(WinArch::Arm64);
    let namespace = &mut h.process.state_mut().object_namespace;
    namespace.native_machine = Some(0xaa64);
    namespace
        .select_security_device(SecurityDevice {
            kernel: (10, 0, 29708),
            revision: 1003,
            native_machine: 0xaa64,
            device_type: 0x39,
            characteristics: 0x100,
        })
        .unwrap();
    h.name("\\Device\\KsecDD");
    let io = h.base + 64;
    let input = h.base + 256;
    let output = h.base + 512;
    let handle_out = h.base;
    let attrs = h.attrs();
    h.process.state().space.w32(attrs + 24, 0).unwrap();
    assert_eq!(
        h.invoke_api("NtOpenFile", &[handle_out, 0x100003, attrs, io, 7, 0x20]),
        STATUS_SUCCESS
    );
    let file = h.process.state().space.u64(handle_out).unwrap();

    let watch = &observation["watch"];
    let watch_args = [
        handle_out,
        watch["event_access"].as_u64().unwrap(),
        0,
        watch["event_type"].as_u64().unwrap(),
        watch["event_initial"].as_u64().unwrap(),
    ];
    assert_eq!(h.invoke_api("NtCreateEvent", &watch_args), STATUS_SUCCESS);
    let event = h.process.state().space.u64(handle_out).unwrap();
    let event_id = h.process.state().objects.id(event).unwrap();
    let watch_prefix = bytes(&watch["input_prefix"]);
    let memory = &h.process.state().space;
    memory.wr(input, &watch_prefix).unwrap();
    memory
        .w64(input + watch_prefix.len() as u64, event)
        .unwrap();
    memory.wr(io, &[0xa5; 16]).unwrap();
    let control = observation["control_code"].as_u64().unwrap();
    let mut args = [
        file,
        0,
        0,
        0,
        io,
        control,
        input,
        watch["input_bytes"].as_u64().unwrap(),
        0,
        watch["output_bytes"].as_u64().unwrap(),
    ];

    // An inaccessible output must leave both the IOSB and event ownership alone.
    assert_eq!(
        h.invoke_api("NtDeviceIoControlFile", &args),
        STATUS_ACCESS_VIOLATION
    );
    let state = h.process.state();
    assert_eq!(state.space.bytes(io, 16).unwrap(), [0xa5; 16]);
    assert_eq!(
        state
            .objects
            .file_state(file)
            .unwrap()
            .security_provider_event,
        None
    );

    args[8] = output;
    state
        .space
        .w64(input + watch_prefix.len() as u64, file)
        .unwrap();
    assert_eq!(
        h.invoke_api("NtDeviceIoControlFile", &args),
        STATUS_OBJECT_TYPE_MISMATCH
    );
    h.process
        .state()
        .space
        .w64(input + watch_prefix.len() as u64, event)
        .unwrap();
    assert_eq!(h.invoke_api("NtDeviceIoControlFile", &args), STATUS_SUCCESS);
    assert_eq!(h.invoke_api("NtDeviceIoControlFile", &args), STATUS_SUCCESS);
    let state = h.process.state();
    assert_eq!(
        state.space.u64(io).unwrap(),
        watch["status"].as_u64().unwrap()
    );
    assert_eq!(
        state.space.u64(io + 8).unwrap(),
        watch["information"].as_u64().unwrap()
    );
    assert_eq!(state.space.bytes(output, 8).unwrap(), [0xa5; 8]);
    assert!(matches!(
        state.objects.get(event),
        Some(Object::Event { signaled: 0, .. })
    ));

    let lookup = &observation["lookup"];
    let mut expected = bytes(&lookup["output"]);
    let padding = lookup["zeroed_unspecified_padding"].as_array().unwrap();
    let start = padding[0].as_u64().unwrap() as usize;
    let end = padding[1].as_u64().unwrap() as usize;
    expected[start..end].fill(0);
    let mut guarded_destination = [0xa5; 384];
    guarded_destination[..expected.len()].copy_from_slice(&expected);
    state.space.wr(input, &bytes(&lookup["input"])).unwrap();
    args[7] = lookup["input_bytes"].as_u64().unwrap();
    args[9] = lookup["output_bytes"].as_u64().unwrap();
    assert_eq!(h.invoke_api("NtDeviceIoControlFile", &args), STATUS_SUCCESS);
    let state = h.process.state();
    assert_eq!(
        state.space.u64(io).unwrap(),
        lookup["status"].as_u64().unwrap()
    );
    assert_eq!(
        state.space.u64(io + 8).unwrap(),
        lookup["information"].as_u64().unwrap()
    );
    assert_eq!(state.space.bytes(output, 384).unwrap(), guarded_destination);

    // Duplicate file handles share the registration and release it once.
    assert_eq!(
        h.invoke_api(
            "NtDuplicateObject",
            &[u64::MAX, file, u64::MAX, handle_out, 0, 0, 2]
        ),
        STATUS_SUCCESS
    );
    let duplicate = h.process.state().space.u64(handle_out).unwrap();
    assert_eq!(h.invoke_api("NtClose", &[event]), STATUS_SUCCESS);
    assert_eq!(h.invoke_api("NtClose", &[file]), STATUS_SUCCESS);
    assert!(h.process.state().objects.obj(event_id).is_some());
    assert_eq!(h.invoke_api("NtClose", &[duplicate]), STATUS_SUCCESS);
    assert!(h.process.state().objects.obj(event_id).is_none());
    assert_eq!(
        h.invoke_api("NtDeviceIoControlFile", &args),
        STATUS_INVALID_HANDLE
    );
}
