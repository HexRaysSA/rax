use super::*;
use crate::user::windows::object_namespace::security_device::SecurityDevice;

#[test]
fn valid_security_device_unknown_type_clears_last_error_all_abis() {
    for arch in WinArch::ALL {
        let mut harness = Harness::new(arch);
        let device = SecurityDevice {
            kernel: (10, 0, 29704),
            revision: 1010,
            native_machine: 0xaa64,
            device_type: 0x39,
            characteristics: 0x100,
        }
        .selected()
        .unwrap();
        let handle = harness
            .process
            .state_mut()
            .objects
            .insert(Object::SecurityFile(device));
        harness
            .process
            .state_mut()
            .space
            .w32(harness.thread.teb + offsets(arch).teb_last_error, 0x1234)
            .unwrap();
        assert_eq!(harness.value("GetFileType", &[handle.into()]), 0);
        assert_eq!(harness.error(), 0);
        harness.close(handle.into());
    }
}

#[test]
fn native_security_device_wait_grants_and_last_error_all_abis() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-ksecdd/native-open-controls-v3.json"
    )))
    .unwrap();
    let mut observations = 0;
    for arch in WinArch::ALL {
        let key = match arch {
            WinArch::X86 => "x86",
            WinArch::X64 => "x64",
            WinArch::Arm64 => "arm64",
        };
        for row in corpus["callers"][key]["rows"].as_array().unwrap() {
            if row.get("initial_wait").is_none() {
                continue;
            }
            let mut harness = Harness::new(arch);
            let p = harness.process.state_mut();
            let id = p.objects.create(Object::SecurityFile(SecurityDevice {
                kernel: (10, 0, 29704),
                revision: 1010,
                native_machine: 0xaa64,
                device_type: 0x39,
                characteristics: 0x100,
            }));
            p.objects
                .set_file_mode(id, row["options"].as_u64().unwrap() as u32);
            let handle = p
                .objects
                .open_access(id, false, row["access"].as_u64().unwrap() as u32)
                .unwrap();
            for (result_key, error_key) in [
                ("initial_wait", "initial_wait_error"),
                ("after_queries_wait", "after_queries_wait_error"),
            ] {
                harness
                    .process
                    .state_mut()
                    .space
                    .w32(harness.thread.teb + offsets(arch).teb_last_error, 0x1234)
                    .unwrap();
                assert_eq!(
                    harness.value("WaitForSingleObject", &[handle.into(), 0]),
                    row[result_key].as_u64().unwrap(),
                    "{arch}/{}",
                    row["label"]
                );
                assert_eq!(harness.error() as u64, row[error_key].as_u64().unwrap());
                observations += 1;
            }
            harness.close(handle.into());
        }
    }
    assert_eq!(observations, 168);
}
