//! Native ARM64 class-2 observations from two local installed images.
use super::*;

#[test]
fn mapped_filename_26200_replays_installed_local_image_queries() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/profile-26200-local-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus["schema"], 1);
    assert_eq!(corpus["native_kernel"], serde_json::json!([10, 0, 26200]));
    assert_eq!(corpus["native_machine"], 0xaa64);
    let subjects = corpus["subjects"].as_object().unwrap();
    assert_eq!(subjects.len(), 2);
    let mut count = 0;
    for (subject, observation) in subjects {
        let (mut process, mut thread, base) = setup(WinArch::Arm64);
        let p = process.state_mut();
        kernel_profile(p, 26200, 0xaa64);
        let name = captured_units(observation["name_utf16le"].as_str().unwrap());
        let executable = p.modules.exe().base;
        p.vm.record_mapped_filename(executable, Filename::Captured(name.into()))
            .unwrap();
        let output_base = base + 128;
        let returned_base = base + 64;
        for row in observation["rows"].as_array().unwrap() {
            let case = row["case"].as_str().unwrap();
            let length = row["length"].as_u64().unwrap();
            let poison = u8::try_from(row["poison"].as_u64().unwrap()).unwrap();
            p.space.wr(base, &[poison; 2048]).unwrap();
            let (address, output, returned) = match case {
                "length" => (executable, output_base, returned_base),
                "no_result" => (executable, output_base, 0),
                "null_empty" => (executable, 0, returned_base),
                "unaligned" => (executable, output_base + 1, returned_base),
                "address_and_alignment" => (u64::MAX, output_base + 1, returned_base),
                _ => panic!("unrecognized native mapped-filename case {case}"),
            };
            arguments(
                p,
                &mut thread,
                &[u64::MAX, address, 2, output, length, returned],
            );
            let label = format!("{subject} {case} length {length} poison {poison:02x}");
            assert!(
                matches!(dispatch(p, &mut thread), Outcome::Continue),
                "{label}"
            );
            assert_eq!(
                thread.cpu.gpr(0) as u32,
                row["status"].as_u64().unwrap() as u32,
                "{label}"
            );
            assert_eq!(
                p.space.ptr(returned_base, 8).unwrap(),
                row["returned"].as_u64().unwrap(),
                "{label} ReturnLength"
            );
            let expected = decode_hex(row["bytes"].as_str().unwrap());
            let mut actual = p.space.bytes(output_base, expected.len()).unwrap();
            if output != 0 {
                let slot = (output - output_base) as usize + 8;
                if expected[slot..slot + 8] == 16u64.to_le_bytes() {
                    assert_eq!(
                        p.space.ptr(output + 8, 8).unwrap(),
                        output + 16,
                        "{label} Buffer"
                    );
                    actual[slot..slot + 8].copy_from_slice(&16u64.to_le_bytes());
                }
            }
            assert_eq!(actual, expected, "{label} output");
            count += 1;
        }
    }
    assert_eq!(count, corpus["native_queries"].as_u64().unwrap());
}

#[test]
fn mapped_filename_26200_refuses_unmeasured_guest_views_and_remote_names() {
    for (arch, machine, filename) in [
        (WinArch::X86, 0xaa64, r"\Device\HarddiskVolume1\app.exe"),
        (WinArch::X64, 0xaa64, r"\Device\HarddiskVolume1\app.exe"),
        (WinArch::Arm64, 0x8664, r"\Device\HarddiskVolume1\app.exe"),
        (WinArch::Arm64, 0xaa64, r"\Device\Mup\server\share\app.exe"),
        (
            WinArch::Arm64,
            0xaa64,
            r"\Device\HarddiskVolumeOther\app.exe",
        ),
    ] {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        kernel_profile(p, 26200, machine);
        p.space.wr(base, &[0xa5; 2048]).unwrap();
        let executable = p.modules.exe().base;
        p.vm.record_mapped_filename(
            executable,
            Filename::Captured(filename.encode_utf16().collect::<Vec<_>>().into()),
        )
        .unwrap();
        let committed = p.vm.committed_bytes();
        arguments(
            p,
            &mut thread,
            &[
                arch.ptr(u64::MAX),
                executable,
                2,
                base + 128,
                1024,
                base + 64,
            ],
        );
        assert!(
            matches!(dispatch(p, &mut thread), Outcome::Fail(reason)
            if reason.contains("mapped filename") && reason.contains("profile")),
            "{arch} {machine:04x} {filename}"
        );
        assert_eq!(p.space.bytes(base, 2048).unwrap(), [0xa5; 2048]);
        assert_eq!(p.vm.committed_bytes(), committed);
    }
}
