//! Kernel-29704 qualification uses independently captured native query results.
use super::*;

#[test]
fn mapped_filename_29704_replays_fresh_native_queries_with_independent_names() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/profile-29704-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus["kernel"], serde_json::json!([10, 0, 29704]));
    assert_eq!(corpus["native_machine"], 0xaa64);
    assert_eq!(corpus["native_queries"], 1359);
    assert_eq!(corpus["baseline_capture"]["native_queries"], 24);
    replay_complete(&corpus, 29704);
}

#[test]
fn mapped_filename_29708_replays_native_queries_and_paired_volume_controls() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/profile-29708-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus["kernel"], serde_json::json!([10, 0, 29708]));
    assert_eq!(corpus["revision"], 1003);
    assert_eq!(corpus["native_machine"], 0xaa64);
    assert_eq!(corpus["complete_baselines"].as_array().unwrap().len(), 24);
    assert_eq!(corpus["coverage"]["complete-query"], 1359);
    assert_eq!(corpus["volume"]["filesystem"], "NTFS");
    replay_complete(&corpus, 29708);
    replay_paired(corpus["paired"].as_array().unwrap(), 29708);
}

fn replay_complete(corpus: &serde_json::Value, build: u32) {
    let groups: Vec<_> = corpus["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            (
                group["replay_version"].as_u64().unwrap() as usize - 1,
                group["corpus"].clone(),
            )
        })
        .collect();
    replay(&groups, 3, 1359, build, 0xaa64, true);
}

#[test]
fn mapped_filename_29704_replays_paired_local_and_network_short_buffers() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/paired-29704-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus["kernel"], serde_json::json!([10, 0, 29704]));
    assert_eq!(corpus["row_count"], 414);
    replay_paired(corpus["rows"].as_array().unwrap(), 29704);
}

fn replay_paired(rows: &[serde_json::Value], build: u32) {
    assert_eq!(rows.len(), 414);
    let baselines: Vec<_> = rows
        .iter()
        .filter(|row| row["kind"] == "baseline")
        .collect();
    assert_eq!(baselines.len(), 12);
    let mut queries = 0;
    for row in rows.iter().filter(|row| row["kind"] == "query") {
        let arch = match row["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown architecture {other}"),
        };
        let baseline = baselines
            .iter()
            .find(|base| {
                base["location"] == row["location"]
                    && base["arch"] == row["arch"]
                    && base["version"] == row["version"]
            })
            .unwrap();
        let observation = &row["observation"];
        let native_exit = row.get("native_exit_code").unwrap_or(&row["exit_code"]);
        assert_eq!(native_exit, 0);
        assert_eq!(observation["raised"], 0);
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        kernel_profile(p, build, 0xaa64);
        let executable = p.modules.exe().base;
        p.vm.record_mapped_filename(
            executable,
            Filename::Captured(captured_name(baseline).into()),
        )
        .unwrap();
        p.space.wr(base, &[0xcc; 16384]).unwrap();
        let output = base + 128;
        let returned = base + 64;
        arguments(
            p,
            &mut thread,
            &[
                arch.ptr(u64::MAX),
                executable,
                2,
                output,
                observation["length"].as_u64().unwrap(),
                returned,
            ],
        );
        assert!(matches!(dispatch(p, &mut thread), Outcome::Continue));
        let label = format!(
            "{arch} {} v{} case {}",
            row["location"], row["version"], row["case"]
        );
        assert_eq!(
            thread.cpu.gpr(0) as u32,
            observation["status"].as_u64().unwrap() as u32,
            "{label}"
        );
        assert_eq!(
            p.space.ptr(returned, arch.ptr_size()).unwrap(),
            observation["returned"].as_u64().unwrap(),
            "{label} ReturnLength"
        );
        for page in 0..3 {
            assert_eq!(
                p.vm.query(base + page * PAGE_SIZE).unwrap().protect,
                observation["protect"][page as usize].as_u64().unwrap() as u32,
                "{label} protection"
            );
        }
        let mut expected = decode_hex(observation["output_hex"].as_str().unwrap());
        let mut actual = p.space.bytes(output, expected.len()).unwrap();
        let pointer = arch.ptr_size() as usize;
        if expected[pointer..2 * pointer]
            .iter()
            .any(|&byte| byte != 0xcc)
        {
            assert_eq!(observation["buffer_offset"], 2 * pointer);
            assert_eq!(
                p.space
                    .ptr(output + pointer as u64, pointer as u64)
                    .unwrap(),
                output + 2 * pointer as u64,
                "{label} Buffer"
            );
            expected[pointer..2 * pointer].fill(0);
            actual[pointer..2 * pointer].fill(0);
        }
        assert_eq!(actual, expected, "{label} output");
        queries += 1;
    }
    assert_eq!(queries, 402);
}

#[test]
fn mapped_filename_arm64_profiles_refuse_unknown_native_identity_without_publication() {
    for arch in WinArch::ALL {
        for (major, minor, build, machine) in [
            (10, 0, 29703, Some(0xaa64)),
            (10, 0, 29705, Some(0xaa64)),
            (10, 0, 29707, Some(0xaa64)),
            (10, 0, 29709, Some(0xaa64)),
            (10, 0, 29699, Some(0xaa64)),
            (10, 1, 29704, Some(0xaa64)),
            (11, 0, 29704, Some(0xaa64)),
            (10, 0, 29704, None),
            (10, 0, 29704, Some(0x14c)),
            (10, 0, 29704, Some(0x8664)),
            (10, 1, 29708, Some(0xaa64)),
            (10, 0, 29708, None),
            (10, 0, 29708, Some(0x8664)),
        ] {
            let (mut process, mut thread, base) = setup(arch);
            let p = process.state_mut();
            kernel_profile(p, build, machine.unwrap_or(0));
            let native = p.native.as_mut().unwrap();
            native.version.major = major;
            native.version.minor = minor;
            native.object_namespace.native_machine = machine;
            // Guest version spoofing cannot qualify an uncaptured native kernel.
            std::sync::Arc::make_mut(&mut p.cfg).version.build = 29704;
            p.space.wr(base, &[0xa5; 2048]).unwrap();
            let handles = p.objects.handle_count();
            let committed = p.vm.committed_bytes();
            let executable = p.modules.exe().base;
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
                    if reason.contains("mapped filename kernel copy profile is not captured")),
                "{arch} {major}.{minor}.{build} {machine:?}"
            );
            assert_eq!(p.space.bytes(base, 2048).unwrap(), [0xa5; 2048]);
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.vm.committed_bytes(), committed);
        }
    }
}

#[test]
fn mapped_filename_29708_does_not_qualify_registry_thunk_copy() {
    let (mut process, mut thread) = fixture(WinArch::X86, "NtQueryKey", 0x23);
    let p = process.state_mut();
    kernel_profile(p, 29708, 0xaa64);
    let base =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space.wr(base, &[0xa5; 256]).unwrap();
    // Misalignment enters the WoW64 copy path even when the handle is invalid.
    arguments(p, &mut thread, &[0, 0, base + 129, 8, base + 64]);
    assert!(matches!(
        dispatch(p, &mut thread),
        Outcome::Fail(reason) if reason.contains("kernel copy profile is not captured")
    ));
    assert_eq!(p.space.bytes(base, 256).unwrap(), [0xa5; 256]);
}
