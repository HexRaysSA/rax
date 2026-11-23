//! Local-volume filename sweeps from x86 processes on Windows 11 ARM64.
use super::*;
use std::collections::BTreeSet;

#[test]
fn mapped_filename_26200_wow64_replays_local_volume_copy_boundaries() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/profile-26200-wow64-local-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus["schema"], 1);
    assert_eq!(corpus["native_kernel"], serde_json::json!([10, 0, 26200]));
    assert_eq!(corpus["native_machine"], 0xaa64);
    assert_eq!(corpus["guest_machine"], 0x014c);
    let mut seen_modes = BTreeSet::new();
    let mut observations = 0;
    for group in corpus["corpora"].as_array().unwrap() {
        let modes = group["modes"].as_array().unwrap();
        assert!(!modes.is_empty());
        let subjects = group["subjects"].as_object().unwrap();
        assert_eq!(subjects.len(), 8);
        let mut count = 0;
        for (subject, record) in subjects {
            let arch = WinArch::X86;
            let (mut process, mut thread, base) = setup(arch);
            let p = process.state_mut();
            kernel_profile(p, 26200, 0xaa64);
            let executable = p.modules.exe().base;
            let name = decode_hex(record["name_utf16le"].as_str().unwrap());
            let units = captured_units(record["name_utf16le"].as_str().unwrap());
            p.vm.record_mapped_filename(executable, Filename::Captured(units.into()))
                .unwrap();
            let mut complete = Vec::new();
            complete.extend((name.len() as u16).to_le_bytes());
            complete.extend((name.len() as u16 + 2).to_le_bytes());
            complete.extend([8, 0, 0, 0]);
            complete.extend(name);
            complete.extend([0, 0]);
            let boundary = base + 2 * PAGE_SIZE;
            let returned = base + 64;
            let committed = p.vm.committed_bytes();
            let entry_stack = thread.cpu.sp();
            let poison = 0xa5;
            for (case, initial_protection, first) in [
                ("length", prot::READWRITE, 0),
                ("noaccess", prot::NOACCESS, 1),
                ("guard", prot::READWRITE | prot::GUARD, 1),
            ] {
                let mut next = first;
                for range in record["ranges"][case].as_array().unwrap() {
                    let values = range.as_array().unwrap();
                    assert_eq!(values.len(), 7);
                    let value = |at: usize| values[at].as_u64().unwrap();
                    assert_eq!(value(0), next);
                    assert!(value(1) >= value(0));
                    next = value(1) + 1;
                    let prefix = value(5) as usize;
                    let pointer = values[6].as_str().unwrap();
                    let mut expected = vec![poison; complete.len() + 2];
                    expected[..prefix].copy_from_slice(&complete[..prefix]);
                    if pointer == "temporary" {
                        expected[4..8].fill(0xfe);
                    }
                    for variable in value(0)..=value(1) {
                        let (length, clip) = if case == "length" {
                            (variable, 512)
                        } else {
                            (512, variable)
                        };
                        let output = boundary - clip;
                        let label = format!("{subject}: {case} length {length} clip {clip}");
                        p.space.wr(output, &vec![poison; expected.len()]).unwrap();
                        p.space.w32(returned, 0xa5a5_a5a5).unwrap();
                        p.vm.protect(boundary, PAGE_SIZE, initial_protection)
                            .unwrap();
                        thread.cpu.set_sp(entry_stack);
                        arguments(
                            p,
                            &mut thread,
                            &[arch.ptr(u64::MAX), executable, 2, output, length, returned],
                        );
                        assert_eq!(dispatch(p, &mut thread), Outcome::Continue, "{label}");
                        assert_eq!(thread.cpu.gpr(0) as u32, value(2) as u32, "{label}");
                        assert_eq!(p.space.u32(returned).unwrap(), value(3) as u32, "{label}");
                        assert_eq!(
                            p.vm.query(boundary).unwrap().protect,
                            value(4) as u32,
                            "{label}"
                        );
                        p.vm.protect(boundary, PAGE_SIZE, prot::READWRITE).unwrap();
                        let mut actual = p.space.bytes(output, expected.len()).unwrap();
                        let buffer = u32::from_le_bytes(actual[4..8].try_into().unwrap()) as u64;
                        match pointer {
                            "inline" => {
                                assert_eq!(buffer, output + 8, "{label}");
                                actual[4..8].copy_from_slice(&[8, 0, 0, 0]);
                            }
                            "temporary" => {
                                assert!((p.vm.low()..p.vm.high()).contains(&buffer), "{label}");
                                assert!(p.vm.allocation(buffer).is_none(), "{label}");
                                actual[4..8].fill(0xfe);
                            }
                            "untouched" => assert_eq!(buffer, 0xa5a5_a5a5, "{label}"),
                            other => panic!("unrecognized native pointer disposition {other}"),
                        }
                        assert_eq!(actual, expected, "{label}");
                        assert_eq!(p.vm.committed_bytes(), committed, "{label}");
                        count += 1;
                    }
                }
                assert_eq!(next, complete.len() as u64 + 2);
            }
        }
        for mode in modes {
            let mode = mode.as_str().unwrap();
            assert!(seen_modes.insert(mode));
            assert_eq!(count, corpus["receipt"]["rows"][mode].as_u64().unwrap());
            observations += count;
        }
    }
    assert_eq!(
        seen_modes,
        BTreeSet::from(["default", "disabled", "enabled"])
    );
    assert_eq!(observations, 14_280);
}
