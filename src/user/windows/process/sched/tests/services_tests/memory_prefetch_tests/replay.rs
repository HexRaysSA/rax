use super::*;
use serde_json::Value;

fn number(row: &Value, name: &str) -> u64 {
    row[name].as_u64().unwrap()
}

fn relocated(bytes: &str, native_target: u64, target: u64, width: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..bytes.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&bytes[at..at + 2], 16).unwrap())
        .collect();
    let original = data.clone();
    for at in 0..=data.len() - width {
        let mut value = [0; 8];
        value[..width].copy_from_slice(&original[at..at + width]);
        let pointer = u64::from_le_bytes(value);
        if (native_target..native_target + 16384).contains(&pointer) {
            let adjusted = target + pointer - native_target;
            data[at..at + width].copy_from_slice(&adjusted.to_le_bytes()[..width]);
        }
    }
    data
}

fn corpus(text: &str, arch_count: usize) {
    let data: Value = serde_json::from_str(text).unwrap();
    assert_eq!(data["state"], "finished");
    let rows = data["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 342 * arch_count);
    let mut compared = 0;
    let mut declared_frontiers = 0;
    for row in rows {
        assert_eq!(row["exit_code"], 0);
        let observed = &row["observation"];
        assert_eq!(number(observed, "exception"), 0);
        let class = number(observed, "class");
        if (1..9).contains(&class) {
            // These exploratory rows own future classes, not class0 coverage.
            // A separate runtime test requires their explicit frontier errors.
            declared_frontiers += 1;
            continue;
        }
        let arch = match row["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unrecognized ABI {other}"),
        };
        let id = row["case"].as_u64().unwrap() as u32;
        let label = format!("{arch}/{id}");
        let (mut process, mut t) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
        let p = process.state_mut();
        let setup = inputs::prepare(p, id);
        assert_eq!(setup.args[1], class, "{label}");
        assert_eq!(setup.args[2], number(observed, "count"), "{label}");
        assert_eq!(setup.args[5], number(observed, "length"), "{label}");
        assert_eq!(
            valid_mask(p, setup.target),
            number(observed, "before_valid") as u32,
            "{label}"
        );
        let target_protect = p.vm.query(setup.target).unwrap().protect;
        let committed = p.vm.committed_bytes();
        let handles = p.objects.handle_count();
        assert_eq!(enter(p, &mut t, setup.args), Outcome::Continue, "{label}");
        assert_eq!(t.cpu.gpr(0), number(observed, "status"), "{label}");
        assert_eq!(
            u64::from(
                p.space
                    .u32(t.teb + layout::offsets(arch).teb_last_error)
                    .unwrap()
            ),
            number(observed, "last_error"),
            "{label}/LastError",
        );
        assert_eq!(
            valid_mask(p, setup.target),
            number(observed, "after_valid") as u32,
            "{label}"
        );
        assert_eq!(
            p.vm.query(setup.target).unwrap().protect,
            target_protect,
            "{label}"
        );
        assert_eq!(p.vm.committed_bytes(), committed, "{label}");
        assert_eq!(p.objects.handle_count(), handles, "{label}");
        for (index, address, name) in [(0, setup.base, "range"), (1, setup.base + 8192, "info")] {
            let protect = p.vm.query(address).unwrap().protect;
            assert_eq!(
                u64::from(protect),
                observed["protect_after"][index].as_u64().unwrap(),
                "{label}"
            );
            let accessible = protect & (prot::GUARD | prot::NOACCESS) == 0;
            let mask = number(observed, &format!("{name}_snapshot_mask"));
            assert_eq!(
                mask,
                if accessible { u32::MAX as u64 } else { 0 },
                "{label}"
            );
            if accessible {
                let expected = relocated(
                    observed[format!("{name}_snapshot")].as_str().unwrap(),
                    number(observed, "target"),
                    setup.target,
                    arch.ptr_size() as usize,
                );
                let mut expected = expected;
                if id == 55 && name == "range" && arch.ptr_size() == 8 {
                    // The shifted copy overwrites only the high half of the
                    // original first pointer. Relocate its surviving low half
                    // as well, after proving those exact native input bytes.
                    let original = observed["range_snapshot"].as_str().unwrap();
                    let native = number(observed, "target").to_le_bytes();
                    assert_eq!(
                        &original[..8],
                        &native[..4]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    expected[..4].copy_from_slice(&setup.target.to_le_bytes()[..4]);
                }
                assert_eq!(
                    p.space.bytes(address + 128, 32).unwrap(),
                    expected,
                    "{label}/{name}"
                );
            }
        }
        compared += 1;
    }
    assert_eq!(compared, 274 * arch_count);
    assert_eq!(declared_frontiers, 68 * arch_count);
}

#[test]
fn native_memory_prefetch_replays_822_independent_class0_and_invalid_class_rows() {
    corpus(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-memory-prefetch/observations-arm64-29695-v4.json"
        )),
        3,
    );
}

#[cfg(windows)]
#[test]
fn native_memory_prefetch_replays_fresh_amd64_kernel_observations_when_requested() {
    if let Some(path) = std::env::var_os("RAX_NATIVE_MEMORY_PREFETCH_CORPUS") {
        corpus(&std::fs::read_to_string(path).unwrap(), 2);
    } else {
        // The mandatory retained corpus above runs on every Windows invocation;
        // the qualification workflow additionally supplies this fresh producer.
        corpus(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-memory-prefetch/observations-arm64-29695-v4.json"
            )),
            3,
        );
    }
}
