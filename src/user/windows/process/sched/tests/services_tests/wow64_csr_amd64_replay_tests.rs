//! Replay all native AMD64 caller bytes, faults, resources and CSR publication.
use super::*;
use serde_json::Value;

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn seed(p: &mut Proc, b: u64, before: &Value) {
    for (label, at) in [("buffer", b + 4096), ("inside", b + 8192)] {
        let row = &before[label];
        if row["read"] == true && row["got"].as_u64().unwrap_or(0) != 0 {
            p.space.wr(at, &bytes(&row["hex"])).unwrap();
        }
    }
}

fn outputs(p: &Proc, request: &[u64; 5], data: &Value, label: &str) {
    for (name, address) in [("buffer", request[2]), ("inside", request[4])] {
        let row = &data[name];
        if row.is_null() || address == 0 {
            continue;
        }
        if let Some(protection) = row["protect"].as_u64() {
            assert_eq!(
                u64::from(p.vm.query(address).unwrap().protect),
                protection,
                "{label}:{name}"
            );
        } else if row["read"] == true {
            let expected = bytes(&row["hex"]);
            assert_eq!(
                p.space.bytes(address, expected.len()).unwrap(),
                expected,
                "{label}:{name}"
            );
        } else {
            assert!(p.space.u8(address).is_err(), "{label}:{name}");
        }
    }
}

fn publication_changed(step: &Value, width: u64) -> bool {
    step["peb_changes"].as_array().unwrap().iter().any(|row| {
        if row["width"].as_u64() != Some(width) {
            return false;
        }
        let offset = row["offset"].as_u64().unwrap();
        let ranges: &[(u64, u64)] = if width == 64 {
            &[(0x88, 8), (0x98, 8), (0x380, 8)]
        } else {
            &[(0x4c, 4), (0x54, 4), (0x248, 8)]
        };
        ranges
            .iter()
            .any(|&(base, bytes)| (base..base + bytes).contains(&offset))
    })
}

fn mappings(p: &Proc, step: &Value, label: &str) {
    for region in step["new_mappings"].as_array().unwrap() {
        let connection = p.wow64.as_ref().unwrap().csr.as_ref().unwrap();
        let port = match p.objects.get(connection.port.into()).unwrap() {
            Object::LpcPort(port) => port,
            _ => panic!("owned CSR port"),
        };
        let relative = region["base"].as_u64().unwrap() - region["allocation"].as_u64().unwrap();
        let native_protection = region["protect"].as_u64().unwrap();
        let base = if native_protection == u64::from(prot::READWRITE) {
            port.view().unwrap().base
        } else {
            connection.base
        };
        let actual = p.vm.query(base + relative).unwrap();
        assert_eq!(
            u64::from(actual.state),
            region["state"].as_u64().unwrap(),
            "{label}"
        );
        assert_eq!(u64::from(actual.protect), native_protection, "{label}");
        assert_eq!(actual.size, region["bytes"].as_u64().unwrap(), "{label}");
        assert_eq!(actual.base, base + relative, "{label}");
        assert_eq!(actual.allocation_base, base, "{label}");
        assert_eq!(
            u64::from(actual.kind),
            region["type"].as_u64().unwrap(),
            "{label}"
        );
    }
}

#[test]
fn wow64_csr_amd64_replays_62_native_cases_and_76_returns() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-wow64-csr-amd64/matrix-profiles-v1.json"
    )).unwrap();
    let mut cases = 0;
    let mut returns = 0;
    for profile in corpus["projections"].as_array().unwrap() {
        let build = profile["kernel"][2].as_u64().unwrap() as u32;
        assert!(matches!(build, 20348 | 26100));
        assert_eq!(profile["native_machine"], 0x8664);
        assert_eq!(profile["case_count"], 31);
        assert_eq!(profile["return_count"], 38);
        for row in profile["samples"].as_array().unwrap() {
            let label = row["mode"].as_str().unwrap();
            let mode = label.strip_prefix("retry-").unwrap_or(label);
            let (mut process, mut thread, b) = setup(build, 2);
            let p = process.state_mut();
            seed(p, b, &row["before"]);
            let mut request = args(b);
            super::super::replay::configure(p, b, mode, &mut request);
            let mut native_published = false;
            let mut wow_published = false;
            for step in row["steps"].as_array().unwrap() {
                if mode == "guard-inside-null-buffer" && step["ordinal"] == 1 {
                    request[2] = 0;
                }
                let handles = p.objects.handle_count();
                let committed = p.vm.committed_bytes();
                let expected = u32::from_str_radix(step["status"].as_str().unwrap(), 16).unwrap();
                assert_eq!(
                    invoke(p, &mut thread, &request),
                    expected,
                    "build {build}:{label}"
                );
                let added = step["handles_after"].as_u64().unwrap()
                    - step["handles_before"].as_u64().unwrap();
                assert_eq!(
                    p.objects.handle_count() as u64,
                    handles as u64 + added,
                    "{label}"
                );
                let mapped: u64 = step["new_mappings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|row| row["state"] == 0x1000)
                    .map(|row| row["bytes"].as_u64().unwrap())
                    .sum();
                assert_eq!(p.vm.committed_bytes(), committed + mapped, "{label}");
                native_published |= publication_changed(step, 64);
                wow_published |= publication_changed(step, 32);
                assert_eq!(
                    p.wow64.as_ref().unwrap().csr.is_some(),
                    native_published,
                    "{label}"
                );
                if native_published {
                    publication(p, wow_published);
                } else {
                    let native = p.wow64.as_ref().unwrap().native_peb;
                    for offset in [0x88, 0x98, 0x380] {
                        assert_eq!(p.space.u64(native + offset).unwrap(), 0, "{label}");
                    }
                    for offset in [0x4c, 0x54] {
                        assert_eq!(p.space.u32(p.peb + offset).unwrap(), 0, "{label}");
                    }
                    assert_eq!(p.space.u64(p.peb + 0x248).unwrap(), 0, "{label}");
                }
                outputs(p, &request, &step["data"], label);
                mappings(p, step, label);
                returns += 1;
            }
            cases += 1;
        }
    }
    assert_eq!((cases, returns), (62, 76));
}
