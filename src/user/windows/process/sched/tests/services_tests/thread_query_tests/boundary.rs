//! Independent native page-protection and copy-frontier replay.
use super::*;

fn normalized_output(
    captured: &[u8],
    window: u64,
    output: u64,
    record: &[u8],
    granule: usize,
) -> Vec<u8> {
    let mut expected = vec![0xa5; captured.len()];
    // Native records contain host IDs/pointers/priority/topology. Preserve the
    // observed publication frontier, replacing only complete published fields
    // with the independently specified virtual process/thread values.
    for at in (0..record.len()).step_by(granule) {
        let begin = output + at as u64;
        let end = begin + granule as u64;
        if begin >= window && end <= window + captured.len() as u64 {
            let begin = (begin - window) as usize;
            if captured[begin..begin + granule]
                .iter()
                .any(|byte| *byte != 0xa5)
            {
                expected[begin..begin + granule].copy_from_slice(&record[at..at + granule]);
            }
        }
    }
    expected
}

#[test]
fn native_thread_query_replays_208_native_and_pure_wow64_page_boundary_observations() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-thread-query/boundary-observations-v3.json"
    ))
    .unwrap();
    let mut seen = 0;
    for arch in WinArch::ALL {
        let run = corpus["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| (run["pointer_bytes"] == 4) == (arch == WinArch::X86))
            .unwrap();
        let (mut process, mut current, _) = setup(arch);
        let p = process.state_mut();
        thread::create(p, 0x1234_2000, 0, 0x10000, false).unwrap();
        let memory =
            p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        for row in run["rows"].as_array().unwrap().iter().filter(|row| {
            let class = row["class"].as_u64().unwrap();
            // Class59 and native class60 are captured recognized classes,
            // outside the implemented0/9/12 contract. Do not invent records.
            matches!(class, 0 | 9 | 12) || class >= 61 || arch == WinArch::X86 && class == 60
        }) {
            let class = row["class"].as_u64().unwrap();
            if row["case"] == "class-range" {
                assert_eq!(
                    u64::from(call(
                        p,
                        &mut current,
                        [arch.ptr(u64::MAX - 1), class, memory, 0, memory + 8192]
                    )),
                    row["status"].as_u64().unwrap()
                );
                seen += 1;
                continue;
            }
            let offset = row["output_offset"].as_u64().unwrap();
            let returned = row["return_offset"].as_u64().unwrap();
            p.space.wr(memory, &[0xa5; 16384]).unwrap();
            for (page, protection) in row["protection_before"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                p.vm.protect(
                    memory + page as u64 * 4096,
                    4096,
                    protection.as_u64().unwrap() as u32,
                )
                .unwrap();
            }
            let status = call(
                p,
                &mut current,
                [
                    arch.ptr(u64::MAX - 1),
                    class,
                    memory + offset,
                    row["length"].as_u64().unwrap(),
                    memory + 8192 + returned,
                ],
            );
            assert_eq!(
                u64::from(status),
                row["status"].as_u64().unwrap(),
                "{arch}/{row}"
            );
            for (page, protection) in row["protection_after"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                assert_eq!(
                    u64::from(p.vm.query(memory + page as u64 * 4096).unwrap().protect),
                    protection.as_u64().unwrap(),
                    "{arch}/{row}"
                );
            }
            p.vm.protect(memory, 16384, prot::READWRITE).unwrap();
            let width = arch.ptr_size() as usize;
            let mut record = vec![
                0;
                if class == 0 {
                    if width == 4 { 28 } else { 48 }
                } else if class == 9 {
                    width
                } else {
                    4
                }
            ];
            if class == 0 {
                for (index, value) in [
                    259,
                    current.teb,
                    u64::from(p.pid),
                    u64::from(current.tid),
                    1,
                ]
                .into_iter()
                .enumerate()
                {
                    put(&mut record, index * width, value, width);
                }
                put(&mut record, 5 * width, 8, 4);
            } else if class == 9 {
                put(&mut record, 0, current.start, width);
            }
            let granule = if class == 0 { width } else { record.len() };
            for (field, window, bytes) in [
                ("output_prefix_hex", 0, 64),
                ("output_boundary_hex", 4032, 128),
            ] {
                let expected = normalized_output(
                    &hex(row[field].as_str().unwrap()),
                    window,
                    offset,
                    &record,
                    granule,
                );
                assert_eq!(
                    p.space.bytes(memory + window, bytes).unwrap(),
                    expected,
                    "{arch}/{row}"
                );
            }
            for (field, window, bytes) in [
                ("return_prefix_hex", 8192, 16),
                ("return_boundary_hex", 12272, 32),
            ] {
                assert_eq!(
                    p.space.bytes(memory + window, bytes).unwrap(),
                    hex(row[field].as_str().unwrap()),
                    "{arch}/{row}"
                );
            }
            seen += 1;
        }
    }
    assert_eq!(seen, 208);
}
