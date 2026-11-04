use super::*;

fn corpus() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-file-state-set/observations-v1.json"
    )))
    .unwrap()
}

fn label(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => "arm64",
        WinArch::X64 => "x64",
        WinArch::X86 => "x86",
    }
}

#[test]
fn file_state_set_replays_native_scalars_transitions_grants_and_duplicate_lifetimes() {
    let corpus = corpus();
    let rows = corpus["scalars"].as_array().unwrap();
    assert_eq!(rows.len(), 12720);
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let mut current = None;
        for row in rows.iter().filter(|row| row["arch"] == label(arch)) {
            if row["sequence"] == 0 || row["step"] == 0 {
                if let Some(r) = current.take() {
                    release(p, r);
                }
                current = Some(resource(p, row["role"].as_str().unwrap()));
            }
            let r = current.as_ref().unwrap();
            assert_eq!(
                snapshot(p, &mut thread, r.handle, base + 2 * PAGE_SIZE),
                row["before"],
                "before {row}"
            );
            p.space.wr(base, &[0xA5; 128]).unwrap();
            let input = unhex(row["value"].as_str().unwrap());
            p.space.wr(base + 64, &input).unwrap();
            let error = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0x12345678).unwrap();
            let result = invoke(
                p,
                &mut thread,
                &[
                    r.handle,
                    base,
                    base + 64,
                    row["length"].as_u64().unwrap(),
                    row["class"].as_u64().unwrap(),
                ],
            );
            assert_eq!(u64::from(result), row["status"].as_u64().unwrap(), "{row}");
            assert_eq!(
                hex(&p.space.bytes(base, 2 * arch.ptr_size() as usize).unwrap()),
                row["io"].as_str().unwrap(),
                "IOSB {row}"
            );
            assert_eq!(
                hex(&p.space.bytes(base + 64, 16).unwrap()),
                row["input_after"].as_str().unwrap(),
                "input {row}"
            );
            assert_eq!(
                snapshot(p, &mut thread, r.handle, base + 2 * PAGE_SIZE),
                row["after"],
                "after {row}"
            );
            if let Some(h) = r.parent {
                assert_eq!(
                    snapshot(p, &mut thread, h, base + 2 * PAGE_SIZE),
                    row["parent_after"],
                    "parent {row}"
                );
            }
            if let Some(h) = r.independent {
                assert_eq!(
                    snapshot(p, &mut thread, h, base + 2 * PAGE_SIZE),
                    row["independent_after"],
                    "independent {row}"
                );
            }
            assert_eq!(p.space.u32(error).unwrap(), 0x12345678);
        }
        release(p, current.unwrap());
    }
}

fn decoded(row: &Value, key: &str, bytes: usize) -> Vec<u8> {
    let mut data = vec![0xA5; bytes];
    for (offset, value) in row[key].as_object().unwrap() {
        let offset = offset.parse::<usize>().unwrap();
        let changed = unhex(value.as_str().unwrap());
        data[offset..offset + changed.len()].copy_from_slice(&changed);
    }
    data
}

#[test]
fn file_state_set_replays_native_faults_aliasing_guard_visits_and_late_side_effects() {
    let corpus = corpus();
    let rows = corpus["faults"].as_array().unwrap();
    assert_eq!(rows.len(), 9555);
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let data = base + 3 * PAGE_SIZE;
        for row in rows.iter().filter(|row| row["arch"] == label(arch)) {
            p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
            p.space
                .wr(base, &vec![0xA5; 6 * PAGE_SIZE as usize])
                .unwrap();
            let r = resource(p, row["role"].as_str().unwrap());
            assert_eq!(
                snapshot(p, &mut thread, r.handle, base + 2 * PAGE_SIZE),
                row["before"],
                "before {row}"
            );
            let (mut io, mut input) = (base + 64, data + 64);
            let which = row["case"].as_u64().unwrap();
            match which {
                0 => {}
                1 => io = 0,
                2 => input = 0,
                3 => {
                    io = 0;
                    input = 0;
                }
                4 => io = 1,
                5 => input = 1,
                6 => {
                    io = 1;
                    input = 1;
                }
                7 => io += 1,
                8 => input += 1,
                9 => io = base + PAGE_SIZE - 4,
                10 => io = base + PAGE_SIZE - arch.ptr_size(),
                11 => input = data + PAGE_SIZE - 4,
                12..=16 => {}
                17 => input = io,
                18 => input = io + arch.ptr_size(),
                19 => input = arch.ptr(u64::MAX - 3),
                20 => io = arch.ptr(u64::MAX - 3),
                21 => io = data + 68,
                _ => panic!("unknown control {row}"),
            }
            let class = row["class"].as_u64().unwrap();
            let value = if class == 14 {
                7
            } else if class == 16 {
                0x20
            } else {
                1
            };
            if (base..=base + 2 * PAGE_SIZE - 8).contains(&input)
                || (data..=data + 2 * PAGE_SIZE - 8).contains(&input)
            {
                p.space.w64(input, value).unwrap();
            }
            for page in [base + PAGE_SIZE, data + PAGE_SIZE] {
                p.vm.protect(page, PAGE_SIZE, prot::NOACCESS).unwrap();
            }
            if matches!(which, 12 | 14) {
                p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            if matches!(which, 13 | 14) {
                p.vm.protect(data, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            if which == 15 {
                p.vm.protect(data, PAGE_SIZE, prot::READONLY).unwrap();
            }
            if which == 16 {
                p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
            }
            let result = invoke(
                p,
                &mut thread,
                &[r.handle, io, input, row["length"].as_u64().unwrap(), class],
            );
            assert_eq!(
                u64::from(result),
                row["status"].as_u64().unwrap(),
                "status {row}"
            );
            assert_eq!(
                u64::from(p.vm.query(base).unwrap().protect),
                row["io_protect"].as_u64().unwrap(),
                "IOSB guard {row}"
            );
            assert_eq!(
                u64::from(p.vm.query(data).unwrap().protect),
                row["input_protect"].as_u64().unwrap(),
                "input guard {row}"
            );
            p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
            for (key, address, bytes) in [
                ("io_base", base + 48, 64),
                ("input_base", data + 48, 160),
                ("io_tail", base + PAGE_SIZE - 24, 48),
                ("input_tail", data + PAGE_SIZE - 24, 64),
            ] {
                assert_eq!(
                    p.space.bytes(address, bytes).unwrap(),
                    decoded(row, key, bytes),
                    "{key} {row}"
                );
            }
            assert_eq!(
                snapshot(p, &mut thread, r.handle, base + 2 * PAGE_SIZE),
                row["after"],
                "after {row}"
            );
            if let Some(h) = r.parent {
                assert_eq!(
                    snapshot(p, &mut thread, h, base + 2 * PAGE_SIZE),
                    row["parent_after"],
                    "parent {row}"
                );
            }
            release(p, r);
        }
    }
}
