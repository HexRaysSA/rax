use super::*;

fn pointer(state: &Proc, address: u64, offset: u64, value: u64) {
    state
        .space
        .wptr(address + offset, state.arch.ptr_size(), value)
        .unwrap();
}

fn inputs(state: &mut Proc, base: u64, case: &str) -> [u64; 11] {
    let width = state.arch.ptr_size();
    state.space.wr(base, &[0xa5; 1024]).unwrap();
    let mut args = [
        base,
        0x1fffff,
        0,
        state.arch.ptr(u64::MAX),
        0x1234_5000,
        0,
        1,
        0,
        0,
        0,
        0,
    ];
    if case.starts_with("oa-") {
        let offset = case
            .strip_prefix("oa-align-")
            .map(|n| n.parse::<u64>().unwrap())
            .unwrap_or(0);
        let attributes = base + 256 + offset;
        state
            .space
            .wr(attributes, &vec![0; (6 * width) as usize])
            .unwrap();
        state.space.w32(attributes, 6 * width as u32).unwrap();
        args[2] = attributes;
        match case {
            "oa-zero-length" => state.space.w32(attributes, 0).unwrap(),
            "oa-other-width-length" => state
                .space
                .w32(attributes, if width == 8 { 24 } else { 48 })
                .unwrap(),
            "oa-inherit" => state.space.w32(attributes + 3 * width, 2).unwrap(),
            "oa-exclusive" => state.space.w32(attributes + 3 * width, 0x20).unwrap(),
            "oa-current-thread-root" => {
                pointer(state, attributes, width, state.arch.ptr(u64::MAX - 1))
            }
            "oa-bad-pointer" => args[2] = 1,
            "oa-empty-name" => {
                state
                    .space
                    .wr(base + 384, &vec![0; (2 * width) as usize])
                    .unwrap();
                pointer(state, attributes, 2 * width, base + 384);
            }
            "oa-normal" => {}
            _ => assert!(case.starts_with("oa-align-")),
        }
    } else if case.starts_with("list-")
        || case.starts_with("cid-align-")
        || case.starts_with("return-align-")
    {
        let offset = case
            .strip_prefix("list-align-")
            .map(|n| n.parse::<u64>().unwrap())
            .unwrap_or(0);
        let list = base + 512 + offset;
        args[10] = list;
        for (index, value) in [
            9 * width,
            0x10003,
            2 * width,
            base + 32,
            base + 64,
            0x10004,
            width,
            base + 48,
            base + 72,
        ]
        .into_iter()
        .enumerate()
        {
            pointer(state, list, index as u64 * width, value);
        }
        match case {
            "list-zero-length" => pointer(state, list, 0, 0),
            "list-header-only" => pointer(state, list, 0, width),
            "list-incomplete-entry" => pointer(state, list, 0, 2 * width),
            "list-unknown-attribute" => pointer(state, list, width, 0x100ff),
            "list-short-cid" => pointer(state, list, 2 * width, width),
            "list-long-teb" => pointer(state, list, 6 * width, 2 * width),
            "list-bad-return-length" => pointer(state, list, 4 * width, 1),
            "list-bad-output" => pointer(state, list, 3 * width, 1),
            "list-normal" => {}
            _ => {
                if let Some(offset) = case.strip_prefix("cid-align-") {
                    pointer(
                        state,
                        list,
                        3 * width,
                        base + 128 + offset.parse::<u64>().unwrap(),
                    );
                } else if let Some(offset) = case.strip_prefix("return-align-") {
                    pointer(
                        state,
                        list,
                        4 * width,
                        base + 160 + offset.parse::<u64>().unwrap(),
                    );
                } else {
                    assert!(case.starts_with("list-align-"));
                }
            }
        }
    } else {
        match case {
            "normal" => {}
            "output-null" => args[0] = 0,
            "output-unaligned" => args[0] += 1,
            "process-null" => args[3] = 0,
            "process-current-thread" => args[3] = state.arch.ptr(u64::MAX - 1),
            "access-zero" => args[1] = 0,
            "flags-reserved-8" => args[6] |= 8,
            "flags-reserved-80" => args[6] |= 0x80,
            _ => panic!("unclassified native case {case}"),
        }
    }
    args
}

fn changed(state: &Proc, base: u64, offset: u64, bytes: usize) -> bool {
    state
        .space
        .bytes(base + offset, bytes)
        .unwrap()
        .iter()
        .any(|byte| *byte != 0xa5)
}

#[test]
fn native_thread_create_replays_state_independent_status_and_copy_records() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-nt-thread-lifecycle/create-thread-validation-observations-v4.json"
    )).unwrap();
    let mut count = 0;
    let mut differences = Vec::new();
    for arch in WinArch::ALL {
        let profile = corpus["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| {
                p["architecture"].as_str()
                    == Some(if arch == WinArch::X86 { "x86" } else { "arm64" })
            })
            .unwrap();
        for row in profile["rows"].as_array().unwrap() {
            let case = row["case"].as_str().unwrap();
            // Placement is replayed under a controlled empty VM by the stack
            // allocator tests. The arbitrary native handle0x123 depends on the
            // observer's live handle namespace and is not a portable input.
            if case.starts_with("zero-bits-") || case == "process-invalid" {
                continue;
            }
            let (mut process, mut caller) = fixture(arch, "NtCreateThreadEx", SERVICE);
            let state = process.state_mut();
            state.exe_stack_reserve = profile["image_defaults"]["stack_reserve"].as_u64().unwrap();
            state.exe_stack_commit = profile["image_defaults"]["stack_commit"].as_u64().unwrap();
            let base = state
                .vm
                .allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
            let args = inputs(state, base, case);
            assert_eq!(
                enter(state, &mut caller, args),
                Outcome::Continue,
                "{arch}/{case}"
            );
            let actual = caller.cpu.gpr(0) as u32;
            let expected = row["status"].as_u64().unwrap() as u32;
            if actual != expected {
                differences.push(format!(
                    "{arch}/{case}/status: {actual:#x} != {expected:#x}"
                ));
            }
            for (field, offset, bytes) in [
                ("output_changed", 0, 2 * arch.ptr_size() as usize),
                ("cid_changed", 32, 2 * arch.ptr_size() as usize),
                ("teb_changed", 48, arch.ptr_size() as usize),
            ] {
                let actual = changed(state, base, offset, bytes);
                let expected = row[field].as_bool().unwrap();
                if actual != expected {
                    differences.push(format!("{arch}/{case}/{field}: {actual} != {expected}"));
                }
            }
            for (field, offset) in [("cid_returned", 64), ("teb_returned", 72)] {
                let actual = state.space.ptr(base + offset, arch.ptr_size()).unwrap();
                let expected = row[field].as_u64().unwrap();
                if actual != expected {
                    differences.push(format!(
                        "{arch}/{case}/{field}: {actual:#x} != {expected:#x}"
                    ));
                }
            }
            count += 1;
        }
    }
    assert_eq!(count, 159);
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn native_thread_create_output_faults_release_unpublished_guest_resources() {
    use crate::user::windows::nt::status::{STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT};

    for arch in WinArch::ALL {
        for case in ["list-bad-output", "list-bad-return-length"] {
            let (mut process, mut caller) = fixture(arch, "NtCreateThreadEx", SERVICE);
            let state = process.state_mut();
            let base = state
                .vm
                .allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
            let args = inputs(state, base, case);
            let threads = state.threads.len();
            let objects = state.objects.iter().count();
            let allocations = state.vm.allocations().count();
            assert_eq!(enter(state, &mut caller, args), Outcome::Continue);
            assert_eq!(
                caller.cpu.gpr(0) as u32,
                if arch == WinArch::X86 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                },
                "{arch}/{case}"
            );
            assert_eq!(state.threads.len(), threads, "{arch}/{case}");
            assert_eq!(state.objects.iter().count(), objects, "{arch}/{case}");
            assert_eq!(state.vm.allocations().count(), allocations, "{arch}/{case}");
            let word = state.space.ptr(base, arch.ptr_size()).unwrap();
            assert!(state.objects.get(word).is_none(), "{arch}/{case}");
        }
    }
}
