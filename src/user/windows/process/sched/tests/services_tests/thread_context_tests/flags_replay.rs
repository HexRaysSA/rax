use super::native_replay::{corpus, select_native};
use super::*;

#[test]
fn native_thread_context_replays_native_requested_flags_and_unselected_bytes() {
    let mut failures = Vec::new();
    for arch in WinArch::ALL {
        let (mut process, mut current, scratch) = setup(arch);
        let p = process.state_mut();
        let tid = thread::create(p, 0x1234_1000, 0, 0x10000, false).unwrap();
        select_native(p, tid);
        let handle = u64::from(
            p.objects
                .open_access(p.threads[&tid].obj, false, 24)
                .unwrap(),
        );
        let original = p.threads[&tid].cpu.new_thread();
        let saved = RegContext::capture(&original);
        let flags_offset = if arch == WinArch::X64 { 48 } else { 0 };
        let mut gets = 0;
        let mut sets = 0;
        for line in corpus(arch).lines() {
            let values: Vec<_> = line.split_whitespace().collect();
            if !matches!(values[2], "00000000" | "00000001") {
                continue;
            }
            let get = values[2] == "00000000";
            let fields = if get { 14 } else { 7 };
            let row: Vec<_> = values[1..fields]
                .iter()
                .map(|v| u32::from_str_radix(v, 16).unwrap())
                .collect();
            p.threads.get_mut(&tid).unwrap().cpu = original.new_thread();
            p.space.wr(scratch, &vec![0xa5; 2048]).unwrap();
            if !get {
                saved.write(&p.space, scratch).unwrap();
            }
            p.space.w32(scratch + flags_offset, row[2]).unwrap();
            let before = p.space.bytes(scratch, 2048).unwrap();
            let name = if get {
                "NtGetContextThread"
            } else {
                "NtSetContextThread"
            };
            let error = current.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0x7654_3210).unwrap();
            if get {
                gets += 1;
            } else {
                sets += 1;
            }
            let actual = status(p, &mut current, name, &[handle, scratch]);
            if actual != row[3] {
                failures.push(format!(
                    "{arch}/{name}/flags{:#x}: status{actual:#x}, native{:#x}",
                    row[2], row[3]
                ));
                continue;
            }
            assert_eq!(row[4], 0);
            assert_eq!(p.space.u32(error).unwrap(), row[5]);
            if get {
                let mask = values[14].as_bytes();
                assert_eq!(mask.len(), 6144);
                let after = p.space.bytes(scratch, 2048).unwrap();
                for n in 0..2048 {
                    if mask[n] == b'0' {
                        assert_eq!(
                            after[n], before[n],
                            "{arch}/flags{:#x}/unselected byte{n}",
                            row[2]
                        );
                    }
                }
                assert_eq!(
                    p.space.u32(scratch + flags_offset).unwrap(),
                    row[if arch == WinArch::X64 { 11 } else { 9 }],
                    "{arch}/flags{:#x}/returned flags",
                    row[2]
                );
            }
        }
        assert_eq!(gets, 74);
        assert_eq!(sets, 74);
        p.objects.close(handle).unwrap();
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
