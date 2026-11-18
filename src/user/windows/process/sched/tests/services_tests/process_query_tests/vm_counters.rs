use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    length: u32,
    handle: u32,
    output_offset: i32,
    return_offset: i32,
    status: u32,
}

fn query(p: &mut Proc, t: &mut Thread, handle: u64, out: u64, bytes: u32, returned: u64) -> u32 {
    arguments(p, t, handle, 3, out, bytes, returned);
    assert_eq!(dispatch(p, t), Outcome::Continue);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_process_vm_counters_replay_query_lengths_rights_and_guard_bytes() {
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-process-vm-counters/queries-29708-arm64.json"
    ))
    .unwrap();
    assert_eq!(corpus.cases.len(), 35);
    let (mut process, mut thread, scratch) = setup(WinArch::Arm64);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, 29708, 0xAA64);
    for case in corpus.cases {
        let handle = match case.handle {
            u32::MAX => u64::MAX,
            0 => 0,
            0xFFFF_FFFD => {
                let event = p.objects.create(Object::Event {
                    manual: false,
                    signaled: 0,
                });
                u64::from(p.objects.open(event, false))
            }
            rights => {
                let process = p.objects.create(Object::Process {
                    pid: p.pid,
                    exit_code: None,
                });
                u64::from(p.objects.open_access(process, false, rights).unwrap())
            }
        };
        let pointer = |base, offset| u64::try_from(offset).map_or(0, |offset| base + offset);
        let mut output = [0xA5; 152];
        let mut length = [0xD4; 12];
        p.space.wr(scratch, &output).unwrap();
        p.space.wr(scratch + 256, &length).unwrap();
        let copy = p.vm.process_counters(case.length == 112);
        let status = query(
            p,
            &mut thread,
            handle,
            pointer(scratch, case.output_offset),
            case.length,
            pointer(scratch + 256, case.return_offset),
        );
        assert_eq!(status, case.status, "{}", case.name);
        if status == 0 {
            let offset = usize::try_from(case.output_offset).unwrap();
            let bytes = case.length as usize;
            output[offset..offset + bytes].copy_from_slice(&copy[..bytes]);
            if let Ok(offset) = usize::try_from(case.return_offset) {
                length[offset..offset + 4].copy_from_slice(&case.length.to_le_bytes());
            }
        }
        assert_eq!(
            p.space.bytes(scratch, output.len()).unwrap(),
            output,
            "{}",
            case.name
        );
        assert_eq!(
            p.space.bytes(scratch + 256, length.len()).unwrap(),
            length,
            "{}",
            case.name
        );
    }
}

#[test]
fn native_process_vm_counters_distinguish_reservation_commit_touch_and_release() {
    let (mut process, mut thread, scratch) = setup(WinArch::Arm64);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, 29708, 0xAA64);
    let snapshot = |p: &mut Proc, thread: &mut Thread| {
        assert_eq!(query(p, thread, u64::MAX, scratch, 112, 0), 0);
        let mut words = [0; 14];
        for (index, word) in words.iter_mut().enumerate() {
            *word = p.space.u64(scratch + index as u64 * 8).unwrap();
        }
        words
    };
    let before = snapshot(p, &mut thread);
    let bytes = PAGE_SIZE * 128;
    let base =
        p.vm.allocate(None, bytes, mem::RESERVE, prot::READWRITE)
            .unwrap()
            .0;
    let reserved = snapshot(p, &mut thread);
    assert_eq!(reserved[1], before[1] + bytes);
    assert_eq!(reserved[9], before[9]);
    assert_eq!(reserved[4], before[4]);

    p.vm.commit(base, bytes, prot::READWRITE).unwrap();
    let committed = snapshot(p, &mut thread);
    assert_eq!(committed[1], reserved[1]);
    assert_eq!(committed[9], before[9] + bytes);
    assert_eq!(committed[11], committed[9]);
    assert_eq!(committed[4], before[4]);

    for page in 0..128 {
        p.space.w32(base + page * PAGE_SIZE, 1).unwrap();
    }
    let touched = snapshot(p, &mut thread);
    assert_eq!(touched[2], committed[2] + 128);
    assert_eq!(touched[4], before[4] + bytes);
    assert_eq!(touched[12], before[12] + bytes);
    assert_eq!(touched[13], before[13]);

    p.vm.decommit(base, bytes).unwrap();
    let decommitted = snapshot(p, &mut thread);
    assert_eq!(decommitted[1], reserved[1]);
    assert_eq!(decommitted[4], before[4]);
    assert_eq!(decommitted[9], before[9]);
    assert_eq!(decommitted[12], before[12]);
    p.vm.release(base).unwrap();
    let released = snapshot(p, &mut thread);
    assert_eq!(released[1], before[1]);
    for peak in [0, 3, 10] {
        assert_eq!(released[peak], touched[peak]);
    }
}
