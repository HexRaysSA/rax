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

#[derive(Deserialize)]
struct Wow64Corpus {
    geometry: Wow64Capture,
    faults: Wow64Capture,
}

#[derive(Deserialize)]
struct Wow64Capture {
    cases: Vec<Wow64Case>,
}

#[derive(Deserialize)]
struct Wow64Case {
    name: String,
    length: u32,
    handle: u32,
    visible: Pointer,
    output: Pointer,
    returned: Pointer,
    length_observation: Pointer,
    initial_protection: u32,
    protection: u32,
    status: u32,
    length_value: u32,
    image: String,
    return_page: String,
}

#[derive(Deserialize)]
struct Pointer {
    base: Base,
    offset: i32,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Base {
    First,
    Boundary,
    Absolute,
}

impl Pointer {
    fn resolve(&self, first: u64, boundary: u64) -> u64 {
        let base = match self.base {
            Base::First => first,
            Base::Boundary => boundary,
            Base::Absolute => 0,
        };
        base.checked_add_signed(i64::from(self.offset)).unwrap()
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
        .collect()
}

fn handle(p: &mut Proc, value: u32) -> u64 {
    match value {
        u32::MAX => u64::MAX,
        0 => 0,
        0xFFFF_FFFE => u64::MAX - 1,
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
    }
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
        let handle = handle(p, case.handle);
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
fn wow64_process_vm_counters_replay_lengths_rights_padding_and_copy_faults() {
    let corpus: Wow64Corpus = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-process-vm-counters/queries-29708-wow64-x86.json"
    ))
    .unwrap();
    assert_eq!(corpus.geometry.cases.len(), 55);
    assert_eq!(corpus.faults.cases.len(), 26);
    let (mut process, mut thread, _) = setup(WinArch::X86);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, 29708, 0xAA64);
    let (first, _) =
        p.vm.allocate(
            None,
            2 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap();
    let boundary = first + PAGE_SIZE;
    for case in corpus.geometry.cases.into_iter().chain(corpus.faults.cases) {
        let visible = case.visible.resolve(first, boundary);
        let output = case.output.resolve(first, boundary);
        let returned = case.returned.resolve(first, boundary);
        let length_observation = case.length_observation.resolve(first, boundary);
        let mut expected = unhex(&case.image);
        p.space.wr(visible, &vec![0xA5; expected.len()]).unwrap();
        p.space.wr(first + 256, &[0xD4; 5]).unwrap();
        p.space.wr(boundary - 2, &[0xA5; 4]).unwrap();
        p.vm.protect(boundary, PAGE_SIZE, case.initial_protection)
            .unwrap();
        if case.status == 0 {
            // Native capture supplies padding and surrounding bytes. Derive
            // sampled counter values independently from the guest's 64-bit
            // record because the host has a different process address space.
            let bytes = case.length as usize;
            let offset = (output - visible) as usize;
            let native = p.vm.process_counters(bytes == 64);
            for (slot, field) in expected[offset..offset + bytes.min(52)]
                .chunks_exact_mut(4)
                .zip(native.chunks_exact(8))
            {
                slot.copy_from_slice(&field[..4]);
            }
            if bytes == 64 {
                expected[offset + 56..offset + bytes].copy_from_slice(&native[104..112]);
            }
        }
        let handle = handle(p, case.handle);
        let status = query(p, &mut thread, handle, output, case.length, returned);
        assert_eq!(status, case.status, "{}", case.name);
        assert_eq!(
            p.vm.query(boundary).unwrap().protect,
            case.protection,
            "{}",
            case.name
        );
        p.vm.protect(boundary, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(
            p.space.u32(length_observation).unwrap(),
            case.length_value,
            "{}",
            case.name
        );
        assert_eq!(
            p.space.bytes(visible, expected.len()).unwrap(),
            expected,
            "{}",
            case.name
        );
        assert_eq!(
            p.space.bytes(boundary - 2, 4).unwrap(),
            unhex(&case.return_page),
            "{}",
            case.name
        );
    }
}

#[test]
fn native_process_vm_counters_distinguish_reservation_commit_touch_and_release() {
    check_vm_counter_lifecycle(WinArch::Arm64, 29708, 0xaa64);
    check_vm_counter_lifecycle(WinArch::Arm64, 26200, 0xaa64);
    check_vm_counter_lifecycle(WinArch::X64, 26100, 0x8664);
}

#[test]
fn wow64_process_vm_counters_distinguish_reservation_commit_touch_and_release() {
    check_vm_counter_lifecycle(WinArch::X86, 29708, 0xaa64);
}

fn check_vm_counter_lifecycle(arch: WinArch, build: u32, machine: u16) {
    let (mut process, mut thread, scratch) = setup(arch);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, build, machine);
    let snapshot = |p: &mut Proc, thread: &mut Thread| {
        let mut words = [0; 14];
        if arch == WinArch::X86 {
            assert_eq!(query(p, thread, u64::MAX, scratch, 64, 0), 0);
            for (index, word) in words[..13].iter_mut().enumerate() {
                *word = u64::from(p.space.u32(scratch + index as u64 * 4).unwrap());
            }
            words[13] = p.space.u64(scratch + 56).unwrap();
        } else {
            assert_eq!(query(p, thread, u64::MAX, scratch, 112, 0), 0);
            for (index, word) in words.iter_mut().enumerate() {
                *word = p.space.u64(scratch + index as u64 * 8).unwrap();
            }
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
