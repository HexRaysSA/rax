//! Byte-exact current-process quota observations from the selected Windows host.
use super::*;
use crate::user::windows::process::quota::{CLASS, Limits};
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    captures: Vec<Capture>,
}

#[derive(Deserialize)]
struct Capture {
    snapshot: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    handle: u32,
    length: u32,
    output_offset: i32,
    returned_offset: i32,
    status: u32,
    image: String,
    returned: String,
}

#[derive(Deserialize)]
struct Wow64Corpus {
    geometry: Capture,
    faults: FaultCapture,
}

#[derive(Deserialize)]
struct FaultCapture {
    cases: Vec<FaultCase>,
}

#[derive(Deserialize)]
struct FaultCase {
    name: String,
    length: u32,
    handle: u32,
    output: Destination,
    returned: Destination,
    prefix: u64,
    status: u32,
    protect: u32,
    length_value: u32,
    image: String,
    return_page: String,
    snapshot: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Destination {
    Normal,
    Null,
    Low,
    Readonly,
    Guard,
    ReadonlyGuard,
    Cross,
    Unaligned,
}

impl Destination {
    fn address(self, normal: u64, boundary: u64, prefix: u64) -> u64 {
        match self {
            Self::Normal => normal,
            Self::Null => 0,
            Self::Low => 4,
            Self::Readonly | Self::Guard | Self::ReadonlyGuard => boundary,
            Self::Cross => boundary - prefix,
            Self::Unaligned => normal + 1,
        }
    }

    fn protection(self) -> Option<u32> {
        match self {
            Self::Readonly | Self::Cross => Some(prot::READONLY),
            Self::Guard => Some(prot::READWRITE | prot::GUARD),
            Self::ReadonlyGuard => Some(prot::READONLY | prot::GUARD),
            _ => None,
        }
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
        0xFFFF_FFFE => u64::MAX - 1,
        0xFFFF_FFFD => {
            let event = p.objects.create(Object::Event {
                manual: false,
                signaled: 0,
            });
            u64::from(p.objects.open(event, false))
        }
        0 => 0,
        rights => {
            let process = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            u64::from(p.objects.open_access(process, false, rights).unwrap())
        }
    }
}

fn replay_snapshot(arch: WinArch, snapshot: &str) -> Limits {
    let bytes = unhex(snapshot);
    let mut words = [0; 11];
    if arch == WinArch::X86 {
        assert_eq!(bytes.len(), 56);
        for (index, offset) in [
            (0, 0),
            (1, 4),
            (2, 8),
            (3, 12),
            (4, 16),
            (6, 32),
            (7, 36),
            (8, 40),
            (9, 44),
        ] {
            let value = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            words[index] = if value == u32::MAX {
                u64::MAX
            } else {
                u64::from(value)
            };
        }
        words[5] = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        words[10] = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
    } else {
        assert_eq!(bytes.len(), words.len() * 8);
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
    }
    Limits::replay(words)
}

fn replay_geometry(arch: WinArch, capture: Capture) {
    let (mut process, mut t, scratch) = setup(arch);
    let p = process.state_mut();
    p.quota_limits = Some(replay_snapshot(arch, &capture.snapshot));
    for case in capture.cases {
        p.space.wr(scratch, &[0xA5; 112]).unwrap();
        p.space.wr(scratch + 256, &[0xD4; 12]).unwrap();
        let output = match case.output_offset {
            -1 => 0,
            -2 => p.vm.high(),
            offset => scratch + u64::try_from(offset).unwrap(),
        };
        let returned = match case.returned_offset {
            -1 => 0,
            -2 => 4,
            offset => scratch + u64::try_from(offset).unwrap(),
        };
        let handle = handle(p, case.handle);
        arguments(p, &mut t, handle, CLASS, output, case.length, returned);
        assert_eq!(dispatch(p, &mut t), Outcome::Continue, "{}", case.name);
        assert_eq!(t.cpu.gpr(0), u64::from(case.status), "{}", case.name);
        assert_eq!(
            p.space.bytes(scratch, 112).unwrap(),
            unhex(&case.image),
            "{}",
            case.name
        );
        assert_eq!(
            p.space.bytes(scratch + 256, 12).unwrap(),
            unhex(&case.returned),
            "{}",
            case.name
        );
    }
}

#[test]
fn native_process_quota_replays_lengths_rights_fault_precedence_and_aliases() {
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-process-quota/queries-29708-arm64.json"
    ))
    .unwrap();
    assert_eq!(
        corpus
            .captures
            .iter()
            .map(|capture| capture.cases.len())
            .collect::<Vec<_>>(),
        [30, 9]
    );
    for capture in corpus.captures {
        replay_geometry(WinArch::Arm64, capture);
    }
}

#[test]
fn wow64_process_quota_replays_lengths_rights_padding_and_aliases() {
    let corpus = wow64_corpus();
    assert_eq!(corpus.geometry.cases.len(), 30);
    replay_geometry(WinArch::X86, corpus.geometry);
}

#[test]
fn wow64_process_quota_replays_fault_order_and_guard_consumption() {
    let corpus = wow64_corpus();
    assert_eq!(corpus.faults.cases.len(), 26);
    let (mut process, mut t, scratch) = setup(WinArch::X86);
    let p = process.state_mut();
    let pages =
        p.vm.allocate(
            None,
            2 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    let boundary = pages + PAGE_SIZE;
    for case in corpus.faults.cases {
        p.quota_limits = Some(replay_snapshot(WinArch::X86, &case.snapshot));
        p.space.wr(scratch, &[0xd4; 5]).unwrap();
        p.space.wr(pages, &[0xa5; 56]).unwrap();
        p.space.wr(boundary - 56, &[0xa5; 112]).unwrap();
        let protection = case
            .output
            .protection()
            .or(case.returned.protection())
            .unwrap_or(prot::READWRITE);
        p.vm.protect(boundary, PAGE_SIZE, protection).unwrap();
        let output = case.output.address(pages, boundary, case.prefix);
        let returned = case.returned.address(scratch, boundary, case.prefix);
        let handle = handle(p, case.handle);
        arguments(p, &mut t, handle, CLASS, output, case.length, returned);
        assert_eq!(dispatch(p, &mut t), Outcome::Continue, "{}", case.name);
        assert_eq!(t.cpu.gpr(0), u64::from(case.status), "{}", case.name);
        assert_eq!(
            p.vm.query(boundary).unwrap().protect,
            case.protect,
            "{}",
            case.name
        );
        p.vm.protect(boundary, PAGE_SIZE, prot::READWRITE).unwrap();
        let visible = if matches!(case.output, Destination::Low | Destination::Null) {
            pages
        } else {
            output
        };
        let visible_length = scratch + u64::from(matches!(case.returned, Destination::Unaligned));
        assert_eq!(
            p.space.u32(visible_length).unwrap(),
            case.length_value,
            "{}",
            case.name
        );
        assert_eq!(
            p.space.bytes(visible, 56).unwrap(),
            unhex(&case.image),
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
fn wow64_process_quota_rejects_unqualified_oversized_size_t() {
    let mut words = [0; 11];
    words[0] = u64::from(u32::MAX) + 1;
    assert!(Limits::replay(words).wow64_encoded().is_none());
    words[0] = u64::MAX;
    assert!(Limits::replay(words).wow64_encoded().is_some());
}

fn wow64_corpus() -> Wow64Corpus {
    serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-process-quota/queries-29708-wow64-x86.json"
    ))
    .unwrap()
}
