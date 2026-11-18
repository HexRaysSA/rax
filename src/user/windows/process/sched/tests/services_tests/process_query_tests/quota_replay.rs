//! Byte-exact current-process quota observations from the selected ARM64 host.
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
        let mut limits = [0; 11];
        let bytes = unhex(&capture.snapshot);
        assert_eq!(bytes.len(), limits.len() * 8);
        for (word, bytes) in limits.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        let (mut process, mut t, scratch) = setup(WinArch::Arm64);
        let p = process.state_mut();
        p.quota_limits = Some(Limits::replay(limits));
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
}
