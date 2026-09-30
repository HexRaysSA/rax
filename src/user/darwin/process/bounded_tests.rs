//! Static Mach-O fixtures exercise bounded execution without a host dyld.
use super::*;
use crate::user::image::macho::*;

const TEXT: u64 = 0x1_0000_0000;
const ENTRY: u64 = TEXT + 0x1000;
const PAGE: u64 = 0x4000;

fn command(kind: u32, body: &[u8]) -> Vec<u8> {
    [
        kind.to_le_bytes().to_vec(),
        ((8 + body.len()) as u32).to_le_bytes().to_vec(),
        body.to_vec(),
    ]
    .concat()
}
fn segment(name: &[u8], address: u64, size: u64, file_size: u64, protection: u32) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[..name.len()].copy_from_slice(name);
    for value in [address, size, 0, file_size] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [protection, protection, 0, 0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    command(LC_SEGMENT_64, &body)
}
fn process(abi: DarwinAbi) -> DarwinProcess {
    let (kind, subtype, flavor, count, pc_index) = match abi {
        DarwinAbi::X86_64 => (
            CPU_TYPE_X86_64,
            CPU_SUBTYPE_X86_64_ALL,
            X86_THREAD_STATE64,
            X86_THREAD_STATE64_COUNT,
            16,
        ),
        DarwinAbi::Arm64 => (
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            ARM_THREAD_STATE64,
            ARM_THREAD_STATE64_COUNT,
            32,
        ),
    };
    let mut thread = Vec::new();
    thread.extend_from_slice(&flavor.to_le_bytes());
    thread.extend_from_slice(&count.to_le_bytes());
    thread.resize(8 + count as usize * 4, 0);
    thread[8 + pc_index * 8..8 + (pc_index + 1) * 8].copy_from_slice(&ENTRY.to_le_bytes());
    let commands = [
        segment(b"__PAGEZERO", 0, TEXT, 0, 0),
        segment(b"__TEXT", TEXT, PAGE, PAGE, VM_PROT_READ | VM_PROT_EXECUTE),
        command(LC_UNIXTHREAD, &thread),
    ];
    let mut bytes = Vec::new();
    for value in [
        MH_MAGIC_64,
        kind,
        subtype,
        MH_EXECUTE,
        commands.len() as u32,
        commands.iter().map(Vec::len).sum::<usize>() as u32,
        0,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for command in commands {
        bytes.extend(command);
    }
    bytes.resize(PAGE as usize, 0);
    // exit(37): BSD class 2 / syscall 1 on x86-64, x16=1 on arm64.
    let code = match abi {
        DarwinAbi::X86_64 => vec![0xb8, 1, 0, 0, 2, 0xbf, 37, 0, 0, 0, 0x0f, 0x05],
        DarwinAbi::Arm64 => [0xd280_0030u32, 0xd280_04a0, 0xd400_0001]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    };
    bytes[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    let mut config = DarwinConfig::new("/bounded-test", vec![b"/bounded-test".to_vec()], vec![]);
    config.abi = Some(abi);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    config.slice_insns = 1;
    DarwinProcess::spawn(
        config,
        ImageFile {
            path: "/bounded-test".into(),
            host_path: "/bounded-test".into(),
            vnode_path: "/bounded-test".into(),
            bytes: bytes.into(),
            file_id: (0, 0),
            slice: None,
        },
    )
    .unwrap()
}
fn finish(p: &mut DarwinProcess) {
    for _ in 0..100 {
        match p.run_slice(1, &AtomicBool::new(false)) {
            RunStatus::BudgetExhausted => {}
            RunStatus::Complete(status) => {
                assert_eq!(status, ExitStatus::Exited(37));
                return;
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
    panic!("exit did not complete within 100 turns");
}

#[test]
fn bounded_zero_cancel_resume_and_cached_exit_both_darwin_abis() {
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let cancelled = AtomicBool::new(true);
        assert_eq!(p.run_slice(0, &cancelled), RunStatus::BudgetExhausted);
        assert_eq!(p.run_slice(10, &cancelled), RunStatus::Cancelled);
        assert_eq!(p.proc.threads.values().next().unwrap().cpu.pc(), ENTRY);
        cancelled.store(false, Ordering::Release);
        finish(&mut p);
        assert_eq!(
            p.run_slice(0, &cancelled),
            RunStatus::Complete(ExitStatus::Exited(37))
        );
        p.proc.exit = None;
        assert_eq!(p.run(), ExitStatus::Exited(37));
    }
}

#[test]
fn bounded_indefinite_wait_cancellation_and_posted_wake_both_darwin_abis() {
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let tid = *p.proc.threads.keys().next().unwrap();
        let key = WaitKey::Address(0x1234);
        p.proc.threads.get_mut(&tid).unwrap().wait = Some(Wait::key(key, None));
        let cancelled = AtomicBool::new(false);
        assert_eq!(p.run_slice(u64::MAX, &cancelled), RunStatus::Blocked);
        assert!(p.proc.threads[&tid].wait.is_some());
        cancelled.store(true, Ordering::Release);
        assert_eq!(p.run_slice(10, &cancelled), RunStatus::Cancelled);
        assert!(p.proc.threads[&tid].wait.is_some());
        p.proc.post(key);
        cancelled.store(false, Ordering::Release);
        finish(&mut p);
    }
}
