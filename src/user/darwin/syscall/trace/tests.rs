//! Frame-record walks over hand-built stacks, and the report layout.

use super::*;
use crate::isa::arm::aarch64::pauth::PauthAlgorithm;
use crate::user::mm::{Mapping, SpaceConfig};

/// The program's text.
const PROGRAM: u64 = 0x1_0000_0000;
/// The shared cache's text.
const CACHE: u64 = 0x1_8000_0000;
/// The stack.
const STACK: u64 = 0x7000_0000;
/// A page.
const PAGE: u64 = 0x4000;

fn space() -> AddressSpace {
    AddressSpace::new(SpaceConfig {
        arena_bytes: 16 << 20,
        va_limit: 1 << 47,
        reserved_phys: Vec::new(),
    })
    .expect("space")
}

/// Maps the program and cache text (read-execute) and a read-write stack.
fn map(space: &AddressSpace) {
    let text = Perms::READ | Perms::EXEC;
    space
        .map(
            PROGRAM,
            PAGE,
            Mapping::anonymous(text).named("/bin/program"),
        )
        .expect("program");
    space
        .map(
            CACHE,
            PAGE,
            Mapping::anonymous(text).named("[shared region]"),
        )
        .expect("cache");
    space
        .map(STACK, PAGE, Mapping::anonymous(Perms::READ | Perms::WRITE))
        .expect("stack");
}

/// Writes frame records: each `(fp, caller_fp, return_address)`.
fn records(space: &AddressSpace, chain: &[(u64, u64, u64)]) {
    for &(fp, caller_fp, ret) in chain {
        space.write(fp, &caller_fp.to_le_bytes()).expect("fp slot");
        space.write(fp + 8, &ret.to_le_bytes()).expect("lr slot");
    }
}

fn addrs(frames: &[Frame]) -> Vec<u64> {
    frames.iter().map(|f| f.addr).collect()
}

/// An x86-64 thread in a `SYSCALL` stub: `[RSP]` holds the stub's return
/// address and `RBP` its caller's frame record.
fn x86_in_stub(rsp_word: u64, rbp: u64) -> DarwinCpu {
    let space = space();
    map(&space);
    let mut cpu = DarwinCpu::new(DarwinAbi::X86_64, &space);
    let rsp = STACK + 0xf00;
    space.write(rsp, &rsp_word.to_le_bytes()).expect("rsp slot");
    cpu.set_sp(rsp);
    cpu.set_reg(X86_RBP, rbp);
    cpu
}

#[test]
fn x86_64_walk_takes_the_stub_return_then_the_frame_records() {
    let cpu = x86_in_stub(CACHE + 0x123, STACK + 0xf10);
    let space = cpu.space();
    records(
        space,
        &[
            (STACK + 0xf10, STACK + 0xf40, CACHE + 0x456),
            (STACK + 0xf40, STACK + 0xf80, PROGRAM + 0x789),
            (STACK + 0xf80, 0, PROGRAM + 0xabc),
        ],
    );
    let frames = backtrace(space, &cpu, CACHE + 0x10, 16);
    assert_eq!(
        addrs(&frames),
        [
            CACHE + 0x10,
            CACHE + 0x123,
            CACHE + 0x456,
            PROGRAM + 0x789,
            PROGRAM + 0xabc,
        ]
    );
    let images: Vec<Option<&str>> = frames.iter().map(|f| f.image.as_deref()).collect();
    assert_eq!(
        images,
        [
            Some("[shared region]"),
            Some("[shared region]"),
            Some("[shared region]"),
            Some("/bin/program"),
            Some("/bin/program"),
        ]
    );
}

#[test]
fn walk_stops_at_the_requested_depth() {
    let cpu = x86_in_stub(CACHE + 0x123, STACK + 0xf10);
    let space = cpu.space();
    records(
        space,
        &[
            (STACK + 0xf10, STACK + 0xf40, CACHE + 0x456),
            (STACK + 0xf40, 0, PROGRAM + 0x789),
        ],
    );
    for (depth, expected) in [
        (0, &[][..]),
        (1, &[CACHE + 0x10][..]),
        (2, &[CACHE + 0x10, CACHE + 0x123][..]),
        (3, &[CACHE + 0x10, CACHE + 0x123, CACHE + 0x456][..]),
    ] {
        let frames = backtrace(space, &cpu, CACHE + 0x10, depth);
        assert_eq!(addrs(&frames), expected, "depth {depth}");
    }
}

#[test]
fn a_stub_return_outside_code_is_skipped() {
    // A function with its own record that traps inline: the word at RSP is
    // a local (here a stack address), not a return address.
    let cpu = x86_in_stub(STACK + 0x800, STACK + 0xf10);
    let space = cpu.space();
    records(space, &[(STACK + 0xf10, 0, PROGRAM + 0x789)]);
    let frames = backtrace(space, &cpu, CACHE + 0x10, 16);
    assert_eq!(addrs(&frames), [CACHE + 0x10, PROGRAM + 0x789]);
}

#[test]
fn walk_ends_on_a_corrupt_chain() {
    let cases: [(&str, u64, &[(u64, u64, u64)], &[u64]); 5] = [
        (
            "a caller record below the callee's",
            STACK + 0xf40,
            &[(STACK + 0xf40, STACK + 0xf10, PROGRAM + 0x789)],
            &[PROGRAM + 0x789],
        ),
        (
            "a record pointing at itself",
            STACK + 0xf40,
            &[(STACK + 0xf40, STACK + 0xf40, PROGRAM + 0x789)],
            &[PROGRAM + 0x789],
        ),
        (
            "a return address into data",
            STACK + 0xf40,
            &[
                (STACK + 0xf40, STACK + 0xf80, STACK + 0x10),
                (STACK + 0xf80, 0, PROGRAM + 0x789),
            ],
            &[],
        ),
        (
            "a misaligned frame pointer",
            STACK + 0xf44,
            &[(STACK + 0xf40, 0, PROGRAM + 0x789)],
            &[],
        ),
        ("an unmapped frame pointer", STACK + PAGE + 0x40, &[], &[]),
    ];
    for (what, fp, chain, walked) in cases {
        let cpu = x86_in_stub(0, fp);
        let space = cpu.space();
        records(space, chain);
        let frames = backtrace(space, &cpu, CACHE + 0x10, 16);
        let mut expected = vec![CACHE + 0x10];
        expected.extend_from_slice(walked);
        assert_eq!(addrs(&frames), expected, "{what}");
    }
}

#[test]
fn arm64_walk_strips_signed_returns_and_reports_lr_once() {
    let mut cpu = crate::user::darwin::pauth::tests::cpu(PauthAlgorithm::Qarma5, true);
    let space = cpu.space().clone();
    map(&space);
    let DarwinCpu::Arm64(core) = &cpu else {
        unreachable!()
    };
    let pauth = UserPauth::from_cpu(core);
    // arm64e saves `PACIBSP`-signed return addresses; the walk must find
    // the code under any signature.
    let fp = STACK + 0xf10;
    let signed = pauth.sign(PROGRAM + 0x789, PauthKeyKind::Ib, fp + 0x10);
    assert_ne!(signed, PROGRAM + 0x789, "the signature changes the pointer");
    records(
        &space,
        &[
            (fp, STACK + 0xf40, CACHE + 0x456),
            (STACK + 0xf40, 0, signed),
        ],
    );
    // A function whose record is set up when it traps: LR equals the
    // first record's return address and is reported once.
    cpu.set_reg(ARM64_LR, CACHE + 0x456);
    cpu.set_reg(ARM64_FP, fp);
    let frames = backtrace(&space, &cpu, CACHE + 0x10, 16);
    assert_eq!(
        addrs(&frames),
        [CACHE + 0x10, CACHE + 0x456, PROGRAM + 0x789]
    );

    // A leaf stub: LR is the stub's return and precedes the records.
    cpu.set_reg(ARM64_LR, CACHE + 0x123);
    let frames = backtrace(&space, &cpu, CACHE + 0x10, 16);
    assert_eq!(
        addrs(&frames),
        [CACHE + 0x10, CACHE + 0x123, CACHE + 0x456, PROGRAM + 0x789]
    );
}

#[test]
fn report_puts_the_pc_before_the_call_and_the_frames_after() {
    let frames = vec![
        Frame {
            addr: CACHE + 0x10,
            image: Some(Arc::from("[shared region]")),
        },
        Frame {
            addr: 0x5000,
            image: None,
        },
    ];
    let x86 = CallSite {
        abi: DarwinAbi::X86_64,
        pc: CACHE + 0x10,
        show_pc: true,
        frames: frames.clone(),
    };
    assert_eq!(
        report(0x103, Some(&x86), "getpid() = 7"),
        "[0x103] rip=0x180000010 getpid() = 7\n\
         [0x103]  > 0x180000010 [shared region]\n\
         [0x103]  > 0x5000\n"
    );
    let arm64 = CallSite {
        abi: DarwinAbi::Arm64,
        pc: CACHE + 0x10,
        show_pc: true,
        frames: Vec::new(),
    };
    assert_eq!(
        report(0x103, Some(&arm64), "getpid() = 7"),
        "[0x103] pc=0x180000010 getpid() = 7\n"
    );
    let stack_only = CallSite {
        show_pc: false,
        frames,
        ..arm64
    };
    assert_eq!(
        report(0x203, Some(&stack_only), "getpid() = 7"),
        "[0x203] getpid() = 7\n\
         [0x203]  > 0x180000010 [shared region]\n\
         [0x203]  > 0x5000\n"
    );
    assert_eq!(
        report(0x103, None, "getpid() = 7"),
        "[0x103] getpid() = 7\n"
    );
}
