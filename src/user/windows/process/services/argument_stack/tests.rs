use super::{BYTES, adrp_add, guard_cookie, scoped_entry_sp};
use crate::user::cpu::x86_64::RESERVED_PHYS;
use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};
use crate::user::windows::arch::{CpuStop, InstructionRoute, WinArch, WinCpu};
use crate::user::windows::hle::{Arg, Conv, args::read_arg};
use crate::user::windows::memory::Mem;

const START: u64 = 0x7ffa_1b49_1b20;
const BASE: u64 = 0x7ffa_1b31_0000;
const SP: u64 = 0x20000;
// Direct bytes captured at NtCreateFile in the installed 10.0.29698.0 NTDLL.
const NATIVE: [u32; 13] = [
    0xd100_43ff,
    0xf0ff_fff0,
    0x9100_c210,
    0xf900_03f0,
    0xd400_0aa1,
    0xf940_03e9,
    0xf0ff_fff0,
    0x9100_c210,
    0xeb09_0210,
    0x9100_43ff,
    0x54ff_25c1,
    0xd280_0009,
    0xd65f_03c0,
];

fn bytes(words: &[u32; 13]) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    for (target, word) in bytes.chunks_exact_mut(4).zip(words) {
        target.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[test]
fn guarded_arm64ec_ntdll_frame_matches_the_captured_complete_stub() {
    assert_eq!(
        guard_cookie(&bytes(&NATIVE), START, 0x55),
        Some(0x7ffa_1b49_0030)
    );
    assert_eq!(guard_cookie(&bytes(&NATIVE), START, 0x56), None);
    for index in [0, 3, 4, 5, 8, 9, 10, 11, 12] {
        let mut altered = NATIVE;
        altered[index] ^= 1;
        assert_eq!(
            guard_cookie(&bytes(&altered), START, 0x55),
            None,
            "word {index}"
        );
    }
    let mut altered = NATIVE;
    altered[7] += 1 << 10;
    assert_eq!(
        guard_cookie(&bytes(&altered), START, 0x55),
        None,
        "different cookie addresses"
    );
}

#[test]
fn guarded_arm64ec_address_decode_checks_registers_and_page_displacements() {
    assert_eq!(
        adrp_add(0xf0ff_fff0, 0x9100_c210, START + 4),
        Some(0x7ffa_1b49_0030)
    );
    assert_eq!(adrp_add(0x9000_0010, 0x9100_0210, 0x2000), Some(0x2000));
    assert_eq!(
        adrp_add(0xf0ff_fff0, 0x9100_0210, 0),
        None,
        "negative address"
    );
    assert_eq!(
        adrp_add(0x9000_0011, 0x9100_0210, START),
        None,
        "wrong ADRP register"
    );
    assert_eq!(
        adrp_add(0x9000_0010, 0x9100_0230, START),
        None,
        "wrong ADD source"
    );
}

#[test]
fn guarded_arm64ec_nine_to_eleven_arguments_skip_the_cookie_without_moving_sp() {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 64 * PAGE_SIZE,
        reserved_phys: RESERVED_PHYS.to_vec(),
    })
    .unwrap();
    space
        .map(
            START & !(PAGE_SIZE - 1),
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::EXEC),
        )
        .unwrap();
    space
        .map(
            SP,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    space.write_raw(START, &bytes(&NATIVE)).unwrap();
    space.w64(SP, 0x7ffa_1b49_0030).unwrap();
    space.w64(SP + 8, 0x80).unwrap();
    space.w64(SP + 16, 0x60).unwrap();
    space.w64(SP + 24, 0).unwrap();
    space.w64(SP + 32, 0).unwrap();
    let before = space.bytes(SP, 40).unwrap();
    let mut cpu = WinCpu::new(WinArch::X64, &space);
    cpu.set_sp(SP + 8);
    cpu.set_pc(START);
    let stop = cpu.run_routed(5, |_, arch, _| {
        Ok(if arch == WinArch::X64 {
            InstructionRoute::Enter {
                target: START,
                thunk: START,
            }
        } else {
            InstructionRoute::Stay
        })
    });
    assert!(matches!(stop, CpuStop::Svc { imm: 0x55, pc } if pc == START + 16));
    assert!(cpu.is_arm64ec());
    assert_eq!(cpu.arch(), WinArch::X64);
    assert_eq!(cpu.instruction_arch(), WinArch::Arm64);
    assert_eq!(cpu.sp(), SP);
    let arguments = [
        Arg::Ptr,
        Arg::I32,
        Arg::Ptr,
        Arg::Ptr,
        Arg::Ptr,
        Arg::I32,
        Arg::I32,
        Arg::I32,
        Arg::I32,
        Arg::Ptr,
        Arg::I32,
    ];
    let adjusted = scoped_entry_sp(&space, BASE, 0x400000, 0x55, START + 16, SP).unwrap();
    assert_eq!(adjusted, SP + 16);
    assert_eq!(
        read_arg(&cpu, &space, SP, &arguments, Conv::Stdcall, 8).unwrap(),
        0x1b49_0030,
        "the unadjusted I32 reader exposes the guard cookie's low word as argument 9"
    );
    assert_eq!(
        read_arg(&cpu, &space, adjusted, &arguments, Conv::Stdcall, 8).unwrap(),
        0x60
    );
    assert_eq!(
        read_arg(&cpu, &space, adjusted, &arguments, Conv::Stdcall, 9).unwrap(),
        0
    );
    assert_eq!(
        read_arg(&cpu, &space, adjusted, &arguments, Conv::Stdcall, 10).unwrap(),
        0
    );
    assert_eq!(cpu.sp(), SP);
    assert_eq!(space.bytes(SP, 40).unwrap(), before);
    assert!(matches!(
        cpu.run_routed(8, |_, _, _| Ok(InstructionRoute::Stay)),
        CpuStop::Yield
    ));
    assert_eq!(cpu.sp(), SP + 16, "native postlude restores its own stack");
    assert_eq!(
        cpu.pc(),
        0x80,
        "native postlude returns through the saved link"
    );
    assert_eq!(
        cpu.call_gpr(9),
        0,
        "native postlude clears its scratch register"
    );
    assert_eq!(cpu.call_gpr(16), 0, "native cookie comparison succeeded");
    assert!(scoped_entry_sp(&space, BASE, 0x400000, 0x55, START + 16, u64::MAX - 15).is_err());
    assert!(scoped_entry_sp(&space, BASE, START - BASE + 32, 0x55, START + 16, SP).is_err());
    assert_eq!(
        scoped_entry_sp(&space, BASE, 0x400000, 0x55, BASE + 4, SP).unwrap(),
        SP
    );
}
