//! Native IA-32e compatibility-mode MMIO with nonzero data segment bases.
use super::*;

const OFFSET: u64 = 0x8000;
const CODE16_BASE: u64 = 0xe000;
const FLAGS: u64 = 0x8d7;
const REPLY: u128 = 0x1100_ffee_ddcc_bbaa_8877_6655_4433_2211;
const XMM: [u64; 2] = [0x5b2a_4d18_f321_6c09, 0x9786_b5a4_2310_efcd];

#[derive(Clone, Copy)]
enum DataSegment {
    Ds,
    Fs,
    Gs,
    Ss,
}

type Case = (&'static str, &'static [u8], usize, bool, DataSegment, u64);

fn compatibility_state(
    memory: &GuestMemoryWrapper,
    cpu: &mut dyn VCpu,
    code32: bool,
    offset: u64,
    segment: DataSegment,
) {
    let mut guest = state(cpu);
    guest.sregs.cs.l = false;
    guest.sregs.cs.db = code32;
    if code32 {
        word(memory, 0x9008, 0x00cf_9b00_0000_ffff);
    } else {
        guest.regs.rip = CODE - CODE16_BASE;
        guest.sregs.cs.base = CODE16_BASE;
        guest.sregs.cs.g = false;
        guest.sregs.cs.limit = 0xffff;
        word(memory, 0x9008, 0x0000_9b00_0000_ffff | (CODE16_BASE << 16));
    }
    let data = match segment {
        DataSegment::Ds => &mut guest.sregs.ds,
        DataSegment::Fs => &mut guest.sregs.fs,
        DataSegment::Gs => &mut guest.sregs.gs,
        DataSegment::Ss => {
            guest.regs.rbp = offset;
            guest.regs.rsi = 0;
            &mut guest.sregs.ss
        }
    };
    let base = MMIO - offset;
    data.selector = 32;
    data.base = base;
    let descriptor = 0x00cf_9300_0000_ffff | ((base & 0x00ff_ffff) << 16) | ((base >> 24) << 56);
    word(memory, 0x9020, descriptor);
    guest.regs.rax = SEED as u32 as u64;
    guest.regs.rdi = offset;
    guest.regs.rflags = FLAGS;
    guest.regs.xmm[0] = XMM;
    cpu.set_state(&CpuState::X86_64(guest)).unwrap();
}

pub(super) fn run(output: &Path) {
    // Address-size override uses [DI] or moffs16. The other forms use [EDI]
    // or moffs32. Only the FS case leaves DS at its original zero base.
    let cases: &[Case] = &[
        (
            "mov-read-byte",
            &[0x8a, 0x07][..],
            1,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "mov-write-byte-a16",
            &[0x67, 0x88, 0x05],
            1,
            false,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "mov-read-word-a16",
            &[0x67, 0x66, 0x8b, 0x05],
            2,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "mov-write-word",
            &[0x66, 0x89, 0x07],
            2,
            false,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "moffs-read-dword-a16",
            &[0x67, 0xa1, 0x00, 0x80],
            4,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "moffs-write-dword-fs",
            &[0x64, 0xa3, 0x00, 0x80, 0, 0],
            4,
            false,
            DataSegment::Fs,
            OFFSET,
        ),
        (
            "movsd-read",
            &[0xf2, 0x0f, 0x10, 0x07],
            8,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "movsd-write-a16",
            &[0x67, 0xf2, 0x0f, 0x11, 0x05],
            8,
            false,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "movups-read",
            &[0x0f, 0x10, 0x07],
            16,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "movupd-write-a16",
            &[0x67, 0x66, 0x0f, 0x11, 0x05],
            16,
            false,
            DataSegment::Ds,
            OFFSET,
        ),
    ];
    run_cases(output, "compat", true, cases);
}

pub(super) fn run16(output: &Path) {
    // BP+SI selects SS without a segment prefix. The 32-bit address override
    // uses a value above u16::MAX to distinguish it from a 16-bit offset.
    let cases: &[Case] = &[
        (
            "mov-read-byte",
            &[0x8a, 0x05],
            1,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "mov-write-byte-ss",
            &[0x88, 0x02],
            1,
            false,
            DataSegment::Ss,
            OFFSET,
        ),
        (
            "mov-read-word",
            &[0x8b, 0x05],
            2,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "mov-write-word-a32",
            &[0x67, 0x89, 0x07],
            2,
            false,
            DataSegment::Ds,
            0x18000,
        ),
        (
            "moffs-read-dword",
            &[0x66, 0xa1, 0x00, 0x80],
            4,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "moffs-write-dword-gs",
            &[0x65, 0x66, 0xa3, 0x00, 0x80],
            4,
            false,
            DataSegment::Gs,
            OFFSET,
        ),
        (
            "movsd-read",
            &[0xf2, 0x0f, 0x10, 0x05],
            8,
            true,
            DataSegment::Ds,
            OFFSET,
        ),
        (
            "movupd-write",
            &[0x66, 0x0f, 0x11, 0x05],
            16,
            false,
            DataSegment::Ds,
            OFFSET,
        ),
    ];
    run_cases(output, "compat16", false, cases);
}

fn run_cases(output: &Path, profile: &str, code32: bool, cases: &[Case]) {
    let code_base = if code32 { 0 } else { CODE16_BASE };
    let start_ip = CODE - code_base;
    assert!(!output.exists());
    let mut case = 0;
    let mut xmm_bytes = [0; 16];
    xmm_bytes[..8].copy_from_slice(&XMM[0].to_le_bytes());
    xmm_bytes[8..].copy_from_slice(&XMM[1].to_le_bytes());
    let gpr_bytes = SEED.to_le_bytes();

    for &(name, code, size, read, segment, offset) in cases {
        for restore in [false, true] {
            let memory = guest_memory(code);
            let marker = MARKER as u32;
            let mut suffix = if code32 { vec![0xba] } else { vec![0x66, 0xba] }; // MOV EDX, imm32.
            suffix.extend_from_slice(&marker.to_le_bytes());
            suffix.push(0xf4);
            memory
                .memory()
                .write_slice(&suffix, GuestAddress(CODE + code.len() as u64))
                .unwrap();

            let (mut vm, mut cpu) = machine(&memory);
            compatibility_state(&memory, cpu.as_mut(), code32, offset, segment);
            let pending = |cpu: &mut dyn VCpu| {
                match event(cpu) {
                    VcpuExit::MmioRead { addr, size: got } if read => {
                        assert_eq!((addr, usize::from(got)), (MMIO, size));
                    }
                    VcpuExit::MmioWrite { addr, ref data } if !read => {
                        let expected = if size > 4 {
                            &xmm_bytes[..size]
                        } else {
                            &gpr_bytes[..size]
                        };
                        assert_eq!((addr, data.as_slice()), (MMIO, expected));
                    }
                    other => panic!("unexpected compatibility-mode exit for {name}: {other:?}"),
                }
                assert!(cpu.get_state().is_err());
                assert!(cpu.io_completion_result().is_err());
            };
            pending(cpu.as_mut());
            if restore {
                let boundary = vm.checkpoint_boundary().unwrap();
                let (snapshot, backend) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
                let CpuState::X86_64(saved) = &snapshot.state else {
                    panic!("expected a compatibility-mode checkpoint");
                };
                assert_eq!(saved.regs.rip, start_ip);
                assert!(!saved.sregs.cs.l);
                assert_eq!(
                    (saved.sregs.cs.base, saved.sregs.cs.db),
                    (code_base, code32)
                );
                assert_ne!(saved.sregs.efer & 0x400, 0);
                drop(boundary);
                drop(cpu);
                drop(vm);
                (vm, cpu) = machine(&memory);
                cpu.restore_checkpoint_context(
                    &snapshot.state,
                    &snapshot.emulator,
                    backend.as_ref(),
                )
                .unwrap();
                pending(cpu.as_mut());
            }
            if read {
                cpu.complete_io_in(&REPLY.to_le_bytes()[..size]);
            } else {
                cpu.complete_io_out().unwrap();
            }
            cpu.io_completion_result().unwrap();
            let next = state(cpu.as_ref());
            assert_eq!(next.regs.rip, start_ip + code.len() as u64);
            assert_eq!(next.regs.rflags, FLAGS);

            let after = event(cpu.as_mut());
            assert!(
                matches!(after, VcpuExit::Hlt),
                "expected HLT after {name}: {after:?}"
            );
            let finished = state(cpu.as_ref());
            assert!(!finished.sregs.cs.l);
            assert_eq!(
                (finished.sregs.cs.base, finished.sregs.cs.db),
                (code_base, code32)
            );
            assert_ne!(finished.sregs.efer & 0x400, 0);
            assert_eq!(
                finished.regs.rip,
                start_ip + code.len() as u64 + suffix.len() as u64
            );
            assert_eq!(finished.regs.rdx as u32, marker);
            assert_eq!(finished.regs.rdi as u32, offset as u32);
            assert_eq!(finished.regs.rflags, FLAGS);
            let mask = u64::MAX >> (64 - 8 * size.min(8));
            let value = if size <= 4 {
                let expected = if read {
                    (SEED & !mask) | (REPLY as u64 & mask)
                } else {
                    SEED
                };
                assert_eq!(finished.regs.rax as u32, expected as u32);
                assert_eq!(finished.regs.xmm[0], XMM);
                expected & mask
            } else {
                assert_eq!(finished.regs.rax as u32, SEED as u32);
                let expected = if read {
                    [
                        REPLY as u64,
                        if size == 16 { (REPLY >> 64) as u64 } else { 0 },
                    ]
                } else {
                    XMM
                };
                assert_eq!(finished.regs.xmm[0], expected);
                expected[0]
            };
            drop(cpu);
            drop(vm);
            let suffix = if restore { "-restored" } else { "" };
            record(
                output,
                case,
                &format!("{profile}-{name}{suffix}"),
                size,
                value,
            );
            case += 1;
        }
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
