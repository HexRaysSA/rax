//! Native IA-32e compatibility-mode MMIO with nonzero data segment bases.
use super::*;

const OFFSET: u64 = 0x8000;
const FLAGS: u64 = 0x8d7;
const REPLY: u128 = 0x1100_ffee_ddcc_bbaa_8877_6655_4433_2211;
const XMM: [u64; 2] = [0x5b2a_4d18_f321_6c09, 0x9786_b5a4_2310_efcd];

fn compatibility_state(memory: &GuestMemoryWrapper, cpu: &mut dyn VCpu, fs_override: bool) {
    let mut guest = state(cpu);
    guest.sregs.cs.l = false;
    guest.sregs.cs.db = true;
    word(memory, 0x9008, 0x00cf_9b00_0000_ffff);
    let data = if fs_override {
        &mut guest.sregs.fs
    } else {
        &mut guest.sregs.ds
    };
    let base = MMIO - OFFSET;
    data.selector = 32;
    data.base = base;
    let descriptor = 0x00cf_9300_0000_ffff | ((base & 0x00ff_ffff) << 16) | ((base >> 24) << 56);
    word(memory, 0x9020, descriptor);
    guest.regs.rax = SEED as u32 as u64;
    guest.regs.rdi = OFFSET;
    guest.regs.rflags = FLAGS;
    guest.regs.xmm[0] = XMM;
    cpu.set_state(&CpuState::X86_64(guest)).unwrap();
}

pub(super) fn run(output: &Path) {
    // Address-size override uses [DI] or moffs16. The other forms use [EDI]
    // or moffs32. Only the FS case leaves DS at its original zero base.
    let cases = [
        ("mov-read-byte", &[0x8a, 0x07][..], 1, true, false),
        ("mov-write-byte-a16", &[0x67, 0x88, 0x05], 1, false, false),
        (
            "mov-read-word-a16",
            &[0x67, 0x66, 0x8b, 0x05],
            2,
            true,
            false,
        ),
        ("mov-write-word", &[0x66, 0x89, 0x07], 2, false, false),
        (
            "moffs-read-dword-a16",
            &[0x67, 0xa1, 0x00, 0x80],
            4,
            true,
            false,
        ),
        (
            "moffs-write-dword-fs",
            &[0x64, 0xa3, 0x00, 0x80, 0, 0],
            4,
            false,
            true,
        ),
        ("movsd-read", &[0xf2, 0x0f, 0x10, 0x07], 8, true, false),
        (
            "movsd-write-a16",
            &[0x67, 0xf2, 0x0f, 0x11, 0x05],
            8,
            false,
            false,
        ),
        ("movups-read", &[0x0f, 0x10, 0x07], 16, true, false),
        (
            "movupd-write-a16",
            &[0x67, 0x66, 0x0f, 0x11, 0x05],
            16,
            false,
            false,
        ),
    ];
    assert!(!output.exists());
    let mut case = 0;
    let mut xmm_bytes = [0; 16];
    xmm_bytes[..8].copy_from_slice(&XMM[0].to_le_bytes());
    xmm_bytes[8..].copy_from_slice(&XMM[1].to_le_bytes());
    let gpr_bytes = SEED.to_le_bytes();

    for (name, code, size, read, fs_override) in cases {
        for restore in [false, true] {
            let memory = guest_memory(code);
            let marker = MARKER as u32;
            let mut suffix = vec![0xba]; // MOV EDX, imm32.
            suffix.extend_from_slice(&marker.to_le_bytes());
            suffix.push(0xf4);
            memory
                .memory()
                .write_slice(&suffix, GuestAddress(CODE + code.len() as u64))
                .unwrap();

            let (mut vm, mut cpu) = machine(&memory);
            compatibility_state(&memory, cpu.as_mut(), fs_override);
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
                assert_eq!(saved.regs.rip, CODE);
                assert!(!saved.sregs.cs.l && saved.sregs.cs.db);
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
            assert_eq!(next.regs.rip, CODE + code.len() as u64);
            assert_eq!(next.regs.rflags, FLAGS);

            let after = event(cpu.as_mut());
            assert!(
                matches!(after, VcpuExit::Hlt),
                "expected HLT after {name}: {after:?}"
            );
            let finished = state(cpu.as_ref());
            assert!(!finished.sregs.cs.l && finished.sregs.cs.db);
            assert_ne!(finished.sregs.efer & 0x400, 0);
            assert_eq!(
                finished.regs.rip,
                CODE + code.len() as u64 + suffix.len() as u64
            );
            assert_eq!(finished.regs.rdx as u32, marker);
            assert_eq!(finished.regs.rdi as u32, OFFSET as u32);
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
            record(output, case, &format!("compat-{name}{suffix}"), size, value);
            case += 1;
        }
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
