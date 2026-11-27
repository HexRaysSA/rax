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

enum DeviceIo<'a> {
    Read(&'a [u8]),
    Write(&'a [u8]),
}

struct Transaction<'a> {
    name: &'a str,
    code: &'a [u8],
    code32: bool,
    segment: DataSegment,
    offset: u64,
    index: u64,
    ecx: u32,
    io: DeviceIo<'a>,
}

impl Transaction<'_> {
    fn configure(&self, memory: &GuestMemoryWrapper, cpu: &mut dyn VCpu) {
        let mut guest = state(cpu);
        guest.sregs.cs.l = false;
        guest.sregs.cs.db = self.code32;
        if self.code32 {
            word(memory, 0x9008, 0x00cf_9b00_0000_ffff);
        } else {
            guest.regs.rip = CODE - CODE16_BASE;
            guest.sregs.cs.base = CODE16_BASE;
            guest.sregs.cs.g = false;
            guest.sregs.cs.limit = 0xffff;
            word(memory, 0x9008, 0x0000_9b00_0000_ffff | (CODE16_BASE << 16));
        }
        let data = match self.segment {
            DataSegment::Ds => &mut guest.sregs.ds,
            DataSegment::Fs => &mut guest.sregs.fs,
            DataSegment::Gs => &mut guest.sregs.gs,
            DataSegment::Ss => {
                guest.regs.rbp = self.offset;
                guest.regs.rsi = 0;
                &mut guest.sregs.ss
            }
        };
        let base = MMIO - self.offset;
        data.selector = 32;
        data.base = base;
        let descriptor =
            0x00cf_9300_0000_ffff | ((base & 0x00ff_ffff) << 16) | ((base >> 24) << 56);
        word(memory, 0x9020, descriptor);
        guest.regs.rax = SEED as u32 as u64;
        guest.regs.rdi = self.index;
        guest.regs.rcx = u64::from(self.ecx);
        guest.regs.rflags = FLAGS;
        guest.regs.xmm[0] = XMM;
        cpu.set_state(&CpuState::X86_64(guest)).unwrap();
    }

    fn check_mode(&self, guest: &X86_64CpuState) {
        let base = if self.code32 { 0 } else { CODE16_BASE };
        assert!(!guest.sregs.cs.l);
        assert_eq!(
            (guest.sregs.cs.base, guest.sregs.cs.db),
            (base, self.code32)
        );
        assert_ne!(guest.sregs.efer & 0x400, 0);
    }

    fn run(&self, expected_flags: u64, restore: bool) -> X86_64CpuState {
        let start_ip = CODE - if self.code32 { 0 } else { CODE16_BASE };
        let memory = guest_memory(self.code);
        let marker = MARKER as u32;
        let mut suffix = if self.code32 {
            vec![0xba]
        } else {
            vec![0x66, 0xba]
        }; // MOV EDX, imm32.
        suffix.extend_from_slice(&marker.to_le_bytes());
        suffix.push(0xf4);
        memory
            .memory()
            .write_slice(&suffix, GuestAddress(CODE + self.code.len() as u64))
            .unwrap();

        let (mut vm, mut cpu) = machine(&memory);
        self.configure(&memory, cpu.as_mut());
        let pending = |cpu: &mut dyn VCpu| {
            let exit = event(cpu);
            match (&self.io, exit) {
                (DeviceIo::Read(reply), VcpuExit::MmioRead { addr, size }) => {
                    assert_eq!(
                        (addr, usize::from(size)),
                        (MMIO, reply.len()),
                        "{}",
                        self.name
                    );
                }
                (DeviceIo::Write(expected), VcpuExit::MmioWrite { addr, data }) => {
                    assert_eq!((addr, data.as_slice()), (MMIO, *expected), "{}", self.name);
                }
                (_, other) => panic!(
                    "unexpected compatibility-mode exit for {}: {other:?}",
                    self.name
                ),
            }
            assert!(cpu.get_state().is_err());
            assert!(cpu.io_completion_result().is_err());
        };
        pending(cpu.as_mut());
        if restore {
            let boundary = vm.checkpoint_boundary().unwrap();
            let (snapshot, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
            let CpuState::X86_64(saved) = &snapshot.state else {
                panic!("expected a compatibility-mode checkpoint");
            };
            assert_eq!(saved.regs.rip, start_ip);
            self.check_mode(saved);
            let context = context.expect("native MMIO context");
            drop(boundary);
            drop(cpu);
            drop(vm);
            (vm, cpu) = machine(&memory);
            cpu.restore_checkpoint_context(&snapshot.state, &snapshot.emulator, Some(&context))
                .unwrap();
        }
        pending(cpu.as_mut());
        match &self.io {
            DeviceIo::Read(reply) => cpu.complete_io_in(reply),
            DeviceIo::Write(_) => cpu.complete_io_out().unwrap(),
        }
        cpu.io_completion_result().unwrap();
        let next = state(cpu.as_ref());
        let resume_ip = start_ip + self.code.len() as u64;
        assert_eq!(next.regs.rip, resume_ip, "{}", self.name);
        assert_eq!(next.regs.rflags, expected_flags, "{}", self.name);

        let after = event(cpu.as_mut());
        assert!(
            matches!(after, VcpuExit::Hlt),
            "expected HLT after {}: {after:?}",
            self.name
        );
        let finished = state(cpu.as_ref());
        self.check_mode(&finished);
        assert_eq!(finished.regs.rip, resume_ip + suffix.len() as u64);
        assert_eq!(finished.regs.rdx as u32, marker);
        assert_eq!(finished.regs.rdi as u32, self.index as u32);
        assert_eq!(finished.regs.rcx as u32, self.ecx);
        assert_eq!(finished.regs.rflags, expected_flags, "{}", self.name);
        assert_eq!(finished.regs.rax as u32, next.regs.rax as u32);
        drop(cpu);
        drop(vm);
        finished
    }
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
    assert!(!output.exists());
    let mut case = 0;
    let mut xmm_bytes = [0; 16];
    xmm_bytes[..8].copy_from_slice(&XMM[0].to_le_bytes());
    xmm_bytes[8..].copy_from_slice(&XMM[1].to_le_bytes());
    let gpr_bytes = SEED.to_le_bytes();
    let reply = REPLY.to_le_bytes();

    for &(name, code, size, read, segment, offset) in cases {
        let io = if read {
            DeviceIo::Read(&reply[..size])
        } else if size > 4 {
            DeviceIo::Write(&xmm_bytes[..size])
        } else {
            DeviceIo::Write(&gpr_bytes[..size])
        };
        let transaction = Transaction {
            name,
            code,
            code32,
            segment,
            offset,
            index: offset,
            ecx: 0,
            io,
        };
        for restore in [false, true] {
            let finished = transaction.run(FLAGS, restore);
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
    report(case);
}

pub(super) fn run_bmi1(output: &Path) {
    let mut observations = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    let mut case = 0;
    let index = 0x18000;
    for (code32, address32, segment, segment_prefix) in [
        (false, false, DataSegment::Ds, None),
        (false, true, DataSegment::Gs, Some(0x65)),
        (true, false, DataSegment::Fs, Some(0x64)),
        (true, true, DataSegment::Ds, None),
    ] {
        let code_bits = if code32 { 32 } else { 16 };
        let address_bits = if address32 { 32 } else { 16 };
        let offset = if address32 {
            index
        } else {
            u64::from(index as u16)
        };
        let rm = if address32 { 7 } else { 5 }; // EDI or DI.
        for (high_bits, variant) in [(0, "base"), (0x40, "vvvv"), (0x80, "w"), (0xc0, "w-vvvv")] {
            for (operation, [vex, opcode, modrm], reply, ecx, expected, flags) in bmi1::cases(4) {
                let mut code = Vec::with_capacity(7);
                code.extend(segment_prefix);
                if code32 != address32 {
                    code.push(0x67);
                }
                code.extend([0xc4, 0xe2, vex ^ high_bits, opcode, (modrm & !7) | rm]);
                let reply = (reply as u32).to_le_bytes();
                let name = format!("bmi1-{code_bits}-{address_bits}-{variant}-{operation}");
                let transaction = Transaction {
                    name: &name,
                    code: &code,
                    code32,
                    segment,
                    offset,
                    index,
                    ecx: ecx as u32,
                    io: DeviceIo::Read(&reply),
                };
                let expected_flags = bmi1::flags_after(opcode, FLAGS, flags);
                for restore in [false, true] {
                    let finished = transaction.run(expected_flags, restore);
                    let result = finished.regs.rax as u32;
                    assert_eq!(u64::from(result), expected, "{name}, restored={restore}");
                    assert_eq!(finished.regs.xmm[0], XMM);
                    let suffix = if restore { "-restored" } else { "" };
                    writeln!(
                        observations,
                        concat!(
                            "{{\"case\":{},\"name\":\"{}{}\",\"width\":{},\"value\":{},",
                            "\"code_bits\":{},\"address_bits\":{},\"vex_high_bits\":{},",
                            "\"restored\":{},\"rflags\":{},\"rip\":{},\"passed\":true}}"
                        ),
                        case,
                        name,
                        suffix,
                        reply.len(),
                        result,
                        code_bits,
                        address_bits,
                        high_bits,
                        restore,
                        finished.regs.rflags,
                        finished.regs.rip,
                    )
                    .unwrap();
                    case += 1;
                }
            }
        }
    }
    assert_eq!(case, 384);
    report(case);
}

fn report(case: usize) {
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
