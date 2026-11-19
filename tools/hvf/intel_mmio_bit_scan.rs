//! BSF and BSR memory reads on an Intel Hypervisor.framework vCPU.
use super::*;

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (opcode, direct, restored) in [(0xbc, "bsf", "bsf-restored"), (0xbd, "bsr", "bsr-restored")]
    {
        for (prefix, width, preserved) in [
            (&[0x66][..], 2, SEED & !0xffff),
            (&[][..], 4, 0),
            (&[0x48][..], 8, 0),
        ] {
            let code = [prefix, &[0x0f, opcode, 0x07]].concat();
            let top = width * 8 - 1;
            let mixed = if opcode == 0xbc { 2 } else { top } as u64;
            for (source, expected, flags) in [
                (0u64, SEED, 0x42),
                (1u64 << top, preserved | top as u64, 2),
                ((1u64 << top) | 4, preserved | mixed, 2),
            ] {
                for (restore, name) in [(false, direct), (true, restored)] {
                    scalar_read(
                        &code,
                        &source.to_le_bytes()[..width],
                        expected,
                        flags,
                        restore,
                    );
                    record(output, case, name, width, expected);
                    case += 1;
                }
            }
        }
    }
    assert_eq!(case, 36);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}

fn read_ram(code: &[u8], source: u64) -> (u64, u64) {
    let address = CODE as u32 + 0x1000;
    let mut program = vec![0xbf]; // MOV EDI, imm32
    program.extend(address.to_le_bytes());
    program.extend_from_slice(code);
    let memory = guest_memory(&program);
    word(&memory, u64::from(address), source);
    let (_vm, mut cpu) = machine(&memory);
    let exit = event(cpu.as_mut());
    assert!(matches!(exit, VcpuExit::Hlt), "RAM oracle exit: {exit:?}");
    let result = state(cpu.as_ref()).regs;
    assert_eq!(result.rip, CODE + program.len() as u64 + 11);
    assert_eq!(result.r10, MARKER);
    (result.rax, result.rflags)
}

pub(super) fn run_counts(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (opcode, count_names, scan_names, scan_index) in [
        (
            0xbc,
            ["tzcnt", "tzcnt-restored"],
            ["rep-bsf", "rep-bsf-restored"],
            0,
        ),
        (
            0xbd,
            ["lzcnt", "lzcnt-restored"],
            ["rep-bsr", "rep-bsr-restored"],
            63,
        ),
    ] {
        // With both extreme source bits set, either count gives zero and
        // sets ZF. Either legacy scan instead clears ZF on this source.
        let (index, flags) = read_ram(&[0xf3, 0x48, 0x0f, opcode, 0x07], 0x8000_0000_0000_0001);
        let counts = flags & 0x40 != 0;
        assert_eq!(index, if counts { 0 } else { scan_index });
        let (names, defined) = if counts {
            (count_names, 0x41)
        } else {
            (scan_names, 0x40)
        };
        for (prefix, width) in [(&[][..], 4), (&[0x66][..], 2), (&[0x48][..], 8)] {
            let code = [&[0xf3][..], prefix, &[0x0f, opcode, 0x07]].concat();
            let high = 1u64 << (width * 8 - 1);
            for source in [0, 1, high, high | 4] {
                let (ram_value, ram_flags) = read_ram(&code, source);
                let expected = if !counts && source == 0 {
                    SEED
                } else {
                    ram_value
                };
                let expected_flags = 2 | (ram_flags & defined);
                for (restore, name) in [false, true].into_iter().zip(names) {
                    scalar_read(
                        &code,
                        &source.to_le_bytes()[..width],
                        expected,
                        expected_flags,
                        restore,
                    );
                    record(output, case, name, width, expected);
                    case += 1;
                }
            }
        }
    }
    assert_eq!(case, 48);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
