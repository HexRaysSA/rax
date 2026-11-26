//! Actual Intel HVF read exits for carry-less multiply, including owner restore.
use super::xmm::{alignment_fault, enable_guest_avx, packed_binary_case};
use super::{CODE, MARKER, MMIO, event, guest_memory, machine, read_word, record, state, word};
use rax::vm::vcpu::{CpuState, VcpuExit};
use std::{arch::x86_64::__cpuid_count, path::Path};
use vm_memory::{Bytes, GuestAddress};

const WIDE: [u8; 7] = [0xc4, 0x63, 0x3d, 0x44, 0x7f, 3, 0];
const VPCLMULQDQ: u32 = 1 << 10;
const FAULTS: [(u64, bool); 6] = [
    (6, false),
    (7, false),
    (8, true),
    (12, true),
    (13, true),
    (14, true),
];

// QEMU 11.1.2 ordinary RAM results. The wide reference concatenates two
// independently executed VEX.128 products with different lane inputs.
const CASES: [(usize, u8, u128, u128); 8] = [
    (
        1,
        0x00,
        0x2bd2f23b6ef2def9b023e41ab45edd47,
        0x00586ed7a8ef92afb1d9ecbae58bffc0,
    ),
    (
        1,
        0x81,
        0x114b828cffa365e8f987755ce0a1838f,
        0x18ce372d0efad0c4d0c67e2bf1038ac0,
    ),
    (
        1,
        0x1e,
        0x560cf9f9d8d42eeea46d4841d6658bdf,
        0x018e0431756e4d65b503416068cbd990,
    ),
    (
        1,
        0x9f,
        0x227cf7b9d172fc4d59cb666e928f7c57,
        0x4b3f93d6d098e06920f8af199e1b9c50,
    ),
    (
        6,
        0x00,
        0x3a035b9c7f9f9b1bef69739bc4dcf63c,
        0x323413644cc51734504ab22d252cb3f1,
    ),
    (
        6,
        0x81,
        0x19a85dc20bf9d266bc34696b17e3ecac,
        0x1423b79fd7def127a6b1ea8ccd691509,
    ),
    (
        6,
        0x1e,
        0x01a96b3837c3aa900e8f08de45a22b8c,
        0x7e5b3aad0ef2939c355a888ffce9de89,
    ),
    (
        6,
        0x9f,
        0x00f9c66101ac0301aedb6ff14b570c5c,
        0x23136f79d5d75457265ff2cc873cd531,
    ),
];

fn probe_wide_operand(name: &str, operand: u64) -> bool {
    const IDT: u64 = 0xc000;
    const HANDLERS: u64 = 0xb000;
    const CPUID: u64 = CODE + 0x2000;
    const ZERO_OPERAND: [u8; 32] = [0; 32];
    let memory = guest_memory(&WIDE);
    word(&memory, 0x4000, 0x4000_009b);
    for (vector, _) in FAULTS {
        let handler = HANDLERS + vector * 32;
        let gate = (handler & 0xffff) | (8 << 16) | (0x8e << 40) | ((handler >> 16) << 48);
        word(&memory, IDT + vector * 16, gate);
        word(&memory, IDT + vector * 16 + 8, handler >> 32);
        // MOV R8D, vector; HLT. Keep the hardware exception frame intact.
        let code = [0x41, 0xb8, vector as u8, 0, 0, 0, 0xf4];
        memory
            .memory()
            .write_slice(&code, GuestAddress(handler))
            .unwrap();
    }
    // MOV EAX, 7; XOR ECX, ECX; CPUID; MOV EAX, ECX; OUT 0xe9, EAX.
    let cpuid = [
        0xb8, 7, 0, 0, 0, 0x31, 0xc9, 0x0f, 0xa2, 0x89, 0xc8, 0xe7, 0xe9,
    ];
    memory
        .memory()
        .write_slice(&cpuid, GuestAddress(CPUID))
        .unwrap();
    let (_vm, mut cpu) = machine(&memory);
    enable_guest_avx(&memory, cpu.as_mut());
    let mut input = state(cpu.as_ref());
    input.regs.rip = CPUID;
    input.sregs.idt.base = IDT;
    input.sregs.idt.limit = 4095;
    cpu.set_state(&CpuState::X86_64(input)).unwrap();
    let exit = event(cpu.as_mut());
    let VcpuExit::IoOut { port: 0xe9, data } = exit else {
        panic!("VPCLMULQDQ {name} guest CPUID did not report: {exit:?}");
    };
    let guest_ecx = u32::from_le_bytes(data.try_into().unwrap());
    let guest_feature = guest_ecx & VPCLMULQDQ != 0;
    cpu.complete_io_out().unwrap();
    cpu.io_completion_result().unwrap();
    eprintln!(
        "VPCLMULQDQ {name} guest CPUID.07H.0:ECX={guest_ecx:#010x}, feature={guest_feature}, XCR0=7"
    );

    let mut input = state(cpu.as_ref());
    input.regs.rip = CODE;
    input.regs.rdi = operand;
    cpu.set_state(&CpuState::X86_64(input)).unwrap();
    let mut exit = event(cpu.as_mut());
    let read = matches!(exit, VcpuExit::MmioRead { addr, size: 32 } if addr == MMIO + 3);
    if operand == MMIO && read {
        eprintln!(
            "VPCLMULQDQ {name} device read address={:#x}, size=32",
            MMIO + 3
        );
        cpu.complete_io_in(&ZERO_OPERAND);
        cpu.io_completion_result().unwrap();
        exit = event(cpu.as_mut());
    }
    let after = state(cpu.as_ref());
    if matches!(exit, VcpuExit::Hlt) {
        if after.regs.rip == CODE + WIDE.len() as u64 + 11 && after.regs.r10 == MARKER {
            eprintln!("VPCLMULQDQ {name} retired");
            return guest_feature && read == (operand == MMIO);
        }
        for (vector, has_error) in FAULTS {
            if after.regs.r8 == vector && after.regs.rip == HANDLERS + vector * 32 + 7 {
                let frame = after.regs.rsp;
                let error = has_error.then(|| read_word(&memory, frame));
                let fault_rip = read_word(&memory, frame + if has_error { 8 } else { 0 });
                eprintln!(
                    "VPCLMULQDQ {name} guest fault vector={vector}, error={error:#x?}, rip={fault_rip:#x}"
                );
                return false;
            }
        }
    }
    eprintln!("VPCLMULQDQ {name} exit={exit:?}, rip={:#x}", after.regs.rip);
    false
}

pub(super) fn run(output: &Path, wide: bool) {
    assert!(!output.exists(), "observations must be new");
    if wide {
        let host_ecx = (__cpuid_count(0, 0).eax >= 7).then(|| __cpuid_count(7, 0).ecx);
        let host_feature = host_ecx.is_some_and(|ecx| ecx & VPCLMULQDQ != 0);
        eprintln!("VPCLMULQDQ host CPUID.07H.0:ECX={host_ecx:#010x?}, feature={host_feature}");
        // This unaligned RAM operand is in a fresh guest's zeroed page.
        let ram = probe_wide_operand("RAM", 0x16000);
        let mmio = probe_wide_operand("MMIO", MMIO);
        assert!(
            host_feature && ram && mmio,
            "VPCLMULQDQ qualification requires host and guest feature bits and retirement in both probes"
        );
    }
    let qwords = |bytes: [u8; 32]| {
        std::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
    };
    let mut index = 0;
    for (pattern, control, low, high) in CASES {
        let source: [u8; 32] =
            std::array::from_fn(|i| (pattern * 37 + i / 16 * 61 + i % 16 * 23) as u8);
        let reply: [u8; 32] =
            std::array::from_fn(|i| (pattern * 11 + i % 16 * 13).wrapping_sub(i / 16 * 43) as u8);
        let w = if control & 2 == 0 { 0 } else { 0x80 };
        let legacy = [0x66, 0x44, 0x0f, 0x3a, 0x44, 0x3f, control];
        let vex128 = [0xc4, 0x63, 0x39 | w, 0x44, 0x7f, 3, control];
        let mut vex256 = WIDE;
        vex256[2] |= w;
        vex256[6] = control;
        let forms: &[(&str, &[u8], usize, bool)] = if wide {
            &[("vex256", &vex256, 32, true)]
        } else {
            &[
                ("legacy", &legacy, 16, false),
                ("vex128", &vex128, 16, true),
            ]
        };
        let mut expected = [0; 32];
        expected[..16].copy_from_slice(&low.to_le_bytes());
        if wide {
            expected[16..].copy_from_slice(&high.to_le_bytes());
        }
        for &(form, code, width, vex) in forms {
            for (restore, phase) in [(false, "direct"), (true, "restored")] {
                let result = packed_binary_case(
                    code,
                    vex,
                    restore,
                    qwords(source),
                    &reply[..width],
                    qwords(expected),
                );
                record(
                    output,
                    index,
                    &format!("pclmul-{form}-{pattern}-{control:02x}-{phase}"),
                    width,
                    result,
                );
                index += 1;
            }
        }
    }
    if !wide {
        let code = [0x66, 0x44, 0x0f, 0x3a, 0x44, 0x7f, 3, 0x11];
        let fault_pc = alignment_fault(&code, true, 3);
        record(output, index, "pclmul-legacy-alignment", 0, fault_pc);
        index += 1;
    }
    println!("{{\"cases\":{index},\"failed\":0,\"guest_execution_performed\":true}}");
}
