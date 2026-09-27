//! 16- and 32-bit x86 decode. Encodings and lengths are from LLVM 23.1.1
//! (`llvm-mc -triple=i386` and `i386-unknown-unknown-code16`, lengths from
//! `llvm-objdump`), except BOUND (`62 /r`, SDM Vol. 2A), which LLVM does
//! not assemble. Branches are assembled with the displacement in the
//! comment; targets are checked at PC 0x1000.

use super::*;

/// (code size, encoding, length, control-flow kind).
const CASES: &[(u32, &str, usize, &str)] = &[
    (32, "40", 1, "fallthrough"),               // incl %eax
    (16, "40", 1, "fallthrough"),               // incw %ax
    (32, "b878563412", 5, "fallthrough"),       // movl $0x12345678, %eax
    (16, "b83412", 3, "fallthrough"),           // movw $0x1234, %ax
    (16, "66b878563412", 6, "fallthrough"),     // movl $0x12345678, %eax
    (16, "a13412", 3, "fallthrough"),           // movw 0x1234, %ax
    (16, "8b00", 2, "fallthrough"),             // movw (%bx,%si), %ax
    (16, "8b833412", 4, "fallthrough"),         // movw 0x1234(%bp,%di), %ax
    (16, "67668b4c9810", 6, "fallthrough"),     // movl 0x10(%eax,%ebx,4), %ecx
    (32, "8b0c9d78563412", 7, "fallthrough"),   // movl 0x12345678(,%ebx,4), %ecx
    (32, "67668b4f10", 5, "fallthrough"),       // movw 0x10(%bx), %cx
    (32, "a178563412", 5, "fallthrough"),       // movl 0x12345678, %eax
    (16, "06", 1, "fallthrough"),               // pushw %es
    (32, "1f", 1, "fallthrough"),               // popl %ds
    (32, "27", 1, "fallthrough"),               // daa
    (32, "60", 1, "fallthrough"),               // pushal
    (32, "6203", 2, "fallthrough"),             // bound %eax, (%ebx)
    (16, "c537", 2, "fallthrough"),             // ldsw (%bx), %si
    (32, "c418", 2, "fallthrough"),             // lesl (%eax), %ebx
    (32, "d6", 1, "fallthrough"),               // salc
    (32, "f70078563412", 6, "fallthrough"),     // testl $0x12345678, (%eax)
    (16, "f60701", 3, "fallthrough"),           // testb $1, (%bx)
    (16, "c8100001", 4, "fallthrough"),         // enter $16, $1
    (32, "69c300100000", 6, "fallthrough"),     // imull $0x1000, %ebx, %eax
    (32, "0fa4d803", 4, "fallthrough"),         // shldl $3, %ebx, %eax
    (32, "c5ec58d9", 4, "fallthrough"),         // vaddps %ymm1, %ymm2, %ymm3
    (32, "c5f9700c9801", 6, "fallthrough"),     // vpshufd $1, (%eax,%ebx,4), %xmm1
    (32, "62f16c59585840", 7, "fallthrough"),   // vaddps 0x100(%eax){1to16}, %zmm2, %zmm3 {%k1}
    (16, "c4e3fd00d101", 6, "fallthrough"),     // vpermq $1, %ymm1, %ymm2
    (32, "660f380008", 5, "fallthrough"),       // pshufb (%eax), %xmm1
    (32, "660f3a0fd103", 6, "fallthrough"),     // palignr $3, %xmm1, %xmm2
    (32, "eb20", 2, "branch"),                  // jmp .+0x20
    (32, "0f8400100000", 6, "cond_branch"),     // je .+0x1000
    (16, "0f850001", 4, "cond_branch"),         // jne .+0x100
    (32, "e210", 2, "cond_branch_reg"),         // loop .+0x10
    (16, "e310", 2, "cond_branch_reg"),         // jcxz .+0x10
    (32, "e800010000", 5, "call"),              // calll .+0x100
    (16, "e80001", 3, "call"),                  // callw .+0x100
    (32, "ffe0", 2, "indirect_branch"),         // jmpl *%eax
    (32, "ff54cb10", 4, "indirect_call"),       // calll *0x10(%ebx,%ecx,8)
    (16, "eaf0ff00f0", 5, "indirect_branch"),   // ljmp $0xf000, $0xfff0
    (32, "9a785634120800", 7, "indirect_call"), // lcalll $0x8, $0x12345678
    (32, "ff28", 2, "indirect_branch"),         // ljmpl *(%eax)
    (32, "c3", 1, "return"),                    // retl
    (16, "c20400", 3, "return"),                // retw $4
    (32, "cb", 1, "return"),                    // lretl
    (32, "cf", 1, "trap"),                      // iretl
    (32, "cd80", 2, "trap"),                    // int $0x80
    (32, "cc", 1, "trap"),                      // int3
    (32, "ce", 1, "trap"),                      // into
    (16, "f4", 1, "trap"),                      // hlt
    (32, "0f0b", 2, "trap"),                    // ud2
    (32, "0f34", 2, "syscall"),                 // sysenter
    (32, "c7f810000000", 6, "cond_branch"),     // xbegin .+0x10
    (32, "c6f801", 3, "fallthrough"),           // xabort $1
];

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn lengths_and_control_flow_match_llvm() {
    for &(bits, hex, len, kind) in CASES {
        // Trailing bytes must not be consumed.
        let mut code = bytes(hex);
        code.extend_from_slice(&[0x90; 4]);
        let insn = decode(&code, 0x1000, bits).unwrap_or_else(|e| panic!("{hex}: {e}"));
        assert_eq!(insn.len, len, "{bits}-bit {hex}");
        let flow = control_flow_json(&insn, 0x1000);
        assert_eq!(flow["kind"], kind, "{bits}-bit {hex}: {flow}");
    }
}

#[test]
fn rex_bytes_are_inc_and_dec_outside_64_bit_mode() {
    // 40 90: `inc eax ; nop` in 32-bit code, `rex nop` in 64-bit code.
    for bits in [16, 32] {
        assert_eq!(decode(&[0x40, 0x90], 0, bits).unwrap().len, 1);
    }
}

#[test]
fn relative_targets_wrap_to_the_operand_size() {
    // jmp +0x7F at IP 0xFFF0 in 16-bit code: (0xFFF2 + 0x7F) mod 2^16.
    let insn = decode(&[0xEB, 0x7F], 0xFFF0, 16).unwrap();
    assert_eq!(insn.flow, Flow::Branch(0x0071));
    // A 66 prefix gives 32-bit code a 16-bit IP too.
    let insn = decode(&[0x66, 0xE9, 0x00, 0x00], 0x1_FFFC, 32).unwrap();
    assert_eq!(insn.flow, Flow::Branch(0x0000));
    // je +0x1000 at 0x1000: the 6-byte form targets 0x2006.
    let insn = decode(&[0x0F, 0x84, 0x00, 0x10, 0x00, 0x00], 0x1000, 32).unwrap();
    assert_eq!(
        insn.flow,
        Flow::CondBranch {
            target: 0x2006,
            register: false
        }
    );
    assert_eq!(control_flow_json(&insn, 0x1000)["fallthrough"], "0x1006");
}

#[test]
fn invalid_forms_trap_and_truncation_fails() {
    for (bits, code) in [
        (32, &[0x8D, 0xC0][..]),      // lea with a register operand
        (32, &[0xFE, 0xD0]),          // inc/dec group /2
        (16, &[0x8E, 0xC8]),          // mov cs, ax
        (32, &[0x0F, 0x04]),          // reserved
        (32, &[0x0F, 0xC5, 0x00, 1]), // pextrw with a memory operand
    ] {
        let insn = decode(code, 0, bits).unwrap();
        assert_eq!(insn.flow, Flow::Trap("undefined"), "{code:x?}");
    }
    assert!(
        decode(&[0x66, 0xB8, 0x34, 0x12], 0, 16).is_err(),
        "imm32 needs 4 bytes"
    );
    assert!(decode(&[0x0F], 0, 32).is_err());
    // Fifteen prefixes leave no room for an opcode.
    assert!(decode(&[0x66; 16], 0, 32).is_err());
}
