//! Whether the instruction about to run takes a branch: what a block step
//! (`PTRACE_SINGLEBLOCK`) traps after. With `IA32_DEBUGCTL.BTF` and
//! `EFLAGS.TF` set, the processor raises its single-step debug exception
//! "only after instructions that cause a branch" (Intel SDM Vol. 3B,
//! §19.4.3, "Single-Stepping on Branches"; §19.4.1: "single-stepping the
//! processor on taken branches").
//!
//! The instruction is classified from its bytes in 64-bit mode and the
//! state before it runs: unconditional transfers (`JMP`, `CALL`, `RET`,
//! `IRET`, the `FF /2`..`/5` forms, APX `JMPABS`) always branch; `Jcc`,
//! `LOOP`, `LOOPE`, `LOOPNE`, and `JRCXZ` branch when their condition holds,
//! even to the next instruction. Instructions that trap or enter the kernel
//! (`INT`, `SYSCALL`) end the step another way.

/// A control transfer's condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transfer {
    /// Always taken.
    Always,
    /// `Jcc` with this condition code.
    Cond(u8),
    /// `LOOPNE` (0), `LOOPE` (1), or `LOOP` (2).
    Loop(u8),
    /// `JRCXZ` (`JECXZ` with an address-size prefix).
    Jrcxz,
}

/// The condition code `cc` (the low nibble of `Jcc`) against `rflags`
/// (SDM Vol. 1, Appendix B, "EFLAGS Condition Codes").
fn holds(cc: u8, rflags: u64) -> bool {
    let flag = |bit: u32| rflags & (1 << bit) != 0;
    let (cf, pf, zf, sf, of) = (flag(0), flag(2), flag(6), flag(7), flag(11));
    let base = match cc >> 1 {
        0 => of,
        1 => cf,
        2 => zf,
        3 => cf || zf,
        4 => sf,
        5 => pf,
        6 => sf != of,
        _ => zf || sf != of,
    };
    base != (cc & 1 != 0)
}

/// Decodes the prefixes and opcode of `code` (64-bit mode): the transfer it
/// is, if any, and whether an address-size prefix makes its count `ECX`.
fn transfer(code: &[u8]) -> Option<(Transfer, bool)> {
    let mut i = 0;
    let mut addr32 = false;
    // Legacy prefixes, and REX (which counts only right before the
    // opcode; the classification does not need its bits).
    while let Some(&b) = code.get(i) {
        match b {
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0xf0 | 0xf2 | 0xf3 | 0x40..=0x4f => {}
            0x67 => addr32 = true,
            _ => break,
        }
        i += 1;
    }
    // REX2 (APX): its M0 bit selects map 1 without the 0F escape; W with
    // map 0's A1 is JMPABS.
    let (map1, rex2_w) = match *code.get(i)? {
        0xd5 => {
            let payload = *code.get(i + 1)?;
            i += 2;
            (payload & 0x80 != 0, Some(payload & 0x08 != 0))
        }
        0x0f => {
            i += 1;
            (true, None)
        }
        _ => (false, None),
    };
    let op = *code.get(i)?;
    let t = if map1 {
        match op {
            0x80..=0x8f => Transfer::Cond(op & 0xf),
            _ => return None,
        }
    } else {
        match op {
            0x70..=0x7f => Transfer::Cond(op & 0xf),
            0xe0..=0xe2 => Transfer::Loop(op - 0xe0),
            0xe3 => Transfer::Jrcxz,
            0xe8 | 0xe9 | 0xeb | 0xc2 | 0xc3 | 0xca | 0xcb | 0xcf => Transfer::Always,
            // CALL near and far, JMP near and far, indirect.
            0xff => match (*code.get(i + 1)? >> 3) & 7 {
                2..=5 => Transfer::Always,
                _ => return None,
            },
            0xa1 if rex2_w == Some(true) => Transfer::Always,
            _ => return None,
        }
    };
    Some((t, addr32))
}

/// Whether the instruction in `code` branches when it runs with `rflags`
/// and `rcx`.
pub fn taken(code: &[u8], rflags: u64, rcx: u64) -> bool {
    let Some((t, addr32)) = transfer(code) else {
        return false;
    };
    let count = if addr32 { rcx & 0xffff_ffff } else { rcx };
    let zf = rflags & (1 << 6) != 0;
    match t {
        Transfer::Always => true,
        Transfer::Cond(cc) => holds(cc, rflags),
        // The count is decremented first; the branch needs it nonzero.
        Transfer::Loop(kind) => {
            count != 1
                && match kind {
                    0 => !zf,
                    1 => zf,
                    _ => true,
                }
        }
        Transfer::Jrcxz => count == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZF: u64 = 1 << 6;
    const CF: u64 = 1;
    const SF: u64 = 1 << 7;
    const OF: u64 = 1 << 11;

    #[test]
    fn unconditional_transfers_always_branch() {
        for code in [
            &[0xeb, 0x00][..],                           // jmp .+2 (to the next instruction)
            &[0xe9, 0, 0, 0, 0],                         // jmp rel32
            &[0xe8, 0, 0, 0, 0],                         // call rel32
            &[0xc3],                                     // ret
            &[0xf3, 0xc3],                               // rep ret
            &[0xc2, 8, 0],                               // ret 8
            &[0x48, 0xcf],                               // iretq
            &[0xff, 0xd0],                               // call *%rax
            &[0x41, 0xff, 0xe3],                         // jmp *%r11
            &[0x3e, 0xff, 0x25, 0, 0, 0, 0],             // notrack jmp *0(%rip)
            &[0xff, 0x1c, 0x24],                         // lcall *(%rsp)
            &[0xd5, 0x08, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0], // jmpabs
        ] {
            assert!(taken(code, 0, 0), "{code:02x?}");
        }
    }

    #[test]
    fn other_instructions_do_not_branch() {
        for code in [
            &[0x90][..],                                 // nop
            &[0xff, 0xc0],                               // inc %eax (FF /0)
            &[0xff, 0x30],                               // push (%rax) (FF /6)
            &[0x0f, 0x05],                               // syscall
            &[0xcd, 0x80],                               // int $0x80
            &[0xa1, 0, 0, 0, 0, 0, 0, 0, 0],             // mov moffs, %eax
            &[0xd5, 0x00, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0], // REX2 without W: not JMPABS
            &[0x0f, 0x1f, 0x00],                         // nopl (%rax)
            &[],
            &[0x66], // a prefix alone
        ] {
            assert!(!taken(code, ZF | CF | SF | OF, 5), "{code:02x?}");
        }
    }

    #[test]
    fn conditional_jumps_branch_when_their_condition_holds() {
        // (cc, flags that satisfy it, flags that do not)
        for (cc, yes, no) in [
            (0x0, OF, 0),
            (0x1, 0, OF),
            (0x2, CF, 0),
            (0x3, 0, CF),
            (0x4, ZF, 0),
            (0x5, 0, ZF),
            (0x6, ZF, 0),
            (0x7, 0, CF),
            (0x8, SF, 0),
            (0x9, 0, SF),
            (0xa, 1 << 2, 0),
            (0xb, 0, 1 << 2),
            (0xc, SF, SF | OF),
            (0xd, SF | OF, SF),
            (0xe, ZF, 0),
            (0xf, 0, ZF),
        ] {
            for code in [vec![0x70 | cc, 0], vec![0x0f, 0x80 | cc, 0, 0, 0, 0]] {
                assert!(taken(&code, yes, 0), "{code:02x?} with {yes:#x}");
                assert!(!taken(&code, no, 0), "{code:02x?} with {no:#x}");
            }
        }
    }

    #[test]
    fn loops_count_rcx_or_ecx() {
        // loop: taken unless the decremented count is zero.
        assert!(taken(&[0xe2, 0xfe], 0, 2));
        assert!(!taken(&[0xe2, 0xfe], 0, 1));
        assert!(taken(&[0xe2, 0xfe], 0, 0), "0 wraps to all ones");
        // With 0x67 the count is ECX: RCX = 1 << 32 | 1 counts as 1.
        assert!(taken(&[0xe2, 0xfe], 0, (1 << 32) | 1));
        assert!(!taken(&[0x67, 0xe2, 0xfe], 0, (1 << 32) | 1));
        // loope needs ZF, loopne its absence.
        assert!(taken(&[0xe1, 0xfe], ZF, 5));
        assert!(!taken(&[0xe1, 0xfe], 0, 5));
        assert!(taken(&[0xe0, 0xfe], 0, 5));
        assert!(!taken(&[0xe0, 0xfe], ZF, 5));
        // jrcxz and jecxz.
        assert!(taken(&[0xe3, 0x00], 0, 0));
        assert!(!taken(&[0xe3, 0x00], 0, 1 << 32));
        assert!(taken(&[0x67, 0xe3, 0x00], 0, 1 << 32));
    }
}
