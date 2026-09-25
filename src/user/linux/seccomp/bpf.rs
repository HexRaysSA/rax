//! Classic BPF as seccomp takes it (`linux/filter.h`, `linux/bpf_common.h`):
//! the checks a filter passes before it is installed (`bpf_check_classic`
//! in `net/core/filter.c`, then `seccomp_check_filter`), and running one
//! over a `struct seccomp_data`.
//!
//! A filter runs as the kernel runs a classic program: 32-bit
//! accumulator (`A`) and index (`X`) registers, 16 scratch words, forward
//! jumps only, loads of 32-bit words of the `seccomp_data` in the guest's
//! byte order. A division by a zero `X` ends the program with 0 (as the
//! classic-to-eBPF conversion makes it), and a shift by `X` uses its low 5
//! bits (as a 32-bit eBPF shift does).

/// `struct sock_filter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Insn {
    /// From the guest's 8 bytes.
    pub fn decode(b: &[u8]) -> Insn {
        Insn {
            code: u16::from_le_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_le_bytes(b[4..8].try_into().unwrap()),
        }
    }
}

// Instruction classes, sizes, modes, operations, and sources.
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xA0;
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xA0;
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;
/// `BPF_A` (a `BPF_RET` source).
pub const BPF_A: u16 = 0x10;
pub const BPF_TAX: u16 = 0x00;
pub const BPF_TXA: u16 = 0x80;
/// `BPF_MAXINSNS`, `BPF_MEMWORDS`.
pub const BPF_MAXINSNS: usize = 4096;
const BPF_MEMWORDS: u32 = 16;
/// `SKF_AD_OFF`: the ancillary-data loads, none of which seccomp takes.
const SKF_AD_OFF: u32 = 0xFFFF_F000;
/// `sizeof(struct seccomp_data)`.
pub const SECCOMP_DATA: u32 = 64;

/// `chk_code_allowed`: the classic codes the kernel knows.
fn known(code: u16) -> bool {
    let alu = |op| [BPF_ALU | op | BPF_K, BPF_ALU | op | BPF_X];
    let jmp = |op| [BPF_JMP | op | BPF_K, BPF_JMP | op | BPF_X];
    [
        BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_MOD, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH,
    ]
    .into_iter()
    .flat_map(alu)
    .chain(
        [BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JSET]
            .into_iter()
            .flat_map(jmp),
    )
    .chain([
        BPF_ALU | BPF_NEG,
        BPF_LD | BPF_W | BPF_ABS,
        BPF_LD | BPF_H | BPF_ABS,
        BPF_LD | BPF_B | BPF_ABS,
        BPF_LD | BPF_W | BPF_LEN,
        BPF_LD | BPF_W | BPF_IND,
        BPF_LD | BPF_H | BPF_IND,
        BPF_LD | BPF_B | BPF_IND,
        BPF_LD | BPF_IMM,
        BPF_LD | BPF_MEM,
        BPF_LDX | BPF_W | BPF_LEN,
        BPF_LDX | BPF_B | BPF_MSH,
        BPF_LDX | BPF_IMM,
        BPF_LDX | BPF_MEM,
        BPF_ST,
        BPF_STX,
        BPF_MISC | BPF_TAX,
        BPF_MISC | BPF_TXA,
        BPF_RET | BPF_K,
        BPF_RET | BPF_A,
        BPF_JMP | BPF_JA,
    ])
    .any(|c| c == code)
}

/// Whether `code` is a conditional jump.
fn conditional(code: u16) -> bool {
    code & 0x07 == BPF_JMP && code & 0xF0 != BPF_JA
}

/// `bpf_check_classic` and `check_load_and_stores`, then
/// `seccomp_check_filter`: whether `prog` may be installed (a non-empty
/// program the caller already bounded by `BPF_MAXINSNS`).
pub fn check(prog: &[Insn]) -> bool {
    let len = prog.len();
    for (pc, i) in prog.iter().enumerate() {
        if !known(i.code) {
            return false;
        }
        let ok = match i.code {
            c if c == BPF_ALU | BPF_DIV | BPF_K || c == BPF_ALU | BPF_MOD | BPF_K => i.k != 0,
            c if c == BPF_ALU | BPF_LSH | BPF_K || c == BPF_ALU | BPF_RSH | BPF_K => i.k < 32,
            c if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM || c == BPF_ST || c == BPF_STX => {
                i.k < BPF_MEMWORDS
            }
            c if c == BPF_JMP | BPF_JA => (i.k as usize) < len - pc - 1,
            c if conditional(c) => pc + i.jt as usize + 1 < len && pc + i.jf as usize + 1 < len,
            // No ancillary load is one seccomp takes; see below.
            c if c & 0x07 == BPF_LD && c & 0xE0 == BPF_ABS => i.k < SKF_AD_OFF,
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    if !matches!(prog[len - 1].code, c if c == BPF_RET | BPF_K || c == BPF_RET | BPF_A) {
        return false;
    }
    // check_load_and_stores: a scratch word is read only where every path
    // to the load stored it.
    let mut masks = vec![u16::MAX; len];
    let mut valid: u16 = 0;
    for (pc, i) in prog.iter().enumerate() {
        valid &= masks[pc];
        match i.code {
            c if c == BPF_ST || c == BPF_STX => valid |= 1 << i.k,
            c if c == BPF_LD | BPF_MEM || c == BPF_LDX | BPF_MEM => {
                if valid & (1 << i.k) == 0 {
                    return false;
                }
            }
            c if c == BPF_JMP | BPF_JA => {
                masks[pc + 1 + i.k as usize] &= valid;
                valid = u16::MAX;
            }
            c if conditional(c) => {
                masks[pc + 1 + i.jt as usize] &= valid;
                masks[pc + 1 + i.jf as usize] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    // seccomp_check_filter: only these codes, and word loads of the data.
    prog.iter().all(|i| match i.code {
        c if c == BPF_LD | BPF_W | BPF_ABS => i.k < SECCOMP_DATA && i.k & 3 == 0,
        c if c == BPF_LD | BPF_W | BPF_LEN || c == BPF_LDX | BPF_W | BPF_LEN => true,
        c => {
            let alu = [
                BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH,
            ]
            .iter()
            .any(|op| c == BPF_ALU | op | BPF_K || c == BPF_ALU | op | BPF_X);
            alu || c == BPF_ALU | BPF_NEG
                || c == BPF_RET | BPF_K
                || c == BPF_RET | BPF_A
                || c == BPF_LD | BPF_IMM
                || c == BPF_LDX | BPF_IMM
                || c == BPF_MISC | BPF_TAX
                || c == BPF_MISC | BPF_TXA
                || c == BPF_LD | BPF_MEM
                || c == BPF_LDX | BPF_MEM
                || c == BPF_ST
                || c == BPF_STX
                || c == BPF_JMP | BPF_JA
                || conditional(c)
        }
    })
}

/// `bpf_convert_filter`'s length pass over a checked `prog` (as
/// `seccomp_check_filter` rewrote its data loads): how many eBPF
/// instructions it becomes, the length `seccomp_attach_filter` bounds. The
/// prologue clears `A` and `X` and keeps the context (3); a return of `K`
/// moves `K` first (2); a division by `X` tests `X` first (5); a
/// conditional jump on a negative `K` moves `K` to a register first (one
/// more), and one whose false branch is not the next instruction takes a
/// second, unconditional jump unless inverting the condition makes it the
/// true branch (`JEQ`, `JGT`, and `JGE` whose true branch is the next);
/// every other instruction is one.
pub fn converted_len(prog: &[Insn]) -> usize {
    let each = |i: &Insn| match i.code {
        c if c == BPF_RET | BPF_K => 2,
        c if c == BPF_ALU | BPF_DIV | BPF_X || c == BPF_ALU | BPF_MOD | BPF_X => 5,
        c if conditional(c) => {
            let neg = usize::from(c & BPF_X == 0 && (i.k as i32) < 0);
            let single = i.jf == 0 || (i.jt == 0 && c & 0xF0 != BPF_JSET);
            neg + if single { 1 } else { 2 }
        }
        _ => 1,
    };
    3 + prog.iter().map(each).sum::<usize>()
}

/// Runs a checked `prog` over the `struct seccomp_data` bytes `data`: its
/// return value.
pub fn run(prog: &[Insn], data: &[u8; SECCOMP_DATA as usize]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; BPF_MEMWORDS as usize];
    let mut pc = 0usize;
    loop {
        let i = prog[pc];
        pc += 1;
        let src = |x: u32| if i.code & BPF_X != 0 { x } else { i.k };
        match i.code & 0x07 {
            BPF_LD => match i.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    let k = i.k as usize;
                    a = u32::from_le_bytes(data[k..k + 4].try_into().unwrap());
                }
                c if c == BPF_LD | BPF_W | BPF_LEN => a = SECCOMP_DATA,
                c if c == BPF_LD | BPF_MEM => a = mem[i.k as usize],
                _ => a = i.k,
            },
            BPF_LDX => match i.code {
                c if c == BPF_LDX | BPF_W | BPF_LEN => x = SECCOMP_DATA,
                c if c == BPF_LDX | BPF_MEM => x = mem[i.k as usize],
                _ => x = i.k,
            },
            BPF_ST => mem[i.k as usize] = a,
            BPF_STX => mem[i.k as usize] = x,
            BPF_ALU => {
                let v = src(x);
                a = match i.code & 0xF0 {
                    BPF_ADD => a.wrapping_add(v),
                    BPF_SUB => a.wrapping_sub(v),
                    BPF_MUL => a.wrapping_mul(v),
                    BPF_DIV if v == 0 => return 0,
                    BPF_DIV => a / v,
                    BPF_OR => a | v,
                    BPF_AND => a & v,
                    BPF_XOR => a ^ v,
                    BPF_LSH => a << (v & 31),
                    BPF_RSH => a >> (v & 31),
                    _ => a.wrapping_neg(),
                };
            }
            BPF_JMP => {
                if i.code & 0xF0 == BPF_JA {
                    pc += i.k as usize;
                    continue;
                }
                let v = src(x);
                let taken = match i.code & 0xF0 {
                    BPF_JEQ => a == v,
                    BPF_JGT => a > v,
                    BPF_JGE => a >= v,
                    _ => a & v != 0,
                };
                pc += if taken { i.jt } else { i.jf } as usize;
            }
            BPF_RET => return if i.code & BPF_A != 0 { a } else { i.k },
            _ => {
                if i.code & 0xF8 == BPF_TXA {
                    a = x;
                } else {
                    x = a;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
        Insn { code, jt, jf, k }
    }

    fn ret(k: u32) -> Insn {
        ins(BPF_RET | BPF_K, 0, 0, k)
    }

    #[test]
    fn checks_follow_bpf_check_classic_and_seccomp_check_filter() {
        assert!(check(&[ret(0x7fff_0000)]));
        // The last must return.
        assert!(!check(&[ins(BPF_LD | BPF_IMM, 0, 0, 1)]));
        // Division by a zero constant, shifts past 31, scratch past 15.
        assert!(!check(&[ins(BPF_ALU | BPF_DIV | BPF_K, 0, 0, 0), ret(0)]));
        assert!(!check(&[ins(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 32), ret(0)]));
        assert!(!check(&[ins(BPF_ST, 0, 0, 16), ret(0)]));
        // Jumps inside the program.
        assert!(!check(&[ins(BPF_JMP | BPF_JA, 0, 0, 1), ret(0)]));
        assert!(!check(&[ins(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0), ret(0)]));
        assert!(check(&[
            ins(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0),
            ret(1),
            ret(0)
        ]));
        // A scratch word read before a store on some path.
        assert!(!check(&[ins(BPF_LD | BPF_MEM, 0, 0, 3), ret(0)]));
        let stored_on_one_path = [
            ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
            ins(BPF_ST, 0, 0, 2),
            ins(BPF_LD | BPF_MEM, 0, 0, 2),
            ret(0),
        ];
        assert!(!check(&stored_on_one_path));
        // Seccomp's own rules: word loads of the data, aligned and inside
        // it; no byte or halfword loads, no MOD, no indexed loads.
        assert!(check(&[ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 60), ret(0)]));
        assert!(!check(&[ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 64), ret(0)]));
        assert!(!check(&[ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 2), ret(0)]));
        assert!(!check(&[ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0), ret(0)]));
        assert!(!check(&[ins(BPF_ALU | BPF_MOD | BPF_K, 0, 0, 3), ret(0)]));
        assert!(!check(&[ins(BPF_LD | BPF_W | BPF_IND, 0, 0, 0), ret(0)]));
        assert!(!check(&[ins(0xFFFF, 0, 0, 0), ret(0)]));
    }

    /// A program with every kind of conversion, reaching `RET_ALLOW`.
    fn every_conversion() -> Vec<Insn> {
        let j = |op: u16, jt, jf, k| ins(BPF_JMP | op, jt, jf, k);
        vec![
            ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
            ins(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0),
            ins(BPF_LDX | BPF_W | BPF_LEN, 0, 0, 0),
            j(BPF_JEQ | BPF_K, 0, 0, 5),
            j(BPF_JEQ | BPF_K, 0, 1, 5),
            j(BPF_JGT | BPF_K, 1, 1, 5),
            j(BPF_JSET | BPF_K, 0, 1, 1),
            j(BPF_JGE | BPF_K, 0, 0, 0x8000_0000),
            j(BPF_JEQ | BPF_X, 0, 0, 0),
            ins(BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0),
            ins(BPF_ALU | BPF_DIV | BPF_K, 0, 0, 3),
            ins(BPF_ALU | BPF_NEG, 0, 0, 0),
            ins(BPF_ST, 0, 0, 0),
            ins(BPF_LD | BPF_MEM, 0, 0, 0),
            ins(BPF_MISC | BPF_TAX, 0, 0, 0),
            ins(BPF_JMP | BPF_JA, 0, 0, 0),
            ins(BPF_LD | BPF_IMM, 0, 0, 0x7FFF_0000),
            ins(BPF_RET | BPF_A, 0, 0, 0),
            ret(0),
        ]
    }

    #[test]
    fn lengths_follow_bpf_convert_filter() {
        let one = |i: Insn| converted_len(&[i]) - 3;
        let j = |op: u16, jt, jf, k| ins(BPF_JMP | op, jt, jf, k);
        assert_eq!(one(ret(0)), 2);
        assert_eq!(one(ins(BPF_RET | BPF_A, 0, 0, 0)), 1);
        assert_eq!(one(ins(BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0)), 5);
        assert_eq!(one(ins(BPF_ALU | BPF_DIV | BPF_K, 0, 0, 3)), 1);
        assert_eq!(one(ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4)), 1);
        // The false branch falls through: one jump.
        assert_eq!(one(j(BPF_JSET | BPF_K, 3, 0, 1)), 1);
        // The true branch falls through: the inverted condition, except
        // for JSET, which has none.
        for op in [BPF_JEQ, BPF_JGT, BPF_JGE] {
            assert_eq!(one(j(op | BPF_K, 0, 3, 1)), 1);
            assert_eq!(one(j(op | BPF_X, 0, 3, 0)), 1);
        }
        assert_eq!(one(j(BPF_JSET | BPF_K, 0, 3, 1)), 2);
        // Neither: a conditional and an unconditional jump.
        assert_eq!(one(j(BPF_JEQ | BPF_K, 1, 2, 1)), 2);
        // A negative K is moved to a register first.
        assert_eq!(one(j(BPF_JEQ | BPF_K, 0, 0, 0x8000_0000)), 2);
        assert_eq!(one(j(BPF_JEQ | BPF_K, 1, 2, u32::MAX)), 3);
        assert_eq!(one(j(BPF_JEQ | BPF_K, 1, 2, i32::MAX as u32)), 2);
        assert_eq!(one(ins(BPF_JMP | BPF_JA, 0, 0, 7)), 1);
        let every = every_conversion();
        assert!(check(&every));
        assert_eq!((every.len(), converted_len(&every)), (19, 30));
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&39u32.to_le_bytes());
        assert_eq!(run(&every, &data), 0x7FFF_0000);
    }

    #[test]
    fn programs_run_as_classic_bpf() {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&39u32.to_le_bytes());
        data[4..8].copy_from_slice(&0xC000_003Eu32.to_le_bytes());
        // if (arch == X86_64 && nr == 39) ERRNO(1) else ALLOW.
        let prog = [
            ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
            ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0xC000_003E),
            ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
            ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 39),
            ret(0x0005_0001),
            ret(0x7fff_0000),
        ];
        assert!(check(&prog));
        assert_eq!(run(&prog, &data), 0x0005_0001);
        data[0] = 40;
        assert_eq!(run(&prog, &data), 0x7fff_0000);
        // Arithmetic, scratch, and X; a division by a zero X returns 0.
        let calc = [
            ins(BPF_LD | BPF_IMM, 0, 0, 7),
            ins(BPF_ST, 0, 0, 0),
            ins(BPF_LDX | BPF_IMM, 0, 0, 3),
            ins(BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0),
            ins(BPF_LDX | BPF_MEM, 0, 0, 0),
            ins(BPF_ALU | BPF_SUB | BPF_X, 0, 0, 0),
            ins(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 4),
            ins(BPF_RET | BPF_A, 0, 0, 0),
        ];
        assert!(check(&calc));
        assert_eq!(run(&calc, &data), (7 * 3 - 7) << 4);
        let zero = [
            ins(BPF_LD | BPF_IMM, 0, 0, 9),
            ins(BPF_LDX | BPF_IMM, 0, 0, 0),
            ins(BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0),
            ret(0x7fff_0000),
        ];
        assert_eq!(run(&zero, &data), 0);
        // LEN and JSET.
        let len = [
            ins(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0),
            ins(BPF_JMP | BPF_JSET | BPF_K, 0, 1, 0x40),
            ret(1),
            ret(2),
        ];
        assert_eq!(run(&len, &data), 1);
    }
}
