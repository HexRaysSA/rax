//! The instructions the compiler needs, for AArch64.
//!
//! Register use: x19 holds the thread's record and x20 the address of the
//! current activation's values, for as long as native code runs; x0 carries
//! a helper's result and the status a function returns. x9, x10 and x11 are
//! the registers [`Reg`] names; x12 to x14 and x16 are scratch within one
//! method here. Nothing but x19 and x20 is live from one method to the next,
//! except what the caller keeps in a [`Reg`].

use crate::Error;

use super::{
    BLOCK, CELL, Condition, HIGH, Helper, LEASE, LOW, Reg, SCRATCH, Shift, TARGET, VALUES,
    helper_offset,
};

/// A place in the code, bound once and jumped to from anywhere.
#[derive(Clone, Copy)]
pub(super) struct Label(usize);

const THREAD: u32 = 19;
const CELLS: u32 = 20;
const RESULT: u32 = 0;
/// The address of a cell.
const ADDRESS: u32 = 12;
/// A cell's tag, or a constant on its way to memory.
const TEMPORARY: u32 = 13;
/// The address of a second cell, when one is copied to another.
const SECOND: u32 = 14;
const CALLEE: u32 = 16;
const ZERO: u32 = 31;

fn register(reg: Reg) -> u32 {
    match reg {
        Reg::A => 9,
        Reg::B => 10,
        Reg::C => 11,
    }
}

/// The condition code that holds after `cmp lhs, rhs` when the comparison
/// does.
fn code(condition: Condition) -> u32 {
    match condition {
        Condition::Eq => 0,
        Condition::Ne => 1,
        Condition::Uge => 2,
        Condition::Ult => 3,
        Condition::Ugt => 8,
        Condition::Ule => 9,
        Condition::Sge => 10,
        Condition::Slt => 11,
        Condition::Sgt => 12,
        Condition::Sle => 13,
    }
}

pub(super) struct Assembler {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    /// Unconditional branches to patch: where, and to which label.
    fixups: Vec<(usize, Label)>,
}

impl Assembler {
    pub(super) fn new() -> Self {
        Self {
            code: Vec::new(),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    pub(super) fn offset(&self) -> usize {
        self.code.len()
    }

    fn word(&mut self, word: u32) {
        self.code.extend_from_slice(&word.to_le_bytes());
    }

    pub(super) fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    pub(super) fn bind(&mut self, label: Label) {
        self.labels[label.0] = Some(self.code.len());
    }

    /// `ldr xt, [xn, #offset]`
    fn load(&mut self, target: u32, base: u32, offset: usize) {
        self.word(0xF940_0000 | ((offset as u32 / 8) << 10) | (base << 5) | target);
    }

    /// `str xt, [xn, #offset]`
    fn store(&mut self, source: u32, base: u32, offset: usize) {
        self.word(0xF900_0000 | ((offset as u32 / 8) << 10) | (base << 5) | source);
    }

    /// `mov xd, #value`, in as many instructions as the value needs.
    fn constant(&mut self, target: u32, value: u64) {
        self.word(0xD280_0000 | ((value as u32 & 0xffff) << 5) | target);
        for part in 1..4 {
            let bits = (value >> (16 * part)) as u32 & 0xffff;
            if bits != 0 {
                self.word(0xF280_0000 | (part << 21) | (bits << 5) | target);
            }
        }
    }

    /// `target = base + offset`
    fn address(&mut self, target: u32, base: u32, offset: u64) {
        if offset < 1 << 24 {
            // add target, base, #low ; add target, target, #high, lsl #12
            self.word(0x9100_0000 | ((offset as u32 & 0xfff) << 10) | (base << 5) | target);
            if offset >> 12 != 0 {
                self.word(0x9140_0000 | ((offset as u32 >> 12) << 10) | (target << 5) | target);
            }
        } else {
            self.constant(target, offset);
            // add target, base, target
            self.word(0x8B00_0000 | (target << 16) | (base << 5) | target);
        }
    }

    /// The address of the cell of `slot`.
    fn cell(&mut self, target: u32, slot: u32) {
        self.address(target, CELLS, CELL * u64::from(slot));
    }

    /// `b label`
    pub(super) fn jump(&mut self, label: Label) {
        self.fixups.push((self.code.len(), label));
        self.word(0x1400_0000);
    }

    /// Jump to `label` if the condition code holds.
    fn jump_on(&mut self, code: u32, label: Label) {
        // b.<opposite> +8 ; b label
        self.word(0x5400_0000 | (2 << 5) | (code ^ 1));
        self.jump(label);
    }

    /// Skip the next instruction if `register` is zero.
    fn skip_if_zero(&mut self, register: u32) {
        // cbz register, +8
        self.word(0xB400_0000 | (2 << 5) | register);
    }

    /// Skip the next instruction if `register` is not zero.
    fn skip_if_nonzero(&mut self, register: u32) {
        // cbnz register, +8
        self.word(0xB500_0000 | (2 << 5) | register);
    }

    pub(super) fn jump_if_result_nonzero(&mut self, label: Label) {
        self.skip_if_zero(RESULT);
        self.jump(label);
    }

    pub(super) fn jump_if_result_is(&mut self, value: u64, label: Label) {
        if value < 4096 {
            // cmp x0, #value
            self.word(0xF100_001F | ((value as u32) << 10) | (RESULT << 5));
        } else {
            self.constant(TEMPORARY, value);
            // cmp x0, x13
            self.word(0xEB00_001F | (TEMPORARY << 16) | (RESULT << 5));
        }
        self.jump_on(0, label);
    }

    /// Call `helper(thread, argument)`; its result is the result register.
    pub(super) fn call_helper(&mut self, helper: Helper, argument: u64) {
        self.load(CALLEE, THREAD, helper_offset(helper));
        // mov x0, x19
        self.word(0xAA00_03E0 | (THREAD << 16) | RESULT);
        self.constant(1, argument);
        // blr x16
        self.word(0xD63F_0000 | (CALLEE << 5));
    }

    /// Call the code whose address the thread's record holds as its target.
    pub(super) fn call_target(&mut self) {
        self.load(CALLEE, THREAD, TARGET);
        self.word(0xD63F_0000 | (CALLEE << 5));
    }

    /// One step: take it out of the lease, after getting a new lease if this
    /// one is used up; leave through `exit` if there is none to be had.
    pub(super) fn step(&mut self, exit: Label) {
        self.load(TEMPORARY, THREAD, LEASE);
        // cbnz x13, over the refill: six instructions
        self.word(0xB500_0000 | (7 << 5) | TEMPORARY);
        self.load(CALLEE, THREAD, helper_offset(Helper::Refill));
        self.word(0xAA00_03E0 | (THREAD << 16) | RESULT);
        self.word(0xD63F_0000 | (CALLEE << 5));
        self.jump_if_result_nonzero(exit);
        self.load(TEMPORARY, THREAD, LEASE);
        // sub x13, x13, #1
        self.word(0xD100_0000 | (1 << 10) | (TEMPORARY << 5) | TEMPORARY);
        self.store(TEMPORARY, THREAD, LEASE);
    }

    /// The start of a function: keep the return address.
    pub(super) fn enter(&mut self) {
        // stp x29, x30, [sp, #-16]!
        self.word(0xA9BF_7BFD);
    }

    /// Return to the caller with the result register as the status.
    pub(super) fn leave(&mut self) {
        // ldp x29, x30, [sp], #16 ; ret
        self.word(0xA8C1_7BFD);
        self.word(0xD65F_03C0);
    }

    /// What the host calls: `fn(thread, code) -> status`. It gives the
    /// thread's record its register and calls `code`.
    pub(super) fn host_entry(&mut self) {
        self.word(0xA9BF_7BFD);
        // stp x19, x20, [sp, #-16]!
        self.word(0xA9BF_53F3);
        // mov x19, x0 ; blr x1
        self.word(0xAA00_03E0 | THREAD);
        self.word(0xD63F_0000 | (1 << 5));
        // ldp x19, x20, [sp], #16
        self.word(0xA8C1_53F3);
        self.leave();
    }

    /// Take the address of the current activation's values from the
    /// thread's record.
    pub(super) fn load_values(&mut self) {
        self.load(CELLS, THREAD, VALUES);
    }

    /// Record which block is current.
    pub(super) fn store_block(&mut self, block: u32) {
        self.constant(TEMPORARY, u64::from(block));
        // str w13, [x19, #BLOCK]
        self.word(0xB900_0000 | ((BLOCK as u32 / 4) << 10) | (THREAD << 5) | TEMPORARY);
    }

    /// Leave the address of the cell of `slot` in the address register, and
    /// go to `slow` unless the cell holds an integer.
    fn integer_cell(&mut self, slot: u32, slow: Label) {
        self.cell(ADDRESS, slot);
        // ldrb w13, [x12]
        self.word(0x3940_0000 | (ADDRESS << 5) | TEMPORARY);
        self.skip_if_zero(TEMPORARY);
        self.jump(slow);
    }

    /// The low 64 bits of the integer in a cell; `slow` if it holds anything
    /// else.
    pub(super) fn load_int(&mut self, reg: Reg, slot: u32, slow: Label) {
        self.integer_cell(slot, slow);
        self.load(register(reg), ADDRESS, LOW);
    }

    /// Whether the integer in a cell is not zero, as a value that is zero or
    /// not; `slow` if the cell holds anything else.
    pub(super) fn load_truth(&mut self, reg: Reg, slot: u32, slow: Label) {
        self.integer_cell(slot, slow);
        self.load(register(reg), ADDRESS, LOW);
        self.load(TEMPORARY, ADDRESS, HIGH);
        // orr reg, reg, x13
        self.word(0xAA00_0000 | (TEMPORARY << 16) | (register(reg) << 5) | register(reg));
    }

    /// Make a cell the integer in `reg`, zero-extended.
    pub(super) fn store_int(&mut self, slot: u32, reg: Reg) {
        self.cell(ADDRESS, slot);
        self.store(ZERO, ADDRESS, 0);
        self.store(register(reg), ADDRESS, LOW);
        self.store(ZERO, ADDRESS, HIGH);
    }

    /// Make a cell a value known when compiling: its tag, and its fields if
    /// it has any.
    pub(super) fn store_constant(&mut self, slot: u32, tag: u8, fields: Option<(u64, u64)>) {
        self.cell(ADDRESS, slot);
        let word = |assembler: &mut Self, value: u64, offset: usize| {
            if value == 0 {
                assembler.store(ZERO, ADDRESS, offset);
            } else {
                assembler.constant(TEMPORARY, value);
                assembler.store(TEMPORARY, ADDRESS, offset);
            }
        };
        word(self, u64::from(tag), 0);
        if let Some((low, high)) = fields {
            word(self, low, LOW);
            word(self, high, HIGH);
        }
    }

    /// Copy the 32 bytes at one address register to another.
    fn copy_cell(&mut self, target: u32, source: u32) {
        for half in [0, 2] {
            // ldp x13, x16, [source, #16 * half] ; stp x13, x16, [target, ...]
            self.word(0xA940_0000 | (half << 15) | (CALLEE << 10) | (source << 5) | TEMPORARY);
            self.word(0xA900_0000 | (half << 15) | (CALLEE << 10) | (target << 5) | TEMPORARY);
        }
    }

    /// Copy one cell to another, whatever it holds.
    pub(super) fn copy(&mut self, target: u32, source: u32) {
        self.cell(ADDRESS, source);
        self.cell(SECOND, target);
        self.copy_cell(SECOND, ADDRESS);
    }

    /// Copy a cell to the thread's scratch cell `index`.
    pub(super) fn save(&mut self, index: u32, source: u32) {
        self.cell(ADDRESS, source);
        self.load(SECOND, THREAD, SCRATCH);
        self.address(SECOND, SECOND, CELL * u64::from(index));
        self.copy_cell(SECOND, ADDRESS);
    }

    /// Copy the thread's scratch cell `index` to a cell.
    pub(super) fn restore(&mut self, target: u32, index: u32) {
        self.load(ADDRESS, THREAD, SCRATCH);
        self.address(ADDRESS, ADDRESS, CELL * u64::from(index));
        self.cell(SECOND, target);
        self.copy_cell(SECOND, ADDRESS);
    }

    pub(super) fn copy_register(&mut self, target: Reg, source: Reg) {
        // mov target, source
        self.word(0xAA00_03E0 | (register(source) << 16) | register(target));
    }

    fn three(&mut self, opcode: u32, target: Reg, source: Reg) {
        self.word(opcode | (register(source) << 16) | (register(target) << 5) | register(target));
    }

    /// `target += source`
    pub(super) fn add(&mut self, target: Reg, source: Reg) {
        self.three(0x8B00_0000, target, source);
    }

    /// `target -= source`
    pub(super) fn subtract(&mut self, target: Reg, source: Reg) {
        self.three(0xCB00_0000, target, source);
    }

    /// `target *= source`, the low 64 bits.
    pub(super) fn multiply(&mut self, target: Reg, source: Reg) {
        self.three(0x9B00_7C00, target, source);
    }

    pub(super) fn and(&mut self, target: Reg, source: Reg) {
        self.three(0x8A00_0000, target, source);
    }

    pub(super) fn or(&mut self, target: Reg, source: Reg) {
        self.three(0xAA00_0000, target, source);
    }

    pub(super) fn xor(&mut self, target: Reg, source: Reg) {
        self.three(0xCA00_0000, target, source);
    }

    /// `target += source` as 64-bit integers; `slow` if the signed sum does
    /// not fit and `signed` is set, or the unsigned one and `unsigned`.
    pub(super) fn add_checked(
        &mut self,
        target: Reg,
        source: Reg,
        signed: bool,
        unsigned: bool,
        slow: Label,
    ) {
        // adds
        self.three(0xAB00_0000, target, source);
        if signed {
            self.jump_on(6, slow);
        }
        if unsigned {
            self.jump_on(2, slow);
        }
    }

    /// `target -= source` as 64-bit integers; `slow` if the signed
    /// difference does not fit and `signed` is set, or the unsigned one and
    /// `unsigned`.
    pub(super) fn subtract_checked(
        &mut self,
        target: Reg,
        source: Reg,
        signed: bool,
        unsigned: bool,
        slow: Label,
    ) {
        // subs
        self.three(0xEB00_0000, target, source);
        if signed {
            self.jump_on(6, slow);
        }
        if unsigned {
            // A borrow clears the carry.
            self.jump_on(3, slow);
        }
    }

    /// Shift `value` by the amount in [`Reg::B`], which is below 64.
    pub(super) fn shift(&mut self, shift: Shift, value: Reg) {
        let opcode = match shift {
            Shift::Left => 0x9AC0_2000,
            Shift::Right => 0x9AC0_2400,
            Shift::RightSigned => 0x9AC0_2800,
        };
        self.three(opcode, value, Reg::B);
    }

    /// Replace `reg` by its low `bits` bits as a signed number.
    pub(super) fn sign_extend(&mut self, reg: Reg, bits: u32) {
        if bits < 64 {
            // sbfm reg, reg, #0, #bits-1
            self.word(0x9340_0000 | ((bits - 1) << 10) | (register(reg) << 5) | register(reg));
        }
    }

    /// Replace `reg` by its low `bits` bits as an unsigned number.
    pub(super) fn zero_extend(&mut self, reg: Reg, bits: u32) {
        if bits < 64 {
            // ubfm reg, reg, #0, #bits-1
            self.word(0xD340_0000 | ((bits - 1) << 10) | (register(reg) << 5) | register(reg));
        }
    }

    fn compare(&mut self, lhs: Reg, rhs: Reg) {
        // cmp lhs, rhs
        self.word(0xEB00_001F | (register(rhs) << 16) | (register(lhs) << 5));
    }

    /// `target = lhs <condition> rhs`, as one or zero.
    pub(super) fn set_if(&mut self, condition: Condition, target: Reg, lhs: Reg, rhs: Reg) {
        self.compare(lhs, rhs);
        // cset target, condition
        self.word(0x9A9F_07E0 | ((code(condition) ^ 1) << 12) | register(target));
    }

    pub(super) fn jump_if(&mut self, condition: Condition, lhs: Reg, rhs: Reg, label: Label) {
        self.compare(lhs, rhs);
        self.jump_on(code(condition), label);
    }

    /// Jump if `lhs <condition> value`.
    pub(super) fn jump_if_constant(
        &mut self,
        condition: Condition,
        lhs: Reg,
        value: u64,
        label: Label,
    ) {
        self.constant(TEMPORARY, value);
        // cmp lhs, x13
        self.word(0xEB00_001F | (TEMPORARY << 16) | (register(lhs) << 5));
        self.jump_on(code(condition), label);
    }

    pub(super) fn jump_if_zero(&mut self, reg: Reg, label: Label) {
        self.skip_if_nonzero(register(reg));
        self.jump(label);
    }

    /// The code, with every jump resolved.
    pub(super) fn finish(mut self) -> Result<Vec<u8>, Error> {
        for (at, label) in std::mem::take(&mut self.fixups) {
            let target = self.labels[label.0]
                .ok_or_else(|| Error::semantic("EXEC_INTERNAL", "unbound native label"))?;
            let distance = (target as i64 - at as i64) / 4;
            if !(-(1 << 25)..1 << 25).contains(&distance) {
                return Err(Error::resource(
                    "EXEC_NATIVE_SIZE",
                    "a function is too large for a branch to span",
                ));
            }
            let word = 0x1400_0000 | (distance as u32 & 0x03ff_ffff);
            self.code[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(self.code)
    }
}
