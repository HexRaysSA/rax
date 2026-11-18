//! The instructions the compiler needs, for x86-64 with the System V
//! calling convention.
//!
//! Register use: rbx holds the thread's record and r12 the address of the
//! current activation's values, for as long as native code runs; rax
//! carries a helper's result and the status a function returns. rax, rcx
//! and rdx are the registers [`Reg`] names; r8, r9 and xmm0 are scratch
//! within one method here. Nothing but rbx and r12 is live from one method
//! to the next, except what the caller keeps in a [`Reg`]. The stack is
//! aligned for a call everywhere in a function's body: a function pushes
//! one register on entry.

use crate::Error;

use super::{
    BLOCK, CELL, Condition, HIGH, Helper, LEASE, LOW, Reg, SCRATCH, Shift, TARGET, VALUES,
    helper_offset,
};

/// A place in the code, bound once and jumped to from anywhere.
#[derive(Clone, Copy)]
pub(super) struct Label(usize);

/// The number of a register in an instruction: rax, rcx and rdx.
fn register(reg: Reg) -> u8 {
    match reg {
        Reg::A => 0,
        Reg::B => 1,
        Reg::C => 2,
    }
}

/// The low four bits of the opcode of a jump or a set on `condition`, after
/// `cmp lhs, rhs`.
fn code(condition: Condition) -> u8 {
    match condition {
        Condition::Ult => 0x2,
        Condition::Uge => 0x3,
        Condition::Eq => 0x4,
        Condition::Ne => 0x5,
        Condition::Ule => 0x6,
        Condition::Ugt => 0x7,
        Condition::Slt => 0xC,
        Condition::Sge => 0xD,
        Condition::Sle => 0xE,
        Condition::Sgt => 0xF,
    }
}

pub(super) struct Assembler {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    /// 32-bit displacements to patch: where, and to which label.
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

    fn bytes(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    pub(super) fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    pub(super) fn bind(&mut self, label: Label) {
        self.labels[label.0] = Some(self.code.len());
    }

    /// A displacement to `label`, to be filled in.
    fn displacement(&mut self, label: Label) {
        self.fixups.push((self.code.len(), label));
        self.bytes(&[0; 4]);
    }

    /// `prefix [rbx + offset]`, with the register field given.
    fn thread_operand(&mut self, prefix: &[u8], register_field: u8, offset: usize) {
        self.bytes(prefix);
        self.bytes(&[0x83 | (register_field << 3)]);
        self.bytes(&(offset as u32).to_le_bytes());
    }

    /// `prefix [r12 + offset]`, with the register field given. The prefix
    /// says that the base register is one of the upper eight.
    fn cell_operand(&mut self, prefix: &[u8], register_field: u8, offset: u64) {
        self.bytes(prefix);
        self.bytes(&[0x84 | (register_field << 3), 0x24]);
        self.bytes(&(offset as u32).to_le_bytes());
    }

    /// `prefix [r9 + offset]`, with the register field given.
    fn scratch_operand(&mut self, prefix: &[u8], register_field: u8, offset: u64) {
        self.bytes(prefix);
        self.bytes(&[0x81 | (register_field << 3)]);
        self.bytes(&(offset as u32).to_le_bytes());
    }

    /// `jmp label`
    pub(super) fn jump(&mut self, label: Label) {
        self.bytes(&[0xE9]);
        self.displacement(label);
    }

    /// Jump on the condition whose opcode ends in `code`.
    fn jump_on(&mut self, code: u8, label: Label) {
        self.bytes(&[0x0F, 0x80 | code]);
        self.displacement(label);
    }

    pub(super) fn jump_if_result_nonzero(&mut self, label: Label) {
        // test rax, rax ; jnz label
        self.bytes(&[0x48, 0x85, 0xC0]);
        self.jump_on(0x5, label);
    }

    pub(super) fn jump_if_result_is(&mut self, value: u64, label: Label) {
        if let Ok(small) = i32::try_from(value) {
            // cmp rax, imm32
            self.bytes(&[0x48, 0x3D]);
            self.bytes(&small.to_le_bytes());
        } else {
            // mov r8, imm64 ; cmp rax, r8
            self.bytes(&[0x49, 0xB8]);
            self.bytes(&value.to_le_bytes());
            self.bytes(&[0x4C, 0x39, 0xC0]);
        }
        self.jump_on(0x4, label);
    }

    /// Call `helper(thread, argument)`; its result is the result register.
    pub(super) fn call_helper(&mut self, helper: Helper, argument: u64) {
        // mov rdi, rbx
        self.bytes(&[0x48, 0x89, 0xDF]);
        if let Ok(small) = u32::try_from(argument) {
            // mov esi, imm32
            self.bytes(&[0xBE]);
            self.bytes(&small.to_le_bytes());
        } else {
            // mov rsi, imm64
            self.bytes(&[0x48, 0xBE]);
            self.bytes(&argument.to_le_bytes());
        }
        // call [rbx + helper]
        self.thread_operand(&[0xFF], 2, helper_offset(helper));
    }

    /// Call the code whose address the thread's record holds as its target.
    pub(super) fn call_target(&mut self) {
        self.thread_operand(&[0xFF], 2, TARGET);
    }

    /// One step: take it out of the lease, after getting a new lease if this
    /// one is used up; leave through `exit` if there is none to be had.
    pub(super) fn step(&mut self, exit: Label) {
        let counted = self.label();
        // mov rax, [rbx + lease] ; test rax, rax ; jnz counted
        self.thread_operand(&[0x48, 0x8B], 0, LEASE);
        self.bytes(&[0x48, 0x85, 0xC0]);
        self.jump_on(0x5, counted);
        // mov rdi, rbx ; call [rbx + refill]
        self.bytes(&[0x48, 0x89, 0xDF]);
        self.thread_operand(&[0xFF], 2, helper_offset(Helper::Refill));
        self.jump_if_result_nonzero(exit);
        self.thread_operand(&[0x48, 0x8B], 0, LEASE);
        self.bind(counted);
        // sub rax, 1 ; mov [rbx + lease], rax
        self.bytes(&[0x48, 0x83, 0xE8, 0x01]);
        self.thread_operand(&[0x48, 0x89], 0, LEASE);
    }

    /// The start of a function: one push, which aligns the stack.
    pub(super) fn enter(&mut self) {
        // push rbp
        self.bytes(&[0x55]);
    }

    /// Return to the caller with the result register as the status.
    pub(super) fn leave(&mut self) {
        // pop rbp ; ret
        self.bytes(&[0x5D, 0xC3]);
    }

    /// What the host calls: `fn(thread, code) -> status`. It gives the
    /// thread's record its register and calls `code`. Three pushes' worth of
    /// stack keep it aligned for that call.
    pub(super) fn host_entry(&mut self) {
        // push rbx ; push r12 ; sub rsp, 8
        self.bytes(&[0x53, 0x41, 0x54, 0x48, 0x83, 0xEC, 0x08]);
        // mov rbx, rdi ; call rsi
        self.bytes(&[0x48, 0x89, 0xFB, 0xFF, 0xD6]);
        // add rsp, 8 ; pop r12 ; pop rbx ; ret
        self.bytes(&[0x48, 0x83, 0xC4, 0x08, 0x41, 0x5C, 0x5B, 0xC3]);
    }

    /// Take the address of the current activation's values from the
    /// thread's record.
    pub(super) fn load_values(&mut self) {
        // mov r12, [rbx + values]
        self.thread_operand(&[0x4C, 0x8B], 4, VALUES);
    }

    /// Record which block is current.
    pub(super) fn store_block(&mut self, block: u32) {
        // mov dword [rbx + block], imm32
        self.thread_operand(&[0xC7], 0, BLOCK);
        self.bytes(&block.to_le_bytes());
    }

    /// Go to `slow` unless the cell of `slot` holds an integer.
    fn integer_cell(&mut self, slot: u32, slow: Label) {
        // movzx r8d, byte [cell] ; test r8d, r8d ; jnz slow
        self.cell_operand(&[0x45, 0x0F, 0xB6], 0, CELL * u64::from(slot));
        self.bytes(&[0x45, 0x85, 0xC0]);
        self.jump_on(0x5, slow);
    }

    /// The low 64 bits of the integer in a cell; `slow` if it holds anything
    /// else.
    pub(super) fn load_int(&mut self, reg: Reg, slot: u32, slow: Label) {
        self.integer_cell(slot, slow);
        // mov reg, [cell + low]
        self.cell_operand(
            &[0x49, 0x8B],
            register(reg),
            CELL * u64::from(slot) + LOW as u64,
        );
    }

    /// Whether the integer in a cell is not zero, as a value that is zero or
    /// not; `slow` if the cell holds anything else.
    pub(super) fn load_truth(&mut self, reg: Reg, slot: u32, slow: Label) {
        self.load_int(reg, slot, slow);
        // or reg, [cell + high]
        self.cell_operand(
            &[0x49, 0x0B],
            register(reg),
            CELL * u64::from(slot) + HIGH as u64,
        );
    }

    /// `mov qword [cell + offset], value`
    fn store_word(&mut self, cell: u64, offset: usize, value: u64) {
        if let Ok(small) = i32::try_from(value as i64) {
            // mov qword [..], imm32, sign-extended
            self.cell_operand(&[0x49, 0xC7], 0, cell + offset as u64);
            self.bytes(&small.to_le_bytes());
        } else {
            // mov r8, imm64 ; mov [..], r8
            self.bytes(&[0x49, 0xB8]);
            self.bytes(&value.to_le_bytes());
            self.cell_operand(&[0x4D, 0x89], 0, cell + offset as u64);
        }
    }

    /// Make a cell the integer in `reg`, zero-extended.
    pub(super) fn store_int(&mut self, slot: u32, reg: Reg) {
        let cell = CELL * u64::from(slot);
        self.store_word(cell, 0, 0);
        // mov [cell + low], reg
        self.cell_operand(&[0x49, 0x89], register(reg), cell + LOW as u64);
        self.store_word(cell, HIGH, 0);
    }

    /// Make a cell a value known when compiling: its tag, and its fields if
    /// it has any.
    pub(super) fn store_constant(&mut self, slot: u32, tag: u8, fields: Option<(u64, u64)>) {
        let cell = CELL * u64::from(slot);
        self.store_word(cell, 0, u64::from(tag));
        if let Some((low, high)) = fields {
            self.store_word(cell, LOW, low);
            self.store_word(cell, HIGH, high);
        }
    }

    /// Copy one cell to another, whatever it holds.
    pub(super) fn copy(&mut self, target: u32, source: u32) {
        for half in [0, 16] {
            // movups xmm0, [source] ; movups [target], xmm0
            self.cell_operand(&[0x41, 0x0F, 0x10], 0, CELL * u64::from(source) + half);
            self.cell_operand(&[0x41, 0x0F, 0x11], 0, CELL * u64::from(target) + half);
        }
    }

    /// The address of the thread's scratch cells, in r9.
    fn load_scratch(&mut self) {
        // mov r9, [rbx + scratch]
        self.thread_operand(&[0x4C, 0x8B], 1, SCRATCH);
    }

    /// Copy a cell to the thread's scratch cell `index`.
    pub(super) fn save(&mut self, index: u32, source: u32) {
        self.load_scratch();
        for half in [0, 16] {
            self.cell_operand(&[0x41, 0x0F, 0x10], 0, CELL * u64::from(source) + half);
            // movups [r9 + ..], xmm0
            self.scratch_operand(&[0x41, 0x0F, 0x11], 0, CELL * u64::from(index) + half);
        }
    }

    /// Copy the thread's scratch cell `index` to a cell.
    pub(super) fn restore(&mut self, target: u32, index: u32) {
        self.load_scratch();
        for half in [0, 16] {
            // movups xmm0, [r9 + ..]
            self.scratch_operand(&[0x41, 0x0F, 0x10], 0, CELL * u64::from(index) + half);
            self.cell_operand(&[0x41, 0x0F, 0x11], 0, CELL * u64::from(target) + half);
        }
    }

    /// `opcode target, source` for the instructions whose first operand is
    /// the register or memory one.
    fn two(&mut self, opcode: u8, target: Reg, source: Reg) {
        self.bytes(&[
            0x48,
            opcode,
            0xC0 | (register(source) << 3) | register(target),
        ]);
    }

    pub(super) fn copy_register(&mut self, target: Reg, source: Reg) {
        self.two(0x89, target, source);
    }

    /// `target += source`
    pub(super) fn add(&mut self, target: Reg, source: Reg) {
        self.two(0x01, target, source);
    }

    /// `target -= source`
    pub(super) fn subtract(&mut self, target: Reg, source: Reg) {
        self.two(0x29, target, source);
    }

    /// `target *= source`, the low 64 bits.
    pub(super) fn multiply(&mut self, target: Reg, source: Reg) {
        // imul target, source
        self.bytes(&[
            0x48,
            0x0F,
            0xAF,
            0xC0 | (register(target) << 3) | register(source),
        ]);
    }

    pub(super) fn and(&mut self, target: Reg, source: Reg) {
        self.two(0x21, target, source);
    }

    pub(super) fn or(&mut self, target: Reg, source: Reg) {
        self.two(0x09, target, source);
    }

    pub(super) fn xor(&mut self, target: Reg, source: Reg) {
        self.two(0x31, target, source);
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
        self.add(target, source);
        if signed {
            self.jump_on(0x0, slow);
        }
        if unsigned {
            self.jump_on(0x2, slow);
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
        self.subtract(target, source);
        if signed {
            self.jump_on(0x0, slow);
        }
        if unsigned {
            self.jump_on(0x2, slow);
        }
    }

    /// `A *= B` as 64-bit integers; `slow` if the signed product does not
    /// fit and `signed` is set, or the unsigned one and `unsigned`. Uses
    /// [`Reg::C`].
    pub(super) fn multiply_checked(&mut self, signed: bool, unsigned: bool, slow: Label) {
        if signed && unsigned {
            // The signed product, for its overflow flag alone.
            self.copy_register(Reg::C, Reg::A);
            self.multiply(Reg::C, Reg::B);
            self.jump_on(0x0, slow);
        }
        if unsigned {
            // mul rcx: rdx:rax = rax * rcx, with carry if rdx is not zero.
            self.bytes(&[0x48, 0xF7, 0xE1]);
            self.jump_on(0x2, slow);
        } else {
            self.multiply(Reg::A, Reg::B);
            if signed {
                self.jump_on(0x0, slow);
            }
        }
    }

    /// Shift `value` by the amount in [`Reg::B`], which is below 64.
    pub(super) fn shift(&mut self, shift: Shift, value: Reg) {
        let extension = match shift {
            Shift::Left => 4,
            Shift::Right => 5,
            Shift::RightSigned => 7,
        };
        // shl/shr/sar value, cl
        self.bytes(&[0x48, 0xD3, 0xC0 | (extension << 3) | register(value)]);
    }

    /// `shl/shr/sar reg, amount`
    fn shift_by(&mut self, extension: u8, reg: Reg, amount: u32) {
        self.bytes(&[
            0x48,
            0xC1,
            0xC0 | (extension << 3) | register(reg),
            amount as u8,
        ]);
    }

    /// Replace `reg` by its low `bits` bits as a signed number.
    pub(super) fn sign_extend(&mut self, reg: Reg, bits: u32) {
        if bits < 64 {
            self.shift_by(4, reg, 64 - bits);
            self.shift_by(7, reg, 64 - bits);
        }
    }

    /// Replace `reg` by its low `bits` bits as an unsigned number.
    pub(super) fn zero_extend(&mut self, reg: Reg, bits: u32) {
        if bits < 64 {
            self.shift_by(4, reg, 64 - bits);
            self.shift_by(5, reg, 64 - bits);
        }
    }

    fn compare(&mut self, lhs: Reg, rhs: Reg) {
        self.two(0x39, lhs, rhs);
    }

    /// `target = lhs <condition> rhs`, as one or zero.
    pub(super) fn set_if(&mut self, condition: Condition, target: Reg, lhs: Reg, rhs: Reg) {
        self.compare(lhs, rhs);
        // setcc r8b ; movzx target, r8b
        self.bytes(&[0x41, 0x0F, 0x90 | code(condition), 0xC0]);
        self.bytes(&[0x49, 0x0F, 0xB6, 0xC0 | (register(target) << 3)]);
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
        // mov r8, imm64 ; cmp lhs, r8
        self.bytes(&[0x49, 0xB8]);
        self.bytes(&value.to_le_bytes());
        self.bytes(&[0x4C, 0x39, 0xC0 | register(lhs)]);
        self.jump_on(code(condition), label);
    }

    pub(super) fn jump_if_zero(&mut self, reg: Reg, label: Label) {
        // test reg, reg ; jz label
        self.bytes(&[0x48, 0x85, 0xC0 | (register(reg) << 3) | register(reg)]);
        self.jump_on(0x4, label);
    }

    /// The code, with every jump resolved.
    pub(super) fn finish(mut self) -> Result<Vec<u8>, Error> {
        for (at, label) in std::mem::take(&mut self.fixups) {
            let target = self.labels[label.0]
                .ok_or_else(|| Error::semantic("EXEC_INTERNAL", "unbound native label"))?;
            let distance = i32::try_from(target as i64 - (at as i64 + 4)).map_err(|_| {
                Error::resource(
                    "EXEC_NATIVE_SIZE",
                    "the module is too large for a jump to span",
                )
            })?;
            self.code[at..at + 4].copy_from_slice(&distance.to_le_bytes());
        }
        Ok(self.code)
    }
}
