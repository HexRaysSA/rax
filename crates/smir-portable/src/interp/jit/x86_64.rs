//! The instructions the compiler needs, for x86-64 with the System V
//! calling convention.
//!
//! Register use: rbx holds the thread's record for as long as native code
//! runs; rax carries a helper's result and the status a function returns;
//! rcx is scratch. Nothing else is live across an instruction sequence
//! emitted here. The stack is aligned for a call everywhere in a function's
//! body: a function pushes one register on entry.

use crate::Error;

use super::{Helper, LEASE, TARGET, helper_offset};

/// A place in the code, bound once and jumped to from anywhere.
#[derive(Clone, Copy)]
pub(super) struct Label(usize);

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

    /// `opcode [rbx + offset]`, for the opcodes that take such an operand
    /// with the register field given.
    fn thread_operand(&mut self, prefix: &[u8], register_field: u8, offset: usize) {
        self.bytes(prefix);
        self.bytes(&[0x83 | (register_field << 3)]);
        self.bytes(&(offset as u32).to_le_bytes());
    }

    /// `jmp label`
    pub(super) fn jump(&mut self, label: Label) {
        self.bytes(&[0xE9]);
        self.displacement(label);
    }

    pub(super) fn jump_if_result_nonzero(&mut self, label: Label) {
        // test rax, rax ; jnz label
        self.bytes(&[0x48, 0x85, 0xC0, 0x0F, 0x85]);
        self.displacement(label);
    }

    pub(super) fn jump_if_result_is(&mut self, value: u64, label: Label) {
        if let Ok(small) = i32::try_from(value) {
            // cmp rax, imm32
            self.bytes(&[0x48, 0x3D]);
            self.bytes(&small.to_le_bytes());
        } else {
            // mov rcx, imm64 ; cmp rax, rcx
            self.bytes(&[0x48, 0xB9]);
            self.bytes(&value.to_le_bytes());
            self.bytes(&[0x48, 0x39, 0xC8]);
        }
        // je label
        self.bytes(&[0x0F, 0x84]);
        self.displacement(label);
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
        self.bytes(&[0x48, 0x85, 0xC0, 0x0F, 0x85]);
        self.displacement(counted);
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
    /// thread's record its register and calls `code`.
    pub(super) fn host_entry(&mut self) {
        // push rbx ; mov rbx, rdi ; call rsi ; pop rbx ; ret
        self.bytes(&[0x53, 0x48, 0x89, 0xFB, 0xFF, 0xD6, 0x5B, 0xC3]);
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
