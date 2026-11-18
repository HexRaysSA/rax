//! The instructions the compiler needs, for AArch64.
//!
//! Register use: x19 holds the thread's record for as long as native code
//! runs; x0 carries a helper's result and the status a function returns;
//! x9 and x16 are scratch. Nothing else is live across an instruction
//! sequence emitted here.

use crate::Error;

use super::{Helper, LEASE, TARGET, helper_offset};

/// A place in the code, bound once and jumped to from anywhere.
#[derive(Clone, Copy)]
pub(super) struct Label(usize);

const THREAD: u32 = 19;
const RESULT: u32 = 0;
const SCRATCH: u32 = 9;
const CALLEE: u32 = 16;

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

    /// `b label`
    pub(super) fn jump(&mut self, label: Label) {
        self.fixups.push((self.code.len(), label));
        self.word(0x1400_0000);
    }

    /// Skip the next instruction if `register` is zero.
    fn skip_if_zero(&mut self, register: u32) {
        // cbz register, +8
        self.word(0xB400_0000 | (2 << 5) | register);
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
            self.constant(SCRATCH, value);
            // cmp x0, x9
            self.word(0xEB00_001F | (SCRATCH << 16) | (RESULT << 5));
        }
        // b.ne +8
        self.word(0x5400_0000 | (2 << 5) | 1);
        self.jump(label);
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
        self.load(SCRATCH, THREAD, LEASE);
        // cbnz x9, over the refill: six instructions
        self.word(0xB500_0000 | (7 << 5) | SCRATCH);
        self.load(CALLEE, THREAD, helper_offset(Helper::Refill));
        self.word(0xAA00_03E0 | (THREAD << 16) | RESULT);
        self.word(0xD63F_0000 | (CALLEE << 5));
        self.jump_if_result_nonzero(exit);
        self.load(SCRATCH, THREAD, LEASE);
        // sub x9, x9, #1
        self.word(0xD100_0000 | (1 << 10) | (SCRATCH << 5) | SCRATCH);
        self.store(SCRATCH, THREAD, LEASE);
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
