//! 32-bit load and store instructions (Armv7-M ARM, DDI 0403E.e, A5.3.5 to
//! A5.3.10). Register choices the manual makes UNPREDICTABLE are treated
//! as UNDEFINED. The unprivileged forms (LDRT, STRT, ...) access memory like
//! the privileged ones: there is no MPU.

use super::Fault;
use crate::isa::arm::common::cpu::CpuExit;
use crate::isa::arm::cortex_m::cpu::CortexMCpu;

fn bad(r: u32) -> bool {
    r == 13 || r == 15
}

/// An addressing form of the 32-bit single loads and stores.
struct Address {
    /// The address accessed.
    address: u32,
    /// The base register value to write back, if any.
    writeback: Option<u32>,
}

impl CortexMCpu {
    /// The immediate-offset forms with an 8-bit offset: `P`, `U` and `W`
    /// are hw2 bits 10, 9 and 8. `None` for P = W = 0, which is UNDEFINED.
    fn imm8_address(&self, insn: u32, n: u32) -> Option<Address> {
        let (p, u, w) = (insn & 0x400 != 0, insn & 0x200 != 0, insn & 0x100 != 0);
        if !p && !w {
            return None;
        }
        let base = self.r(n);
        let imm8 = insn & 0xFF;
        let offset = if u {
            base.wrapping_add(imm8)
        } else {
            base.wrapping_sub(imm8)
        };
        Some(Address {
            address: if p { offset } else { base },
            writeback: w.then_some(offset),
        })
    }

    /// The register-offset forms: `[Rn, Rm, LSL #imm2]`.
    fn register_address(&self, insn: u32, n: u32) -> Result<Address, Fault> {
        let m = insn & 0xF;
        if bad(m) {
            return Err(Fault::Undefined(insn));
        }
        Ok(Address {
            address: self.r(n).wrapping_add(self.r(m) << ((insn >> 4) & 3)),
            writeback: None,
        })
    }

    /// The literal forms: `[PC, #+/-imm12]`.
    fn literal_address(&self, insn: u32) -> Address {
        let imm12 = insn & 0xFFF;
        let base = self.pc_aligned();
        Address {
            address: if insn & (1 << 23) != 0 {
                base.wrapping_add(imm12)
            } else {
                base.wrapping_sub(imm12)
            },
            writeback: None,
        }
    }

    /// Load word (A5.3.7).
    pub(super) fn load_word(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op1 = (hw1 >> 7) & 3;
        let op2 = (insn >> 6) & 0x3F;
        let n = hw1 & 0xF;
        let t = (insn >> 12) & 0xF;
        let access = if n == 15 {
            if op1 & 2 != 0 {
                return Err(Fault::Undefined(insn));
            }
            self.literal_address(insn)
        } else if op1 == 0b01 {
            Address {
                address: self.r(n).wrapping_add(insn & 0xFFF),
                writeback: None,
            }
        } else if op1 == 0b00 && op2 == 0 {
            self.register_address(insn, n)?
        } else if op1 == 0b00 && (op2 & 0b100100 == 0b100100 || op2 & 0b111100 == 0b110000) {
            self.imm8_address(insn, n).ok_or(Fault::Undefined(insn))?
        } else if op1 == 0b00 && op2 & 0b111100 == 0b111000 {
            // LDRT.
            if bad(t) {
                return Err(Fault::Undefined(insn));
            }
            Address {
                address: self.r(n).wrapping_add(insn & 0xFF),
                writeback: None,
            }
        } else {
            return Err(Fault::Undefined(insn));
        };
        if access.writeback.is_some() && n == t {
            return Err(Fault::Undefined(insn));
        }
        if t == 15 {
            self.require_last_in_it(insn)?;
        }
        let data = self.mem_u(access.address, 4)?;
        if let Some(value) = access.writeback {
            self.set_r(n, value);
        }
        if t == 15 {
            if access.address & 3 != 0 {
                return Err(Fault::Undefined(insn));
            }
            self.bx_write_pc(data)?;
        } else {
            self.set_r(t, data);
        }
        Ok(CpuExit::Continue)
    }

    /// Load byte and halfword, signed and unsigned, and the memory hints
    /// (A5.3.8, A5.3.9). `size` is 1 or 2.
    pub(super) fn load_narrow(&mut self, insn: u32, size: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op1 = (hw1 >> 7) & 3;
        let signed = op1 & 2 != 0;
        let op2 = (insn >> 6) & 0x3F;
        let n = hw1 & 0xF;
        let t = (insn >> 12) & 0xF;
        // `hint` marks the forms that are PLD/PLI or unallocated hints when
        // the target is PC; the others are UNPREDICTABLE with a PC target.
        let (access, hint) = if n == 15 {
            (self.literal_address(insn), true)
        } else if op1 & 1 != 0 {
            (
                Address {
                    address: self.r(n).wrapping_add(insn & 0xFFF),
                    writeback: None,
                },
                true,
            )
        } else if op2 == 0 {
            (self.register_address(insn, n)?, true)
        } else if op2 & 0b111100 == 0b110000 {
            (
                self.imm8_address(insn, n).ok_or(Fault::Undefined(insn))?,
                true,
            )
        } else if op2 & 0b100100 == 0b100100 {
            (
                self.imm8_address(insn, n).ok_or(Fault::Undefined(insn))?,
                false,
            )
        } else if op2 & 0b111100 == 0b111000 {
            // LDRBT, LDRSBT, LDRHT, LDRSHT.
            (
                Address {
                    address: self.r(n).wrapping_add(insn & 0xFF),
                    writeback: None,
                },
                false,
            )
        } else {
            return Err(Fault::Undefined(insn));
        };
        if t == 15 {
            return if hint {
                // PLD, PLI, or an unallocated hint: no access.
                Ok(CpuExit::Continue)
            } else {
                Err(Fault::Undefined(insn))
            };
        }
        if t == 13 || (access.writeback.is_some() && n == t) {
            return Err(Fault::Undefined(insn));
        }
        let raw = self.mem_u(access.address, size)?;
        let value = match (size, signed) {
            (1, true) => raw as u8 as i8 as u32,
            (2, true) => raw as u16 as i16 as u32,
            _ => raw,
        };
        if let Some(base) = access.writeback {
            self.set_r(n, base);
        }
        self.set_r(t, value);
        Ok(CpuExit::Continue)
    }

    pub(super) fn load_byte(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        self.load_narrow(insn, 1)
    }

    pub(super) fn load_halfword(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        self.load_narrow(insn, 2)
    }

    /// Store single data item (A5.3.10).
    pub(super) fn store_single(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op1 = (hw1 >> 5) & 7;
        let n = hw1 & 0xF;
        let t = (insn >> 12) & 0xF;
        let size = match op1 & 3 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return Err(Fault::Undefined(insn)),
        };
        if n == 15 {
            return Err(Fault::Undefined(insn));
        }
        let access = if op1 & 4 != 0 {
            Address {
                address: self.r(n).wrapping_add(insn & 0xFFF),
                writeback: None,
            }
        } else if insn & 0x800 != 0 {
            self.imm8_address(insn, n).ok_or(Fault::Undefined(insn))?
        } else if (insn >> 6) & 0x3F == 0 {
            self.register_address(insn, n)?
        } else {
            return Err(Fault::Undefined(insn));
        };
        if t == 15 || (t == 13 && size != 4) || (access.writeback.is_some() && n == t) {
            return Err(Fault::Undefined(insn));
        }
        self.set_mem_u(access.address, size, self.r(t))?;
        if let Some(value) = access.writeback {
            self.set_r(n, value);
        }
        Ok(CpuExit::Continue)
    }

    /// Load Multiple and Store Multiple (A5.3.5).
    pub(super) fn load_store_multiple(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op = (hw1 >> 7) & 3;
        let wback = hw1 & 0x20 != 0;
        let load = hw1 & 0x10 != 0;
        let n = hw1 & 0xF;
        let registers = insn & 0xFFFF;
        let count = registers.count_ones();
        let undefined = Err(Fault::Undefined(insn));
        match (op, load) {
            (0b01, true) if wback && n == 13 => {
                // POP T2.
                if count < 2 || registers & 0x2000 != 0 {
                    return undefined;
                }
                self.pop(registers, insn)?;
                return Ok(CpuExit::Continue);
            }
            (0b10, false) if wback && n == 13 => {
                // PUSH T2.
                if count < 2 || registers & 0xA000 != 0 {
                    return undefined;
                }
                self.push(registers, insn)?;
                return Ok(CpuExit::Continue);
            }
            (0b01 | 0b10, _) => {}
            _ => return undefined,
        }
        let increment = op == 0b01;
        if n == 15 || count < 2 || registers & 0x2000 != 0 || (wback && registers & (1 << n) != 0) {
            return undefined;
        }
        if load {
            if registers & 0xC000 == 0xC000 {
                return undefined;
            }
            if registers & 0x8000 != 0 {
                self.require_last_in_it(insn)?;
            }
        } else if registers & 0x8000 != 0 {
            return undefined;
        }
        let base = self.r(n);
        let start = if increment {
            base
        } else {
            base.wrapping_sub(4 * count)
        };
        let end = if increment {
            base.wrapping_add(4 * count)
        } else {
            start
        };
        let mut address = start;
        if load {
            let mut values = [0u32; 16];
            for (i, value) in values.iter_mut().enumerate() {
                if registers & (1 << i) != 0 {
                    *value = self.mem_a(address, 4)?;
                    address = address.wrapping_add(4);
                }
            }
            // The base is written back before a PC load, so an exception
            // return sees the final register state.
            if wback {
                self.set_r(n, end);
            }
            for (i, value) in values.iter().enumerate().take(15) {
                if registers & (1 << i) != 0 {
                    self.set_r(i as u32, *value);
                }
            }
            if registers & 0x8000 != 0 {
                self.bx_write_pc(values[15])?;
            }
        } else {
            for i in 0..15 {
                if registers & (1 << i) != 0 {
                    self.set_mem_a(address, 4, self.r(i))?;
                    address = address.wrapping_add(4);
                }
            }
            if wback {
                self.set_r(n, end);
            }
        }
        Ok(CpuExit::Continue)
    }

    /// Load/store dual or exclusive, table branch (A5.3.6).
    pub(super) fn load_store_dual_exclusive(&mut self, insn: u32) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let op1 = (hw1 >> 7) & 3;
        let op2 = (hw1 >> 4) & 3;
        let op3 = (insn >> 4) & 0xF;
        let n = hw1 & 0xF;
        let t = (insn >> 12) & 0xF;
        let t2 = (insn >> 8) & 0xF;
        let undefined = Err(Fault::Undefined(insn));
        if op1 & 2 != 0 || op2 & 2 != 0 {
            return self.load_store_dual(insn, op2 & 1 != 0, n, t, t2);
        }
        match (op1, op2) {
            (0b00, 0b00) => {
                // STREX.
                let d = t2;
                if bad(d) || bad(t) || n == 15 || d == n || d == t {
                    return undefined;
                }
                let address = self.r(n).wrapping_add((insn & 0xFF) << 2);
                self.store_exclusive(address, 4, t, d)?;
            }
            (0b00, 0b01) => {
                // LDREX.
                if bad(t) || n == 15 || t2 != 0xF {
                    return undefined;
                }
                let address = self.r(n).wrapping_add((insn & 0xFF) << 2);
                self.load_exclusive(address, 4, t)?;
            }
            (0b01, 0b00) => {
                // STREXB, STREXH.
                let d = insn & 0xF;
                let size = match op3 {
                    0b0100 => 1,
                    0b0101 => 2,
                    _ => return undefined,
                };
                if t2 != 0xF || bad(d) || bad(t) || n == 15 || d == n || d == t {
                    return undefined;
                }
                self.store_exclusive(self.r(n), size, t, d)?;
            }
            _ => match op3 {
                0b0000 | 0b0001 => {
                    // TBB, TBH.
                    let m = insn & 0xF;
                    if (insn >> 8) & 0xFF != 0xF0 || n == 13 || bad(m) {
                        return undefined;
                    }
                    self.require_last_in_it(insn)?;
                    let halfwords = if op3 == 0 {
                        self.mem_u(self.r(n).wrapping_add(self.r(m)), 1)?
                    } else {
                        self.mem_u(self.r(n).wrapping_add(self.r(m) << 1), 2)?
                    };
                    self.branch_write_pc(self.r(15).wrapping_add(2 * halfwords));
                }
                0b0100 | 0b0101 => {
                    // LDREXB, LDREXH.
                    if t2 != 0xF || insn & 0xF != 0xF || bad(t) || n == 15 {
                        return undefined;
                    }
                    let size = if op3 == 0b0100 { 1 } else { 2 };
                    self.load_exclusive(self.r(n), size, t)?;
                }
                _ => return undefined,
            },
        }
        Ok(CpuExit::Continue)
    }

    /// LDRD / STRD (immediate, and LDRD literal).
    fn load_store_dual(
        &mut self,
        insn: u32,
        load: bool,
        n: u32,
        t: u32,
        t2: u32,
    ) -> Result<CpuExit, Fault> {
        let hw1 = insn >> 16;
        let (p, u, w) = (hw1 & 0x100 != 0, hw1 & 0x80 != 0, hw1 & 0x20 != 0);
        let imm32 = (insn & 0xFF) << 2;
        let undefined = Err(Fault::Undefined(insn));
        if bad(t) || bad(t2) || (w && (n == t || n == t2)) || (load && t == t2) {
            return undefined;
        }
        if n == 15 && (!load || w || !p) {
            return undefined;
        }
        let base = if n == 15 {
            self.pc_aligned()
        } else {
            self.r(n)
        };
        let offset = if u {
            base.wrapping_add(imm32)
        } else {
            base.wrapping_sub(imm32)
        };
        let address = if p { offset } else { base };
        if load {
            let first = self.mem_a(address, 4)?;
            let second = self.mem_a(address.wrapping_add(4), 4)?;
            self.set_r(t, first);
            self.set_r(t2, second);
        } else {
            self.set_mem_a(address, 4, self.r(t))?;
            self.set_mem_a(address.wrapping_add(4), 4, self.r(t2))?;
        }
        if w {
            self.set_r(n, offset);
        }
        Ok(CpuExit::Continue)
    }

    fn load_exclusive(&mut self, address: u32, size: u32, t: u32) -> Result<(), Fault> {
        let value = self.mem_a(address, size)?;
        self.memory.mark_exclusive(u64::from(address), size as u8);
        self.set_r(t, value);
        Ok(())
    }

    /// Stores when the local monitor holds `address`; Rd reports 0 on
    /// success and 1 on failure. The monitor is cleared either way.
    fn store_exclusive(&mut self, address: u32, size: u32, t: u32, d: u32) -> Result<(), Fault> {
        Self::check_alignment(address, size)?;
        if self.memory.check_exclusive(u64::from(address), size as u8) {
            self.set_mem_a(address, size, self.r(t))?;
            self.set_r(d, 0);
        } else {
            self.set_r(d, 1);
        }
        Ok(())
    }

    fn check_alignment(address: u32, size: u32) -> Result<(), Fault> {
        if address & (size - 1) != 0 {
            Err(Fault::Unaligned { address })
        } else {
            Ok(())
        }
    }
}
