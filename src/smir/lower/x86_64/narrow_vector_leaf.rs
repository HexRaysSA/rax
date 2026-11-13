//! Keep 128-bit consumers separate from wide vector-transfer code.

use super::X86_64Lowerer;
use crate::smir::ir::types::VecWidth;
use crate::smir::lower::LowerError;

impl X86_64Lowerer {
    /// Emit a balanced internal leaf for a narrow consumer in the YMM bridge.
    /// Some translated x86 hosts select legacy source/merge operands when a
    /// narrow operation shares a translated block with YMM transfers. CALL/RET
    /// separates that operation without changing its registers or flags.
    ///
    /// The body must preserve the enclosing RBP and balance its own host stack;
    /// this is an internal register convention, not a host C callback boundary.
    /// The envelope adds 11 code bytes and one transient 8-byte return address.
    /// Emission and fixup take O(1) time and space beyond the body.
    pub(super) fn emit_narrow_vector_leaf(
        &mut self,
        width: VecWidth,
        emit: impl FnOnce(&mut Self) -> Result<(), LowerError>,
    ) -> Result<(), LowerError> {
        if !self.avx_ymm16_vector_state || width != VecWidth::V128 {
            return emit(self);
        }
        self.code.emit_bytes(&[0xE8, 5, 0, 0, 0]); // CALL across the five-byte JMP
        self.code.emit_u8(0xE9);
        let skip = self.code.position();
        self.code.emit_u32(0);
        emit(self)?;
        self.code.emit_u8(0xC3);
        let target = self.code.position();
        let displacement =
            i32::try_from(target - (skip + 4)).map_err(|_| LowerError::RelocationOutOfRange {
                offset: skip,
                target,
            })?;
        self.code.patch_i32(skip, displacement);
        Ok(())
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    #[test]
    fn internal_leaf_preserves_full_register_state_and_body_arithmetic_flags() {
        const STATUS: u64 = 0x8D5;
        for bridge in [false, true] {
            for width in [VecWidth::V128, VecWidth::V256] {
                let mut lowerer = X86_64Lowerer::new();
                lowerer.set_avx_ymm16_vector_state(bridge);
                lowerer.code.emit_bytes(&[0x55, 0x48, 0x89, 0xE5]);
                lowerer
                    .emit_narrow_vector_leaf(width, |lowerer| {
                        lowerer.code.emit_bytes(&[0x48, 0x11, 0xC8]); // ADC RAX,RCX
                        Ok(())
                    })
                    .unwrap();
                lowerer.code.emit_bytes(&[0x5D, 0xC3]);
                let executable = ExecMem::new(lowerer.code.as_slice()).unwrap();
                for (left, right, carry) in [
                    (0u64, 0u64, 0u64),
                    (0, 0, 1),
                    (u64::MAX, 0, 1),
                    (u64::MAX, 1, 0),
                    (i64::MAX as u64, 0, 1),
                    (1u64 << 63, u64::MAX, 1),
                ] {
                    let mut registers = GuestRegs {
                        gpr: std::array::from_fn(|i| 0x1234_0000 + i as u64 * 0x101),
                        rflags: 2 | carry,
                        ..GuestRegs::default()
                    };
                    registers.gpr[0] = left;
                    registers.gpr[1] = right;
                    let mut expected = registers;
                    let wide = u128::from(left) + u128::from(right) + u128::from(carry);
                    let result = wide as u64;
                    let flags = u64::from(wide >> 64 != 0)
                        | (u64::from((result as u8).count_ones() % 2 == 0) << 2)
                        | ((left ^ right ^ result) & 0x10)
                        | (u64::from(result == 0) << 6)
                        | ((result >> 63) << 7)
                        | (u64::from(((left ^ result) & (right ^ result)) >> 63 != 0) << 11);
                    expected.gpr[0] = result;
                    expected.rflags = (expected.rflags & !STATUS) | flags;
                    executable.run(0, &mut registers);
                    expected.host_mxcsr = registers.host_mxcsr;
                    assert_eq!(registers, expected, "bridge={bridge} width={width:?}");
                }
            }
        }
    }
}
