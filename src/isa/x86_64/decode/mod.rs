//! x86_64 instruction decoder with LUT-based prefix detection.

mod dispatch;
pub mod metadata;

use crate::error::{Error, Result};
use crate::isa::x86_64::apx::rex2_reserved_opcode_len;
use crate::isa::x86_64::cpu::{InsnContext, Rex2Prefix, X86_64Vcpu};

/// Lookup table for prefix detection (256 bytes, index = byte value).
/// Value is 1 if the byte is a prefix, 0 otherwise.
static PREFIX_LUT: [u8; 256] = {
    let mut lut = [0u8; 256];
    // Segment overrides
    lut[0x26] = 1;
    lut[0x2E] = 1;
    lut[0x36] = 1;
    lut[0x3E] = 1;
    lut[0x64] = 1;
    lut[0x65] = 1;
    // Operand/address size
    lut[0x66] = 1;
    lut[0x67] = 1;
    // LOCK, REP
    lut[0xF0] = 1;
    lut[0xF2] = 1;
    lut[0xF3] = 1;
    // REX (0x40-0x4F)
    lut[0x40] = 1;
    lut[0x41] = 1;
    lut[0x42] = 1;
    lut[0x43] = 1;
    lut[0x44] = 1;
    lut[0x45] = 1;
    lut[0x46] = 1;
    lut[0x47] = 1;
    lut[0x48] = 1;
    lut[0x49] = 1;
    lut[0x4A] = 1;
    lut[0x4B] = 1;
    lut[0x4C] = 1;
    lut[0x4D] = 1;
    lut[0x4E] = 1;
    lut[0x4F] = 1;
    // REX2 (0xD5) - APX extended prefix
    lut[0xD5] = 1;
    lut
};

pub struct Decoder;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModrmAddressSize {
    Addr16,
    Addr32,
    Addr64,
}

impl Decoder {
    /// Check if byte is a prefix using LUT (faster than match).
    #[inline(always)]
    fn is_prefix(b: u8) -> bool {
        PREFIX_LUT[b as usize] != 0
    }

    /// Decode instruction prefixes and return context.
    #[inline]
    pub fn decode_prefixes(
        bytes: [u8; crate::isa::x86_64::cpu::MAX_INSN_LEN],
        bytes_len: usize,
        boundary_gp: bool,
        is_long_mode: bool,
    ) -> Result<InsnContext> {
        Self::decode_prefixes_with_fault(bytes, bytes_len, boundary_gp, is_long_mode, None)
    }

    pub(super) fn decode_prefixes_with_fault(
        bytes: [u8; crate::isa::x86_64::cpu::MAX_INSN_LEN],
        bytes_len: usize,
        boundary_gp: bool,
        is_long_mode: bool,
        boundary_fault: Option<super::cpu_fetch::DeferredFetchFault>,
    ) -> Result<InsnContext> {
        if bytes_len == 0 {
            // A zero-length fetch only reaches here defensively; a non-canonical
            // RIP is already surfaced as #GP by fetch(). Preserve boundary_gp so
            // the fault, if any, is the architectural #GP rather than a fatal error.
            if boundary_gp {
                return Err(Error::GeneralProtection { error_code: 0 });
            }
            if let Some(fault) = boundary_fault {
                return Err(fault.error());
            }
            return Err(Error::Emulator("instruction too short".to_string()));
        }

        // Fast path: most instructions have no prefixes
        let first = bytes[0];

        if !Self::is_prefix(first) {
            return Ok(InsnContext {
                bytes,
                bytes_len,
                cursor: 0,
                rex: None,
                rex2: None,
                operand_size_override: false,
                address_size_override: false,
                rep_prefix: None,
                op_size: 4,
                rip_relative_offset: 0,
                segment_override: None,
                evex: None,
                opcode: 0,
                boundary_gp,
                boundary_fault,
            });
        }

        // Has prefix(es) - parse them
        let mut ctx = InsnContext {
            bytes,
            bytes_len,
            cursor: 0,
            rex: None,
            rex2: None,
            operand_size_override: false,
            address_size_override: false,
            rep_prefix: None,
            op_size: 4,
            rip_relative_offset: 0,
            segment_override: None,
            evex: None,
            opcode: 0,
            boundary_gp,
            boundary_fault,
        };

        loop {
            if ctx.cursor >= ctx.bytes_len {
                return Err(ctx.out_of_bytes());
            }
            let b = ctx.bytes[ctx.cursor];
            match b {
                0x66 => {
                    ctx.rex = None;
                    ctx.operand_size_override = true;
                }
                0x67 => {
                    ctx.rex = None;
                    ctx.address_size_override = true;
                }
                // REX prefixes exist ONLY in 64-bit mode. In 16/32-bit (real or
                // protected) mode, 0x40-0x4F are INC/DEC r16/r32 opcodes — stop
                // prefix scanning and let the opcode decoder handle them.
                0x40..=0x4F if is_long_mode => ctx.rex = Some(b),
                0xD5 => {
                    // REX2 (APX) only exists in 64-bit mode. Outside long mode,
                    // 0xD5 is the AAD opcode, so stop prefix scanning here and let
                    // the opcode decoder dispatch it (cursor stays on 0xD5).
                    if !is_long_mode {
                        break;
                    }
                    // REX2 prefix: 0xD5 [M:R4:X4:B4:W:R:X:B]
                    // REX2 must be the last prefix before the opcode
                    ctx.cursor += 1;
                    if ctx.cursor >= ctx.bytes_len {
                        return Err(ctx.out_of_bytes());
                    }
                    let payload = ctx.bytes[ctx.cursor];
                    // Decode REX2 payload: [M:R4:X4:B4:W:R:X:B].
                    // Extension bits are non-inverted; see LLVM's APX decoder.
                    ctx.rex2 = Some(Rex2Prefix {
                        m: (payload & 0x80) != 0,  // bit 7: map select
                        r3: (payload & 0x40) != 0, // bit 6: R4 (+16)
                        x3: (payload & 0x20) != 0, // bit 5: X4 (+16)
                        b3: (payload & 0x10) != 0, // bit 4: B4 (+16)
                        w: (payload & 0x08) != 0,  // bit 3: W (operand size)
                        r4: (payload & 0x04) != 0, // bit 2: R (+8)
                        x4: (payload & 0x02) != 0, // bit 1: X (+8)
                        b4: (payload & 0x01) != 0, // bit 0: B (+8)
                    });
                    ctx.cursor += 1;
                    // REX2 is always the last prefix
                    break;
                }
                0xF0 => {
                    ctx.rex = None;
                } // LOCK prefix (legality enforced at dispatch via enforce_lock_prefix)
                0xF2 | 0xF3 => {
                    ctx.rex = None;
                    ctx.rep_prefix = Some(b);
                }
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => {
                    ctx.rex = None;
                    ctx.segment_override = Some(b);
                }
                _ => break,
            }
            ctx.cursor += 1;
        }

        Ok(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86_64::cpu::EvexPrefix;

    #[test]
    fn test_is_prefix() {
        // Segment overrides
        assert!(Decoder::is_prefix(0x26));
        assert!(Decoder::is_prefix(0x2E));
        assert!(Decoder::is_prefix(0x36));
        assert!(Decoder::is_prefix(0x3E));
        assert!(Decoder::is_prefix(0x64));
        assert!(Decoder::is_prefix(0x65));

        // Operand/address size
        assert!(Decoder::is_prefix(0x66));
        assert!(Decoder::is_prefix(0x67));

        // LOCK, REP
        assert!(Decoder::is_prefix(0xF0));
        assert!(Decoder::is_prefix(0xF2));
        assert!(Decoder::is_prefix(0xF3));

        // REX
        for i in 0x40..=0x4F {
            assert!(Decoder::is_prefix(i), "REX 0x{:02X} not detected", i);
        }

        // REX2
        assert!(Decoder::is_prefix(0xD5));

        // Non-prefixes
        assert!(!Decoder::is_prefix(0x00));
        assert!(!Decoder::is_prefix(0x90)); // NOP
        assert!(!Decoder::is_prefix(0xB8)); // MOV
        assert!(!Decoder::is_prefix(0xFF));
    }

    #[test]
    fn test_rex2_decode() {
        use crate::isa::x86_64::cpu::MAX_INSN_LEN;

        // REX2 with M=0, W=1, and all extension bits set.
        let mut bytes = [0u8; MAX_INSN_LEN];
        bytes[0] = 0xD5;
        // 0x7F = 0b0111_1111.
        bytes[1] = 0x7F;
        bytes[2] = 0x90; // NOP opcode
        let ctx = Decoder::decode_prefixes(bytes, 3, false, true).unwrap();
        assert!(ctx.rex2.is_some());
        let rex2 = ctx.rex2.unwrap();
        assert!(!rex2.m); // M=0 (legacy map)
        assert!(rex2.w); // W=1 (64-bit)
        assert!(rex2.r3); // High R extension bit (+16)
        assert!(rex2.r4); // Low R extension bit (+8)
        assert_eq!(ctx.cursor, 2); // Cursor should be after REX2

        // REX2 with M=1 (0F map), W=0, all extension bits cleared.
        // 0xD5 0x80 = REX2 with M=1
        bytes[1] = 0x80;
        let ctx = Decoder::decode_prefixes(bytes, 3, false, true).unwrap();
        let rex2 = ctx.rex2.unwrap();
        assert!(rex2.m); // M=1 (0F map)
        assert!(!rex2.w); // W=0
        assert!(!rex2.r3);
        assert!(!rex2.r4);
    }

    #[test]
    fn test_legacy_prefix_after_rex_clears_rex_state() {
        use crate::isa::x86_64::cpu::MAX_INSN_LEN;

        let mut bytes = [0u8; MAX_INSN_LEN];
        bytes[0] = 0x48; // REX.W
        bytes[1] = 0xF3; // REP after REX: hardware ignores the earlier REX.
        bytes[2] = 0xAB; // STOS
        let ctx = Decoder::decode_prefixes(bytes, 3, false, true).unwrap();
        assert_eq!(ctx.rex, None);
        assert_eq!(ctx.rep_prefix, Some(0xF3));
        assert_eq!(ctx.cursor, 2);

        bytes[0] = 0xF3;
        bytes[1] = 0x48;
        bytes[2] = 0xAB;
        let ctx = Decoder::decode_prefixes(bytes, 3, false, true).unwrap();
        assert_eq!(ctx.rex, Some(0x48));
        assert_eq!(ctx.rep_prefix, Some(0xF3));
        assert_eq!(ctx.cursor, 2);
    }

    // ---- 0x67 address-size override (ModR/M EA computation) ----

    use std::sync::Arc;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    /// Build a minimal 64-bit vcpu (CS.L=1) for exercising decode_modrm_addr.
    /// decode_modrm_addr only reads registers/sregs, so a tiny memory region is fine.
    fn make_vcpu_64() -> X86_64Vcpu {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let mut vcpu = X86_64Vcpu::new(0, mem);
        vcpu.sregs.cs.l = true; // 64-bit mode
        vcpu
    }

    fn make_vcpu_real() -> X86_64Vcpu {
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let mut vcpu = X86_64Vcpu::new(0, mem);
        vcpu.sregs.cr0 = 0;
        vcpu.sregs.cs.l = false;
        vcpu
    }

    /// Compute an effective address the way the decoder does at runtime.
    /// `prefixes` are any legacy prefixes (e.g. 0x67); `modrm` is the ModR/M byte
    /// plus any SIB/displacement bytes. A dummy opcode (0x8B) sits between them, as
    /// in a real instruction, and decode_modrm_addr is invoked at the ModR/M offset.
    fn ea_with_stack_segment(vcpu: &X86_64Vcpu, prefixes: &[u8], modrm: &[u8]) -> (u64, bool) {
        use crate::isa::x86_64::cpu::MAX_INSN_LEN;
        let mut bytes = [0u8; MAX_INSN_LEN];
        let mut len = 0;
        for &b in prefixes {
            bytes[len] = b;
            len += 1;
        }
        bytes[len] = 0x8B; // dummy opcode (MOV r32, r/m32)
        len += 1;
        let modrm_offset = len;
        for &b in modrm {
            bytes[len] = b;
            len += 1;
        }
        let ctx = Decoder::decode_prefixes(bytes, len, false, vcpu.sregs.cs.l).unwrap();
        // After prefixes, cursor points at the opcode; ModR/M starts one byte later.
        assert_eq!(
            ctx.cursor + 1,
            modrm_offset,
            "prefix scan / offset mismatch"
        );
        let (addr, _extra, stack_segment) = vcpu
            .decode_modrm_addr_with_stack_segment(&ctx, modrm_offset)
            .unwrap();
        (addr, stack_segment)
    }

    fn ea(vcpu: &X86_64Vcpu, prefixes: &[u8], modrm: &[u8]) -> u64 {
        ea_with_stack_segment(vcpu, prefixes, modrm).0
    }

    fn ea_evex(vcpu: &X86_64Vcpu, evex: EvexPrefix, modrm: &[u8]) -> u64 {
        use crate::isa::x86_64::cpu::MAX_INSN_LEN;
        let mut bytes = [0u8; MAX_INSN_LEN];
        bytes[0] = 0x8B; // dummy opcode (MOV r32, r/m32)
        let modrm_offset = 1;
        for (i, &b) in modrm.iter().enumerate() {
            bytes[modrm_offset + i] = b;
        }
        let mut ctx =
            Decoder::decode_prefixes(bytes, modrm_offset + modrm.len(), false, true).unwrap();
        ctx.evex = Some(evex);
        let (addr, _extra) = vcpu.decode_modrm_addr(&ctx, modrm_offset).unwrap();
        addr
    }

    fn vector_evex_addr_prefix(b: bool, x: bool) -> EvexPrefix {
        EvexPrefix {
            r: true,
            x,
            b,
            r_prime: true,
            mm: 2,
            w: false,
            vvvv: 0x0f,
            pp: 2,
            z: false,
            ll: 2,
            broadcast: false,
            v_prime: true,
            aaa: 0,
            b4: false,
            x4: false,
            nd: false,
            nf: false,
            apx_mode: false,
        }
    }

    // A fetch truncated at the canonical-address boundary must surface as #GP,
    // not a fatal emulator error or a silent decode of zero padding.
    #[test]
    fn rex2_truncated_payload_is_gp_at_boundary() {
        use crate::isa::x86_64::cpu::MAX_INSN_LEN;
        let mut bytes = [0u8; MAX_INSN_LEN];
        bytes[0] = 0xD5;

        let err = Decoder::decode_prefixes(bytes, 1, true, true).err();
        assert!(
            matches!(err, Some(Error::GeneralProtection { .. })),
            "REX2 payload truncation at the canonical boundary must be #GP, got {err:?}"
        );

        let err = Decoder::decode_prefixes(bytes, 1, false, true).err();
        assert!(matches!(err, Some(Error::Emulator(_))));
    }

    #[test]
    fn modrm_disp_truncation_is_gp_at_boundary() {
        let vcpu = make_vcpu_64();
        use crate::isa::x86_64::cpu::MAX_INSN_LEN;
        let mut bytes = [0u8; MAX_INSN_LEN];
        // mod=10, rm=000 -> [rax + disp32], with the disp32 missing.
        bytes[0] = 0x80;

        let ctx = Decoder::decode_prefixes(bytes, 1, true, true).unwrap();
        let result = vcpu.decode_modrm_addr(&ctx, 0);
        assert!(
            matches!(result, Err(Error::GeneralProtection { .. })),
            "missing disp32 at the canonical boundary must be #GP, got {result:?}"
        );
    }

    #[test]
    fn test_addr67_reg_indirect_truncates_to_32_bits() {
        // MOV r, [RBX] with 0x67: ModRM mod=00 reg=000 rm=011 (RBX) = 0x03.
        let mut vcpu = make_vcpu_64();
        // Low 32 bits = 0x2000, but a high bit is set above bit 31.
        vcpu.regs.rbx = 0x1_0000_2000;

        // Without override: full 64-bit register value is the EA.
        assert_eq!(ea(&vcpu, &[], &[0x03]), 0x1_0000_2000);
        // With 0x67: EA is truncated to 32 bits.
        assert_eq!(ea(&vcpu, &[0x67], &[0x03]), 0x0000_2000);
    }

    #[test]
    fn test_addr67_sib_base_index_scale_disp_truncates() {
        // MOV r, [RBX + RCX*4 + 0x10] with 0x67:
        //   ModRM mod=01 reg=000 rm=100(SIB) = 0x44
        //   SIB   scale=01(*4? -> scale field 2) ... encode scale=2 (=*4): bits 7..6 = 10
        //         index=001(RCX), base=011(RBX) -> (2<<6)|(1<<3)|3 = 0x8B
        //   disp8 = 0x10
        let mut vcpu = make_vcpu_64();
        vcpu.regs.rbx = 0xFFFF_F000; // near top of 32-bit space
        vcpu.regs.rcx = 0x0000_0500; // *4 = 0x1400

        // 64-bit (no override): 0xFFFF_F000 + 0x1400 + 0x10 = 0x1_0000_0410
        assert_eq!(
            ea(&vcpu, &[], &[0x44, 0x8B, 0x10]),
            0xFFFF_F000u64 + 0x1400 + 0x10
        );
        // With 0x67: same sum, then masked to 32 bits -> 0x0000_0410
        assert_eq!(ea(&vcpu, &[0x67], &[0x44, 0x8B, 0x10]), 0x0000_0410);
    }

    #[test]
    fn test_addr_plain_64bit_unaffected() {
        // Plain 64-bit [base+index*scale+disp] must be byte-identical to before.
        let mut vcpu = make_vcpu_64();
        vcpu.regs.rax = 0x1234_5678_9000; // base RAX
        vcpu.regs.rdx = 0x10; // index RDX
        // [RAX + RDX*8 + 0x20]: ModRM mod=01 reg=000 rm=100 = 0x44
        //   SIB scale=11(*8) index=010(RDX) base=000(RAX) = (3<<6)|(2<<3)|0 = 0xD0
        //   disp8 = 0x20
        let got = ea(&vcpu, &[], &[0x44, 0xD0, 0x20]);
        assert_eq!(got, 0x1234_5678_9000u64 + 0x10 * 8 + 0x20);
    }

    #[test]
    fn rex_b_does_not_extend_the_sib_no_base_encoding() {
        let mut vcpu = make_vcpu_64();
        vcpu.regs.r13 = 0x8000;

        // REX.B does not turn mod=00, SIB.base=101 into R13. The encoding
        // remains disp32-only and therefore retains the DS default segment.
        let (address, stack_segment) =
            ea_with_stack_segment(&vcpu, &[0x41], &[0x04, 0x25, 0x34, 0x12, 0x00, 0x00]);
        assert_eq!(address, 0x1234);
        assert!(!stack_segment);
    }

    #[test]
    fn fpu_rex_b_does_not_extend_the_sib_no_base_encoding() {
        use crate::isa::x86_64::cpu::MAX_INSN_LEN;

        let mut vcpu = make_vcpu_64();
        vcpu.regs.r13 = 0x8000;
        let mut bytes = [0_u8; MAX_INSN_LEN];
        bytes[..8].copy_from_slice(&[0x41, 0xD9, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00]);
        let mut ctx = Decoder::decode_prefixes(bytes, 8, false, true).unwrap();
        assert_eq!(ctx.cursor, 1);
        ctx.cursor = 3; // FPU dispatch has consumed opcode D9 and ModR/M 04.

        let address = vcpu.decode_fpu_modrm_addr(&mut ctx, 0x04).unwrap();
        assert_eq!(address, 0x1234);
        assert_eq!(ctx.cursor, 8);
    }

    #[test]
    fn effective_stack_segment_tracks_defaults_and_explicit_overrides() {
        let mut vcpu = make_vcpu_64();
        vcpu.regs.rax = 0x1000;
        vcpu.regs.rbp = 0x2000;

        assert!(ea_with_stack_segment(&vcpu, &[], &[0x45, 0x00]).1);
        assert!(!ea_with_stack_segment(&vcpu, &[0x3E], &[0x45, 0x00]).1);
        assert!(ea_with_stack_segment(&vcpu, &[0x36], &[0x00]).1);
        assert!(!ea_with_stack_segment(&vcpu, &[], &[0x00]).1);
    }

    #[test]
    fn test_evex_sib_base_index_extensions() {
        let mut vcpu = make_vcpu_64();
        vcpu.regs.rdx = 0x1000;
        vcpu.regs.rbx = 0x20;
        vcpu.regs.r10 = 0x4000;
        vcpu.regs.r11 = 0x30;

        let evex = vector_evex_addr_prefix(false, false);

        // ModRM rm=100 selects SIB. SIB scale=01, index=011, base=010 is
        // [rdx + rbx*2] without EVEX, but [r10 + r11*2] with inverted EVEX.B/X.
        assert_eq!(ea_evex(&vcpu, evex, &[0x14, 0x5A]), 0x4000 + 0x30 * 2);

        // Non-SIB ModRM r/m also uses EVEX.B for the base register.
        assert_eq!(ea_evex(&vcpu, evex, &[0x02]), 0x4000);
    }

    #[test]
    fn test_addr67_rip_relative_masks_to_32_bits() {
        // RIP-relative [RIP+disp32]: ModRM mod=00 reg=000 rm=101 = 0x05.
        // With 0x67 in 64-bit mode the EIP-relative result is masked to 32 bits.
        let mut vcpu = make_vcpu_64();
        vcpu.regs.rip = 0x1_0000_1000; // RIP with a bit above 31 set

        // No prefix: opcode at offset 0, ModR/M at offset 1.
        // rip_after = RIP + modrm_offset(1) + 1 (modrm) + 4 (disp32) = RIP + 6; disp32 = 0.
        let no_override = ea(&vcpu, &[], &[0x05, 0x00, 0x00, 0x00, 0x00]);
        assert!(
            no_override > 0xFFFF_FFFF,
            "64-bit RIP-rel should keep high bits"
        );
        assert_eq!(no_override, 0x1_0000_1000u64 + 6);

        // With 0x67: opcode at offset 1, ModR/M at offset 2.
        // rip_after = RIP + modrm_offset(2) + 1 + 4 = RIP + 7; disp32 = 0; masked to 32 bits.
        let with_override = ea(&vcpu, &[0x67], &[0x05, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(with_override, (0x1_0000_1000u64 + 7) & 0xFFFF_FFFF);
    }

    #[test]
    fn real_mode_addr32_ebp_base_defaults_to_ss() {
        let mut vcpu = make_vcpu_real();
        vcpu.sregs.ds.base = 0x1000;
        vcpu.sregs.ss.base = 0x7000;
        vcpu.regs.rbp = 0x20;
        vcpu.regs.rbx = 0x20;

        // In real mode, 0x67 selects 32-bit addressing. [EBP + disp8]
        // defaults to SS.
        assert_eq!(ea(&vcpu, &[0x67], &[0x45, 0x00]), 0x7020);
        // Non-stack base registers keep the DS default.
        assert_eq!(ea(&vcpu, &[0x67], &[0x03]), 0x1020);
    }

    #[test]
    fn real_mode_addr32_sib_esp_base_defaults_to_ss() {
        let mut vcpu = make_vcpu_real();
        vcpu.sregs.ds.base = 0x2000;
        vcpu.sregs.ss.base = 0x8000;
        vcpu.regs.rsp = 0x30;

        // SIB [ESP] also defaults to SS.
        assert_eq!(ea(&vcpu, &[0x67], &[0x04, 0x24]), 0x8030);
    }

    #[test]
    fn real_mode_segment_override_beats_stack_default() {
        let mut vcpu = make_vcpu_real();
        vcpu.sregs.ds.base = 0x3000;
        vcpu.sregs.ss.base = 0x9000;
        vcpu.regs.rbp = 0x40;

        // DS override on a BP-family base must use DS, not the default SS.
        assert_eq!(ea(&vcpu, &[0x3E, 0x67], &[0x45, 0x00]), 0x3040);
    }

    #[test]
    fn real_mode_sib_no_base_defaults_to_ds() {
        let mut vcpu = make_vcpu_real();
        vcpu.sregs.ds.base = 0x4000;
        vcpu.sregs.ss.base = 0xA000;

        // SIB base=5, mod=0 is disp32 with no base register, so the default is DS.
        assert_eq!(
            ea(&vcpu, &[0x67], &[0x04, 0x25, 0x50, 0x00, 0x00, 0x00]),
            0x4050
        );
    }
}

impl X86_64Vcpu {
    /// Enforce LOCK-prefix legality, raising #UD (vector 6) for illegal use.
    ///
    /// The LOCK prefix (0xF0) is architecturally legal *only* on the
    /// memory-destination read-modify-write forms of a fixed instruction set
    /// (ADD, ADC, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B/16B, DEC, INC, NEG,
    /// NOT, OR, SBB, SUB, XOR, XADD, XCHG). Anything else - a non-lockable
    /// opcode, or a lockable opcode whose destination is a register (ModR/M
    /// mod == 3) - raises #UD before the instruction executes.
    ///
    /// rax is a single-vCPU interpreter, so a LOCKed RMW is already atomic (the
    /// whole instruction runs without interleaving); the only architectural
    /// behaviour to add is this decode-time legality check.
    ///
    /// The LOCK prefix is not carried in a dedicated `InsnContext` field (to
    /// avoid widening the struct used on every fetch); instead it is recovered
    /// here by scanning the instruction's prefix region. `opcode` is the
    /// primary opcode byte, `opcode_cursor` is its offset in `ctx.bytes` (so the
    /// prefixes, including any 0xF0, occupy `[0, opcode_cursor)`), and
    /// `ctx.cursor` points just past the primary opcode in both the full-decode
    /// and decode-cache-hit paths.
    ///
    /// Returns `Ok(true)` if the LOCK was illegal and #UD was delivered, so the
    /// caller must stop dispatching this instruction. Returns `Ok(false)` if the
    /// instruction may proceed.
    #[inline(always)]
    #[allow(dead_code)] // retained for non-cache callers / documentation; the hot
    // path now caches the LOCK verdict and calls `enforce_lock_prefix_cold` directly.
    pub(super) fn enforce_lock_prefix(
        &mut self,
        ctx: &InsnContext,
        opcode: u8,
        opcode_cursor: usize,
    ) -> Result<bool> {
        // Fast path (inlined into the hot loop): no LOCK prefix (0xF0) among the
        // prefix bytes => nothing to enforce. This is the overwhelmingly common
        // case (prefix-less instructions resolve to an empty scan). Only when a
        // 0xF0 is actually present do we take the cold legality path.
        if !ctx.bytes[..opcode_cursor.min(ctx.bytes_len)].contains(&0xF0) {
            return Ok(false);
        }
        self.enforce_lock_prefix_cold(ctx, opcode)
    }

    #[cold]
    #[inline(never)]
    pub(super) fn enforce_lock_prefix_cold(
        &mut self,
        ctx: &InsnContext,
        opcode: u8,
    ) -> Result<bool> {
        if Self::lock_is_legal(ctx, opcode) {
            return Ok(false);
        }

        // Illegal LOCK use: deliver #UD (vector 6, no error code). RIP still
        // points at the faulting instruction (it is only advanced by handlers
        // on success), which is the architecturally correct fault behaviour.
        self.inject_exception(6, None)?;
        Ok(true)
    }

    /// Reject opcode-space reservations and XSAVE-family exceptions from the
    /// architectural REX2 applicability table before instruction dispatch.
    ///
    /// For compressed map 1, `ctx.cursor` still names the effective opcode;
    /// for map 0, `opcode` is the already-consumed effective opcode. XSAVE and
    /// XRSTOR aliases require the raw ModR/M group to distinguish them from
    /// valid register-form instructions sharing 0F AE or 0F C7.
    #[inline(always)]
    pub(super) fn reject_reserved_rex2_opcode(
        &mut self,
        ctx: &InsnContext,
        opcode: u8,
    ) -> Result<bool> {
        let Some(rex2) = ctx.rex2 else {
            return Ok(false);
        };
        let effective_opcode = if rex2.m {
            if ctx.cursor >= ctx.bytes_len {
                return Ok(false);
            }
            ctx.bytes[ctx.cursor]
        } else {
            opcode
        };

        let following = if rex2.m && ctx.cursor + 1 < ctx.bytes_len {
            Some(ctx.bytes[ctx.cursor + 1])
        } else {
            None
        };
        if rex2_reserved_opcode_len(rex2.m, effective_opcode, following).is_none() {
            return Ok(false);
        }
        self.inject_exception(6, None)?;
        Ok(true)
    }

    /// Decide whether a LOCK-prefixed instruction is legal. Pure decode-time
    /// inspection of the opcode plus (where relevant) the ModR/M byte.
    fn lock_is_legal(ctx: &InsnContext, opcode: u8) -> bool {
        // For two-byte opcodes the primary byte is 0x0F and the real opcode /
        // ModR/M follow it; for single-byte opcodes the ModR/M (if any) sits at
        // the cursor. Resolve the effective opcode and the ModR/M offset.
        let (eff_opcode, modrm_off, two_byte) = if opcode == 0x0F {
            (
                ctx.bytes.get(ctx.cursor).copied().unwrap_or(0),
                ctx.cursor + 1,
                true,
            )
        } else {
            (opcode, ctx.cursor, false)
        };

        let modrm = ctx.bytes.get(modrm_off).copied().unwrap_or(0);
        // LOCK is only ever legal with a memory destination (ModR/M mod != 3).
        let mem_dest = (modrm >> 6) != 3;
        let reg_field = (modrm >> 3) & 0x07;

        if two_byte {
            match eff_opcode {
                // CMPXCHG r/m, r
                0xB0 | 0xB1 => mem_dest,
                // XADD r/m, r
                0xC0 | 0xC1 => mem_dest,
                // BTS / BTR / BTC (register-source forms)
                0xAB | 0xB3 | 0xBB => mem_dest,
                // Group 8 (0F BA) /5 BTS, /6 BTR, /7 BTC; /4 BT is NOT lockable.
                0xBA => mem_dest && matches!(reg_field, 5 | 6 | 7),
                // Group 9 (0F C7) /1 = CMPXCHG8B / CMPXCHG16B.
                0xC7 => mem_dest && reg_field == 1,
                _ => false,
            }
        } else {
            match eff_opcode {
                // ADD/ADC/AND/OR/SBB/SUB/XOR r/m, r (and the byte forms).
                0x00 | 0x01 // ADD
                | 0x08 | 0x09 // OR
                | 0x10 | 0x11 // ADC
                | 0x18 | 0x19 // SBB
                | 0x20 | 0x21 // AND
                | 0x28 | 0x29 // SUB
                | 0x30 | 0x31 // XOR
                    => mem_dest,
                // XCHG r/m, r (always implicitly locked; LOCK is also accepted).
                0x86 | 0x87 => mem_dest,
                // Group 1 (0x80/0x81/0x82/0x83): /0 ADD /1 OR /2 ADC /3 SBB
                // /4 AND /5 SUB /6 XOR are lockable; /7 CMP is NOT.
                0x80 | 0x81 | 0x82 | 0x83 => mem_dest && reg_field != 7,
                // Group 3 (0xF6/0xF7): /2 NOT and /3 NEG are lockable; the
                // others (TEST/MUL/IMUL/DIV/IDIV) are not.
                0xF6 | 0xF7 => mem_dest && matches!(reg_field, 2 | 3),
                // Group 4 (0xFE): /0 INC, /1 DEC.
                0xFE => mem_dest && matches!(reg_field, 0 | 1),
                // Group 5 (0xFF): /0 INC, /1 DEC are lockable; CALL/JMP/PUSH
                // are not.
                0xFF => mem_dest && matches!(reg_field, 0 | 1),
                _ => false,
            }
        }
    }

    /// Get the segment base address for a segment override prefix.
    /// In 64-bit mode, only FS and GS have non-zero bases.
    #[inline]
    pub(super) fn get_segment_base(&self, segment_override: Option<u8>) -> u64 {
        self.get_segment_base_with_default(segment_override, false)
    }

    #[inline]
    fn get_segment_base_with_default(&self, segment_override: Option<u8>, default_ss: bool) -> u64 {
        match segment_override {
            Some(0x26) => self.sregs.es.base, // ES
            Some(0x2E) => self.sregs.cs.base, // CS
            Some(0x36) => self.sregs.ss.base, // SS
            Some(0x3E) => self.sregs.ds.base, // DS
            Some(0x64) => self.sregs.fs.base, // FS
            Some(0x65) => self.sregs.gs.base, // GS
            // No override: the default data segment is DS. Its base is
            // selector<<4 in real mode and the descriptor base in protected /
            // compatibility mode — 0 for the usual flat model, but non-zero for
            // an OS that runs on based data segments (e.g. TempleOS relocating
            // through ds.base before going flat). Only true 64-bit mode
            // (CS.L=1) ignores data-segment bases, so it stays flat.
            None if self.sregs.cs.l => 0,
            None if default_ss => self.sregs.ss.base,
            None => self.sregs.ds.base,
            _ => 0,
        }
    }

    #[inline]
    fn modrm_base_defaults_to_ss(base_reg: u8) -> bool {
        matches!(base_reg & 0x07, 4 | 5)
    }

    #[inline]
    fn modrm_address_size(&self, ctx: &InsnContext) -> ModrmAddressSize {
        if self.sregs.cs.l {
            if ctx.address_size_override {
                ModrmAddressSize::Addr32
            } else {
                ModrmAddressSize::Addr64
            }
        } else {
            let default_16bit = !self.sregs.cs.db;
            let is_16bit = default_16bit ^ ctx.address_size_override;
            if is_16bit {
                ModrmAddressSize::Addr16
            } else {
                ModrmAddressSize::Addr32
            }
        }
    }

    #[inline]
    fn reg16(&self, reg: u8) -> u64 {
        self.get_reg(reg, 2) & 0xffff
    }

    #[inline]
    fn decode_modrm_addr16(
        &self,
        ctx: &InsnContext,
        bytes: &[u8],
        mod_bits: u8,
        rm_field: u8,
    ) -> Result<(u64, usize, bool)> {
        let (mut addr, default_ss) = match rm_field {
            0 => (self.reg16(3).wrapping_add(self.reg16(6)), false), // BX + SI
            1 => (self.reg16(3).wrapping_add(self.reg16(7)), false), // BX + DI
            2 => (self.reg16(5).wrapping_add(self.reg16(6)), true),  // BP + SI
            3 => (self.reg16(5).wrapping_add(self.reg16(7)), true),  // BP + DI
            4 => (self.reg16(6), false),                             // SI
            5 => (self.reg16(7), false),                             // DI
            6 if mod_bits == 0 => {
                if bytes.len() < 3 {
                    return Err(ctx.out_of_bytes());
                }
                let disp = u16::from_le_bytes([bytes[1], bytes[2]]);
                return Ok((u64::from(disp), 2, false));
            }
            6 => (self.reg16(5), true),  // BP
            7 => (self.reg16(3), false), // BX
            _ => unreachable!(),
        };

        let extra = match mod_bits {
            0 => 0,
            1 => {
                if bytes.len() < 2 {
                    return Err(ctx.out_of_bytes());
                }
                let disp = bytes[1] as i8 as i64;
                addr = (addr as i64).wrapping_add(disp) as u64;
                1
            }
            2 => {
                if bytes.len() < 3 {
                    return Err(ctx.out_of_bytes());
                }
                let disp = i16::from_le_bytes([bytes[1], bytes[2]]) as i64;
                addr = (addr as i64).wrapping_add(disp) as u64;
                2
            }
            _ => unreachable!(),
        };

        Ok((addr & 0xffff, extra, default_ss))
    }

    #[inline]
    fn decode_fpu_modrm_addr16(
        &self,
        ctx: &mut InsnContext,
        mod_bits: u8,
        rm_field: u8,
    ) -> Result<(u64, bool)> {
        let (mut addr, default_ss) = match rm_field {
            0 => (self.reg16(3).wrapping_add(self.reg16(6)), false), // BX + SI
            1 => (self.reg16(3).wrapping_add(self.reg16(7)), false), // BX + DI
            2 => (self.reg16(5).wrapping_add(self.reg16(6)), true),  // BP + SI
            3 => (self.reg16(5).wrapping_add(self.reg16(7)), true),  // BP + DI
            4 => (self.reg16(6), false),                             // SI
            5 => (self.reg16(7), false),                             // DI
            6 if mod_bits == 0 => {
                let disp = ctx.consume_u16()?;
                return Ok((u64::from(disp), false));
            }
            6 => (self.reg16(5), true),  // BP
            7 => (self.reg16(3), false), // BX
            _ => unreachable!(),
        };

        match mod_bits {
            0 => {}
            1 => {
                let disp = ctx.consume_u8()? as i8 as i64;
                addr = (addr as i64).wrapping_add(disp) as u64;
            }
            2 => {
                let disp = ctx.consume_u16()? as i16 as i64;
                addr = (addr as i64).wrapping_add(disp) as u64;
            }
            _ => unreachable!(),
        }

        Ok((addr & 0xffff, default_ss))
    }

    /// Decode ModR/M byte to get effective address.
    /// Returns (address, bytes_consumed_after_modrm).
    #[inline]
    pub(super) fn decode_modrm_addr(
        &self,
        ctx: &InsnContext,
        modrm_offset: usize,
    ) -> Result<(u64, usize)> {
        let (addr, extra, _, _) = self.decode_modrm_addr_with_segment(ctx, modrm_offset)?;
        Ok((addr, extra))
    }

    /// Decode a ModR/M memory address and report whether its effective segment
    /// is SS. This is needed by instructions whose noncanonical-address fault
    /// is #SS(0), rather than #GP(0), for an SS-based operand.
    #[inline]
    pub(super) fn decode_modrm_addr_with_stack_segment(
        &self,
        ctx: &InsnContext,
        modrm_offset: usize,
    ) -> Result<(u64, usize, bool)> {
        let (addr, extra, _, default_ss) =
            self.decode_modrm_addr_with_segment(ctx, modrm_offset)?;
        let stack_segment = match ctx.segment_override {
            Some(0x36) => true,
            Some(_) => false,
            None => default_ss,
        };
        Ok((addr, extra, stack_segment))
    }

    #[inline]
    fn decode_modrm_addr_with_segment(
        &self,
        ctx: &InsnContext,
        modrm_offset: usize,
    ) -> Result<(u64, usize, u64, bool)> {
        let end = ctx.bytes_len.min(ctx.bytes.len());
        let bytes = ctx.bytes.get(modrm_offset..end).unwrap_or(&[]);
        if bytes.is_empty() {
            return Err(ctx.out_of_bytes());
        }

        let modrm = bytes[0];
        let mod_bits = modrm >> 6;
        let rm_field = modrm & 0x07; // Raw r/m field without REX.B
        let rm_ext = if let Some(evex) = ctx.evex {
            if evex.apx_mode {
                ctx.evex_rm_reg()
            } else if evex.b {
                0
            } else {
                8
            }
        } else {
            ctx.any_rex_b()
        };
        let rm = rm_field | rm_ext; // r/m with REX/REX2 or EVEX.B/B4 applied
        let mut extra = 0;

        // mod == 3 means register direct, shouldn't call this function
        if mod_bits == 3 {
            return Err(Error::Emulator(
                "ModR/M: mod=3 is register, not memory".to_string(),
            ));
        }

        let addr_size = self.modrm_address_size(ctx);

        // FAST PATH for the overwhelmingly common memory forms: [reg],
        // [reg+disp8], [reg+disp32] with no SIB (rm!=4), not RIP-relative /
        // disp32-absolute (rm==5 && mod==0), no address-size override, and no
        // segment override (DS/ES/SS/CS bases are 0 in this emulator's flat
        // model, so seg_base is 0). This skips the SIB decode, the RIP-relative
        // branch, the address-size-32 truncation, and the get_segment_base call.
        // Behaviour is identical to the general path below for these cases; it is
        // ~14% of a memory workload so the shortcut is worth the up-front test.
        if rm_field != 4
            && !(rm_field == 5 && mod_bits == 0)
            && !ctx.address_size_override
            && addr_size == ModrmAddressSize::Addr64
            && ctx.segment_override.is_none()
            && (self.sregs.cr0 & 0x1) != 0
            && self.sregs.ds.base == 0
            && self.sregs.ss.base == 0
        // protected 64-bit flat mode only: real mode (PE=0) needs the segment
        // base (selector<<4) folded in, and compatibility/protected 16/32-bit
        // modes have different address-size semantics. Also requires flat DS/SS:
        // a based data segment (e.g. TempleOS in protected mode) must fold
        // ds.base/ss.base in, which only the general path does.
        {
            let base = self.get_reg(rm, 8);
            let default_ss = Self::modrm_base_defaults_to_ss(rm);
            return match mod_bits {
                0 => Ok((base, 0, 0, default_ss)),
                1 => {
                    if bytes.len() < 2 {
                        return Err(ctx.out_of_bytes());
                    }
                    Ok((
                        (base as i64).wrapping_add(bytes[1] as i8 as i64) as u64,
                        1,
                        0,
                        default_ss,
                    ))
                }
                _ => {
                    // mod_bits == 2 (mod == 3 rejected above): disp32
                    if bytes.len() < 5 {
                        return Err(ctx.out_of_bytes());
                    }
                    let disp = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as i64;
                    Ok(((base as i64).wrapping_add(disp) as u64, 4, 0, default_ss))
                }
            };
        }

        if addr_size == ModrmAddressSize::Addr16 {
            let (addr, extra, default_ss) =
                self.decode_modrm_addr16(ctx, bytes, mod_bits, rm_field)?;
            let seg_base = self.get_segment_base_with_default(ctx.segment_override, default_ss);
            let final_addr = addr.wrapping_add(seg_base);
            return Ok((final_addr, extra, seg_base, default_ss));
        }

        let addr_size_32 = addr_size == ModrmAddressSize::Addr32;
        let reg_size: u8 = if addr_size_32 { 4 } else { 8 };

        let mut addr: u64;
        let mut default_ss = false;

        if rm_field == 4 {
            // SIB byte follows
            if bytes.len() < 2 {
                return Err(ctx.out_of_bytes());
            }
            let sib = bytes[1];
            extra += 1;
            let scale = 1u64 << (sib >> 6);
            let index_ext = if let Some(evex) = ctx.evex {
                if evex.apx_mode {
                    ctx.evex_index_reg()
                } else if evex.x {
                    0
                } else {
                    8
                }
            } else if ctx.rex2.is_some() {
                ctx.rex2_x()
            } else {
                ctx.rex.map_or(0, |r| (r & 0x02) << 2)
            };
            let index = ((sib >> 3) & 0x07) | index_ext;
            let base_field = sib & 0x07;
            let base_reg = base_field | rm_ext;
            // The mod=00, SIB.base=101 no-base encoding is independent of
            // REX.B/REX2.B, just as ModR/M.r/m=101 remains RIP-relative.
            let has_base = !(base_field == 5 && mod_bits == 0);

            // Calculate base
            addr = if !has_base {
                // No base, disp32 follows
                0
            } else {
                default_ss = Self::modrm_base_defaults_to_ss(base_reg);
                self.get_reg(base_reg, reg_size)
            };

            // Add scaled index (index=4 means no index)
            if index != 4 {
                addr = addr.wrapping_add(self.get_reg(index, reg_size).wrapping_mul(scale));
            }

            // Handle displacement for base=5, mod=0 case
            if !has_base {
                if bytes.len() < 2 + 4 {
                    return Err(ctx.out_of_bytes());
                }
                let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as i64;
                extra += 4;
                addr = (addr as i64).wrapping_add(disp) as u64;
            }
        } else if rm_field == 5 && mod_bits == 0 {
            // In 64-bit mode (CS.L = 1): RIP-relative addressing [RIP+disp32]
            // In compatibility/legacy mode (CS.L = 0): absolute disp32 [disp32]
            if bytes.len() < 5 {
                return Err(ctx.out_of_bytes());
            }
            let disp = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as i64;
            extra += 4;

            if self.sregs.cs.l {
                // 64-bit mode: RIP-relative addressing
                // RIP points to the next instruction
                let rip_after = self.regs.rip as i64
                    + modrm_offset as i64
                    + 1
                    + 4
                    + ctx.rip_relative_offset as i64;
                // With 0x67 in 64-bit mode, RIP-relative addressing uses 32-bit
                // EIP-relative semantics: the computed address is truncated to 32
                // bits (per Intel SDM Vol. 2, ModR/M with address-size override).
                // The shared truncation below applies the mask for this case too.
                addr = rip_after.wrapping_add(disp) as u64;
            } else {
                // Compatibility/legacy mode: absolute [disp32]
                addr = disp as u64;
            }
        } else {
            // Regular register indirect
            default_ss = Self::modrm_base_defaults_to_ss(rm);
            addr = self.get_reg(rm, reg_size);
        }

        // Handle displacement
        match mod_bits {
            0 => {} // No displacement (except special cases handled above)
            1 => {
                // disp8
                if bytes.len() < extra + 2 {
                    return Err(ctx.out_of_bytes());
                }
                let disp = bytes[extra + 1] as i8 as i64;
                extra += 1;
                addr = (addr as i64).wrapping_add(disp) as u64;
            }
            2 => {
                // disp32
                if bytes.len() < extra + 5 {
                    return Err(ctx.out_of_bytes());
                }
                let disp = i32::from_le_bytes([
                    bytes[extra + 1],
                    bytes[extra + 2],
                    bytes[extra + 3],
                    bytes[extra + 4],
                ]) as i64;
                extra += 4;
                addr = (addr as i64).wrapping_add(disp) as u64;
            }
            _ => {}
        }

        // Truncate the effective address to 32 bits for the 64-bit-mode 0x67
        // case, BEFORE applying the segment base. The base/index were already
        // read as 32-bit values; this masks any displacement carry-out so the
        // computed EA wraps within the 32-bit address space as hardware does.
        if addr_size_32 {
            addr &= 0xFFFF_FFFF;
        }

        // Apply segment override (in 64-bit mode, only FS and GS have non-zero bases)
        let seg_base = self.get_segment_base_with_default(ctx.segment_override, default_ss);
        let final_addr = addr.wrapping_add(seg_base);

        Ok((final_addr, extra, seg_base, default_ss))
    }

    /// Compute the effective address (segment OFFSET) for a ModR/M memory
    /// operand as required by LEA. Identical to `decode_modrm_addr` except it
    /// does NOT fold in the FS/GS segment base: per Intel SDM, LEA computes the
    /// offset part of the address and ignores any segment override. The subtract
    /// is exactly the inverse of the `wrapping_add(seg_base)` in
    /// `decode_modrm_addr` (including the 0x67 32-bit truncation, which happens
    /// before the base is applied), and is a no-op in the common no-override case.
    pub(super) fn decode_lea_addr(
        &self,
        ctx: &InsnContext,
        modrm_offset: usize,
    ) -> Result<(u64, usize)> {
        let (addr, extra, seg_base, _) = self.decode_modrm_addr_with_segment(ctx, modrm_offset)?;
        let offset = addr.wrapping_sub(seg_base);
        Ok((offset, extra))
    }

    /// Decode ModR/M and return (reg, rm, is_memory, address_if_memory, extra_bytes).
    /// This is a convenience function that handles both register and memory operands.
    #[inline]
    pub(super) fn decode_modrm(&self, ctx: &mut InsnContext) -> Result<(u8, u8, bool, u64, usize)> {
        let modrm_start = ctx.cursor;
        let modrm = ctx.consume_u8()?;
        let reg = ((modrm >> 3) & 0x07) | ctx.any_rex_r();
        let rm = (modrm & 0x07) | ctx.any_rex_b();
        let mod_bits = modrm >> 6;

        if mod_bits == 3 {
            // Register operand
            Ok((reg, rm, false, 0, 0))
        } else {
            // Memory operand
            let (addr, extra) = self.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;
            Ok((reg, rm, true, addr, extra))
        }
    }

    /// Read operand from ModR/M - handles both register and memory.
    #[allow(dead_code)]
    pub(super) fn read_rm(&mut self, ctx: &mut InsnContext, size: u8) -> Result<(u64, bool, u64)> {
        let modrm_start = ctx.cursor;
        let modrm = ctx.consume_u8()?;
        let rm = (modrm & 0x07) | ctx.any_rex_b();
        let mod_bits = modrm >> 6;

        if mod_bits == 3 {
            // Register operand
            Ok((self.get_reg(rm, size), false, 0))
        } else {
            // Memory operand
            let (addr, extra) = self.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;
            let value = self.read_mem(addr, size)?;
            Ok((value, true, addr))
        }
    }

    /// Write to operand from ModR/M - handles both register and memory.
    #[allow(dead_code)]
    pub(super) fn write_rm(
        &mut self,
        rm: u8,
        is_memory: bool,
        addr: u64,
        value: u64,
        size: u8,
    ) -> Result<()> {
        if is_memory {
            self.write_mem(addr, value, size)
        } else {
            self.set_reg(rm, value, size);
            Ok(())
        }
    }

    /// Decode ModR/M address when modrm byte has already been consumed.
    /// Used by FPU instructions where the modrm byte determines the operation.
    /// This reads any SIB/displacement bytes from ctx and updates cursor.
    pub(super) fn decode_fpu_modrm_addr(&self, ctx: &mut InsnContext, modrm: u8) -> Result<u64> {
        let mod_bits = modrm >> 6;
        let rm_field = modrm & 0x07;
        let rm = rm_field | ctx.any_rex_b();

        if mod_bits == 3 {
            return Err(Error::Emulator(
                "ModR/M: mod=3 is register, not memory".to_string(),
            ));
        }

        let addr_size = self.modrm_address_size(ctx);
        if addr_size == ModrmAddressSize::Addr16 {
            let (addr, default_ss) = self.decode_fpu_modrm_addr16(ctx, mod_bits, rm_field)?;
            let seg_base = self.get_segment_base_with_default(ctx.segment_override, default_ss);
            return Ok(addr.wrapping_add(seg_base));
        }

        let addr_size_32 = addr_size == ModrmAddressSize::Addr32;
        let reg_size: u8 = if addr_size_32 { 4 } else { 8 };

        let mut addr: u64;
        let mut default_ss = false;

        if rm_field == 4 {
            // SIB byte follows
            let sib = ctx.consume_u8()?;
            let scale = 1u64 << (sib >> 6);
            let index = ((sib >> 3) & 0x07)
                | if ctx.rex2.is_some() {
                    ctx.rex2_x()
                } else {
                    ctx.rex.map_or(0, |r| (r & 0x02) << 2)
                };
            let base_field = sib & 0x07;
            let base_reg = base_field | ctx.any_rex_b();
            let has_base = !(base_field == 5 && mod_bits == 0);

            // Calculate base
            addr = if !has_base {
                // No base, disp32 follows
                let disp = ctx.consume_u32()? as i32 as i64;
                disp as u64
            } else {
                default_ss = Self::modrm_base_defaults_to_ss(base_reg);
                self.get_reg(base_reg, reg_size)
            };

            // Add scaled index (index=4 means no index)
            if index != 4 {
                addr = addr.wrapping_add(self.get_reg(index, reg_size).wrapping_mul(scale));
            }

            // Handle displacement for mod != 0
            match mod_bits {
                1 => {
                    let disp = ctx.consume_u8()? as i8 as i64;
                    addr = (addr as i64).wrapping_add(disp) as u64;
                }
                2 => {
                    let disp = ctx.consume_u32()? as i32 as i64;
                    addr = (addr as i64).wrapping_add(disp) as u64;
                }
                _ => {}
            }
        } else if rm_field == 5 && mod_bits == 0 {
            // RIP-relative addressing (64-bit mode)
            let disp = ctx.consume_u32()? as i32 as i64;
            let rip_after = self.regs.rip as i64 + ctx.cursor as i64;
            addr = rip_after.wrapping_add(disp) as u64;
        } else {
            // Regular register indirect
            default_ss = Self::modrm_base_defaults_to_ss(rm);
            addr = self.get_reg(rm, reg_size);

            // Handle displacement
            match mod_bits {
                1 => {
                    let disp = ctx.consume_u8()? as i8 as i64;
                    addr = (addr as i64).wrapping_add(disp) as u64;
                }
                2 => {
                    let disp = ctx.consume_u32()? as i32 as i64;
                    addr = (addr as i64).wrapping_add(disp) as u64;
                }
                _ => {}
            }
        }

        if addr_size_32 {
            addr &= 0xFFFF_FFFF;
        }

        // Apply segment override (in 64-bit mode, only FS and GS have non-zero bases)
        let seg_base = self.get_segment_base_with_default(ctx.segment_override, default_ss);
        addr = addr.wrapping_add(seg_base);

        Ok(addr)
    }
}
