//! opcode_maps.rs

use crate::smir::lift::x86_64::*;
use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::memory::MemoryError;
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86AluEncoding, X86BlsKind, X86CacheControlKind,
    X86CacheMaintenanceKind, X86CountKind, X86FastSystemTransferKind, X86FastSystemTransferOp,
    X86MsrOp, X86OpHint, X86RepMode, X86SsePrefix, X86StringKind, X86ThreeDNowKind, X86VecAlign,
    X86VecMap, X86X87ArithmeticDestination, X86X87ArithmeticSource, X86X87CompareSource,
    X86X87Constant, X86X87ControlKind, X86X87DataKind, X86X87EnvWidth, X86X87FloatWidth,
    X86X87IntWidth, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
    X86InstructionBytes,
};
use crate::smir::lift::{
    ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter,
};

impl X86_64Lifter {
    /// Lift 0F 38-prefixed (three-byte) opcodes
    pub(crate) fn lift_0f38_opcode(
        &self,
        bytes: &[u8],
        prefix: &X86Prefix,
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::Incomplete {
                addr: pc,
                have: prefix.cursor,
                need: prefix.cursor + 1,
            });
        }

        let opcode3 = bytes[0];
        let after_opcode = &bytes[1..];
        let prefix3 = X86Prefix {
            cursor: prefix.cursor + 1,
            ..prefix.clone()
        };
        match opcode3 {
            0x00 => self.lift_sse_pshufb(after_opcode, &prefix3, pc, ctx),
            0x01..=0x03 | 0x05..=0x07 => {
                self.lift_sse_horizontal_integer(opcode3, after_opcode, &prefix3, pc, ctx)
            }
            0x04 => self.lift_sse_pmaddubsw(after_opcode, &prefix3, pc, ctx),
            0x08..=0x0A => self.lift_sse_psign(opcode3, after_opcode, &prefix3, pc, ctx),
            0x0B => self.lift_sse_pmulhrsw(after_opcode, &prefix3, pc, ctx),
            0x10 | 0x14 | 0x15 => {
                self.lift_sse_variable_blend(opcode3, after_opcode, &prefix3, pc, ctx)
            }
            0x17 => self.lift_sse_ptest(after_opcode, &prefix3, pc, ctx),
            0x1C..=0x1E => self.lift_sse_pabs(opcode3, after_opcode, &prefix3, pc, ctx),
            0x20..=0x25 | 0x30..=0x35 => {
                self.lift_sse_packed_extend(opcode3, after_opcode, &prefix3, pc, ctx)
            }
            0x28 => self.lift_sse_pmuldq(after_opcode, &prefix3, true, pc, ctx),
            0x2A => self.lift_sse_movntdqa(after_opcode, &prefix3, pc, ctx),
            0x2B => self.lift_sse_integer_pack(opcode3, after_opcode, &prefix3, pc, ctx),
            0x29 | 0x37 => self.lift_sse_integer_compare(opcode3, after_opcode, &prefix3, pc, ctx),
            0x38..=0x3F => self.lift_sse_packed_minmax(opcode3, after_opcode, &prefix3, pc, ctx),
            0x40 => self.lift_sse_pmulld(after_opcode, &prefix3, pc, ctx),
            0x41 => self.lift_sse_phminposuw(after_opcode, &prefix3, pc, ctx),
            0xC8..=0xCD => self.lift_sse_sha32(opcode3, after_opcode, &prefix3, false, pc, ctx),
            0xCF => self.lift_sse_gfni(opcode3, after_opcode, &prefix3, false, pc, ctx),
            // F3 selects Intel Key Locker at these map cells, even with a
            // redundant 66 prefix. The fixed guest profile clears
            // CPUID.07H:ECX.KL[23], making #UD decisive at the opcode frontier
            // before ModR/M decode or operand observation.
            0xD8 | 0xDC..=0xDF | 0xFA | 0xFB if prefix3.rep_prefix == Some(0xF3) => {
                Ok(LiftResult {
                    ops: Vec::new(),
                    bytes_consumed: prefix3.cursor,
                    control_flow: ControlFlow::Trap {
                        kind: TrapKind::InvalidOpcode,
                    },
                    branch_targets: Vec::new(),
                })
            }
            0xDB..=0xDF => self.lift_sse_aes_round(opcode3, after_opcode, &prefix3, pc, ctx),
            0x8A | 0x8B => self.lift_movrs_0f38(opcode3, after_opcode, &prefix3, pc, ctx),
            0x82 => self.lift_invpcid_0f38(after_opcode, &prefix3, pc, ctx),
            // Without a mandatory F3 or 66 prefix, this map cell selects
            // WRSSD/WRSSQ rather than ADX. The fixed guest profile clears
            // CPUID.07H:ECX.CET_SS[7], making #UD decisive at the opcode
            // frontier before ModR/M decode or operand observation.
            0xF6 if prefix3.rep_prefix.is_none() && !prefix3.operand_size_override => {
                Ok(LiftResult {
                    ops: Vec::new(),
                    bytes_consumed: prefix3.cursor,
                    control_flow: ControlFlow::Trap {
                        kind: TrapKind::InvalidOpcode,
                    },
                    branch_targets: Vec::new(),
                })
            }
            0xF6 => self.lift_adx_0f38(after_opcode, &prefix3, pc, ctx),
            0xF0 | 0xF1 if prefix3.rep_prefix == Some(0xF2) => {
                self.lift_crc32_0f38(opcode3, after_opcode, &prefix3, pc, ctx)
            }
            0xF0 | 0xF1 => self.lift_movbe_0f38(opcode3, after_opcode, &prefix3, pc, ctx),
            0xF8 => self.lift_movdir64b_0f38(after_opcode, &prefix3, pc, ctx),
            0xF9 => self.lift_movdiri_0f38(after_opcode, &prefix3, pc, ctx),
            0xFC => self.lift_rao_int_0f38(after_opcode, &prefix3, pc, ctx),
            // Intel SDM Vol. 2 classifies the remaining cells as unassigned,
            // VEX/EVEX-only, or legacy features outside RAX's fixed CPUID
            // profile. The direct decoder therefore raises #UD immediately
            // after the map opcode, without fetching a ModR/M or immediate.
            _ => Ok(LiftResult {
                ops: Vec::new(),
                bytes_consumed: prefix3.cursor,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: Vec::new(),
            }),
        }
    }

    pub(crate) fn lift_0f3a_opcode(
        &self,
        bytes: &[u8],
        prefix: &X86Prefix,
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::Incomplete {
                addr: pc,
                have: prefix.cursor,
                need: prefix.cursor + 1,
            });
        }
        let opcode = bytes[0];
        let after_opcode = &bytes[1..];
        let prefix3 = X86Prefix {
            cursor: prefix.cursor + 1,
            ..prefix.clone()
        };
        match opcode {
            0x08..=0x0B => self.lift_sse_round(opcode, after_opcode, &prefix3, pc, ctx),
            0x0C..=0x0E => self.lift_sse_immediate_blend(opcode, after_opcode, &prefix3, pc, ctx),
            0x0F => self.lift_sse_palignr(after_opcode, &prefix3, pc, ctx),
            0x14..=0x17 => self.lift_sse_extract_0f3a(opcode, after_opcode, &prefix3, pc, ctx),
            0x20..=0x22 => self.lift_sse_insert_0f3a(opcode, after_opcode, &prefix3, pc, ctx),
            0x40 | 0x41 => self.lift_sse_dot_product(opcode, after_opcode, &prefix3, pc, ctx),
            0x42 => self.lift_sse_mpsadbw(after_opcode, &prefix3, pc, ctx),
            0x44 => self.lift_sse_pclmulqdq(after_opcode, &prefix3, pc, ctx),
            0x60..=0x63 => self.lift_sse_pcmpxstrx(opcode, after_opcode, &prefix3, pc, ctx),
            0xCC => self.lift_sse_sha32(opcode, after_opcode, &prefix3, true, pc, ctx),
            0xCE | 0xCF => self.lift_sse_gfni(opcode, after_opcode, &prefix3, true, pc, ctx),
            0xDF => self.lift_sse_aes_keygen(after_opcode, &prefix3, pc, ctx),
            // Intel SDM Vol. 2 assigns every legacy 0F 3A form handled above.
            // Other assigned cells require VEX or EVEX, so their legacy
            // spellings and all unassigned cells raise #UD after the map
            // opcode without fetching a ModR/M or immediate byte.
            _ => Ok(LiftResult {
                ops: Vec::new(),
                bytes_consumed: prefix3.cursor,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: Vec::new(),
            }),
        }
    }

    pub(crate) fn lift_prefixed_vec(
        &self,
        pc: u64,
        bytes: &[u8],
        legacy: &X86Prefix,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        // Intel SDM Vol. 2A sections 2.3.2-2.3.4 require #UD when LOCK,
        // 66H/F2H/F3H, or REX precedes VEX. EVEX and APX extended EVEX retain
        // the same prefix-order contract. The violation is decisive as soon as
        // the vector lead byte is present: do not demand any VEX/EVEX payload,
        // opcode, ModR/M, or immediate bytes before establishing the trap.
        // Address-size and segment overrides remain admissible.
        let has_forbidden_legacy_prefix = bytes[..legacy.cursor]
            .iter()
            .any(|byte| !matches!(byte, 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x67));
        if has_forbidden_legacy_prefix
            || legacy.rex.is_some()
            || legacy.rex2.is_some()
            || legacy.lock
            || legacy.operand_size_override
            || legacy.rep_prefix.is_some()
        {
            return Ok(LiftResult {
                ops: Vec::new(),
                bytes_consumed: legacy.cursor + 1,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: Vec::new(),
            });
        }

        // Extended EVEX retains ordinary EVEX prefix ordering, so 67H and
        // segment overrides are legal before an APX MAP4 instruction.  Route
        // MAP4 before the vector decoder rejects the previously reserved map;
        // the APX decoder below preserves both effective-address attributes.
        if bytes.get(legacy.cursor) == Some(&0x62)
            && bytes
                .get(legacy.cursor + 1)
                .is_some_and(|p0| p0 & 0x07 == 4)
        {
            return self.lift_apx_evex_map4(pc, bytes, ctx);
        }

        let decoded = (match bytes.get(legacy.cursor) {
            Some(0x62) => decode_evex_prefix(&bytes[legacy.cursor..], pc),
            _ => decode_vex_prefix(&bytes[legacy.cursor..], pc),
        })
        .map_err(|error| match error {
            LiftError::Incomplete { addr, have, need } => LiftError::Incomplete {
                addr,
                have: legacy.cursor + have,
                need: legacy.cursor + need,
            },
            error => error,
        })?;
        let mut prefix = match decoded {
            VecPrefixDecode::Prefix(prefix) => prefix,
            VecPrefixDecode::InvalidOpcode { bytes_consumed } => {
                return Ok(LiftResult {
                    ops: Vec::new(),
                    bytes_consumed: legacy.cursor + bytes_consumed,
                    control_flow: ControlFlow::Trap {
                        kind: TrapKind::InvalidOpcode,
                    },
                    branch_targets: Vec::new(),
                });
            }
        };
        prefix.bytes += legacy.cursor;
        prefix.address_size_override = legacy.address_size_override;
        prefix.segment_override = legacy.segment_override;
        self.lift_vec_opcode(prefix, bytes, pc, ctx)
    }

    /// Lift every architecturally defined 3DNow! suffix-selected
    /// `0F 0F /r imm8` form. PAVGUSB and PSWAPD reuse generic packed-integer
    /// operations; the remaining operations use the atomic 3DNow! IR family.
    pub(crate) fn lift_3dnow(
        &self,
        bytes: &[u8],
        prefix: &X86Prefix,
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.lock || prefix.rex2.is_some() {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let modrm = decode_modrm(bytes, prefix, pc)?;
        let suffix_offset = modrm.bytes_consumed;
        let Some(&suffix) = bytes.get(suffix_offset) else {
            return Err(LiftError::Incomplete {
                addr: pc,
                have: prefix.cursor + suffix_offset,
                need: prefix.cursor + suffix_offset + 1,
            });
        };
        let bytes_consumed = prefix.cursor + modrm.bytes_consumed + 1;
        let three_d_now_kind = match suffix {
            0x0C => Some(X86ThreeDNowKind::Pi2Fw),
            0x0D => Some(X86ThreeDNowKind::Pi2Fd),
            0x1C => Some(X86ThreeDNowKind::Pf2Iw),
            0x1D => Some(X86ThreeDNowKind::Pf2Id),
            0x8A => Some(X86ThreeDNowKind::PfNAcc),
            0x8E => Some(X86ThreeDNowKind::PfPNAcc),
            0x90 => Some(X86ThreeDNowKind::PfCmpGe),
            0x94 => Some(X86ThreeDNowKind::PfMin),
            0x96 => Some(X86ThreeDNowKind::PfRcp),
            0x97 => Some(X86ThreeDNowKind::PfRsqrt),
            0x9A => Some(X86ThreeDNowKind::PfSub),
            0x9E => Some(X86ThreeDNowKind::PfAdd),
            0xA0 => Some(X86ThreeDNowKind::PfCmpGt),
            0xA4 => Some(X86ThreeDNowKind::PfMax),
            0xA6 => Some(X86ThreeDNowKind::PfRcpIt1),
            0xA7 => Some(X86ThreeDNowKind::PfRsqIt1),
            0xAA => Some(X86ThreeDNowKind::PfSubR),
            0xAE => Some(X86ThreeDNowKind::PfAcc),
            0xB0 => Some(X86ThreeDNowKind::PfCmpEq),
            0xB4 => Some(X86ThreeDNowKind::PfMul),
            0xB6 => Some(X86ThreeDNowKind::PfRcpIt2),
            0xB7 => Some(X86ThreeDNowKind::PmulHrw),
            0xBB | 0xBF => None,
            _ => {
                // AMD APM volume 3 revision 3.37 section A.1.2 leaves these
                // suffixes implementation-specific and explicitly permits an
                // invalid-opcode exception. RAX's configured direct profile
                // rejects 0F 0F, so expose that deterministic terminal result
                // after decoding the complete suffix-selected instruction.
                return Ok(LiftResult {
                    ops: Vec::new(),
                    bytes_consumed,
                    control_flow: ControlFlow::Trap {
                        kind: TrapKind::InvalidOpcode,
                    },
                    branch_targets: Vec::new(),
                });
            }
        };
        let next_pc = pc + bytes_consumed as u64;
        let mut ops = Vec::new();
        let src = if modrm.is_memory {
            let (addr, pre_ops) = self.x86_addr_to_smir(modrm.addr.as_ref().unwrap(), next_pc, ctx);
            ops.extend(pre_ops);
            let loaded = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VLoad {
                    dst: loaded,
                    addr,
                    width: VecWidth::V64,
                },
            ));
            loaded
        } else {
            // 3DNow! has only the eight legacy MM registers. REX.R/REX.B do
            // not extend either register field.
            self.mm(modrm.rm & 7)
        };
        let dst = self.mm(modrm.reg & 7);
        let kind = match suffix {
            0xBB => OpKind::X86PackedShuffleImm {
                dst,
                src,
                width: VecWidth::V64,
                elem: VecElementType::I32,
                imm: 0x01,
                high_words: None,
            },
            0xBF => {
                Self::packed_unsigned_average_kind(dst, dst, src, VecWidth::V64, VecElementType::I8)
            }
            _ => OpKind::X86ThreeDNow {
                dst,
                src1: dst,
                src2: src,
                kind: three_d_now_kind.expect("defined non-generic 3DNow! suffix"),
            },
        };
        ops.push(SmirOp::new(OpId(ops.len() as u16), pc, kind));
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::X86X87Control {
                kind: X86X87ControlKind::EnterMmx,
                addr: None,
            },
        ));
        Ok(LiftResult::fallthrough(ops, bytes_consumed))
    }

    /// Lift 0F-prefixed (two-byte) opcodes
    pub(crate) fn lift_0f_opcode(
        &self,
        bytes: &[u8],
        prefix: &X86Prefix,
        pc: u64,
        ctx: &mut LiftContext,
        map_len: usize,
    ) -> Result<LiftResult, LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::Incomplete {
                addr: pc,
                have: prefix.cursor + map_len.saturating_sub(1),
                need: prefix.cursor + map_len,
            });
        }

        let opcode2 = bytes[0];
        let after_opcode = &bytes[1..];
        let prefix2 = X86Prefix {
            cursor: prefix.cursor + map_len,
            ..prefix.clone()
        };

        match opcode2 {
            0x00 => {
                let Some(modrm) = after_opcode.first() else {
                    return Err(LiftError::Incomplete {
                        addr: pc,
                        have: prefix2.cursor,
                        need: prefix2.cursor + 1,
                    });
                };
                match (modrm >> 3) & 7 {
                    0 | 1 => self.lift_system_selector_store_0f00(after_opcode, &prefix2, pc, ctx),
                    2 | 3 => self.lift_system_selector_load_0f00(after_opcode, &prefix2, pc, ctx),
                    4 | 5 => self.lift_selector_verify_0f00(after_opcode, &prefix2, pc, ctx),
                    6 | 7 => Ok(LiftResult {
                        ops: vec![],
                        bytes_consumed: prefix2.cursor + 1,
                        control_flow: ControlFlow::Trap {
                            kind: TrapKind::InvalidOpcode,
                        },
                        branch_targets: vec![],
                    }),
                    _ => unreachable!("three-bit Group-6 selector changed"),
                }
            }
            0x01 => self.lift_group7_0f01(after_opcode, &prefix2, pc, ctx),
            0x02 | 0x03 => self.lift_selector_query_0f(opcode2, after_opcode, &prefix2, pc, ctx),

            // These blank cells are reserved in both the Intel and AMD
            // legacy map-1 opcode tables. They have no operand encoding, so
            // terminate at the main opcode and expose the architectural #UD
            // directly instead of forcing an interpreter fallback. Intel APX
            // specifies that an opcode which #UDs without REX2 continues to
            // #UD when REX2.M0 selects this map.
            0x04 | 0x0A | 0x0C => Ok(LiftResult {
                ops: vec![],
                bytes_consumed: prefix2.cursor,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: vec![],
            }),

            // CLTS (0F 06): clear CR0.TS after a dynamic privilege check.
            // Intel specifies only LOCK as an invalid prefix; other legacy and
            // REX prefixes are ignored.
            0x06 => {
                if prefix2.lock {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                Ok(LiftResult::fallthrough(
                    vec![SmirOp::new(OpId(0), pc, OpKind::X86Clts)],
                    prefix2.cursor,
                ))
            }

            // Cache maintenance must retain its potentially faulting privilege
            // check through optimization. F3 0F 09 is the enumerated WBNOINVD.
            0x08 | 0x09 => {
                if prefix2.lock {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                let kind = if opcode2 == 0x08 {
                    X86CacheMaintenanceKind::Invd
                } else if prefix2.rep_prefix == Some(0xf3) {
                    X86CacheMaintenanceKind::Wbnoinvd
                } else {
                    X86CacheMaintenanceKind::Wbinvd
                };
                let mut ops = self.rex2_apx_guard_ops(&prefix2, pc);
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::X86CacheMaintenance {
                        kind,
                        next_pc: pc.wrapping_add(prefix2.cursor as u64),
                    },
                ));
                Ok(LiftResult::fallthrough(ops, prefix2.cursor))
            }

            // 3DNow! uses the final imm8 after ModR/M and any displacement as
            // an opcode suffix.
            0x0F => self.lift_3dnow(after_opcode, &prefix2, pc, ctx),

            // AMD SSE4A low-qword extract/insert forms. Mandatory prefixes
            // distinguish them from Intel VMREAD/VMWRITE, which remain absent
            // from RAX's VMX-disabled profile.
            0x78 | 0x79 => self.lift_sse4a_bitfield(opcode2, after_opcode, &prefix2, pc, ctx),

            // MOV r64, CR0/CR2/CR3/CR4/CR8. ModR/M.mod is architecturally
            // ignored, so its raw-byte decoder lives outside generic ModR/M
            // address handling.
            0x20 => self.lift_read_control_0f20(after_opcode, &prefix2, pc, ctx),

            // MOV CR0/CR2/CR3/CR4/CR8, r64. Successful execution changes
            // native admission/translation state and therefore carries the
            // exact next-instruction handoff PC in its SMIR operation.
            0x22 => self.lift_write_control_0f22(after_opcode, &prefix2, pc, ctx),

            // MOV r64, DR0-DR7. ModR/M.mod is ignored and DR4/DR5 validity is
            // dynamic in CR4.DE, so retain the raw encoded selector.
            0x21 => self.lift_read_debug_0f21(after_opcode, &prefix2, pc, ctx),

            // MOV DR0-DR7, r64. This shares the ignored ModR/M.mod and dynamic
            // DR4/DR5 rules, while the SMIR op retains its serializing write.
            0x23 => self.lift_write_debug_0f23(after_opcode, &prefix2, pc, ctx),

            // EMMS marks every x87/MMX register empty while preserving the
            // aliased payloads. FEMMS performs the same defined tag transition
            // but leaves those payloads architecturally undefined; retaining
            // them is one permitted deterministic outcome.
            0x0E | 0x77 => {
                if prefix2.lock || opcode2 == 0x0E && prefix2.rex2.is_some() {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                Ok(LiftResult::fallthrough(
                    vec![SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::X86X87Control {
                            kind: X86X87ControlKind::EmptyMmx,
                            addr: None,
                        },
                    )],
                    prefix2.cursor,
                ))
            }

            // NOP/cache/prefetch hint encodings still consume a complete
            // ModR/M addressing form even though they have no state effect.
            0x0D | 0x18 | 0x19 | 0x1A | 0x1B | 0x1D | 0x1E | 0x1F => {
                // LOCK is invalid for every hint/NOP encoding in this branch.
                // Expose #UD without requiring an otherwise-unused ModR/M or
                // address byte, matching the direct decoder's prefix-legality
                // frontier.
                if prefix2.lock {
                    return Ok(LiftResult {
                        ops: vec![],
                        bytes_consumed: prefix2.cursor,
                        control_flow: ControlFlow::Trap {
                            kind: TrapKind::InvalidOpcode,
                        },
                        branch_targets: vec![],
                    });
                }
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                // F3 0F 1E /1, mod=11 is RDSSPD/RDSSPQ. With CET_SS not
                // enumerated it is architecturally a destination-preserving
                // NOP, so it remains in this no-op path alongside ENDBR/hints.
                let ops = self.rex2_apx_guard_ops(&prefix2, pc);
                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // CLDEMOTE m8 (0F 1C /0). It is an architectural hint with no
            // memory-address exceptions; register forms and nonzero ModR/M.reg
            // encodings are observed fallthrough hints on supported silicon.
            0x1C => {
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                if prefix2.lock {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: after_opcode[..modrm.bytes_consumed.min(after_opcode.len())]
                            .to_vec(),
                    });
                }
                if modrm.is_memory && ((modrm.byte >> 3) & 7) == 0 {
                    let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;
                    let (addr, pre_ops) =
                        self.x86_addr_to_smir(modrm.addr.as_ref().unwrap(), next_pc, ctx);
                    let mut ops = self.rex2_apx_guard_ops(&prefix2, pc);
                    for mut op in pre_ops {
                        op.id = OpId(ops.len() as u16);
                        ops.push(op);
                    }
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::X86CacheControl {
                            addr,
                            kind: X86CacheControlKind::Cldemote,
                        },
                    ));
                    Ok(LiftResult::fallthrough(
                        ops,
                        prefix2.cursor + modrm.bytes_consumed,
                    ))
                } else {
                    Ok(LiftResult::fallthrough(
                        self.rex2_apx_guard_ops(&prefix2, pc),
                        prefix2.cursor + modrm.bytes_consumed,
                    ))
                }
            }

            // Jcc rel32 (0F 80 - 0F 8F)
            0x80..=0x8F => {
                if after_opcode.len() < 4 {
                    return Err(LiftError::Incomplete {
                        addr: pc,
                        have: prefix2.cursor + after_opcode.len(),
                        need: prefix2.cursor + 4,
                    });
                }

                let cc = opcode2 & 0x0F;
                let cond = self.x86_cond(cc);
                let rel = i32::from_le_bytes([
                    after_opcode[0],
                    after_opcode[1],
                    after_opcode[2],
                    after_opcode[3],
                ]) as i64;

                let insn_len = prefix2.cursor + 4;
                let next_pc = pc + insn_len as u64;
                let target = (next_pc as i64 + rel) as u64;

                Ok(LiftResult::cond_branch(
                    vec![],
                    insn_len,
                    cond,
                    target,
                    next_pc,
                ))
            }

            // SETcc (0F 90 - 0F 9F)
            0x90..=0x9F => {
                let cc = opcode2 & 0x0F;
                let cond = self.x86_cond(cc);

                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                let mut ops = Vec::new();
                let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;

                if modrm.is_memory {
                    let x86_addr = modrm.addr.as_ref().unwrap();
                    let (addr, pre_ops) = self.x86_addr_to_smir(x86_addr, next_pc, ctx);
                    ops.extend(pre_ops);

                    let tmp = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::SetCC {
                            dst: tmp,
                            cond,
                            width: OpWidth::W8,
                        },
                    ));
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Store {
                            src: tmp,
                            addr,
                            width: MemWidth::B1,
                        },
                    ));
                } else {
                    let high_dst = self.high_byte_base(modrm.rm, &prefix2);
                    let dst = if high_dst.is_some() {
                        ctx.alloc_vreg()
                    } else {
                        self.gpr(modrm.rm)
                    };
                    ops.push(SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::SetCC {
                            dst,
                            cond,
                            width: OpWidth::W8,
                        },
                    ));
                    if let Some(base) = high_dst {
                        self.merge_high_byte(base, dst, pc, ctx, &mut ops);
                    }
                }

                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // CMOVcc (0F 40 - 0F 4F)
            0x40..=0x4F => {
                let cc = opcode2 & 0x0F;
                let cond = self.x86_cond(cc);
                let op_size = prefix.op_size();
                let width = self.size_to_width(op_size);

                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                let mut ops = Vec::new();
                let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;

                let src = if modrm.is_memory {
                    let x86_addr = modrm.addr.as_ref().unwrap();
                    let (addr, pre_ops) = self.x86_addr_to_smir(x86_addr, next_pc, ctx);
                    ops.extend(pre_ops);

                    let tmp = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: tmp,
                            addr,
                            width: self.size_to_memwidth(op_size),
                            sign: SignExtend::Zero,
                        },
                    ));
                    tmp
                } else {
                    self.gpr(modrm.rm)
                };

                let dst = self.gpr(modrm.reg);
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::CMove {
                        dst,
                        src,
                        cond,
                        width,
                    },
                ));
                // IA-32e clears the upper half even when CMOVcc keeps the low half.
                if width == OpWidth::W32 {
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::ZeroExtend {
                            dst,
                            src: dst,
                            from_width: OpWidth::W32,
                            to_width: OpWidth::W64,
                        },
                    ));
                }

                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // Packed immediate dword/high-word/low-word shuffles.
            0x70 => self.lift_sse_packed_shuffle_imm(after_opcode, &prefix2, pc, ctx),
            0x5B | 0xE6 => {
                self.lift_sse_packed_int_fp_convert(opcode2, after_opcode, &prefix2, pc, ctx)
            }
            0x52 | 0x53 => self.lift_sse_fp_estimate(opcode2, after_opcode, &prefix2, pc, ctx),
            0x14 | 0x15 => self.lift_sse_fp_unpack(opcode2, after_opcode, &prefix2, pc, ctx),
            0x12 | 0x13 | 0x16 | 0x17 if prefix2.rep_prefix.is_none() => {
                self.lift_sse_half_move(opcode2, after_opcode, &prefix2, pc, ctx)
            }
            0x2B if prefix2.rep_prefix.is_some() => {
                self.lift_sse4a_movnt_store(after_opcode, &prefix2, pc, ctx)
            }
            0x2B | 0xE7 => self.lift_sse_movnt(opcode2, after_opcode, &prefix2, pc, ctx),
            0xC2 => self.lift_sse_fp_compare(after_opcode, &prefix2, pc, ctx),
            0xC6 => self.lift_sse_two_source_shuffle_imm(after_opcode, &prefix2, pc, ctx),
            0x12 | 0x16 if prefix2.rep_prefix == Some(0xF3) => {
                self.lift_sse_duplicate_move(opcode2, after_opcode, &prefix2, pc, ctx)
            }
            0x12 if prefix2.rep_prefix == Some(0xF2) => {
                self.lift_sse_duplicate_move(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Prefix-free MMX MOVQ and packed legacy SSE/SSE2 moves.
            0x10 | 0x11 | 0x28 | 0x29 | 0x6F | 0x7F => {
                self.lift_sse_mov(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Scalar MOVQ vector load/store forms.
            0x7E if prefix2.rep_prefix == Some(0xF3) => {
                self.lift_sse_movq_vec(opcode2, after_opcode, &prefix2, pc, ctx)
            }
            0xD6 if matches!(prefix2.rep_prefix, Some(0xF2 | 0xF3)) => {
                self.lift_sse_mmx_xmm_transfer(after_opcode, &prefix2, pc, ctx)
            }
            0xD6 if prefix2.operand_size_override => {
                self.lift_sse_movq_vec(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // MOVD/MOVQ between XMM or MMX and GPR/memory operands.
            0x6E | 0x7E => self.lift_sse_movd_q(opcode2, after_opcode, &prefix2, pc, ctx),

            // MOVMSKPS/MOVMSKPD sign-bit extraction.
            0x50 => self.lift_sse_movmask(after_opcode, &prefix2, pc, ctx),

            // PMOVMSKB byte sign-bit extraction. Prefix-free forms target MMX.
            0xD7 => self.lift_sse_pmovmskb(after_opcode, &prefix2, pc, ctx),

            // Packed low-word multiply. Prefix-free forms target MMX.
            0xD5 => self.lift_sse_pmullw(after_opcode, &prefix2, pc, ctx),

            // Packed signed/unsigned high-word multiply. Prefix-free forms target MMX.
            0xE4 | 0xE5 => self.lift_sse_pmul_high_word(opcode2, after_opcode, &prefix2, pc, ctx),

            // Packed rounded unsigned averages. Prefix-free forms target MMX.
            0xE0 | 0xE3 => self.lift_sse_packed_average(opcode2, after_opcode, &prefix2, pc, ctx),

            // Original packed unsigned-byte and signed-word min/max forms.
            // Prefix-free encodings target MMX state.
            0xDA | 0xDE | 0xEA | 0xEE => {
                self.lift_sse_packed_minmax(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Packed unsigned dword-to-qword multiply. Prefix-free forms target MMX.
            0xF4 => self.lift_sse_pmuldq(after_opcode, &prefix2, false, pc, ctx),

            // Pairwise signed-word multiply-add. Prefix-free forms target MMX.
            0xF5 => self.lift_sse_pmaddwd(after_opcode, &prefix2, pc, ctx),

            // SSE3 alternating and horizontal packed floating-point arithmetic.
            0x7C | 0x7D | 0xD0 => {
                self.lift_sse_addsub_horizontal(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Byte-selective store through the implicit DS:(E)DI/RDI address.
            // Prefix-free forms target MMX state.
            0xF7 => self.lift_sse_maskmovdqu(after_opcode, &prefix2, pc, ctx),

            // Packed shifts by the low 64 bits of an XMM/m128 count source.
            // Prefix-free forms target MMX state.
            0xD1..=0xD3 | 0xE1 | 0xE2 | 0xF1..=0xF3 => {
                self.lift_sse_packed_shift_count(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Packed element and 128-bit-lane shifts by an immediate count.
            // Prefix-free forms target MMX state.
            0x71..=0x73 => self.lift_sse_packed_shift_imm(opcode2, after_opcode, &prefix2, pc, ctx),

            // MOVNTI non-temporal scalar GPR store.
            0xC3 => self.lift_movnti(after_opcode, &prefix2, pc, ctx),

            // LDDQU unaligned 128-bit integer load.
            0xF0 => self.lift_sse_lddqu(after_opcode, &prefix2, pc, ctx),

            // MMX/XMM packed-integer logical operations.
            0xDB | 0xDF | 0xEB | 0xEF => {
                self.lift_sse_integer_logic(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Packed integer equality and signed greater-than comparisons.
            0x64 | 0x65 | 0x66 | 0x74 | 0x75 | 0x76 => {
                self.lift_sse_integer_compare(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Packed integer low/high interleaves.
            0x60 | 0x61 | 0x62 | 0x68 | 0x69 | 0x6A | 0x6C | 0x6D => {
                self.lift_sse_integer_unpack(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // XMM signed/unsigned saturating packs. Prefix-free forms target MMX.
            0x63 | 0x67 | 0x6B => {
                self.lift_sse_integer_pack(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Packed sums of absolute byte differences. Prefix-free forms
            // target MMX state.
            0xF6 => self.lift_sse_psadbw(after_opcode, &prefix2, pc, ctx),

            // Scalar ordered/unordered FP compare setting integer flags.
            0x2E | 0x2F => self.lift_sse_comi(opcode2, after_opcode, &prefix2, pc, ctx),

            // Scalar FP-to-signed-integer conversions.
            // Legacy MMX/SSE conversion forms use no mandatory repeat prefix;
            // 66H selects the packed-double variant. F2H/F3H retain the
            // scalar XMM-to-GPR conversion family below.
            0x2A | 0x2C | 0x2D if prefix2.rep_prefix.is_none() => {
                self.lift_sse_mmx_fp_convert(opcode2, after_opcode, &prefix2, pc, ctx)
            }
            0x2C | 0x2D => self.lift_sse_fp_to_int(opcode2, after_opcode, &prefix2, pc, ctx),

            // Scalar signed-integer-to-FP conversions.
            0x2A => self.lift_sse_int_to_fp(after_opcode, &prefix2, pc, ctx),

            // Packed legacy SSE/SSE2 floating-point arithmetic.
            0x58 | 0x59 | 0x5C | 0x5D | 0x5E | 0x5F => {
                self.lift_sse_packed_arith(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // Scalar single/double precision conversion.
            0x5A => self.lift_sse_scalar_fp_convert(after_opcode, &prefix2, pc, ctx),

            // Packed and scalar SQRTPS/SQRTPD/SQRTSS/SQRTSD.
            0x51 => self.lift_sse_sqrt(after_opcode, &prefix2, pc, ctx),

            // Packed legacy SSE/SSE2 bitwise logic.
            0x54 | 0x55 | 0x56 | 0x57 => {
                self.lift_sse_logic(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // XMM wrapping and saturating packed integer add/subtract.
            0xD4 | 0xD8 | 0xD9 | 0xDC | 0xDD | 0xE8 | 0xE9 | 0xEC | 0xED | 0xF8 | 0xF9 | 0xFA
            | 0xFB | 0xFC | 0xFD | 0xFE => {
                self.lift_sse_packed_add_sub(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // SSE4.1 opcodes (0F 38)
            0x38 if prefix2.rex2_m() => Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            }),
            0x38 => self.lift_0f38_opcode(after_opcode, &prefix2, pc, ctx),
            0x3A if prefix2.rex2_m() => Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            }),
            0x3A => self.lift_0f3a_opcode(after_opcode, &prefix2, pc, ctx),

            // SHLD/SHRD (0F A4/A5/AC/AD)
            0xA4 | 0xA5 | 0xAC | 0xAD => {
                self.lift_shld_shrd(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // BT/BTS/BTR/BTC register-index and immediate Group-8 forms.
            0xA3 | 0xAB | 0xB3 | 0xBB => {
                self.lift_bit_test_reg(opcode2, after_opcode, &prefix2, pc, ctx)
            }
            0xBA => self.lift_bit_test_imm(after_opcode, &prefix2, pc, ctx),

            // LFENCE/MFENCE/SFENCE (0F AE /5,/6,/7 register encodings).
            0xAE => self.lift_fence_0f(after_opcode, &prefix2, pc, ctx),

            // CMPXCHG r/m, r (0F B0/0F B1)
            0xB0 | 0xB1 => self.lift_cmpxchg(opcode2, after_opcode, &prefix2, pc, ctx),

            // XADD r/m, r (0F C0/0F C1)
            0xC0 | 0xC1 => self.lift_xadd(opcode2, after_opcode, &prefix2, pc, ctx),

            // SSE2 word insert/extract forms. Prefix-free encodings target MMX.
            0xC4 | 0xC5 => self.lift_sse_pinsrw_pextrw(opcode2, after_opcode, &prefix2, pc, ctx),

            // Group 9 CMPXCHG, compacted XSAVE, random, and RDPID forms.
            0xC7 => self.lift_xsave_group9_0fc7(after_opcode, &prefix2, pc, ctx),

            // BSWAP r32/r64 (0F C8+rd)
            0xC8..=0xCF => self.lift_bswap_opcode(opcode2, &prefix2, pc),

            // MOVZX r, r/m8 (0F B6)
            0xB6 => {
                let op_size = prefix.op_size();
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                let mut ops = Vec::new();
                let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;
                let src_is_rex_byte_reg = !modrm.is_memory && prefix2.has_rex();
                let src_is_legacy_high_byte =
                    !modrm.is_memory && !prefix2.has_rex() && (4..=7).contains(&(modrm.rm & 7));

                let src = if modrm.is_memory {
                    let x86_addr = modrm.addr.as_ref().unwrap();
                    let (addr, pre_ops) = self.x86_addr_to_smir(x86_addr, next_pc, ctx);
                    ops.extend(pre_ops);

                    let tmp = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: tmp,
                            addr,
                            width: MemWidth::B1,
                            sign: SignExtend::Zero,
                        },
                    ));
                    tmp
                } else if src_is_legacy_high_byte {
                    self.gpr((modrm.rm & 7) - 4)
                } else {
                    self.gpr(modrm.rm)
                };

                let mut op = SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::ZeroExtend {
                        dst: self.gpr(modrm.reg),
                        src,
                        from_width: OpWidth::W8,
                        to_width: self.size_to_width(op_size),
                    },
                );
                if src_is_rex_byte_reg {
                    op.x86_hint = Some(X86OpHint::RexByteReg);
                } else if src_is_legacy_high_byte {
                    op.x86_hint = Some(X86OpHint::LegacyHighByteReg);
                }
                ops.push(op);

                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // MOVZX r, r/m16 (0F B7)
            0xB7 => {
                let op_size = prefix.op_size();
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                let mut ops = Vec::new();
                let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;

                let src = if modrm.is_memory {
                    let x86_addr = modrm.addr.as_ref().unwrap();
                    let (addr, pre_ops) = self.x86_addr_to_smir(x86_addr, next_pc, ctx);
                    ops.extend(pre_ops);

                    let tmp = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: tmp,
                            addr,
                            width: MemWidth::B2,
                            sign: SignExtend::Zero,
                        },
                    ));
                    tmp
                } else {
                    self.gpr(modrm.rm)
                };

                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::ZeroExtend {
                        dst: self.gpr(modrm.reg),
                        src,
                        from_width: OpWidth::W16,
                        to_width: self.size_to_width(op_size),
                    },
                ));

                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // POPCNT/TZCNT/LZCNT (mandatory F3 prefix).
            0xB8 | 0xBC | 0xBD if prefix2.rep_prefix == Some(0xF3) => {
                self.lift_count_0f(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // BSF/BSR (0F BC/0F BD without F3)
            0xBC | 0xBD => self.lift_bsf_bsr(opcode2, after_opcode, &prefix2, pc, ctx),

            // MOVSX r, r/m8 (0F BE)
            0xBE => {
                let op_size = prefix.op_size();
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                let mut ops = Vec::new();
                let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;
                let src_is_rex_byte_reg = !modrm.is_memory && prefix2.has_rex();
                let src_is_legacy_high_byte =
                    !modrm.is_memory && !prefix2.has_rex() && (4..=7).contains(&(modrm.rm & 7));

                let src = if modrm.is_memory {
                    let x86_addr = modrm.addr.as_ref().unwrap();
                    let (addr, pre_ops) = self.x86_addr_to_smir(x86_addr, next_pc, ctx);
                    ops.extend(pre_ops);

                    let tmp = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: tmp,
                            addr,
                            width: MemWidth::B1,
                            sign: SignExtend::Sign,
                        },
                    ));
                    tmp
                } else if src_is_legacy_high_byte {
                    self.gpr((modrm.rm & 7) - 4)
                } else {
                    self.gpr(modrm.rm)
                };

                let mut op = SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::SignExtend {
                        dst: self.gpr(modrm.reg),
                        src,
                        from_width: OpWidth::W8,
                        to_width: self.size_to_width(op_size),
                    },
                );
                if src_is_rex_byte_reg {
                    op.x86_hint = Some(X86OpHint::RexByteReg);
                } else if src_is_legacy_high_byte {
                    op.x86_hint = Some(X86OpHint::LegacyHighByteReg);
                }
                ops.push(op);

                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // MOVSX r, r/m16 (0F BF)
            0xBF => {
                let op_size = prefix.op_size();
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                let mut ops = Vec::new();
                let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;

                let src = if modrm.is_memory {
                    let x86_addr = modrm.addr.as_ref().unwrap();
                    let (addr, pre_ops) = self.x86_addr_to_smir(x86_addr, next_pc, ctx);
                    ops.extend(pre_ops);

                    let tmp = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: tmp,
                            addr,
                            width: MemWidth::B2,
                            sign: SignExtend::Sign,
                        },
                    ));
                    tmp
                } else {
                    self.gpr(modrm.rm)
                };

                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::SignExtend {
                        dst: self.gpr(modrm.reg),
                        src,
                        from_width: OpWidth::W16,
                        to_width: self.size_to_width(op_size),
                    },
                ));

                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // IMUL r, r/m (0F AF)
            0xAF => {
                let op_size = prefix.op_size();
                let width = self.size_to_width(op_size);
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                let mut ops = Vec::new();
                let next_pc = pc + prefix2.cursor as u64 + modrm.bytes_consumed as u64;

                let src = if modrm.is_memory {
                    let x86_addr = modrm.addr.as_ref().unwrap();
                    let (addr, pre_ops) = self.x86_addr_to_smir(x86_addr, next_pc, ctx);
                    ops.extend(pre_ops);

                    let tmp = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: tmp,
                            addr,
                            width: self.size_to_memwidth(op_size),
                            sign: SignExtend::Zero,
                        },
                    ));
                    tmp
                } else {
                    self.gpr(modrm.rm)
                };

                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::MulS {
                        dst_lo: self.gpr(modrm.reg),
                        dst_hi: None,
                        src1: self.gpr(modrm.reg),
                        src2: SrcOperand::Reg(src),
                        width,
                        flags: FlagUpdate::All,
                    },
                ));

                Ok(LiftResult::fallthrough(
                    ops,
                    prefix2.cursor + modrm.bytes_consumed,
                ))
            }

            // SYSCALL (0F 05)
            0x05 => Ok(LiftResult {
                ops: vec![],
                bytes_consumed: prefix2.cursor,
                control_flow: ControlFlow::Syscall,
                branch_targets: vec![],
            }),

            // WRMSR/RDMSR (0F 30/32): ECX selects the MSR and EDX:EAX carries
            // the 64-bit value. LOCK and REX2 are invalid; legacy size/repeat,
            // segment, address-size, and ordinary REX prefixes are ignored.
            0x30 | 0x32 => {
                if prefix2.lock || prefix2.rex2.is_some() {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                Ok(LiftResult::fallthrough(
                    vec![SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::X86Msr(X86MsrOp {
                            eax: self.gpr(0),
                            ecx: self.gpr(1),
                            edx: self.gpr(2),
                            write: opcode2 == 0x30,
                            next_pc: pc.wrapping_add(prefix2.cursor as u64),
                        }),
                    )],
                    prefix2.cursor,
                ))
            }

            // RDTSC (0F 31): EDX:EAX := time-stamp counter.
            0x31 => {
                if prefix2.lock {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                Ok(LiftResult::fallthrough(
                    vec![SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::X86ReadTsc(X86ReadTscOp {
                            dst_lo: self.gpr(0),
                            dst_hi: self.gpr(2),
                            dst_aux: None,
                        }),
                    )],
                    prefix2.cursor,
                ))
            }

            // RDPMC (0F 33): ECX selects a model-specific PMC and EDX:EAX
            // receive its zero-extended value. LOCK and APX REX2 are invalid;
            // other legacy and ordinary REX prefixes are ignored.
            0x33 => {
                if prefix2.lock || prefix2.rex2.is_some() {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                Ok(LiftResult::fallthrough(
                    vec![SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::X86ReadPmc(X86ReadPmcOp {
                            dst_lo: self.gpr(0),
                            dst_hi: self.gpr(2),
                            selector: self.gpr(1),
                        }),
                    )],
                    prefix2.cursor,
                ))
            }

            // Intel SYSENTER/SYSEXIT (0F 34/35). Both instructions own a
            // dynamic terminal control transfer and fixed CS/SS cache update.
            // LOCK is invalid. APX reserves the complete map-1 30H row, so a
            // REX2 form is normally converted to #UD before this dispatcher.
            // Other legacy and ordinary REX prefixes are ignored; only REX.W
            // selects SYSEXIT's 64-bit return form.
            0x34 | 0x35 => {
                if prefix2.lock || prefix2.rex2.is_some() {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                let target = VReg::Arch(ArchReg::X86(X86Reg::Rip));
                let stack_pointer = self.gpr(4);
                let kind = if opcode2 == 0x34 {
                    X86FastSystemTransferKind::Sysenter
                } else {
                    X86FastSystemTransferKind::Sysexit
                };
                Ok(LiftResult {
                    ops: vec![SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::X86FastSystemTransfer(X86FastSystemTransferOp {
                            kind,
                            target,
                            stack_pointer,
                            return_target: self.gpr(2),
                            return_stack_pointer: self.gpr(1),
                            operand64: opcode2 == 0x35 && prefix2.rex_w(),
                            next_pc: pc.wrapping_add(prefix2.cursor as u64),
                        }),
                    )],
                    bytes_consumed: prefix2.cursor,
                    control_flow: ControlFlow::IndirectBranch { target },
                    branch_targets: vec![],
                })
            }

            // CPUID (0F A2): EAX/ECX select the leaf and EAX/EBX/ECX/EDX
            // receive 32-bit zero-extended results. Intel defines only LOCK as
            // invalid; other legacy prefixes are ignored.
            0xA2 => {
                if prefix2.lock {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: vec![opcode2],
                    });
                }
                Ok(LiftResult::fallthrough(
                    vec![SmirOp::new(
                        OpId(0),
                        pc,
                        OpKind::X86Cpuid {
                            dst_eax: self.gpr(0),
                            dst_ebx: self.gpr(3),
                            dst_ecx: self.gpr(1),
                            dst_edx: self.gpr(2),
                            leaf: self.gpr(0),
                            subleaf: self.gpr(1),
                        },
                    )],
                    prefix2.cursor,
                ))
            }

            // PUSH FS/GS (0F A0/A8): selector observation, stack write, and
            // fault-precise RSP commit form one selector-store operation.
            0xA0 | 0xA8 => self.lift_push_segment_0f(opcode2, &prefix2, pc),

            // POP FS/GS (0F A1/A9): the stack read, descriptor transition,
            // selector/cache update, and fault-precise RSP commit are one op.
            0xA1 | 0xA9 => self.lift_pop_segment_0f(opcode2, &prefix2, pc),

            // LSS/LFS/LGS (0F B2/B4/B5): far-pointer memory reads, descriptor
            // effects, segment cache, and paired GPR commit are one atomic op.
            0xB2 | 0xB4 | 0xB5 => {
                self.lift_far_pointer_segment_load_0f(opcode2, after_opcode, &prefix2, pc, ctx)
            }

            // UD2 (0F 0B): architecturally guaranteed invalid opcode trap.
            0x0B => Ok(LiftResult {
                ops: vec![],
                bytes_consumed: prefix2.cursor,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: vec![],
            }),

            // RSM is invalid outside SMM; SMIR exposes no SMM execution state.
            0xAA => Ok(LiftResult {
                ops: vec![],
                bytes_consumed: prefix2.cursor,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: vec![],
            }),

            // UD1 (0F B9 /r) always traps but consumes its ModR/M address form.
            0xB9 => {
                let modrm = decode_modrm(after_opcode, &prefix2, pc)?;
                Ok(LiftResult {
                    ops: vec![],
                    bytes_consumed: prefix2.cursor + modrm.bytes_consumed,
                    control_flow: ControlFlow::Trap {
                        kind: TrapKind::InvalidOpcode,
                    },
                    branch_targets: vec![],
                })
            }

            // UD0 (0F FF /r) always raises #UD. Intel permits processors not
            // to decode its ModR/M byte; the direct emulator uses that profile,
            // so consume only the map opcode and perform no operand fetch.
            0xFF => Ok(LiftResult {
                ops: vec![],
                bytes_consumed: prefix2.cursor,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: vec![],
            }),

            // SYSRET (0F 07)
            0x07 => {
                // Treat as return for lifting purposes
                Ok(LiftResult::ret(vec![], prefix2.cursor))
            }

            // Every architecturally assigned legacy-map encoding admitted by
            // the fixed RAX profile is dispatched above. Remaining cells are
            // unassigned, obsolete test-register encodings, or instructions
            // behind disabled SMX/VMX facilities; all terminate as #UD at the
            // two-byte opcode frontier in both strict and permissive modes.
            _ => Ok(LiftResult {
                ops: vec![],
                bytes_consumed: prefix2.cursor,
                control_flow: ControlFlow::Trap {
                    kind: TrapKind::InvalidOpcode,
                },
                branch_targets: vec![],
            }),
        }
    }
}
