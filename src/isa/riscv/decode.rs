//! RISC-V instruction decoder.
//!
//! [`decode`] resolves a 32-bit instruction word into a fully-populated
//! [`Insn`]; [`decode_compressed`] handles the 16-bit RVC encodings.
//! [`decode_at`] fetches from memory, selecting the width from the low two bits
//! of the first parcel, and is the entry point used by the execution loop.
//!
//! Decoding is gated by the active [`Isa`]: encodings belonging to a disabled
//! extension resolve to [`Op::Illegal`] so the CPU raises an illegal-instruction
//! exception, exactly as hardware would when the extension is absent.

use super::memory::{MemError, Memory};
use super::{Isa, Xlen};

mod hypervisor;
mod op_imm;
mod zfa_moves;
use hypervisor::decode_hypervisor_mem;
use op_imm::{decode_op_imm, decode_op_imm32};
use zfa_moves::decode_zfa_rv32_move;

/// A decoded RISC-V operation. One variant per architectural operation across
/// the I/M/A/F/D/C and Zb* extensions; operand fields live in [`Insn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Op {
    // ---- RV32I / RV64I base ----
    Lui,
    Auipc,
    Jal,
    Jalr,
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
    Lb,
    Lh,
    Lw,
    Lbu,
    Lhu,
    Lwu,
    Ld,
    LdPair,
    Sb,
    Sh,
    Sw,
    Sd,
    SdPair,
    Addi,
    Slti,
    Sltiu,
    Xori,
    Ori,
    Andi,
    Slli,
    Srli,
    Srai,
    Add,
    Sub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Srl,
    Sra,
    Or,
    And,
    Addiw,
    Slliw,
    Srliw,
    Sraiw,
    Addw,
    Subw,
    Sllw,
    Sltw,
    Srlw,
    Sraw,
    Fence,
    FenceI,
    Pause,
    NtlP1,
    NtlPall,
    NtlS1,
    NtlAll,
    CboInval,
    CboClean,
    CboFlush,
    CboZero,
    PrefetchI,
    PrefetchR,
    PrefetchW,
    Ecall,
    Ebreak,
    // ---- Zcmp / Zcmt compressed-only ops ----
    CmPush,
    CmPop,
    CmPopRetz,
    CmPopRet,
    CmMvsa01,
    CmMva01s,
    CmJt,
    CmJalt,
    // ---- privileged / system (subset) ----
    Mret,
    Sret,
    Wfi,
    WrsNto,
    WrsSto,
    /// Legacy user trap-return encoding; reserved by the current privileged ISA.
    Uret,
    /// Legacy supervisor fence encoding; reserved by the current privileged ISA.
    SfenceVm,
    SfenceVma,
    SinvalVma,
    SfenceWInval,
    SfenceInvalIr,
    HfenceVvma,
    HfenceGvma,
    HinvalVvma,
    HinvalGvma,
    HlvB,
    HlvH,
    HlvW,
    HlvD,
    HlvBu,
    HlvHu,
    HlvWu,
    HlvxHu,
    HlvxWu,
    HsvB,
    HsvH,
    HsvW,
    HsvD,
    // ---- Zicsr ----
    Csrrw,
    Csrrs,
    Csrrc,
    Csrrwi,
    Csrrsi,
    Csrrci,
    // ---- M ----
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
    Mulw,
    Divw,
    Divuw,
    Remw,
    Remuw,
    // ---- A (word) ----
    LrW,
    ScW,
    AmoswapW,
    AmoaddW,
    AmoxorW,
    AmoandW,
    AmoorW,
    AmominW,
    AmomaxW,
    AmominuW,
    AmomaxuW,
    AmocasW,
    // ---- A (double) ----
    LrD,
    ScD,
    AmoswapD,
    AmoaddD,
    AmoxorD,
    AmoandD,
    AmoorD,
    AmominD,
    AmomaxD,
    AmominuD,
    AmomaxuD,
    AmocasD,
    // ---- Zacas (quadword; RV64 register-pair form) ----
    AmocasQ,
    // ---- F (single precision) ----
    Flw,
    Fsw,
    FmaddS,
    FmsubS,
    FnmsubS,
    FnmaddS,
    FaddS,
    FsubS,
    FmulS,
    FdivS,
    FsqrtS,
    FsgnjS,
    FsgnjnS,
    FsgnjxS,
    FminS,
    FmaxS,
    FcvtWS,
    FcvtWuS,
    FcvtLS,
    FcvtLuS,
    FmvXW,
    FeqS,
    FltS,
    FleS,
    FclassS,
    FcvtSW,
    FcvtSWu,
    FcvtSL,
    FcvtSLu,
    FmvWX,
    // ---- D (double precision) ----
    Fld,
    Fsd,
    FmaddD,
    FmsubD,
    FnmsubD,
    FnmaddD,
    FaddD,
    FsubD,
    FmulD,
    FdivD,
    FsqrtD,
    FsgnjD,
    FsgnjnD,
    FsgnjxD,
    FminD,
    FmaxD,
    FcvtSD,
    FcvtDS,
    FeqD,
    FltD,
    FleD,
    FclassD,
    FcvtWD,
    FcvtWuD,
    FcvtLD,
    FcvtLuD,
    FcvtDW,
    FcvtDWu,
    FcvtDL,
    FcvtDLu,
    FmvXD,
    FmvDX,
    /// Zfa RV32-only move of the high 32 bits of an f64 register to an x register.
    FmvhXD,
    /// Zfa RV32-only pack of two x registers into an f64 register.
    FmvpDX,
    // ---- Q (quad precision; decode/disassembly parity) ----
    Flq,
    Fsq,
    FmaddQ,
    FmsubQ,
    FnmsubQ,
    FnmaddQ,
    FaddQ,
    FsubQ,
    FmulQ,
    FdivQ,
    FsqrtQ,
    FsgnjQ,
    FsgnjnQ,
    FsgnjxQ,
    FminQ,
    FmaxQ,
    FcvtSQ,
    FcvtQS,
    FcvtDQ,
    FcvtQD,
    FcvtHQ,
    FcvtQH,
    FeqQ,
    FltQ,
    FleQ,
    FclassQ,
    FcvtWQ,
    FcvtWuQ,
    FcvtLQ,
    FcvtLuQ,
    FcvtQW,
    FcvtQWu,
    FcvtQL,
    FcvtQLu,
    // ---- Zba ----
    Sh1add,
    Sh2add,
    Sh3add,
    AddUw,
    Sh1addUw,
    Sh2addUw,
    Sh3addUw,
    SlliUw,
    // ---- Zbb ----
    Andn,
    Orn,
    Xnor,
    Clz,
    Ctz,
    Cpop,
    Max,
    Maxu,
    Min,
    Minu,
    SextB,
    SextH,
    ZextH,
    Rol,
    Ror,
    Rori,
    Orcb,
    Rev8,
    Clzw,
    Ctzw,
    Cpopw,
    Rolw,
    Rorw,
    Roriw,
    // ---- Zbc ----
    Clmul,
    Clmulh,
    Clmulr,
    // ---- Zbs ----
    Bclr,
    Bclri,
    Bext,
    Bexti,
    Binv,
    Binvi,
    Bset,
    Bseti,
    // ---- Zicond ----
    CzeroEqz,
    CzeroNez,
    // ---- Zfa ----
    FliS,
    FliD,
    FminmS,
    FmaxmS,
    FminmD,
    FmaxmD,
    FroundS,
    FroundnxS,
    FroundD,
    FroundnxD,
    FleqS,
    FltqS,
    FleqD,
    FltqD,
    FcvtmodWD,
    // ---- Zbkb ----
    Pack,
    Packh,
    Packw,
    Brev8,
    Zip,
    Unzip,
    // ---- Zfh (half precision) ----
    Flh,
    Fsh,
    FaddH,
    FsubH,
    FmulH,
    FdivH,
    FsqrtH,
    FmaddH,
    FmsubH,
    FnmsubH,
    FnmaddH,
    FsgnjH,
    FsgnjnH,
    FsgnjxH,
    FminH,
    FmaxH,
    FeqH,
    FltH,
    FleH,
    FclassH,
    FcvtSH,
    FcvtHS,
    FcvtDH,
    FcvtHD,
    FcvtWH,
    FcvtWuH,
    FcvtLH,
    FcvtLuH,
    FcvtHW,
    FcvtHWu,
    FcvtHL,
    FcvtHLu,
    FmvXH,
    FmvHX,
    // ---- Zfh + Zfa (half) ----
    FliH,
    FminmH,
    FmaxmH,
    FroundH,
    FroundnxH,
    FleqH,
    FltqH,
    // ---- Zbkx ----
    Xperm4,
    Xperm8,
    // ---- Zknh (SHA) ----
    Sha256Sig0,
    Sha256Sig1,
    Sha256Sum0,
    Sha256Sum1,
    Sha512Sig0,
    Sha512Sig1,
    Sha512Sum0,
    Sha512Sum1,
    Sha512Sig0l,
    Sha512Sig0h,
    Sha512Sig1l,
    Sha512Sig1h,
    Sha512Sum0r,
    Sha512Sum1r,
    // ---- Zksh (SM3) ----
    Sm3p0,
    Sm3p1,
    // ---- Zksed (SM4) ----
    Sm4ed,
    Sm4ks,
    // ---- Zkne / Zknd (AES) ----
    Aes32esi,
    Aes32esmi,
    Aes32dsi,
    Aes32dsmi,
    Aes64es,
    Aes64esm,
    Aes64ds,
    Aes64dsm,
    Aes64ks1i,
    Aes64ks2,
    Aes64im,
    // ---- V (vector configuration) ----
    Vsetvli,
    Vsetivli,
    Vsetvl,
    // ---- V (vector load/store, unit-stride; width in funct3) ----
    Vle,
    Vse,
    Vlse,
    Vsse,
    Vlxei,
    Vsxei,
    Vlm,
    Vsm,
    Vlre,
    Vsre,
    Vlseg,
    Vsseg,
    Vleff,
    // ---- V (vector integer arithmetic; form vv/vx/vi in funct3) ----
    Vadd,
    Vsub,
    Vrsub,
    Vand,
    Vor,
    Vxor,
    Vminu,
    Vmin,
    Vmaxu,
    Vmax,
    Vsll,
    Vsrl,
    Vsra,
    Vmerge, // also vmv.v.* when vm=1
    Vmseq,
    Vmsne,
    Vmsltu,
    Vmslt,
    Vmsleu,
    Vmsle,
    Vmsgtu,
    Vmsgt,
    // ---- V (OPMVV/OPMVX integer multiply/divide) ----
    Vmul,
    Vmulh,
    Vmulhu,
    Vmulhsu,
    Vdivu,
    Vdiv,
    Vremu,
    Vrem,
    // ---- V (OPFVV/OPFVF floating point) ----
    Vfadd,
    Vfsub,
    Vfrsub,
    Vfmul,
    Vfdiv,
    Vfrdiv,
    Vfsqrt,
    Vfmin,
    Vfmax,
    Vfsgnj,
    Vfsgnjn,
    Vfsgnjx,
    Vmfeq,
    Vmfne,
    Vmflt,
    Vmfle,
    Vmfgt,
    Vmfge,
    Vfmacc,
    Vfnmacc,
    Vfmsac,
    Vfnmsac,
    Vfmadd,
    Vfnmadd,
    Vfmsub,
    Vfnmsub,
    // ---- V (OPMVV integer reductions) ----
    Vredsum,
    Vredand,
    Vredor,
    Vredxor,
    Vredminu,
    Vredmin,
    Vredmaxu,
    Vredmax,
    // ---- V (OPFVV floating-point reductions) ----
    Vfredusum,
    Vfredosum,
    Vfredmin,
    Vfredmax,
    // ---- V (scalar element moves: lane 0 <-> x/f register) ----
    VmvXS,
    VmvSX,
    VfmvFS,
    VfmvSF,
    // ---- V (mask-register logical) ----
    Vmand,
    Vmnand,
    Vmandn,
    Vmxor,
    Vmor,
    Vmnor,
    Vmorn,
    Vmxnor,
    // ---- V (integer zero/sign extension, VXUNARY0) ----
    VzextVf2,
    VsextVf2,
    VzextVf4,
    VsextVf4,
    VzextVf8,
    VsextVf8,
    // ---- V (mask population / set / index) ----
    Vcpop,
    Vfirst,
    Vmsbf,
    Vmsof,
    Vmsif,
    Viota,
    Vid,
    // ---- V (slides) ----
    Vslideup,
    Vslidedown,
    Vslide1up,
    Vslide1down,
    Vfslide1up,
    Vfslide1down,
    Vrgather,
    Vrgatherei16,
    Vcompress,
    // ---- V (add/subtract with carry/borrow) ----
    Vadc,
    Vmadc,
    Vsbc,
    Vmsbc,
    // ---- V (saturating fixed-point add/subtract) ----
    Vsaddu,
    Vsadd,
    Vssubu,
    Vssub,
    // ---- V (averaging add/subtract) ----
    Vaaddu,
    Vaadd,
    Vasubu,
    Vasub,
    // ---- V (scaling shift / fractional multiply) ----
    Vssrl,
    Vssra,
    Vsmul,
    // ---- V (widening integer add/subtract) ----
    Vwaddu,
    Vwadd,
    Vwsubu,
    Vwsub,
    VwadduW,
    VwaddW,
    VwsubuW,
    VwsubW,
    // ---- V (widening integer multiply / multiply-accumulate) ----
    Vwmulu,
    Vwmulsu,
    Vwmul,
    Vwmaccu,
    Vwmacc,
    Vwmaccsu,
    Vwmaccus,
    // ---- V (narrowing shift / clip) ----
    Vnsrl,
    Vnsra,
    Vnclipu,
    Vnclip,
    // ---- V (single-width FP/integer conversions, VFUNARY0) ----
    VfcvtXuF,
    VfcvtXF,
    VfcvtFXu,
    VfcvtFX,
    VfcvtRtzXuF,
    VfcvtRtzXF,
    // ---- V (widening FP/integer conversions) ----
    VfwcvtXuF,
    VfwcvtXF,
    VfwcvtFXu,
    VfwcvtFX,
    VfwcvtFF,
    VfwcvtRtzXuF,
    VfwcvtRtzXF,
    // ---- V (narrowing FP/integer conversions) ----
    VfncvtXuF,
    VfncvtXF,
    VfncvtFXu,
    VfncvtFX,
    VfncvtFF,
    VfncvtRodFF,
    VfncvtRtzXuF,
    VfncvtRtzXF,
    // ---- V (widening FP arithmetic) ----
    Vfwadd,
    Vfwsub,
    Vfwmul,
    VfwaddW,
    VfwsubW,
    Vfwmacc,
    Vfwnmacc,
    Vfwmsac,
    Vfwnmsac,
    // ---- V (widening reductions) ----
    Vwredsumu,
    Vwredsum,
    Vfwredusum,
    Vfwredosum,
    // ---- V (classify / whole-register move) ----
    Vfclass,
    Vmvr,
    // ---- V (reciprocal / rsqrt estimates) ----
    Vfrsqrt7,
    Vfrec7,
    // ---- Xsoteria (Google Soteria/GSC vendor extension, RV32) ----
    /// Generalized bit-reverse, register control (CUSTOM-1).
    Grev,
    /// Generalized bit-reverse, immediate control (CUSTOM-0).
    Grevi,
    /// Clear bit `rs2`, register form (CUSTOM-1).
    Bitc,
    /// Clear bit `imm5`, immediate form (CUSTOM-0).
    Bitci,
    /// Set bit `rs2`, register form (CUSTOM-1).
    Bits,
    /// Set bit `imm5`, immediate form (CUSTOM-0).
    Bitsi,
    /// Find last (most-significant) set bit (CUSTOM-0).
    Fls,
    /// Population count (CUSTOM-0).
    Pcnt,
    // ---- Andes XAndesPerf vendor extension ----
    NdsLbgp,
    NdsLbugp,
    NdsLhgp,
    NdsLhugp,
    NdsLwgp,
    NdsLwugp,
    NdsLdgp,
    NdsSbgp,
    NdsShgp,
    NdsSwgp,
    NdsSdgp,
    NdsAddigp,
    NdsBfoz,
    NdsBfos,
    NdsBbc,
    NdsBbs,
    NdsBeqc,
    NdsBnec,
    NdsLeaH,
    NdsLeaW,
    NdsLeaD,
    NdsLeaBZe,
    NdsLeaHZe,
    NdsLeaWZe,
    NdsLeaDZe,
    NdsFfb,
    NdsFfmism,
    NdsFfzmism,
    NdsFlmism,
    // ---- T-Head/Xuantie XThead vendor extension ----
    ThDcacheCall,
    ThDcacheCiall,
    ThDcacheIall,
    ThDcacheCpa,
    ThDcacheCipa,
    ThDcacheIpa,
    ThDcacheCva,
    ThDcacheCiva,
    ThDcacheIva,
    ThDcacheCsw,
    ThDcacheCisw,
    ThDcacheIsw,
    ThDcacheCpal1,
    ThDcacheCval1,
    ThIcacheIall,
    ThIcacheIalls,
    ThIcacheIpa,
    ThIcacheIva,
    ThL2cacheCall,
    ThL2cacheCiall,
    ThL2cacheIall,
    ThSfenceVmas,
    ThSync,
    ThSyncS,
    ThSyncI,
    ThSyncIS,
    ThIpush,
    ThIpop,
    ThAddsl,
    ThSrri,
    ThSrriw,
    ThExt,
    ThExtu,
    ThFf0,
    ThFf1,
    ThRev,
    ThRevw,
    ThTstNbz,
    ThTst,
    ThMveqz,
    ThMvnez,
    ThMula,
    ThMulah,
    ThMulaw,
    ThMuls,
    ThMulsh,
    ThMulsw,
    ThFmvHwX,
    ThFmvXHw,
    ThAndn,
    ThOrn,
    ThXorn,
    ThPackl,
    ThPackh,
    ThPackhl,
    ThLbia,
    ThLbib,
    ThLbuia,
    ThLbuib,
    ThLhia,
    ThLhib,
    ThLhuia,
    ThLhuib,
    ThLwia,
    ThLwib,
    ThLwuia,
    ThLwuib,
    ThLdia,
    ThLdib,
    ThSbia,
    ThSbib,
    ThShia,
    ThShib,
    ThSwia,
    ThSwib,
    ThSdia,
    ThSdib,
    ThLrb,
    ThLrbu,
    ThLrh,
    ThLrhu,
    ThLrw,
    ThLrwu,
    ThLrd,
    ThSrb,
    ThSrh,
    ThSrw,
    ThSrd,
    ThLurb,
    ThLurbu,
    ThLurh,
    ThLurhu,
    ThLurw,
    ThLurwu,
    ThLurd,
    ThSurb,
    ThSurh,
    ThSurw,
    ThSurd,
    ThLdd,
    ThLwd,
    ThLwud,
    ThSdd,
    ThSwd,
    ThFlrd,
    ThFlrw,
    ThFlurd,
    ThFlurw,
    ThFsrd,
    ThFsrw,
    ThFsurd,
    ThFsurw,
    ThVmaqa,
    ThVmaqau,
    ThVmaqasu,
    ThVmaqaus,
    ThVpmaqa,
    ThVpmaqau,
    ThVpmaqasu,
    ThVpmaqaus,
    ThVpnclip,
    ThVpnclipu,
    ThVpwadd,
    ThVpwaddu,
    // ---- Hazard3 (Xh3power/Xh3bextm vendor extension) ----
    /// Enter sleep until unblock or interrupt hint (`slt x0, x0, x0`).
    H3Block,
    /// Post unblock signal hint (`slt x0, x0, x1`).
    H3Unblock,
    /// Bit extract multiple, register shift amount (CUSTOM-0).
    H3Bextm,
    /// Bit extract multiple, immediate shift amount (CUSTOM-0).
    H3Bextmi,
    // ---- sentinel ----
    Illegal,
}

impl Op {
    /// `true` if this is a floating-point (F/D) operation handled by the FP
    /// execution path.
    pub fn is_fp(self) -> bool {
        use Op::*;
        matches!(
            self,
            Flw | Fsw
                | FmaddS
                | FmsubS
                | FnmsubS
                | FnmaddS
                | FaddS
                | FsubS
                | FmulS
                | FdivS
                | FsqrtS
                | FsgnjS
                | FsgnjnS
                | FsgnjxS
                | FminS
                | FmaxS
                | FcvtWS
                | FcvtWuS
                | FcvtLS
                | FcvtLuS
                | FmvXW
                | FeqS
                | FltS
                | FleS
                | FclassS
                | FcvtSW
                | FcvtSWu
                | FcvtSL
                | FcvtSLu
                | FmvWX
                | Fld
                | Fsd
                | FmaddD
                | FmsubD
                | FnmsubD
                | FnmaddD
                | FaddD
                | FsubD
                | FmulD
                | FdivD
                | FsqrtD
                | FsgnjD
                | FsgnjnD
                | FsgnjxD
                | FminD
                | FmaxD
                | FcvtSD
                | FcvtDS
                | FeqD
                | FltD
                | FleD
                | FclassD
                | FcvtWD
                | FcvtWuD
                | FcvtLD
                | FcvtLuD
                | FcvtDW
                | FcvtDWu
                | FcvtDL
                | FcvtDLu
                | FmvXD
                | FmvDX
                | FmvhXD
                | FmvpDX
                | Flq
                | Fsq
                | FmaddQ
                | FmsubQ
                | FnmsubQ
                | FnmaddQ
                | FaddQ
                | FsubQ
                | FmulQ
                | FdivQ
                | FsqrtQ
                | FsgnjQ
                | FsgnjnQ
                | FsgnjxQ
                | FminQ
                | FmaxQ
                | FcvtSQ
                | FcvtQS
                | FcvtDQ
                | FcvtQD
                | FcvtHQ
                | FcvtQH
                | FeqQ
                | FltQ
                | FleQ
                | FclassQ
                | FcvtWQ
                | FcvtWuQ
                | FcvtLQ
                | FcvtLuQ
                | FcvtQW
                | FcvtQWu
                | FcvtQL
                | FcvtQLu
                | FliS
                | FliD
                | FminmS
                | FmaxmS
                | FminmD
                | FmaxmD
                | FroundS
                | FroundnxS
                | FroundD
                | FroundnxD
                | FleqS
                | FltqS
                | FleqD
                | FltqD
                | FcvtmodWD
                | Flh
                | Fsh
                | FaddH
                | FsubH
                | FmulH
                | FdivH
                | FsqrtH
                | FmaddH
                | FmsubH
                | FnmsubH
                | FnmaddH
                | FsgnjH
                | FsgnjnH
                | FsgnjxH
                | FminH
                | FmaxH
                | FeqH
                | FltH
                | FleH
                | FclassH
                | FcvtSH
                | FcvtHS
                | FcvtDH
                | FcvtHD
                | FcvtWH
                | FcvtWuH
                | FcvtLH
                | FcvtLuH
                | FcvtHW
                | FcvtHWu
                | FcvtHL
                | FcvtHLu
                | FmvXH
                | FmvHX
                | FliH
                | FminmH
                | FmaxmH
                | FroundH
                | FroundnxH
                | FleqH
                | FltqH
        )
    }
}

/// A fully decoded instruction with all operand fields resolved.
#[derive(Clone, Copy, Debug)]
pub struct Insn {
    /// The operation.
    pub op: Op,
    /// Destination register (or `rd` for FP).
    pub rd: u8,
    /// First source register.
    pub rs1: u8,
    /// Second source register.
    pub rs2: u8,
    /// Third source register (FMA only).
    pub rs3: u8,
    /// Sign-extended immediate (semantics depend on `op`).
    pub imm: i64,
    /// `funct3` field, reused as the FP rounding-mode field.
    pub funct3: u8,
    /// CSR address (Zicsr) — also carries the 5-bit zimm in `rs1` for the
    /// immediate CSR forms.
    pub csr: u16,
    /// Atomic ordering bit `aq`.
    pub aq: bool,
    /// Atomic ordering bit `rl`.
    pub rl: bool,
    /// Encoded length in bytes (2 for compressed, 4 otherwise).
    pub len: u8,
    /// The raw little-endian instruction bits.
    pub raw: u32,
}

impl Insn {
    /// An illegal instruction of the given length carrying its raw bits.
    fn illegal(raw: u32, len: u8) -> Self {
        Insn {
            op: Op::Illegal,
            rd: 0,
            rs1: 0,
            rs2: 0,
            rs3: 0,
            imm: 0,
            funct3: 0,
            csr: 0,
            aq: false,
            rl: false,
            len,
            raw,
        }
    }

    /// An illegal 16-bit (compressed) parcel.
    pub(crate) fn illegal_compressed(half: u16) -> Self {
        Insn::illegal(half as u32, 2)
    }

    /// `true` for [`Op::Illegal`].
    #[inline]
    pub fn is_illegal(&self) -> bool {
        matches!(self.op, Op::Illegal)
    }

    /// The rounding-mode field of a floating-point instruction.
    #[inline]
    pub fn rm(&self) -> u8 {
        self.funct3
    }
}

/// Errors that can occur while fetching an instruction for decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The instruction parcel could not be read from memory.
    Fetch(MemError),
}

// ---------------------------------------------------------------------------
// Field extraction helpers (operate on the 32-bit instruction word).
// ---------------------------------------------------------------------------

#[inline]
fn opcode(w: u32) -> u32 {
    w & 0x7f
}
#[inline]
fn rd(w: u32) -> u8 {
    ((w >> 7) & 0x1f) as u8
}
#[inline]
fn funct3(w: u32) -> u8 {
    ((w >> 12) & 0x7) as u8
}
#[inline]
fn rs1(w: u32) -> u8 {
    ((w >> 15) & 0x1f) as u8
}
#[inline]
fn rs2(w: u32) -> u8 {
    ((w >> 20) & 0x1f) as u8
}
#[inline]
fn rs3(w: u32) -> u8 {
    ((w >> 27) & 0x1f) as u8
}
#[inline]
fn funct7(w: u32) -> u32 {
    (w >> 25) & 0x7f
}
#[inline]
fn funct2(w: u32) -> u32 {
    (w >> 25) & 0x3
}

// Sign-extended immediates.
#[inline]
fn imm_i(w: u32) -> i64 {
    (w as i32 as i64) >> 20
}
#[inline]
fn imm_s(w: u32) -> i64 {
    let hi = (w >> 25) & 0x7f;
    let lo = (w >> 7) & 0x1f;
    let v = (hi << 5) | lo;
    // sign extend 12 bits
    ((v as i32) << 20 >> 20) as i64
}
#[inline]
fn imm_b(w: u32) -> i64 {
    let b12 = (w >> 31) & 1;
    let b11 = (w >> 7) & 1;
    let b10_5 = (w >> 25) & 0x3f;
    let b4_1 = (w >> 8) & 0xf;
    let v = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    ((v as i32) << 19 >> 19) as i64
}
#[inline]
fn imm_u(w: u32) -> i64 {
    (w & 0xffff_f000) as i32 as i64
}
#[inline]
fn imm_j(w: u32) -> i64 {
    let b20 = (w >> 31) & 1;
    let b19_12 = (w >> 12) & 0xff;
    let b11 = (w >> 20) & 1;
    let b10_1 = (w >> 21) & 0x3ff;
    let v = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    ((v as i32) << 11 >> 11) as i64
}

/// Build a base [`Insn`] with the common register/length fields populated.
fn base(op: Op, w: u32) -> Insn {
    Insn {
        op,
        rd: rd(w),
        rs1: rs1(w),
        rs2: rs2(w),
        rs3: rs3(w),
        imm: 0,
        funct3: funct3(w),
        csr: ((w >> 20) & 0xfff) as u16,
        aq: (w >> 26) & 1 != 0,
        rl: (w >> 25) & 1 != 0,
        len: 4,
        raw: w,
    }
}

/// Decode a 32-bit instruction word under the given XLEN and ISA.
pub fn decode(w: u32, xlen: Xlen, isa: &Isa) -> Insn {
    let rv64 = xlen == Xlen::Rv64;
    match opcode(w) {
        0x37 => with_imm(Op::Lui, w, imm_u(w)),
        0x17 => with_imm(Op::Auipc, w, imm_u(w)),
        0x6f => with_imm(Op::Jal, w, imm_j(w)),
        0x67 if funct3(w) == 0 => with_imm(Op::Jalr, w, imm_i(w)),
        0x63 => decode_branch(w),
        0x03 => decode_load(w, rv64, isa),
        0x23 => decode_store(w, rv64, isa),
        0x13 => decode_op_imm(w, rv64, isa),
        0x1b if rv64 => decode_op_imm32(w, isa),
        0x33 => decode_op(w, rv64, isa),
        0x3b if rv64 => decode_op32(w, isa),
        0x0f => decode_fence(w, isa),
        0x73 => decode_system(w, rv64, isa),
        0x2f if isa.a || isa.zacas => decode_amo(w, rv64, isa),
        0x07 if isa.f || isa.v => decode_load_fp(w, isa),
        0x27 if isa.f || isa.v => decode_store_fp(w, isa),
        0x53 if isa.f => decode_op_fp(w, rv64, isa),
        0x43 if isa.f => decode_fma(Op::FmaddS, Op::FmaddD, Op::FmaddH, Op::FmaddQ, w, isa),
        0x47 if isa.f => decode_fma(Op::FmsubS, Op::FmsubD, Op::FmsubH, Op::FmsubQ, w, isa),
        0x4b if isa.f => decode_fma(Op::FnmsubS, Op::FnmsubD, Op::FnmsubH, Op::FnmsubQ, w, isa),
        0x4f if isa.f => decode_fma(Op::FnmaddS, Op::FnmaddD, Op::FnmaddH, Op::FnmaddQ, w, isa),
        0x57 if isa.v => decode_vector(w),
        0x0b => decode_custom0(w, rv64, isa),
        0x2b => decode_custom1(w, rv64, isa),
        0x5b if isa.xandes => decode_andes_custom2(w, rv64),
        _ => Insn::illegal(w, 4),
    }
}

fn decode_custom0(w: u32, rv64: bool, isa: &Isa) -> Insn {
    if isa.xsoteria && !rv64 {
        let i = decode_xsoteria_custom0(w);
        if !i.is_illegal() {
            return i;
        }
    }
    if isa.xandes {
        let i = decode_andes_custom0(w);
        if !i.is_illegal() {
            return i;
        }
    }
    if isa.xthead {
        let i = decode_thead_custom0(w);
        if !i.is_illegal() {
            return i;
        }
    }
    if isa.xhazard3 {
        let i = decode_hazard3_custom0(w);
        if !i.is_illegal() {
            return i;
        }
    }
    Insn::illegal(w, 4)
}

fn decode_custom1(w: u32, rv64: bool, isa: &Isa) -> Insn {
    if isa.xsoteria && !rv64 {
        let i = decode_xsoteria_custom1(w);
        if !i.is_illegal() {
            return i;
        }
    }
    if isa.xandes {
        let i = decode_andes_custom1(w, rv64);
        if !i.is_illegal() {
            return i;
        }
    }
    Insn::illegal(w, 4)
}

fn thead_bimm6(w: u32) -> u8 {
    ((w >> 20) & 0x3f) as u8
}

fn thead_bimm2(w: u32) -> u8 {
    ((w >> 25) & 0x3) as u8
}

fn decode_thead_custom0(w: u32) -> Insn {
    let f3 = funct3(w);
    let f7 = funct7(w) as u8;
    match f3 {
        0b000 => decode_thead_subop0(w, f7),
        0b001 | 0b010 | 0b011 => decode_thead_arithmetic(w, f3, f7),
        0b100 | 0b101 => decode_thead_mem(w, f3, f7),
        0b110 | 0b111 => {
            let i = decode_thead_mem(w, f3, f7);
            if i.is_illegal() {
                decode_thead_vec(w, f3, f7)
            } else {
                i
            }
        }
        _ => Insn::illegal(w, 4),
    }
}

fn decode_thead_subop0(w: u32, f7: u8) -> Insn {
    use Op::*;

    let rd = rd(w);
    let rs1 = rs1(w);
    let rs2 = rs2(w);
    if rd != 0 {
        return Insn::illegal(w, 4);
    }

    let op = match f7 {
        0 if rs1 == 0 => match rs2 {
            0b00001 => ThDcacheCall,
            0b00011 => ThDcacheCiall,
            0b00010 => ThDcacheIall,
            0b10000 => ThIcacheIall,
            0b10001 => ThIcacheIalls,
            0b10101 => ThL2cacheCall,
            0b10111 => ThL2cacheCiall,
            0b10110 => ThL2cacheIall,
            0b11000 => ThSync,
            0b11001 => ThSyncS,
            0b11010 => ThSyncI,
            0b11011 => ThSyncIS,
            0b00100 => ThIpush,
            0b00101 => ThIpop,
            _ => return Insn::illegal(w, 4),
        },
        1 => match rs2 {
            0b01001 => ThDcacheCpa,
            0b01011 => ThDcacheCipa,
            0b01010 => ThDcacheIpa,
            0b00101 => ThDcacheCva,
            0b00111 => ThDcacheCiva,
            0b00110 => ThDcacheIva,
            0b00001 => ThDcacheCsw,
            0b00011 => ThDcacheCisw,
            0b00010 => ThDcacheIsw,
            0b01000 => ThDcacheCpal1,
            0b00100 => ThDcacheCval1,
            0b11000 => ThIcacheIpa,
            0b10000 => ThIcacheIva,
            _ => return Insn::illegal(w, 4),
        },
        2 => ThSfenceVmas,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

fn decode_thead_arithmetic(w: u32, f3: u8, f7: u8) -> Insn {
    use Op::*;

    if f3 == 0b010 || f3 == 0b011 {
        let msb = f7 >> 1;
        let lsb = thead_bimm6(w);
        if msb < lsb {
            return Insn::illegal(w, 4);
        }
        let mut i = base(if f3 == 0b011 { ThExtu } else { ThExt }, w);
        i.rs2 = msb;
        i.imm = lsb as i64;
        return i;
    }

    let op = match f7 {
        0b0000000..=0b0000011 => ThAddsl,
        0b0001000 | 0b0001001 => ThSrri,
        0b0001010 => ThSrriw,
        0b1000100 | 0b1000101 => ThTst,
        0b0100000 => ThMveqz,
        0b0100001 => ThMvnez,
        0b0010000 => ThMula,
        0b0010100 => ThMulah,
        0b0010010 => ThMulaw,
        0b0010001 => ThMuls,
        0b0010101 => ThMulsh,
        0b0010011 => ThMulsw,
        0b1000010 => ThFf0,
        0b1000011 => ThFf1,
        0b1000001 => ThRev,
        0b1001000 => ThRevw,
        0b1010000 => ThFmvHwX,
        0b1100000 => ThFmvXHw,
        0b1000000 => ThTstNbz,
        0b0000100 => ThAndn,
        0b0000101 => ThOrn,
        0b0000110 => ThXorn,
        0b0001100 => ThPackl,
        0b0001101 => ThPackh,
        0b0001110 => ThPackhl,
        _ => return Insn::illegal(w, 4),
    };

    let mut i = base(op, w);
    match op {
        ThAddsl => i.imm = thead_bimm2(w) as i64,
        ThSrri | ThTst => i.imm = thead_bimm6(w) as i64,
        ThSrriw => i.imm = rs2(w) as i64,
        _ => {}
    }
    i
}

fn decode_thead_vec(w: u32, f3: u8, f7: u8) -> Insn {
    use Op::*;

    let key = f7 >> 1;
    let op = match f3 {
        0b110 => match key {
            0x20 | 0x21 => ThVmaqa,
            0x22 | 0x23 => ThVmaqau,
            0x24 | 0x25 => ThVmaqasu,
            0x27 => ThVmaqaus,
            _ => return Insn::illegal(w, 4),
        },
        0b111 => match key {
            0x20 | 0x21 => ThVpmaqa,
            0x22 | 0x23 => ThVpmaqau,
            0x24 | 0x25 => ThVpmaqasu,
            0x27 => ThVpmaqaus,
            0x28 | 0x29 => ThVpnclip,
            0x2a | 0x2b => ThVpnclipu,
            0x2c | 0x2d => ThVpwadd,
            0x2e | 0x2f => ThVpwaddu,
            _ => return Insn::illegal(w, 4),
        },
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

fn decode_thead_mem(w: u32, f3: u8, f7: u8) -> Insn {
    use Op::*;

    let key = f7 & 0b1111100;
    let op = match f3 {
        0b100 => match key {
            0b0001100 => ThLbia,
            0b0000100 => ThLbib,
            0b1001100 => ThLbuia,
            0b1000100 => ThLbuib,
            0b0011100 => ThLhia,
            0b0010100 => ThLhib,
            0b1011100 => ThLhuia,
            0b1010100 => ThLhuib,
            0b0101100 => ThLwia,
            0b0100100 => ThLwib,
            0b1101100 => ThLwuia,
            0b1100100 => ThLwuib,
            0b0111100 => ThLdia,
            0b0110100 => ThLdib,
            0b0000000 => ThLrb,
            0b1000000 => ThLrbu,
            0b0010000 => ThLrh,
            0b1010000 => ThLrhu,
            0b0100000 => ThLrw,
            0b1100000 => ThLrwu,
            0b0110000 => ThLrd,
            0b0001000 => ThLurb,
            0b1001000 => ThLurbu,
            0b0011000 => ThLurh,
            0b1011000 => ThLurhu,
            0b0101000 => ThLurw,
            0b1101000 => ThLurwu,
            0b0111000 => ThLurd,
            0b1111100 => ThLdd,
            0b1110000 => ThLwd,
            0b1111000 => ThLwud,
            _ => return Insn::illegal(w, 4),
        },
        0b101 => match key {
            0b0001100 => ThSbia,
            0b0000100 => ThSbib,
            0b0011100 => ThShia,
            0b0010100 => ThShib,
            0b0101100 => ThSwia,
            0b0100100 => ThSwib,
            0b0111100 => ThSdia,
            0b0110100 => ThSdib,
            0b0000000 => ThSrb,
            0b0010000 => ThSrh,
            0b0100000 => ThSrw,
            0b0110000 => ThSrd,
            0b0001000 => ThSurb,
            0b0011000 => ThSurh,
            0b0101000 => ThSurw,
            0b0111000 => ThSurd,
            0b1111100 => ThSdd,
            0b1110000 => ThSwd,
            _ => return Insn::illegal(w, 4),
        },
        0b110 => match key {
            0b0110000 => ThFlrd,
            0b0100000 => ThFlrw,
            0b0111000 => ThFlurd,
            0b0101000 => ThFlurw,
            _ => return Insn::illegal(w, 4),
        },
        0b111 => match key {
            0b0110000 => ThFsrd,
            0b0100000 => ThFsrw,
            0b0111000 => ThFsurd,
            0b0101000 => ThFsurw,
            _ => return Insn::illegal(w, 4),
        },
        _ => return Insn::illegal(w, 4),
    };

    let mut i = base(op, w);
    if thead_auto_mem_op(op) {
        if thead_auto_load_op(op) && i.rd == i.rs1 {
            return Insn::illegal(w, 4);
        }
        i.rs2 = rs2(w);
        i.imm = thead_bimm2(w) as i64;
    } else if thead_pair_mem_op(op) {
        if thead_pair_load_op(op) && i.rd == i.rs2 && i.rd == i.rs1 {
            return Insn::illegal(w, 4);
        }
        let slot_size_shift = if matches!(op, ThLdd | ThSdd) { 4 } else { 3 };
        i.imm = ((f7 & 0b11) as i64) << slot_size_shift;
    } else {
        i.imm = thead_bimm2(w) as i64;
    }
    i
}

fn thead_auto_mem_op(op: Op) -> bool {
    use Op::*;
    matches!(
        op,
        ThLbia
            | ThLbib
            | ThLbuia
            | ThLbuib
            | ThLhia
            | ThLhib
            | ThLhuia
            | ThLhuib
            | ThLwia
            | ThLwib
            | ThLwuia
            | ThLwuib
            | ThLdia
            | ThLdib
            | ThSbia
            | ThSbib
            | ThShia
            | ThShib
            | ThSwia
            | ThSwib
            | ThSdia
            | ThSdib
    )
}

fn thead_auto_load_op(op: Op) -> bool {
    use Op::*;
    matches!(
        op,
        ThLbia
            | ThLbib
            | ThLbuia
            | ThLbuib
            | ThLhia
            | ThLhib
            | ThLhuia
            | ThLhuib
            | ThLwia
            | ThLwib
            | ThLwuia
            | ThLwuib
            | ThLdia
            | ThLdib
    )
}

fn thead_pair_mem_op(op: Op) -> bool {
    use Op::*;
    matches!(op, ThLdd | ThLwd | ThLwud | ThSdd | ThSwd)
}

fn thead_pair_load_op(op: Op) -> bool {
    use Op::*;
    matches!(op, ThLdd | ThLwd | ThLwud)
}

fn andes_base(op: Op, w: u32, imm: i64) -> Insn {
    let mut i = with_imm(op, w, imm);
    i.rs1 = 3; // gp is the implicit base for XAndesPerf GP-relative forms.
    i
}

fn sign_flagged(mut imm: i64, w: u32, sign_extend_from_bit: u32) -> i64 {
    if w & 0x8000_0000 != 0 {
        imm |= !((1i64 << sign_extend_from_bit) - 1);
    }
    imm
}

fn andes_gp_lb_imm(w: u32) -> i64 {
    let imm = ((w >> 14) & 0x1)
        | (((w >> 21) & 0x3ff) << 1)
        | (((w >> 20) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15);
    sign_flagged(imm as i64, w, 17)
}

fn andes_gp_lh_imm(w: u32) -> i64 {
    let imm = (((w >> 21) & 0x3ff) << 1)
        | (((w >> 20) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15);
    sign_flagged(imm as i64, w, 17)
}

fn andes_gp_lw_imm(w: u32) -> i64 {
    let imm = (((w >> 22) & 0x1ff) << 2)
        | (((w >> 20) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15)
        | (((w >> 21) & 0x1) << 17);
    sign_flagged(imm as i64, w, 18)
}

fn andes_gp_ld_imm(w: u32) -> i64 {
    let imm = (((w >> 23) & 0xff) << 3)
        | (((w >> 20) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15)
        | (((w >> 21) & 0x3) << 17);
    sign_flagged(imm as i64, w, 19)
}

fn andes_gp_sb_imm(w: u32) -> i64 {
    let imm = ((w >> 14) & 0x1)
        | (((w >> 8) & 0xf) << 1)
        | (((w >> 25) & 0x3f) << 5)
        | (((w >> 7) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15);
    sign_flagged(imm as i64, w, 17)
}

fn andes_gp_sh_imm(w: u32) -> i64 {
    let imm = (((w >> 8) & 0xf) << 1)
        | (((w >> 25) & 0x3f) << 5)
        | (((w >> 7) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15);
    sign_flagged(imm as i64, w, 17)
}

fn andes_gp_sw_imm(w: u32) -> i64 {
    let imm = (((w >> 9) & 0x7) << 2)
        | (((w >> 25) & 0x3f) << 5)
        | (((w >> 7) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15)
        | (((w >> 8) & 0x1) << 17);
    sign_flagged(imm as i64, w, 18)
}

fn andes_gp_sd_imm(w: u32) -> i64 {
    let imm = (((w >> 10) & 0x3) << 3)
        | (((w >> 25) & 0x3f) << 5)
        | (((w >> 7) & 0x1) << 11)
        | (((w >> 17) & 0x7) << 12)
        | (((w >> 15) & 0x3) << 15)
        | (((w >> 8) & 0x3) << 17);
    sign_flagged(imm as i64, w, 19)
}

fn andes_stype_imm10(w: u32) -> i64 {
    let imm = (((w >> 8) & 0xf) << 1) | (((w >> 25) & 0x1f) << 5);
    if w & 0x8000_0000 != 0 {
        (imm as i64) | !((1i64 << 10) - 1)
    } else {
        imm as i64
    }
}

fn decode_andes_custom0(w: u32) -> Insn {
    match (w >> 12) & 0x3 {
        0b00 => andes_base(Op::NdsLbgp, w, andes_gp_lb_imm(w)),
        0b01 => andes_base(Op::NdsAddigp, w, andes_gp_lb_imm(w)),
        0b10 => andes_base(Op::NdsLbugp, w, andes_gp_lb_imm(w)),
        0b11 => {
            let mut i = andes_base(Op::NdsSbgp, w, andes_gp_sb_imm(w));
            i.rs2 = rs2(w);
            i
        }
        _ => unreachable!(),
    }
}

fn decode_andes_custom1(w: u32, rv64: bool) -> Insn {
    match funct3(w) {
        0b000 => {
            let mut i = andes_base(Op::NdsShgp, w, andes_gp_sh_imm(w));
            i.rs2 = rs2(w);
            i
        }
        0b001 => andes_base(Op::NdsLhgp, w, andes_gp_lh_imm(w)),
        0b010 => andes_base(Op::NdsLwgp, w, andes_gp_lw_imm(w)),
        0b100 => {
            let mut i = andes_base(Op::NdsSwgp, w, andes_gp_sw_imm(w));
            i.rs2 = rs2(w);
            i
        }
        0b101 => andes_base(Op::NdsLhugp, w, andes_gp_lh_imm(w)),
        0b011 if rv64 => andes_base(Op::NdsLdgp, w, andes_gp_ld_imm(w)),
        0b110 if rv64 => andes_base(Op::NdsLwugp, w, andes_gp_lw_imm(w)),
        0b111 if rv64 => {
            let mut i = andes_base(Op::NdsSdgp, w, andes_gp_sd_imm(w));
            i.rs2 = rs2(w);
            i
        }
        _ => Insn::illegal(w, 4),
    }
}

fn decode_andes_custom2(w: u32, rv64: bool) -> Insn {
    match funct3(w) {
        0b000 => {
            let op = match funct7(w) {
                0x05 => Op::NdsLeaH,
                0x06 => Op::NdsLeaW,
                0x07 => Op::NdsLeaD,
                0x08 if rv64 => Op::NdsLeaBZe,
                0x09 if rv64 => Op::NdsLeaHZe,
                0x0a if rv64 => Op::NdsLeaWZe,
                0x0b if rv64 => Op::NdsLeaDZe,
                0x10 => Op::NdsFfb,
                0x11 => Op::NdsFfzmism,
                0x12 => Op::NdsFfmism,
                0x13 => Op::NdsFlmism,
                _ => return Insn::illegal(w, 4),
            };
            base(op, w)
        }
        0b010 | 0b011 => {
            let msb = ((w >> 26) & 0x3f) as u8;
            let lsb = ((w >> 20) & 0x3f) as u8;
            if !rv64 && (msb > 0x1f || lsb > 0x1f) {
                return Insn::illegal(w, 4);
            }
            let mut i = base(
                if funct3(w) == 0b010 {
                    Op::NdsBfoz
                } else {
                    Op::NdsBfos
                },
                w,
            );
            i.rs2 = msb;
            i.imm = lsb as i64;
            i
        }
        0b101 | 0b110 => {
            let imm7 = ((w >> 20) & 0x1f) | (((w >> 7) & 0x1) << 5) | (((w >> 30) & 0x1) << 6);
            let mut i = with_imm(
                if funct3(w) == 0b101 {
                    Op::NdsBeqc
                } else {
                    Op::NdsBnec
                },
                w,
                andes_stype_imm10(w),
            );
            i.rs2 = imm7 as u8;
            i
        }
        0b111 => {
            let cimm = ((w >> 20) & 0x1f) | (((w >> 7) & 0x1) << 5);
            if !rv64 && cimm > 0x1f {
                return Insn::illegal(w, 4);
            }
            let mut i = with_imm(
                if (w >> 30) & 0x1 != 0 {
                    Op::NdsBbs
                } else {
                    Op::NdsBbc
                },
                w,
                andes_stype_imm10(w),
            );
            i.rs2 = cimm as u8;
            i
        }
        _ => Insn::illegal(w, 4),
    }
}

/// Hazard3 Xh3bextm CUSTOM-0 (opcode 0x0b).
///
/// `h3.bextm rd, rs1, rs2, nbits`: `funct3=0`, `funct7[6:4]=0`,
/// `funct7[0]=0`, and `nbits = funct7[3:1] + 1`.
///
/// `h3.bextmi rd, rs1, shamt, nbits`: `funct3=4`, `imm[11:9]=0`,
/// `imm[5]=0`, `shamt=imm[4:0]`, and `nbits = imm[8:6] + 1`.
fn decode_hazard3_custom0(w: u32) -> Insn {
    match funct3(w) {
        0b000 => {
            let f7 = funct7(w);
            if f7 & 0x71 != 0 {
                return Insn::illegal(w, 4);
            }
            with_imm(Op::H3Bextm, w, (((f7 >> 1) & 0x7) + 1) as i64)
        }
        0b100 => {
            let imm12 = (w >> 20) & 0xfff;
            if imm12 & 0xe20 != 0 {
                return Insn::illegal(w, 4);
            }
            let mut i = with_imm(Op::H3Bextmi, w, (((imm12 >> 6) & 0x7) + 1) as i64);
            i.rs2 = (imm12 & 0x1f) as u8;
            i
        }
        _ => Insn::illegal(w, 4),
    }
}

/// Xsoteria CUSTOM-0 (opcode 0x0b): immediate and unary bit-manipulation.
///
/// Field layout matches the standard R/I positions: `funct7 = w[31:25]`,
/// `imm5 = w[24:20]`, `rs1 = w[19:15]`, `funct3 = w[14:12]`, `rd = w[11:7]`.
/// Mirrors the IDA `ana_soteria_custom0` decoder. RV32 only (enforced by the
/// caller).
fn decode_xsoteria_custom0(w: u32) -> Insn {
    let f3 = funct3(w);
    let f7 = funct7(w);
    let imm5 = ((w >> 20) & 0x1f) as i64;
    match f3 {
        0b000 if f7 == 0x00 => with_imm(Op::Grevi, w, imm5),
        0b001 if f7 == 0x00 => with_imm(Op::Bitci, w, imm5),
        0b001 if f7 == 0x20 => with_imm(Op::Bitsi, w, imm5),
        // fls / clz / pcnt are unary: the rs2 field (w[24:20]) must be zero.
        0b010 if f7 == 0x00 && imm5 == 0 => base(Op::Fls, w),
        0b010 if f7 == 0x20 && imm5 == 0 => base(Op::Clz, w),
        0b011 if f7 == 0x00 && imm5 == 0 => base(Op::Pcnt, w),
        _ => Insn::illegal(w, 4),
    }
}

/// Xsoteria CUSTOM-1 (opcode 0x2b): register-register bit-manipulation.
/// Mirrors the IDA `ana_soteria_custom1` decoder. RV32 only.
fn decode_xsoteria_custom1(w: u32) -> Insn {
    let f3 = funct3(w);
    let f7 = funct7(w);
    match f3 {
        0b000 if f7 == 0x00 => base(Op::Grev, w),
        0b001 if f7 == 0x00 => base(Op::Bitc, w),
        0b001 if f7 == 0x20 => base(Op::Bits, w),
        _ => Insn::illegal(w, 4),
    }
}

/// OP-V (0x57): vector configuration (funct3 == 0b111) and integer arithmetic
/// (OPIVV/OPIVX/OPIVI).
fn decode_vector(w: u32) -> Insn {
    let f3 = funct3(w);
    // Integer arithmetic: OPIVV(000) / OPIVI(011) / OPIVX(100), op in funct6.
    if f3 == 0b000 || f3 == 0b011 || f3 == 0b100 {
        let funct6 = w >> 26;
        let op = match funct6 {
            0b000000 => Op::Vadd,
            0b000010 if f3 != 0b011 => Op::Vsub, // no OPIVI form
            0b000011 if f3 != 0b000 => Op::Vrsub, // no OPIVV form
            0b001001 => Op::Vand,
            0b001010 => Op::Vor,
            0b001011 => Op::Vxor,
            0b000100 if f3 != 0b011 => Op::Vminu, // vv/vx
            0b000101 if f3 != 0b011 => Op::Vmin,
            0b000110 if f3 != 0b011 => Op::Vmaxu,
            0b000111 if f3 != 0b011 => Op::Vmax,
            0b100101 => Op::Vsll,
            0b101000 => Op::Vsrl,
            0b101001 => Op::Vsra,
            0b010111 => Op::Vmerge, // vmerge (vm=0) / vmv.v.* (vm=1)
            0b011000 => Op::Vmseq,  // vv/vx/vi
            0b011001 => Op::Vmsne,
            0b011010 if f3 != 0b011 => Op::Vmsltu, // vv/vx
            0b011011 if f3 != 0b011 => Op::Vmslt,
            0b011100 => Op::Vmsleu, // vv/vx/vi
            0b011101 => Op::Vmsle,
            0b011110 if f3 != 0b000 => Op::Vmsgtu, // vx/vi
            0b011111 if f3 != 0b000 => Op::Vmsgt,
            // Slides (vx/vi forms; OPIVV 0b001110 is vrgatherei16).
            0b001110 if f3 != 0b000 => Op::Vslideup,
            0b001111 if f3 != 0b000 => Op::Vslidedown,
            // Gathers: vrgather (vv/vx/vi), vrgatherei16 (vv only).
            0b001100 => Op::Vrgather,
            0b001110 if f3 == 0b000 => Op::Vrgatherei16,
            // Widening integer sum reductions (.vs form, OPIVV only).
            0b110000 if f3 == 0b000 => Op::Vwredsumu,
            0b110001 if f3 == 0b000 => Op::Vwredsum,
            // Add/subtract with carry/borrow (vsbc/vmsbc have no immediate form).
            0b010000 => Op::Vadc,
            0b010001 => Op::Vmadc,
            0b010010 if f3 != 0b011 => Op::Vsbc,
            0b010011 if f3 != 0b011 => Op::Vmsbc,
            // Saturating add/subtract (ssub variants have no immediate form).
            0b100000 => Op::Vsaddu,
            0b100001 => Op::Vsadd,
            0b100010 if f3 != 0b011 => Op::Vssubu,
            0b100011 if f3 != 0b011 => Op::Vssub,
            // Scaling shift right (vv/vx/vi) and fractional multiply (vv/vx).
            0b101010 => Op::Vssrl,
            0b101011 => Op::Vssra,
            0b100111 if f3 != 0b011 => Op::Vsmul,
            0b100111 if f3 == 0b011 => Op::Vmvr, // vmv<nr>r.v whole-register move
            // Narrowing shift / clip (wide 2*SEW vs2 source).
            0b101100 => Op::Vnsrl,
            0b101101 => Op::Vnsra,
            0b101110 => Op::Vnclipu,
            0b101111 => Op::Vnclip,
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    // OPMVV(010) / OPMVX(110): integer multiply/divide.
    if f3 == 0b010 || f3 == 0b110 {
        let funct6 = w >> 26;
        let op = match funct6 {
            0b100101 => Op::Vmul,
            0b100111 => Op::Vmulh,
            0b100100 => Op::Vmulhu,
            0b100110 => Op::Vmulhsu,
            0b100000 => Op::Vdivu,
            0b100001 => Op::Vdiv,
            0b100010 => Op::Vremu,
            0b100011 => Op::Vrem,
            // Integer reductions are OPMVV-only (funct3 == 0b010).
            0b000000 if f3 == 0b010 => Op::Vredsum,
            0b000001 if f3 == 0b010 => Op::Vredand,
            0b000010 if f3 == 0b010 => Op::Vredor,
            0b000011 if f3 == 0b010 => Op::Vredxor,
            0b000100 if f3 == 0b010 => Op::Vredminu,
            0b000101 if f3 == 0b010 => Op::Vredmin,
            0b000110 if f3 == 0b010 => Op::Vredmaxu,
            0b000111 if f3 == 0b010 => Op::Vredmax,
            // Scalar element moves (VWXUNARY0 / VRXUNARY0), funct6 = 010000.
            0b010000 if f3 == 0b010 && (w >> 15) & 0x1f == 0 => Op::VmvXS,
            0b010000 if f3 == 0b010 && (w >> 15) & 0x1f == 0b10000 => Op::Vcpop,
            0b010000 if f3 == 0b010 && (w >> 15) & 0x1f == 0b10001 => Op::Vfirst,
            0b010000 if f3 == 0b110 && (w >> 20) & 0x1f == 0 => Op::VmvSX,
            // Mask set / iota / id (VMUNARY0); vs1 field selects the variant.
            0b010100 if f3 == 0b010 => match (w >> 15) & 0x1f {
                0b00001 => Op::Vmsbf,
                0b00010 => Op::Vmsof,
                0b00011 => Op::Vmsif,
                0b10000 => Op::Viota,
                0b10001 => Op::Vid,
                _ => return Insn::illegal(w, 4),
            },
            // Averaging add/subtract (OPMVV/OPMVX).
            0b001000 => Op::Vaaddu,
            0b001001 => Op::Vaadd,
            0b001010 => Op::Vasubu,
            0b001011 => Op::Vasub,
            // Widening integer add/subtract (.w forms take a wide vs2).
            0b110000 => Op::Vwaddu,
            0b110001 => Op::Vwadd,
            0b110010 => Op::Vwsubu,
            0b110011 => Op::Vwsub,
            0b110100 => Op::VwadduW,
            0b110101 => Op::VwaddW,
            0b110110 => Op::VwsubuW,
            0b110111 => Op::VwsubW,
            // Widening multiply / multiply-accumulate (vwmaccus is vx-only).
            0b111000 => Op::Vwmulu,
            0b111010 => Op::Vwmulsu,
            0b111011 => Op::Vwmul,
            0b111100 => Op::Vwmaccu,
            0b111101 => Op::Vwmacc,
            0b111110 if f3 == 0b110 => Op::Vwmaccus,
            0b111111 => Op::Vwmaccsu,
            // Slide-by-one (OPMVX form, funct3 == 0b110).
            0b001110 if f3 == 0b110 => Op::Vslide1up,
            0b001111 if f3 == 0b110 => Op::Vslide1down,
            // Compress active vs2 elements into vd (OPMVV).
            0b010111 if f3 == 0b010 => Op::Vcompress,
            // Mask-register logical ops are OPMVV-only (funct3 == 0b010).
            0b011000 if f3 == 0b010 => Op::Vmandn,
            0b011001 if f3 == 0b010 => Op::Vmand,
            0b011010 if f3 == 0b010 => Op::Vmor,
            0b011011 if f3 == 0b010 => Op::Vmxor,
            0b011100 if f3 == 0b010 => Op::Vmorn,
            0b011101 if f3 == 0b010 => Op::Vmnand,
            0b011110 if f3 == 0b010 => Op::Vmnor,
            0b011111 if f3 == 0b010 => Op::Vmxnor,
            // Integer extension (VXUNARY0); the vs1 field selects the variant.
            0b010010 if f3 == 0b010 => match (w >> 15) & 0x1f {
                0b00010 => Op::VzextVf8,
                0b00011 => Op::VsextVf8,
                0b00100 => Op::VzextVf4,
                0b00101 => Op::VsextVf4,
                0b00110 => Op::VzextVf2,
                0b00111 => Op::VsextVf2,
                _ => return Insn::illegal(w, 4),
            },
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    // OPFVV(001) / OPFVF(101): floating-point arithmetic.
    if f3 == 0b001 || f3 == 0b101 {
        let vf = f3 == 0b101;
        let funct6 = w >> 26;
        let vs1 = (w >> 15) & 0x1f;
        let op = match funct6 {
            0b000000 => Op::Vfadd,
            0b000010 => Op::Vfsub,
            0b100111 if vf => Op::Vfrsub,
            0b001110 if vf => Op::Vfslide1up,
            0b001111 if vf => Op::Vfslide1down,
            // Widening FP arithmetic.
            0b110000 => Op::Vfwadd,
            0b110010 => Op::Vfwsub,
            0b110100 => Op::VfwaddW,
            0b110110 => Op::VfwsubW,
            0b111000 => Op::Vfwmul,
            0b111100 => Op::Vfwmacc,
            0b111101 => Op::Vfwnmacc,
            0b111110 => Op::Vfwmsac,
            0b111111 => Op::Vfwnmsac,
            0b100100 => Op::Vfmul,
            0b100000 => Op::Vfdiv,
            0b100001 if vf => Op::Vfrdiv,
            0b000100 => Op::Vfmin,
            0b000110 => Op::Vfmax,
            0b001000 => Op::Vfsgnj,
            0b001001 => Op::Vfsgnjn,
            0b001010 => Op::Vfsgnjx,
            0b011000 => Op::Vmfeq,
            0b011001 => Op::Vmfle,
            0b011011 => Op::Vmflt,
            0b011100 => Op::Vmfne,
            0b011101 if vf => Op::Vmfgt,
            0b011111 if vf => Op::Vmfge,
            0b101100 => Op::Vfmacc,
            0b101101 => Op::Vfnmacc,
            0b101110 => Op::Vfmsac,
            0b101111 => Op::Vfnmsac,
            0b101000 => Op::Vfmadd,
            0b101001 => Op::Vfnmadd,
            0b101010 => Op::Vfmsub,
            0b101011 => Op::Vfnmsub,
            // FP reductions are OPFVV-only (.vs form).
            0b000001 if !vf => Op::Vfredusum,
            0b000011 if !vf => Op::Vfredosum,
            0b000101 if !vf => Op::Vfredmin,
            0b000111 if !vf => Op::Vfredmax,
            0b110001 if !vf => Op::Vfwredusum,
            0b110011 if !vf => Op::Vfwredosum,
            // FP scalar element moves (VWFUNARY0 / VRFUNARY0), funct6 = 010000.
            0b010000 if !vf && vs1 == 0 => Op::VfmvFS,
            0b010000 if vf && (w >> 20) & 0x1f == 0 => Op::VfmvSF,
            // OPFVF merge form: vfmv.v.f vd, rs1 (funct6 = 010111, vm=1,
            // vs2=0). The masked code point is not defined in the f form.
            0b010111 if vf && (w >> 25) & 1 == 1 && (w >> 20) & 0x1f == 0 => Op::Vmerge,
            // Single-width conversions (VFUNARY0); vs1 field selects the variant.
            0b010010 if !vf => match vs1 {
                0b00000 => Op::VfcvtXuF,
                0b00001 => Op::VfcvtXF,
                0b00010 => Op::VfcvtFXu,
                0b00011 => Op::VfcvtFX,
                0b00110 => Op::VfcvtRtzXuF,
                0b00111 => Op::VfcvtRtzXF,
                0b01000 => Op::VfwcvtXuF,
                0b01001 => Op::VfwcvtXF,
                0b01010 => Op::VfwcvtFXu,
                0b01011 => Op::VfwcvtFX,
                0b01100 => Op::VfwcvtFF,
                0b01110 => Op::VfwcvtRtzXuF,
                0b01111 => Op::VfwcvtRtzXF,
                0b10000 => Op::VfncvtXuF,
                0b10001 => Op::VfncvtXF,
                0b10010 => Op::VfncvtFXu,
                0b10011 => Op::VfncvtFX,
                0b10100 => Op::VfncvtFF,
                0b10101 => Op::VfncvtRodFF,
                0b10110 => Op::VfncvtRtzXuF,
                0b10111 => Op::VfncvtRtzXF,
                _ => return Insn::illegal(w, 4),
            },
            0b010011 if !vf && vs1 == 0 => Op::Vfsqrt,
            0b010011 if !vf && vs1 == 0b00100 => Op::Vfrsqrt7,
            0b010011 if !vf && vs1 == 0b00101 => Op::Vfrec7,
            0b010011 if !vf && vs1 == 0b10000 => Op::Vfclass,
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    if f3 != 0b111 {
        return Insn::illegal(w, 4);
    }
    if (w >> 31) & 1 == 0 {
        // vsetvli: 11-bit vtypei in bits[30:20].
        let mut i = base(Op::Vsetvli, w);
        i.imm = ((w >> 20) & 0x7ff) as i64;
        i
    } else if (w >> 30) & 1 == 1 {
        // vsetivli: 10-bit vtypei in bits[29:20]; AVL is the 5-bit rs1 field.
        let mut i = base(Op::Vsetivli, w);
        i.imm = ((w >> 20) & 0x3ff) as i64;
        i
    } else if (w >> 25) & 0x3f == 0 {
        // vsetvl: vtype comes from rs2.
        base(Op::Vsetvl, w)
    } else {
        Insn::illegal(w, 4)
    }
}

#[inline]
fn with_imm(op: Op, w: u32, imm: i64) -> Insn {
    let mut i = base(op, w);
    i.imm = imm;
    i
}

fn decode_branch(w: u32) -> Insn {
    let op = match funct3(w) {
        0 => Op::Beq,
        1 => Op::Bne,
        4 => Op::Blt,
        5 => Op::Bge,
        6 => Op::Bltu,
        7 => Op::Bgeu,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_b(w))
}

fn decode_load(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let op = match funct3(w) {
        0 => Op::Lb,
        1 => Op::Lh,
        2 => Op::Lw,
        3 if rv64 => Op::Ld,
        3 if isa.zilsd && rd(w) & 1 == 0 => Op::LdPair,
        4 => Op::Lbu,
        5 => Op::Lhu,
        6 if rv64 => Op::Lwu,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_i(w))
}

fn decode_store(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let op = match funct3(w) {
        0 => Op::Sb,
        1 => Op::Sh,
        2 => Op::Sw,
        3 if rv64 => Op::Sd,
        3 if isa.zilsd && rs2(w) & 1 == 0 => Op::SdPair,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_s(w))
}

// OP (R-type): base, M, Zba/Zbb/Zbc/Zbs overlays.
fn decode_op(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    let f7 = funct7(w);
    // M extension.
    if isa.m && f7 == 0b0000001 {
        let op = match f3 {
            0 => Op::Mul,
            1 => Op::Mulh,
            2 => Op::Mulhsu,
            3 => Op::Mulhu,
            4 => Op::Div,
            5 => Op::Divu,
            6 => Op::Rem,
            7 => Op::Remu,
            _ => unreachable!(),
        };
        return base(op, w);
    }
    // Zba.
    if isa.zba && f7 == 0b0010000 {
        let op = match f3 {
            2 => Op::Sh1add,
            4 => Op::Sh2add,
            6 => Op::Sh3add,
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    // Zbb logical-with-negate.
    if isa.zbb && f7 == 0b0100000 {
        match f3 {
            7 => return base(Op::Andn, w),
            6 => return base(Op::Orn, w),
            4 => return base(Op::Xnor, w),
            _ => {}
        }
    }
    // Zbb rotate.
    if isa.zbb && f7 == 0b0110000 {
        match f3 {
            1 => return base(Op::Rol, w),
            5 => return base(Op::Ror, w),
            _ => {}
        }
    }
    // Zbb min/max and Zbc carry-less multiply share funct7=0b0000101.
    if f7 == 0b0000101 {
        if isa.zbc {
            match f3 {
                1 => return base(Op::Clmul, w),
                2 => return base(Op::Clmulr, w),
                3 => return base(Op::Clmulh, w),
                _ => {}
            }
        }
        if isa.zbb {
            match f3 {
                4 => return base(Op::Min, w),
                5 => return base(Op::Minu, w),
                6 => return base(Op::Max, w),
                7 => return base(Op::Maxu, w),
                _ => {}
            }
        }
    }
    // Zbs single-bit (register).
    if isa.zbs {
        match (f7, f3) {
            (0b0100100, 1) => return base(Op::Bclr, w),
            (0b0100100, 5) => return base(Op::Bext, w),
            (0b0110100, 1) => return base(Op::Binv, w),
            (0b0010100, 1) => return base(Op::Bset, w),
            _ => {}
        }
    }
    // Zicond integer conditional.
    if isa.zicond && f7 == 0b0000111 {
        match f3 {
            5 => return base(Op::CzeroEqz, w),
            7 => return base(Op::CzeroNez, w),
            _ => {}
        }
    }
    // Zknh SHA-512 RV32 register-pair helpers.
    if isa.zknh && !rv64 && f3 == 0 {
        match f7 {
            0x28 => return base(Op::Sha512Sum0r, w),
            0x29 => return base(Op::Sha512Sum1r, w),
            0x2a => return base(Op::Sha512Sig0l, w),
            0x2b => return base(Op::Sha512Sig1l, w),
            0x2e => return base(Op::Sha512Sig0h, w),
            0x2f => return base(Op::Sha512Sig1h, w),
            _ => {}
        }
    }
    // Zbkb pack/packh.
    if isa.zbkb && f7 == 0b0000100 {
        match f3 {
            4 => return base(Op::Pack, w),
            7 => return base(Op::Packh, w),
            _ => {}
        }
    }
    // Zbkx crossbar permute.
    if isa.zbkx && f7 == 0b0010100 {
        match f3 {
            2 => return base(Op::Xperm4, w),
            4 => return base(Op::Xperm8, w),
            _ => {}
        }
    }
    if f3 == 0 {
        // AES-32 round helpers (Zkne / Zknd), RV32-only. funct7[6:5] is `bs`.
        if !rv64 {
            let bs = (f7 >> 5) as i64;
            match f7 {
                0b0010001 | 0b0110001 | 0b1010001 | 0b1110001 if isa.zkne => {
                    return with_imm(Op::Aes32esi, w, bs);
                }
                0b0010011 | 0b0110011 | 0b1010011 | 0b1110011 if isa.zkne => {
                    return with_imm(Op::Aes32esmi, w, bs);
                }
                0b0010101 | 0b0110101 | 0b1010101 | 0b1110101 if isa.zknd => {
                    return with_imm(Op::Aes32dsi, w, bs);
                }
                0b0010111 | 0b0110111 | 0b1010111 | 0b1110111 if isa.zknd => {
                    return with_imm(Op::Aes32dsmi, w, bs);
                }
                _ => {}
            }
        }
        // AES-64 round / key-schedule (Zkne / Zknd), RV64-only.
        if rv64 {
            match f7 {
                0b0011001 if isa.zkne => return base(Op::Aes64es, w),
                0b0011011 if isa.zkne => return base(Op::Aes64esm, w),
                0b0011101 if isa.zknd => return base(Op::Aes64ds, w),
                0b0011111 if isa.zknd => return base(Op::Aes64dsm, w),
                0b0111111 if isa.zkne || isa.zknd => return base(Op::Aes64ks2, w),
                _ => {}
            }
        }
        // SM4 (Zksed): funct7 low 5 bits select ed/ks, top 2 bits carry `bs`.
        if isa.zksed {
            let bs = (f7 >> 5) as i64;
            match f7 & 0b0011111 {
                0b11000 => return with_imm(Op::Sm4ed, w, bs),
                0b11010 => return with_imm(Op::Sm4ks, w, bs),
                _ => {}
            }
        }
    }
    // Zihintntl: ADD x0, x0, x2..x5.
    if isa.zihintntl && f7 == 0 && f3 == 0 && rd(w) == 0 && rs1(w) == 0 {
        match rs2(w) {
            2 => return base(Op::NtlP1, w),
            3 => return base(Op::NtlPall, w),
            4 => return base(Op::NtlS1, w),
            5 => return base(Op::NtlAll, w),
            _ => {}
        }
    }
    // Hazard3 Xh3power hints: SLT x0, x0, x0/x1.
    if isa.xhazard3 && f7 == 0 && f3 == 2 && rd(w) == 0 && rs1(w) == 0 {
        match rs2(w) {
            0 => return base(Op::H3Block, w),
            1 => return base(Op::H3Unblock, w),
            _ => {}
        }
    }
    // Base RV32I/RV64I.
    let op = match (f7, f3) {
        (0b0000000, 0) => Op::Add,
        (0b0100000, 0) => Op::Sub,
        (0b0000000, 1) => Op::Sll,
        (0b0000000, 2) => Op::Slt,
        (0b0000000, 3) => Op::Sltu,
        (0b0000000, 4) => Op::Xor,
        (0b0000000, 5) => Op::Srl,
        (0b0100000, 5) => Op::Sra,
        (0b0000000, 6) => Op::Or,
        (0b0000000, 7) => Op::And,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

// OP-32 (RV64 R-type word ops): base, M, Zba/Zbb overlays.
fn decode_op32(w: u32, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    let f7 = funct7(w);
    if isa.m && f7 == 0b0000001 {
        let op = match f3 {
            0 => Op::Mulw,
            4 => Op::Divw,
            5 => Op::Divuw,
            6 => Op::Remw,
            7 => Op::Remuw,
            _ => return Insn::illegal(w, 4),
        };
        return base(op, w);
    }
    if isa.zba {
        match (f7, f3) {
            (0b0000100, 0) => return base(Op::AddUw, w),
            (0b0010000, 2) => return base(Op::Sh1addUw, w),
            (0b0010000, 4) => return base(Op::Sh2addUw, w),
            (0b0010000, 6) => return base(Op::Sh3addUw, w),
            _ => {}
        }
    }
    if isa.zbb {
        // ZEXT.H (RV64): funct7=0b0000100, funct3=4, rs2=0.
        if f7 == 0b0000100 && f3 == 4 && rs2(w) == 0 {
            return base(Op::ZextH, w);
        }
        if f7 == 0b0110000 {
            match f3 {
                1 => return base(Op::Rolw, w),
                5 => return base(Op::Rorw, w),
                _ => {}
            }
        }
    }
    // Zbkb packw (RV64): funct7=0b0000100, funct3=4, rs2 != 0.
    if isa.zbkb && f7 == 0b0000100 && f3 == 4 && rs2(w) != 0 {
        return base(Op::Packw, w);
    }
    let op = match (f7, f3) {
        (0b0000000, 0) => Op::Addw,
        (0b0100000, 0) => Op::Subw,
        (0b0000000, 1) => Op::Sllw,
        (0b0000000, 2) if isa.xida_sltw => Op::Sltw,
        (0b0000000, 5) => Op::Srlw,
        (0b0100000, 5) => Op::Sraw,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

fn decode_fence(w: u32, isa: &Isa) -> Insn {
    match funct3(w) {
        0 if isa.zihintpause
            && rd(w) == 0
            && rs1(w) == 0
            && ((w >> 28) & 0xf) == 0
            && ((w >> 24) & 0xf) == 1
            && ((w >> 20) & 0xf) == 0 =>
        {
            base(Op::Pause, w)
        }
        0 => base(Op::Fence, w),
        1 if isa.zifencei => base(Op::FenceI, w),
        2 if rd(w) == 0 && funct7(w) == 0 => match rs2(w) {
            0 if isa.zicbom => base(Op::CboInval, w),
            1 if isa.zicbom => base(Op::CboClean, w),
            2 if isa.zicbom => base(Op::CboFlush, w),
            4 if isa.zicboz => base(Op::CboZero, w),
            _ => Insn::illegal(w, 4),
        },
        _ => Insn::illegal(w, 4),
    }
}

fn decode_system(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    if f3 == 0 {
        // PRIV: distinguished by funct7/rs2 and requires rd == x0.
        if rd(w) != 0 {
            return Insn::illegal(w, 4);
        }
        return match funct7(w) {
            0x00 if rs1(w) == 0 => match rs2(w) {
                0x00 => base(Op::Ecall, w),
                0x01 => base(Op::Ebreak, w),
                0x0d if isa.zawrs => base(Op::WrsNto, w),
                0x1d if isa.zawrs => base(Op::WrsSto, w),
                _ => Insn::illegal(w, 4),
            },
            0x08 if rs1(w) == 0 && rs2(w) == 0x02 => base(Op::Sret, w),
            0x08 if rs1(w) == 0 && rs2(w) == 0x05 => base(Op::Wfi, w),
            0x09 => base(Op::SfenceVma, w),
            0x0b if isa.svinval => base(Op::SinvalVma, w),
            0x0c if isa.svinval && rs1(w) == 0 && rs2(w) == 0 => base(Op::SfenceWInval, w),
            0x0c if isa.svinval && rs1(w) == 0 && rs2(w) == 1 => base(Op::SfenceInvalIr, w),
            0x11 if isa.h => base(Op::HfenceVvma, w),
            0x13 if isa.h => base(Op::HinvalVvma, w),
            0x18 if rs1(w) == 0 && rs2(w) == 0x02 => base(Op::Mret, w),
            0x31 if isa.h => base(Op::HfenceGvma, w),
            0x33 if isa.h => base(Op::HinvalGvma, w),
            _ => Insn::illegal(w, 4),
        };
    }
    if f3 == 4 && isa.h {
        return decode_hypervisor_mem(w, rv64);
    }
    if !isa.zicsr {
        return Insn::illegal(w, 4);
    }
    let op = match f3 {
        1 => Op::Csrrw,
        2 => Op::Csrrs,
        3 => Op::Csrrc,
        5 => Op::Csrrwi,
        6 => Op::Csrrsi,
        7 => Op::Csrrci,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

fn decode_amo(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    let funct5 = (w >> 27) & 0x1f;
    let width = match f3 {
        0b010 => 4, // .W
        0b011 if rv64 => 8,
        0b100 if rv64 => 16,
        _ => return Insn::illegal(w, 4),
    };
    let op = match (funct5, width) {
        (0b00010, 4) => Op::LrW,
        (0b00011, 4) => Op::ScW,
        (0b00001, 4) => Op::AmoswapW,
        (0b00000, 4) => Op::AmoaddW,
        (0b00100, 4) => Op::AmoxorW,
        (0b01100, 4) => Op::AmoandW,
        (0b01000, 4) => Op::AmoorW,
        (0b10000, 4) => Op::AmominW,
        (0b10100, 4) => Op::AmomaxW,
        (0b11000, 4) => Op::AmominuW,
        (0b11100, 4) => Op::AmomaxuW,
        (0b00101, 4) if isa.zacas => Op::AmocasW,
        (0b00010, 8) => Op::LrD,
        (0b00011, 8) => Op::ScD,
        (0b00001, 8) => Op::AmoswapD,
        (0b00000, 8) => Op::AmoaddD,
        (0b00100, 8) => Op::AmoxorD,
        (0b01100, 8) => Op::AmoandD,
        (0b01000, 8) => Op::AmoorD,
        (0b10000, 8) => Op::AmominD,
        (0b10100, 8) => Op::AmomaxD,
        (0b11000, 8) => Op::AmominuD,
        (0b11100, 8) => Op::AmomaxuD,
        (0b00101, 8) if isa.zacas => Op::AmocasD,
        (0b00101, 16) if isa.zacas => Op::AmocasQ,
        _ => return Insn::illegal(w, 4),
    };
    // LR requires rs2 == 0.
    if matches!(op, Op::LrW | Op::LrD) && rs2(w) != 0 {
        return Insn::illegal(w, 4);
    }
    if matches!(op, Op::AmocasQ) && (rd(w) & 1 != 0 || rs2(w) & 1 != 0) {
        return Insn::illegal(w, 4);
    }
    base(op, w)
}

fn decode_load_fp(w: u32, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    // Vector unit-stride load (width 8/16/32/64 in funct3).
    if isa.v && matches!(f3, 0 | 5 | 6 | 7) {
        let nf = (w >> 29) & 7;
        let mop = (w >> 26) & 3;
        let lumop = (w >> 20) & 0x1f;
        return match mop {
            0b00 => match lumop {
                0b00000 if nf == 0 => base(Op::Vle, w),
                0b00000 => base(Op::Vlseg, w), // unit-stride segment (nf+1 fields)
                0b01000 => base(Op::Vlre, w),  // whole register (nf+1 regs)
                0b01011 if nf == 0 => base(Op::Vlm, w),
                0b10000 if nf == 0 => base(Op::Vleff, w), // fault-only-first
                0b10000 => base(Op::Vlseg, w),            // segment fault-only-first
                _ => Insn::illegal(w, 4),
            },
            0b10 if nf == 0 => base(Op::Vlse, w), // strided
            0b10 => base(Op::Vlseg, w),           // strided segment
            0b01 | 0b11 if nf == 0 => base(Op::Vlxei, w), // indexed
            0b01 | 0b11 => base(Op::Vlseg, w),    // indexed segment
            _ => Insn::illegal(w, 4),
        };
    }
    let op = match f3 {
        1 if isa.f && isa.zfh => Op::Flh,
        2 if isa.f => Op::Flw,
        3 if isa.f && isa.d => Op::Fld,
        4 if isa.f && isa.q => Op::Flq,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_i(w))
}

fn decode_store_fp(w: u32, isa: &Isa) -> Insn {
    let f3 = funct3(w);
    // Vector unit-stride store (width 8/16/32/64 in funct3).
    if isa.v && matches!(f3, 0 | 5 | 6 | 7) {
        let nf = (w >> 29) & 7;
        let mop = (w >> 26) & 3;
        let sumop = (w >> 20) & 0x1f;
        return match mop {
            0b00 => match sumop {
                0b00000 if nf == 0 => base(Op::Vse, w),
                0b00000 => base(Op::Vsseg, w), // unit-stride segment
                0b01000 => base(Op::Vsre, w),  // whole register
                0b01011 if nf == 0 => base(Op::Vsm, w),
                _ => Insn::illegal(w, 4),
            },
            0b10 if nf == 0 => base(Op::Vsse, w), // strided
            0b10 => base(Op::Vsseg, w),           // strided segment
            0b01 | 0b11 if nf == 0 => base(Op::Vsxei, w), // indexed
            0b01 | 0b11 => base(Op::Vsseg, w),    // indexed segment
            _ => Insn::illegal(w, 4),
        };
    }
    let op = match f3 {
        1 if isa.f && isa.zfh => Op::Fsh,
        2 if isa.f => Op::Fsw,
        3 if isa.f && isa.d => Op::Fsd,
        4 if isa.f && isa.q => Op::Fsq,
        _ => return Insn::illegal(w, 4),
    };
    with_imm(op, w, imm_s(w))
}

fn decode_fma(single: Op, double: Op, half: Op, quad: Op, w: u32, isa: &Isa) -> Insn {
    match funct2(w) {
        0b00 => base(single, w),
        0b01 if isa.d => base(double, w),
        0b10 if isa.zfh => base(half, w),
        0b11 if isa.q => base(quad, w),
        _ => Insn::illegal(w, 4),
    }
}

// OP-FP (0x53): selected by funct7, with funct3 reused as rm or sub-op.
/// Zfa additional FP ops layered over the OP-FP encoding space.
fn decode_zfa(f7: u32, f3: u8, rs2f: u8, isa: &Isa) -> Option<Op> {
    Some(match (f7, f3, rs2f) {
        (0b0010100, 2, _) => Op::FminmS,
        (0b0010100, 3, _) => Op::FmaxmS,
        (0b0010101, 2, _) if isa.d => Op::FminmD,
        (0b0010101, 3, _) if isa.d => Op::FmaxmD,
        (0b0100000, _, 4) => Op::FroundS,
        (0b0100000, _, 5) => Op::FroundnxS,
        (0b0100001, _, 4) if isa.d => Op::FroundD,
        (0b0100001, _, 5) if isa.d => Op::FroundnxD,
        (0b1010000, 4, _) => Op::FleqS,
        (0b1010000, 5, _) => Op::FltqS,
        (0b1010001, 4, _) if isa.d => Op::FleqD,
        (0b1010001, 5, _) if isa.d => Op::FltqD,
        (0b1111000, 0, 1) => Op::FliS,
        (0b1111001, 0, 1) if isa.d => Op::FliD,
        (0b1100001, 1, 8) if isa.d => Op::FcvtmodWD,
        _ => return None,
    })
}

/// Zfh half-precision ops layered over the OP-FP encoding space (`fmt = 10`).
fn decode_zfh(f7: u32, f3: u8, rs2f: u8, rv64: bool, isa: &Isa) -> Option<Op> {
    let zfa = isa.zfa;
    Some(match (f7, f3, rs2f) {
        (0b0000010, _, _) => Op::FaddH,
        (0b0000110, _, _) => Op::FsubH,
        (0b0001010, _, _) => Op::FmulH,
        (0b0001110, _, _) => Op::FdivH,
        (0b0101110, _, 0) => Op::FsqrtH,
        (0b0010010, 0, _) => Op::FsgnjH,
        (0b0010010, 1, _) => Op::FsgnjnH,
        (0b0010010, 2, _) => Op::FsgnjxH,
        (0b0010110, 0, _) => Op::FminH,
        (0b0010110, 1, _) => Op::FmaxH,
        (0b0010110, 2, _) if zfa => Op::FminmH,
        (0b0010110, 3, _) if zfa => Op::FmaxmH,
        (0b0100000, _, 2) => Op::FcvtSH,
        (0b0100010, _, 0) => Op::FcvtHS,
        (0b0100001, _, 2) if isa.d => Op::FcvtDH,
        (0b0100010, _, 1) if isa.d => Op::FcvtHD,
        (0b0100010, _, 3) if isa.q => Op::FcvtHQ,
        (0b0100010, _, 4) if zfa => Op::FroundH,
        (0b0100010, _, 5) if zfa => Op::FroundnxH,
        (0b1100010, _, 0) => Op::FcvtWH,
        (0b1100010, _, 1) => Op::FcvtWuH,
        (0b1100010, _, 2) if rv64 => Op::FcvtLH,
        (0b1100010, _, 3) if rv64 => Op::FcvtLuH,
        (0b1101010, _, 0) => Op::FcvtHW,
        (0b1101010, _, 1) => Op::FcvtHWu,
        (0b1101010, _, 2) if rv64 => Op::FcvtHL,
        (0b1101010, _, 3) if rv64 => Op::FcvtHLu,
        (0b1110010, 0, 0) => Op::FmvXH,
        (0b1110010, 1, 0) => Op::FclassH,
        (0b1111010, 0, 0) => Op::FmvHX,
        (0b1111010, 0, 1) if zfa => Op::FliH,
        (0b1010010, 0, _) => Op::FleH,
        (0b1010010, 1, _) => Op::FltH,
        (0b1010010, 2, _) => Op::FeqH,
        (0b1010010, 4, _) if zfa => Op::FleqH,
        (0b1010010, 5, _) if zfa => Op::FltqH,
        _ => return None,
    })
}

fn decode_op_fp(w: u32, rv64: bool, isa: &Isa) -> Insn {
    let f7 = funct7(w);
    let f3 = funct3(w);
    let rs2f = rs2(w);
    let d = isa.d;
    if isa.zfa {
        if let Some(op) = decode_zfa_rv32_move(f7, f3, rs2f, rv64, isa) {
            return base(op, w);
        }
        if let Some(op) = decode_zfa(f7, f3, rs2f, isa) {
            return base(op, w);
        }
    }
    if isa.zfh {
        if let Some(op) = decode_zfh(f7, f3, rs2f, rv64, isa) {
            return base(op, w);
        }
    }
    let op = match f7 {
        0b0000000 => Op::FaddS,
        0b0000001 if d => Op::FaddD,
        0b0000011 if isa.q => Op::FaddQ,
        0b0000100 => Op::FsubS,
        0b0000101 if d => Op::FsubD,
        0b0000111 if isa.q => Op::FsubQ,
        0b0001000 => Op::FmulS,
        0b0001001 if d => Op::FmulD,
        0b0001011 if isa.q => Op::FmulQ,
        0b0001100 => Op::FdivS,
        0b0001101 if d => Op::FdivD,
        0b0001111 if isa.q => Op::FdivQ,
        0b0101100 if rs2f == 0 => Op::FsqrtS,
        0b0101101 if d && rs2f == 0 => Op::FsqrtD,
        0b0101111 if isa.q && rs2f == 0 => Op::FsqrtQ,
        0b0010000 => match f3 {
            0 => Op::FsgnjS,
            1 => Op::FsgnjnS,
            2 => Op::FsgnjxS,
            _ => return Insn::illegal(w, 4),
        },
        0b0010001 if d => match f3 {
            0 => Op::FsgnjD,
            1 => Op::FsgnjnD,
            2 => Op::FsgnjxD,
            _ => return Insn::illegal(w, 4),
        },
        0b0010011 if isa.q => match f3 {
            0 => Op::FsgnjQ,
            1 => Op::FsgnjnQ,
            2 => Op::FsgnjxQ,
            _ => return Insn::illegal(w, 4),
        },
        0b0010100 => match f3 {
            0 => Op::FminS,
            1 => Op::FmaxS,
            _ => return Insn::illegal(w, 4),
        },
        0b0010101 if d => match f3 {
            0 => Op::FminD,
            1 => Op::FmaxD,
            _ => return Insn::illegal(w, 4),
        },
        0b0010111 if isa.q => match f3 {
            0 => Op::FminQ,
            1 => Op::FmaxQ,
            _ => return Insn::illegal(w, 4),
        },
        0b0100000 if d && rs2f == 1 => Op::FcvtSD,
        0b0100000 if isa.q && rs2f == 3 => Op::FcvtSQ,
        0b0100001 if d && rs2f == 0 => Op::FcvtDS,
        0b0100001 if d && isa.q && rs2f == 3 => Op::FcvtDQ,
        0b0100011 if isa.q => match rs2f {
            0 => Op::FcvtQS,
            1 if d => Op::FcvtQD,
            2 if isa.zfh => Op::FcvtQH,
            _ => return Insn::illegal(w, 4),
        },
        0b1100000 => match rs2f {
            0 => Op::FcvtWS,
            1 => Op::FcvtWuS,
            2 if rv64 => Op::FcvtLS,
            3 if rv64 => Op::FcvtLuS,
            _ => return Insn::illegal(w, 4),
        },
        0b1100001 if d => match rs2f {
            0 => Op::FcvtWD,
            1 => Op::FcvtWuD,
            2 if rv64 => Op::FcvtLD,
            3 if rv64 => Op::FcvtLuD,
            _ => return Insn::illegal(w, 4),
        },
        0b1100011 if isa.q => match rs2f {
            0 => Op::FcvtWQ,
            1 => Op::FcvtWuQ,
            2 if rv64 => Op::FcvtLQ,
            3 if rv64 => Op::FcvtLuQ,
            _ => return Insn::illegal(w, 4),
        },
        0b1101000 => match rs2f {
            0 => Op::FcvtSW,
            1 => Op::FcvtSWu,
            2 if rv64 => Op::FcvtSL,
            3 if rv64 => Op::FcvtSLu,
            _ => return Insn::illegal(w, 4),
        },
        0b1101001 if d => match rs2f {
            0 => Op::FcvtDW,
            1 => Op::FcvtDWu,
            2 if rv64 => Op::FcvtDL,
            3 if rv64 => Op::FcvtDLu,
            _ => return Insn::illegal(w, 4),
        },
        0b1101011 if isa.q => match rs2f {
            0 => Op::FcvtQW,
            1 => Op::FcvtQWu,
            2 if rv64 => Op::FcvtQL,
            3 if rv64 => Op::FcvtQLu,
            _ => return Insn::illegal(w, 4),
        },
        0b1110000 if rs2f == 0 => match f3 {
            0 => Op::FmvXW,
            1 => Op::FclassS,
            _ => return Insn::illegal(w, 4),
        },
        0b1110001 if d && rs2f == 0 => match f3 {
            0 if rv64 => Op::FmvXD,
            1 => Op::FclassD,
            _ => return Insn::illegal(w, 4),
        },
        0b1110011 if isa.q && rs2f == 0 => match f3 {
            1 => Op::FclassQ,
            _ => return Insn::illegal(w, 4),
        },
        0b1010000 => match f3 {
            0 => Op::FleS,
            1 => Op::FltS,
            2 => Op::FeqS,
            _ => return Insn::illegal(w, 4),
        },
        0b1010001 if d => match f3 {
            0 => Op::FleD,
            1 => Op::FltD,
            2 => Op::FeqD,
            _ => return Insn::illegal(w, 4),
        },
        0b1010011 if isa.q => match f3 {
            0 => Op::FleQ,
            1 => Op::FltQ,
            2 => Op::FeqQ,
            _ => return Insn::illegal(w, 4),
        },
        0b1111000 if rs2f == 0 && f3 == 0 => Op::FmvWX,
        0b1111001 if d && rv64 && rs2f == 0 && f3 == 0 => Op::FmvDX,
        _ => return Insn::illegal(w, 4),
    };
    base(op, w)
}

/// Fetch and decode the instruction at `pc`, selecting 16- or 32-bit width.
pub fn decode_at(mem: &dyn Memory, pc: u64, xlen: Xlen, isa: &Isa) -> Result<Insn, DecodeError> {
    let lo = mem.read_u16(pc).map_err(DecodeError::Fetch)?;
    if lo & 0b11 != 0b11 {
        // 16-bit compressed parcel.
        return Ok(decode_compressed(lo, xlen, isa));
    }
    let hi = mem.read_u16(pc + 2).map_err(DecodeError::Fetch)?;
    let w = (lo as u32) | ((hi as u32) << 16);
    Ok(decode(w, xlen, isa))
}

/// Decode a 16-bit compressed parcel. When `C` is disabled (or the parcel is
/// the reserved all-zero word) the result is an illegal instruction.
pub fn decode_compressed(half: u16, xlen: Xlen, isa: &Isa) -> Insn {
    if !isa.c || half == 0 {
        return Insn::illegal(half as u32, 2);
    }
    decode_rvc(half, xlen, isa)
}

/// Decode a non-zero 16-bit compressed parcel into the equivalent base
/// operation. Implemented in full by the C-extension phase.
fn decode_rvc(half: u16, xlen: Xlen, isa: &Isa) -> Insn {
    super::compressed::decode_rvc(half, xlen, isa)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(w: u32) -> Insn {
        decode(w, Xlen::Rv64, &Isa::rv64gc())
    }

    #[test]
    fn decode_addi() {
        // addi a0, a1, 5  => imm=5, rs1=11, rd=10, funct3=0, opcode=0x13
        let w = (5u32 << 20) | (11 << 15) | (0 << 12) | (10 << 7) | 0x13;
        let i = dec(w);
        assert_eq!(i.op, Op::Addi);
        assert_eq!(i.rd, 10);
        assert_eq!(i.rs1, 11);
        assert_eq!(i.imm, 5);
    }

    #[test]
    fn decode_add_sub() {
        let add = (1u32 << 20) | (2 << 15) | (0 << 12) | (3 << 7) | 0x33;
        assert_eq!(dec(add).op, Op::Add);
        let sub = (0b0100000u32 << 25) | (1 << 20) | (2 << 15) | (0 << 12) | (3 << 7) | 0x33;
        assert_eq!(dec(sub).op, Op::Sub);
    }

    #[test]
    fn decode_branch_imm() {
        // beq x1, x2, +8 : imm=8
        // imm[12|10:5]=funct7, imm[4:1|11]=rd-ish. Build via fields.
        // For +8: bit3 set. b4_1 = 0b0100 (=4 -> *2=8). b11=0,b12=0,b10_5=0.
        let b4_1 = 0b0100u32; // bits [4:1] => value 8
        let w = (b4_1 << 8) | (2 << 20) | (1 << 15) | (0 << 12) | 0x63;
        let i = dec(w);
        assert_eq!(i.op, Op::Beq);
        assert_eq!(i.imm, 8);
    }

    #[test]
    fn decode_m_mul() {
        let w = (0b0000001u32 << 25) | (2 << 20) | (1 << 15) | (0 << 12) | (3 << 7) | 0x33;
        assert_eq!(dec(w).op, Op::Mul);
    }

    #[test]
    fn decode_slli_rv64() {
        // slli a0, a1, 40 (6-bit shamt)
        let w = (40u32 << 20) | (11 << 15) | (1 << 12) | (10 << 7) | 0x13;
        let i = dec(w);
        assert_eq!(i.op, Op::Slli);
        assert_eq!(i.imm, 40);
    }

    #[test]
    fn decode_cbo_zero_requires_zicboz_and_full_funct12() {
        let cbo_zero = (0x004u32 << 20) | (10 << 15) | (2 << 12) | 0x0f;
        assert_eq!(dec(cbo_zero).op, Op::CboZero);

        let mut no_zicboz = Isa::rv64gc();
        no_zicboz.zicboz = false;
        assert!(decode(cbo_zero, Xlen::Rv64, &no_zicboz).is_illegal());

        let reserved_high_funct12 = cbo_zero | (1 << 31);
        assert_eq!((reserved_high_funct12 >> 20) & 0x1f, 4);
        assert!(decode(reserved_high_funct12, Xlen::Rv64, &Isa::rv64gc()).is_illegal());
        for reserved_funct7_bit in [1 << 25, 1 << 26] {
            assert!(
                decode(cbo_zero | reserved_funct7_bit, Xlen::Rv64, &Isa::rv64gc()).is_illegal()
            );
        }
    }

    #[test]
    fn decode_cbo_management_and_prefetch_hints() {
        let cbo = |rs2: u32| (rs2 << 20) | (10 << 15) | (2 << 12) | 0x0f;
        assert_eq!(dec(cbo(0)).op, Op::CboInval);
        assert_eq!(dec(cbo(1)).op, Op::CboClean);
        assert_eq!(dec(cbo(2)).op, Op::CboFlush);
        assert_eq!(dec(cbo(4)).op, Op::CboZero);
        for operation in [0, 1, 2, 4] {
            for reserved_funct7_bit in [1 << 25, 1 << 26] {
                assert!(dec(cbo(operation) | reserved_funct7_bit).is_illegal());
            }
        }

        let prefetch =
            |kind: u32, off: u32| (off << 25) | (kind << 20) | (10 << 15) | (6 << 12) | 0x13;
        let i = dec(prefetch(0, 0x7f));
        assert_eq!(i.op, Op::PrefetchI);
        assert_eq!(i.imm, -32);
        assert_eq!(dec(prefetch(1, 0)).op, Op::PrefetchR);
        assert_eq!(dec(prefetch(3, 0)).op, Op::PrefetchW);
    }

    #[test]
    fn vector_memory_decode_is_independent_of_f_and_accepts_segment_fof() {
        let mut vector_only = Isa::rv_i();
        vector_only.v = true;

        let vle8 = (1 << 25) | (10 << 15) | (1 << 7) | 0x07;
        let vse8 = (1 << 25) | (10 << 15) | (1 << 7) | 0x27;
        let vlseg2e8ff = 0x2305_0007;
        assert_eq!(decode(vle8, Xlen::Rv64, &vector_only).op, Op::Vle);
        assert_eq!(decode(vse8, Xlen::Rv64, &vector_only).op, Op::Vse);
        assert_eq!(decode(vlseg2e8ff, Xlen::Rv64, &vector_only).op, Op::Vlseg);

        let flw = (10 << 15) | (2 << 12) | (1 << 7) | 0x07;
        assert!(decode(flw, Xlen::Rv64, &vector_only).is_illegal());
    }

    #[test]
    fn decode_zawrs_zihintpause_zihintntl_and_zacas() {
        assert_eq!(dec(0x0100_000f).op, Op::Pause);
        assert_eq!(dec(0x00d0_0073).op, Op::WrsNto);
        assert_eq!(dec(0x01d0_0073).op, Op::WrsSto);
        assert_eq!(dec((2 << 20) | 0x33).op, Op::NtlP1);
        assert_eq!(dec((5 << 20) | 0x33).op, Op::NtlAll);

        let amocas = |funct3: u32, rd: u32, rs2: u32| {
            (0b00101 << 27) | (rs2 << 20) | (10 << 15) | (funct3 << 12) | (rd << 7) | 0x2f
        };
        assert_eq!(dec(amocas(0b010, 5, 6)).op, Op::AmocasW);
        assert_eq!(dec(amocas(0b011, 6, 8)).op, Op::AmocasD);
        assert_eq!(dec(amocas(0b100, 6, 8)).op, Op::AmocasQ);
        assert!(decode(amocas(0b100, 5, 8), Xlen::Rv64, &Isa::rv64gc()).is_illegal());
        assert!(decode(amocas(0b100, 6, 9), Xlen::Rv64, &Isa::rv64gc()).is_illegal());
    }

    #[test]
    fn decode_rv32_zilsd_load_store_pairs() {
        let mut isa = Isa::rv64gc();
        isa.zilsd = true;

        let load_pair = (8u32 << 20) | (10 << 15) | (3 << 12) | (6 << 7) | 0x03;
        let i = decode(load_pair, Xlen::Rv32, &isa);
        assert_eq!(i.op, Op::LdPair);
        assert_eq!(i.rd, 6);
        assert_eq!(i.rs1, 10);
        assert_eq!(i.imm, 8);

        let odd_load_pair = load_pair | (1 << 7);
        assert!(decode(odd_load_pair, Xlen::Rv32, &isa).is_illegal());

        let store_pair = (6 << 20) | (10 << 15) | (3 << 12) | (8 << 7) | 0x23;
        let i = decode(store_pair, Xlen::Rv32, &isa);
        assert_eq!(i.op, Op::SdPair);
        assert_eq!(i.rs1, 10);
        assert_eq!(i.rs2, 6);
        assert_eq!(i.imm, 8);

        let mut disabled = isa;
        disabled.zilsd = false;
        assert!(decode(load_pair, Xlen::Rv32, &disabled).is_illegal());
        assert!(decode(store_pair, Xlen::Rv32, &disabled).is_illegal());
    }

    // ---- Xsoteria decode edge cases ----

    fn enc(funct7: u32, f5: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (funct7 << 25) | (f5 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    #[test]
    fn decode_xida_sltw_is_opt_in_rv64_only() {
        let sltw = enc(0, 6, 5, 0b010, 7, 0x3b);
        assert!(decode(sltw, Xlen::Rv64, &Isa::rv64gc()).is_illegal());

        let mut isa = Isa::rv64gc();
        isa.xida_sltw = true;
        let i = decode(sltw, Xlen::Rv64, &isa);
        assert_eq!(i.op, Op::Sltw);
        assert_eq!(i.rd, 7);
        assert_eq!(i.rs1, 5);
        assert_eq!(i.rs2, 6);
        assert!(decode(sltw, Xlen::Rv32, &isa).is_illegal());
    }

    #[test]
    fn decode_rv32_aes32_scalar_crypto_is_gated() {
        let aes32esi = enc(0x11, 7, 6, 0, 5, 0x33);
        let aes32esmi = enc(0x33, 7, 6, 0, 5, 0x33);
        let aes32dsi = enc(0x55, 7, 6, 0, 5, 0x33);
        let aes32dsmi = enc(0x77, 7, 6, 0, 5, 0x33);

        let mut isa = Isa::rv_i();
        isa.zkne = true;
        isa.zknd = true;

        let i = decode(aes32esi, Xlen::Rv32, &isa);
        assert_eq!(i.op, Op::Aes32esi);
        assert_eq!(i.imm, 0);
        assert_eq!(decode(aes32esmi, Xlen::Rv32, &isa).op, Op::Aes32esmi);
        assert_eq!(decode(aes32esmi, Xlen::Rv32, &isa).imm, 1);
        assert_eq!(decode(aes32dsi, Xlen::Rv32, &isa).op, Op::Aes32dsi);
        assert_eq!(decode(aes32dsi, Xlen::Rv32, &isa).imm, 2);
        assert_eq!(decode(aes32dsmi, Xlen::Rv32, &isa).op, Op::Aes32dsmi);
        assert_eq!(decode(aes32dsmi, Xlen::Rv32, &isa).imm, 3);

        assert!(decode(aes32esi, Xlen::Rv64, &isa).is_illegal());
        assert!(decode(aes32dsmi, Xlen::Rv64, &isa).is_illegal());

        let mut no_zkne = isa;
        no_zkne.zkne = false;
        assert!(decode(aes32esi, Xlen::Rv32, &no_zkne).is_illegal());
        assert!(decode(aes32esmi, Xlen::Rv32, &no_zkne).is_illegal());

        let mut no_zknd = isa;
        no_zknd.zknd = false;
        assert!(decode(aes32dsi, Xlen::Rv32, &no_zknd).is_illegal());
        assert!(decode(aes32dsmi, Xlen::Rv32, &no_zknd).is_illegal());

        assert!(decode(enc(0x19, 7, 6, 0, 5, 0x33), Xlen::Rv32, &isa).is_illegal());
        assert!(decode(enc(0x18, 0, 6, 1, 5, 0x13), Xlen::Rv32, &isa).is_illegal());
    }

    #[test]
    fn decode_rv32_sha512_pair_crypto_is_gated() {
        let mut isa = Isa::rv_i();
        isa.zknh = true;

        for (f7, op) in [
            (0x28, Op::Sha512Sum0r),
            (0x29, Op::Sha512Sum1r),
            (0x2a, Op::Sha512Sig0l),
            (0x2b, Op::Sha512Sig1l),
            (0x2e, Op::Sha512Sig0h),
            (0x2f, Op::Sha512Sig1h),
        ] {
            let w = enc(f7, 7, 6, 0, 5, 0x33);
            assert_eq!(decode(w, Xlen::Rv32, &isa).op, op);
            assert!(decode(w, Xlen::Rv64, &isa).is_illegal());
        }

        let mut disabled = isa;
        disabled.zknh = false;
        assert!(decode(enc(0x28, 7, 6, 0, 5, 0x33), Xlen::Rv32, &disabled).is_illegal());

        let sha512sum0 = enc(0x08, 4, 6, 1, 5, 0x13);
        assert!(decode(sha512sum0, Xlen::Rv32, &isa).is_illegal());
        assert_eq!(decode(sha512sum0, Xlen::Rv64, &isa).op, Op::Sha512Sum0);
    }

    #[test]
    fn decode_q_extension_is_opt_in_and_excludes_q_moves() {
        let flq = (16u32 << 20) | (10 << 15) | (4 << 12) | (10 << 7) | 0x07;
        let fsq = (10u32 << 20) | (10 << 15) | (4 << 12) | (16 << 7) | 0x27;
        let fadd_q = enc(0b0000011, 11, 10, 0, 12, 0x53);
        let fsqrt_q = enc(0b0101111, 0, 10, 0, 12, 0x53);
        let fcvt_q_d = enc(0b0100011, 1, 11, 0, 10, 0x53);
        let fcvt_w_q = enc(0b1100011, 0, 11, 0, 10, 0x53);
        let fclass_q = enc(0b1110011, 0, 11, 1, 10, 0x53);
        let fmadd_q = (13u32 << 27) | (0b11 << 25) | (12 << 20) | (11 << 15) | (10 << 7) | 0x43;

        assert!(decode(fadd_q, Xlen::Rv64, &Isa::rv64gc()).is_illegal());

        let mut isa = Isa::rv64gc();
        isa.q = true;
        assert_eq!(decode(flq, Xlen::Rv64, &isa).op, Op::Flq);
        assert_eq!(decode(fsq, Xlen::Rv64, &isa).op, Op::Fsq);
        assert_eq!(decode(fadd_q, Xlen::Rv64, &isa).op, Op::FaddQ);
        assert_eq!(decode(fsqrt_q, Xlen::Rv64, &isa).op, Op::FsqrtQ);
        assert_eq!(decode(fcvt_q_d, Xlen::Rv64, &isa).op, Op::FcvtQD);
        assert_eq!(decode(fcvt_w_q, Xlen::Rv64, &isa).op, Op::FcvtWQ);
        assert_eq!(decode(fclass_q, Xlen::Rv64, &isa).op, Op::FclassQ);
        assert_eq!(decode(fmadd_q, Xlen::Rv64, &isa).op, Op::FmaddQ);

        assert!(decode(enc(0b1110011, 0, 11, 0, 10, 0x53), Xlen::Rv64, &isa).is_illegal());
        assert!(decode(enc(0b1111011, 0, 11, 0, 10, 0x53), Xlen::Rv64, &isa).is_illegal());
    }

    #[test]
    fn decode_zbkb_zip_unzip_rv32_only() {
        let zip = enc(0x04, 15, 10, 0b001, 5, 0x13);
        let unzip = enc(0x04, 15, 10, 0b101, 5, 0x13);
        assert_eq!(decode(zip, Xlen::Rv32, &Isa::rv64gc()).op, Op::Zip);
        assert_eq!(decode(unzip, Xlen::Rv32, &Isa::rv64gc()).op, Op::Unzip);
        assert!(decode(zip, Xlen::Rv64, &Isa::rv64gc()).is_illegal());

        let mut no_zbkb = Isa::rv64gc();
        no_zbkb.zbkb = false;
        assert!(decode(zip, Xlen::Rv32, &no_zbkb).is_illegal());
        assert!(decode(unzip, Xlen::Rv32, &no_zbkb).is_illegal());
    }

    #[test]
    fn decode_privileged_fence_and_hypervisor_tables() {
        let sys = |funct7: u32, rs2: u32, rs1: u32| enc(funct7, rs2, rs1, 0, 0, 0x73);
        assert!(decode(sys(0x00, 0x02, 0), Xlen::Rv64, &Isa::rv64gc()).is_illegal());
        assert_eq!(
            decode(sys(0x08, 0x02, 0), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::Sret
        );
        assert!(decode(0x1040_0073, Xlen::Rv64, &Isa::rv64gc()).is_illegal());
        assert!(decode(sys(0x08, 0x04, 10), Xlen::Rv64, &Isa::rv64gc()).is_illegal());
        assert_eq!(
            decode(sys(0x09, 11, 10), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::SfenceVma
        );
        assert_eq!(
            decode(sys(0x0b, 11, 10), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::SinvalVma
        );
        assert_eq!(
            decode(sys(0x0c, 0, 0), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::SfenceWInval
        );
        assert_eq!(
            decode(sys(0x0c, 1, 0), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::SfenceInvalIr
        );
        assert_eq!(
            decode(sys(0x11, 11, 10), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HfenceVvma
        );
        assert_eq!(
            decode(sys(0x31, 11, 10), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HfenceGvma
        );
        assert_eq!(
            decode(sys(0x13, 11, 10), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HinvalVvma
        );
        assert_eq!(
            decode(sys(0x33, 11, 10), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HinvalGvma
        );

        assert_eq!(
            decode(enc(0x30, 0, 10, 0b100, 5, 0x73), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HlvB
        );
        assert_eq!(
            decode(enc(0x32, 3, 10, 0b100, 5, 0x73), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HlvxHu
        );
        assert_eq!(
            decode(enc(0x34, 1, 10, 0b100, 5, 0x73), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HlvWu
        );
        assert_eq!(
            decode(enc(0x35, 7, 10, 0b100, 0, 0x73), Xlen::Rv64, &Isa::rv64gc()).op,
            Op::HsvW
        );
        assert!(decode(enc(0x35, 7, 10, 0b100, 1, 0x73), Xlen::Rv64, &Isa::rv64gc()).is_illegal());

        let mut no_svinval = Isa::rv64gc();
        no_svinval.svinval = false;
        assert!(decode(sys(0x0b, 11, 10), Xlen::Rv64, &no_svinval).is_illegal());
        assert!(decode(sys(0x0c, 0, 0), Xlen::Rv64, &no_svinval).is_illegal());

        let mut no_h = Isa::rv64gc();
        no_h.h = false;
        assert!(decode(sys(0x11, 11, 10), Xlen::Rv64, &no_h).is_illegal());
        assert!(decode(enc(0x30, 0, 10, 0b100, 5, 0x73), Xlen::Rv64, &no_h).is_illegal());
        assert!(decode(enc(0x34, 1, 10, 0b100, 5, 0x73), Xlen::Rv32, &Isa::rv64gc()).is_illegal());
    }

    #[test]
    fn xsoteria_rejects_bad_funct() {
        let isa = Isa::ti50();
        // CUSTOM-0 funct3=0 requires funct7==0; funct7=0x20 is illegal.
        assert!(decode(enc(0x20, 0, 1, 0b000, 2, 0x0b), Xlen::Rv32, &isa).is_illegal());
        // CUSTOM-0 funct3=0b111 is undefined.
        assert!(decode(enc(0x00, 0, 1, 0b111, 2, 0x0b), Xlen::Rv32, &isa).is_illegal());
        // CUSTOM-1 funct3=0b010 is undefined (no register grev variant there).
        assert!(decode(enc(0x00, 3, 1, 0b010, 2, 0x2b), Xlen::Rv32, &isa).is_illegal());
    }

    #[test]
    fn xsoteria_unary_requires_zero_rs2_field() {
        let isa = Isa::ti50();
        // pcnt/clz/fls are unary: a non-zero rs2 field [24:20] must be rejected.
        assert!(decode(enc(0x00, 0, 1, 0b011, 2, 0x0b), Xlen::Rv32, &isa).op == Op::Pcnt);
        assert!(decode(enc(0x00, 5, 1, 0b011, 2, 0x0b), Xlen::Rv32, &isa).is_illegal());
        assert!(decode(enc(0x00, 0, 1, 0b010, 2, 0x0b), Xlen::Rv32, &isa).op == Op::Fls);
        assert!(decode(enc(0x20, 7, 1, 0b010, 2, 0x0b), Xlen::Rv32, &isa).is_illegal());
    }

    #[test]
    fn xsoteria_immediate_field_decodes_to_imm() {
        // grevi rd=x3, rs1=x1, imm5=24 -> rev8 control.
        let insn = decode(enc(0x00, 24, 1, 0b000, 3, 0x0b), Xlen::Rv32, &Isa::ti50());
        assert_eq!(insn.op, Op::Grevi);
        assert_eq!(insn.rd, 3);
        assert_eq!(insn.rs1, 1);
        assert_eq!(insn.imm, 24);
    }

    #[test]
    fn xthead_decode_scalar_and_memory_tables() {
        let isa = Isa {
            xthead: true,
            ..Isa::rv64gc()
        };

        assert_eq!(
            decode(enc(0, 0b11000, 0, 0b000, 0, 0x0b), Xlen::Rv64, &isa).op,
            Op::ThSync
        );
        let dcache_cpa = decode(enc(1, 0b01001, 10, 0b000, 0, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(dcache_cpa.op, Op::ThDcacheCpa);
        assert_eq!(dcache_cpa.rs1, 10);

        let addsl = decode(enc(2, 6, 5, 0b001, 7, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(addsl.op, Op::ThAddsl);
        assert_eq!(addsl.imm, 2);

        let srri = decode(enc(0x09, 3, 10, 0b001, 5, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(srri.op, Op::ThSrri);
        assert_eq!(srri.imm, 35);

        let ext = decode(enc(12 << 1, 4, 10, 0b010, 5, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(ext.op, Op::ThExt);
        assert_eq!(ext.rs2, 12);
        assert_eq!(ext.imm, 4);
        assert!(decode(enc(4 << 1, 12, 10, 0b010, 5, 0x0b), Xlen::Rv64, &isa).is_illegal());

        let lbia = decode(enc(0x0d, 0b11110, 11, 0b100, 10, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(lbia.op, Op::ThLbia);
        assert_eq!(lbia.rs2, 0b11110);
        assert_eq!(lbia.imm, 1);
        assert!(decode(enc(0x0c, 1, 10, 0b100, 10, 0x0b), Xlen::Rv64, &isa).is_illegal());

        let lrw = decode(enc(0x22, 12, 11, 0b100, 10, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(lrw.op, Op::ThLrw);
        assert_eq!(lrw.imm, 2);

        let lwd = decode(enc(0x72, 12, 11, 0b100, 10, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(lwd.op, Op::ThLwd);
        assert_eq!(lwd.imm, 16);

        let flrw = decode(enc(0x22, 12, 11, 0b110, 10, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(flrw.op, Op::ThFlrw);
        assert_eq!(flrw.imm, 2);

        assert!(
            decode(
                enc(0, 0b11000, 0, 0b000, 0, 0x0b),
                Xlen::Rv64,
                &Isa::rv64gc()
            )
            .is_illegal()
        );
    }

    #[test]
    fn xthead_decode_vdot_tables_after_fmem() {
        let isa = Isa {
            xthead: true,
            ..Isa::rv64gc()
        };

        let vmaqa_vv = decode(enc((0x20 << 1) | 1, 3, 2, 0b110, 1, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(vmaqa_vv.op, Op::ThVmaqa);
        assert_eq!(vmaqa_vv.rd, 1);
        assert_eq!(vmaqa_vv.rs1, 2);
        assert_eq!(vmaqa_vv.rs2, 3);

        let vmaqau_vx = decode(enc((0x23 << 1) | 1, 4, 5, 0b110, 6, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(vmaqau_vx.op, Op::ThVmaqau);
        assert_eq!(vmaqau_vx.rs1, 5);
        assert_eq!(vmaqau_vx.rs2, 4);

        let vmaqaus_vx = decode(enc((0x27 << 1) | 1, 4, 5, 0b110, 6, 0x0b), Xlen::Rv64, &isa);
        assert_eq!(vmaqaus_vx.op, Op::ThVmaqaus);

        // IDA has no vector-vector encoding for th.vmaqaus.
        assert!(decode(enc((0x26 << 1) | 1, 4, 5, 0b110, 6, 0x0b), Xlen::Rv64, &isa).is_illegal());

        assert_eq!(
            decode(enc((0x20 << 1) | 1, 3, 2, 0b111, 1, 0x0b), Xlen::Rv64, &isa).op,
            Op::ThVpmaqa
        );
        assert_eq!(
            decode(enc((0x28 << 1) | 1, 3, 2, 0b111, 1, 0x0b), Xlen::Rv64, &isa).op,
            Op::ThVpnclip
        );
        assert_eq!(
            decode(enc((0x2d << 1) | 1, 3, 2, 0b111, 1, 0x0b), Xlen::Rv64, &isa).op,
            Op::ThVpwadd
        );

        assert!(
            decode(
                enc((0x20 << 1) | 1, 3, 2, 0b110, 1, 0x0b),
                Xlen::Rv64,
                &Isa::rv64gc()
            )
            .is_illegal()
        );
    }

    #[test]
    fn xthead_custom0_priority_matches_ida() {
        let both = Isa {
            xthead: true,
            xhazard3: true,
            ..Isa::rv_i()
        };
        assert_eq!(
            decode(enc(0, 0b11000, 0, 0b000, 0, 0x0b), Xlen::Rv32, &both).op,
            Op::ThSync
        );
        assert_eq!(
            decode(enc(0b0000110, 2, 1, 0b000, 3, 0x0b), Xlen::Rv32, &both).op,
            Op::H3Bextm
        );
    }

    #[test]
    fn hazard3_decode_power_hints_and_custom0() {
        let isa = Isa {
            xhazard3: true,
            ..Isa::rv_i()
        };

        assert_eq!(
            decode(enc(0, 0, 0, 0b010, 0, 0x33), Xlen::Rv32, &isa).op,
            Op::H3Block
        );
        assert_eq!(
            decode(enc(0, 1, 0, 0b010, 0, 0x33), Xlen::Rv32, &isa).op,
            Op::H3Unblock
        );
        assert_eq!(
            decode(enc(0, 0, 0, 0b010, 0, 0x33), Xlen::Rv32, &Isa::rv_i()).op,
            Op::Slt
        );

        let bextm = enc(0b0000110, 5, 1, 0b000, 3, 0x0b);
        let insn = decode(bextm, Xlen::Rv32, &isa);
        assert_eq!(insn.op, Op::H3Bextm);
        assert_eq!(insn.rd, 3);
        assert_eq!(insn.rs1, 1);
        assert_eq!(insn.rs2, 5);
        assert_eq!(insn.imm, 4);

        let bextmi = enc(0, (0b101 << 6) | 17, 1, 0b100, 3, 0x0b);
        let insn = decode(bextmi, Xlen::Rv32, &isa);
        assert_eq!(insn.op, Op::H3Bextmi);
        assert_eq!(insn.rs2, 17);
        assert_eq!(insn.imm, 6);

        assert!(decode(bextm, Xlen::Rv32, &Isa::rv_i()).is_illegal());
    }

    #[test]
    fn hazard3_rejects_reserved_custom0_fields() {
        let isa = Isa {
            xhazard3: true,
            ..Isa::rv_i()
        };
        // h3.bextm requires funct7[6:4] == 0 and funct7[0] == 0.
        assert!(decode(enc(0b0010000, 5, 1, 0b000, 3, 0x0b), Xlen::Rv32, &isa).is_illegal());
        assert!(decode(enc(0b0000001, 5, 1, 0b000, 3, 0x0b), Xlen::Rv32, &isa).is_illegal());

        // h3.bextmi requires imm[11:9] == 0 and imm[5] == 0.
        assert!(decode(enc(0, 1 << 9, 1, 0b100, 3, 0x0b), Xlen::Rv32, &isa).is_illegal());
        assert!(decode(enc(0, 1 << 5, 1, 0b100, 3, 0x0b), Xlen::Rv32, &isa).is_illegal());
    }

    #[test]
    fn andes_decode_gp_relative_and_custom2() {
        let isa = Isa {
            xandes: true,
            ..Isa::rv64gc()
        };

        let lbgp = (3 << 21) | (1 << 14) | (5 << 7) | 0x0b;
        let insn = decode(lbgp, Xlen::Rv64, &isa);
        assert_eq!(insn.op, Op::NdsLbgp);
        assert_eq!(insn.rd, 5);
        assert_eq!(insn.rs1, 3);
        assert_eq!(insn.imm, 7);

        let sbgp = (6 << 20) | (0b11 << 12) | 0x0b;
        let insn = decode(sbgp, Xlen::Rv64, &isa);
        assert_eq!(insn.op, Op::NdsSbgp);
        assert_eq!(insn.rs1, 3);
        assert_eq!(insn.rs2, 6);

        assert_eq!(
            decode((0b011 << 12) | (5 << 7) | 0x2b, Xlen::Rv64, &isa).op,
            Op::NdsLdgp
        );
        assert_eq!(
            decode((0b110 << 12) | (5 << 7) | 0x2b, Xlen::Rv64, &isa).op,
            Op::NdsLwugp
        );
        assert!(decode((0b110 << 12) | (5 << 7) | 0x2b, Xlen::Rv32, &isa).is_illegal());

        let bfoz = (12 << 26) | (4 << 20) | (10 << 15) | (0b010 << 12) | (5 << 7) | 0x5b;
        let insn = decode(bfoz, Xlen::Rv64, &isa);
        assert_eq!(insn.op, Op::NdsBfoz);
        assert_eq!(insn.rs1, 10);
        assert_eq!(insn.rs2, 12);
        assert_eq!(insn.imm, 4);

        let lea_w = (0x06 << 25) | (5 << 20) | (4 << 15) | (3 << 7) | 0x5b;
        assert_eq!(decode(lea_w, Xlen::Rv64, &isa).op, Op::NdsLeaW);

        let beqc = (1 << 30) | (5 << 20) | (10 << 15) | (0b101 << 12) | (1 << 7) | 0x5b;
        let insn = decode(beqc, Xlen::Rv64, &isa);
        assert_eq!(insn.op, Op::NdsBeqc);
        assert_eq!(insn.rs2, 0b1100101);
    }

    #[test]
    fn andes_takes_custom0_priority_over_hazard3_like_ida() {
        let isa = Isa {
            xandes: true,
            xhazard3: true,
            ..Isa::rv_i()
        };
        assert_eq!(
            decode(enc(0, 0, 0, 0b000, 2, 0x0b), Xlen::Rv32, &isa).op,
            Op::NdsLbgp
        );
    }
}
