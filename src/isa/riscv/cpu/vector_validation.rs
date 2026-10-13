//! Architectural encoding and register-group validation for RVV data operations.
//!
//! These checks run before the data-path dispatcher mutates architectural state.
//! Keeping them together makes the direct interpreter and the opaque SMIR/JIT
//! helper paths reject the same reserved encodings at the same guest frontier.

use super::{Insn, Op, RiscVCpu, Trap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Emul {
    numerator: u8,
    denominator: u8,
}

impl Emul {
    fn from_vtype(vtype: u64) -> Option<Self> {
        match vtype & 0x7 {
            0b000 => Some(Self::new(1, 1)),
            0b001 => Some(Self::new(2, 1)),
            0b010 => Some(Self::new(4, 1)),
            0b011 => Some(Self::new(8, 1)),
            0b101 => Some(Self::new(1, 8)),
            0b110 => Some(Self::new(1, 4)),
            0b111 => Some(Self::new(1, 2)),
            0b100 => None,
            _ => None,
        }
    }

    fn new(mut numerator: u8, mut denominator: u8) -> Self {
        while numerator % 2 == 0 && denominator % 2 == 0 {
            numerator /= 2;
            denominator /= 2;
        }
        Self {
            numerator,
            denominator,
        }
    }

    fn widen(self) -> Self {
        Self::new(self.numerator * 2, self.denominator)
    }

    fn narrow(self, factor: u8) -> Self {
        Self::new(self.numerator, self.denominator * factor)
    }

    fn scale(self, numerator: u8, denominator: u8) -> Self {
        Self::new(self.numerator * numerator, self.denominator * denominator)
    }

    fn is_at_least_one(self) -> bool {
        self.numerator >= self.denominator
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegisterGroup {
    first: u8,
    count: u8,
}

impl RegisterGroup {
    fn for_emul(first: u8, emul: Emul) -> Option<Self> {
        // RVV reserves any instruction whose effective register group is larger
        // than eight vector registers or smaller than the minimum fractional
        // LMUL supported by this ELEN=64 implementation (1/8).
        if u16::from(emul.numerator) > 8 * u16::from(emul.denominator)
            || u16::from(emul.denominator) > 8 * u16::from(emul.numerator)
        {
            return None;
        }

        // Fractional EMUL occupies a fraction of one named architectural
        // register and therefore has no multi-register alignment constraint.
        let count = if emul.numerator < emul.denominator {
            1
        } else {
            if emul.numerator % emul.denominator != 0 {
                return None;
            }
            emul.numerator / emul.denominator
        };
        if first % count != 0 || first.checked_add(count)? > 32 {
            return None;
        }
        Some(Self { first, count })
    }

    fn overlaps(self, other: Self) -> bool {
        let self_end = self.first + self.count;
        let other_end = other.first + other.count;
        self.first < other_end && other.first < self_end
    }

    fn last(self) -> u8 {
        self.first + self.count - 1
    }
}

#[inline]
fn illegal(insn: &Insn) -> Trap {
    Trap::illegal(insn.raw)
}

fn current_lmul(cpu: &RiscVCpu, insn: &Insn) -> Result<Emul, Trap> {
    Emul::from_vtype(cpu.vtype).ok_or_else(|| illegal(insn))
}

fn same_width_group(cpu: &RiscVCpu, insn: &Insn, first: u8) -> Result<RegisterGroup, Trap> {
    RegisterGroup::for_emul(first, current_lmul(cpu, insn)?).ok_or_else(|| illegal(insn))
}

fn validate_slide_up(cpu: &RiscVCpu, insn: &Insn) -> Result<(), Trap> {
    let destination = same_width_group(cpu, insn, insn.rd)?;
    let source = same_width_group(cpu, insn, insn.rs2)?;
    if destination.overlaps(source) {
        return Err(illegal(insn));
    }
    Ok(())
}

fn validate_narrowing(cpu: &RiscVCpu, insn: &Insn) -> Result<(), Trap> {
    let lmul = current_lmul(cpu, insn)?;
    let destination = RegisterGroup::for_emul(insn.rd, lmul).ok_or_else(|| illegal(insn))?;
    let source = RegisterGroup::for_emul(insn.rs2, lmul.widen()).ok_or_else(|| illegal(insn))?;

    // A narrow destination may overlap the lowest-numbered part of its wide
    // source group. Any other overlap is reserved.
    if destination.overlaps(source) && destination.first != source.first {
        return Err(illegal(insn));
    }
    Ok(())
}

fn validate_wider_destination_overlap(
    insn: &Insn,
    destination: RegisterGroup,
    source: RegisterGroup,
    source_emul: Emul,
) -> Result<(), Trap> {
    // For a wider destination, overlap is legal only when the narrow source
    // has EMUL >= 1 and occupies the highest-numbered part of the destination.
    if destination.overlaps(source)
        && (!source_emul.is_at_least_one() || destination.last() != source.last())
    {
        return Err(illegal(insn));
    }
    Ok(())
}

fn validate_widening_data(
    cpu: &RiscVCpu,
    insn: &Insn,
    wide_vs2: bool,
    vector_vs1: bool,
    destination_is_source: bool,
) -> Result<(), Trap> {
    let narrow_emul = current_lmul(cpu, insn)?;
    let wide_emul = narrow_emul.widen();
    let destination = RegisterGroup::for_emul(insn.rd, wide_emul).ok_or_else(|| illegal(insn))?;

    let vs2_emul = if wide_vs2 { wide_emul } else { narrow_emul };
    let vs2 = RegisterGroup::for_emul(insn.rs2, vs2_emul).ok_or_else(|| illegal(insn))?;
    if !wide_vs2 {
        if destination_is_source && destination.overlaps(vs2) {
            // A destructive widening accumulate would otherwise read the same
            // register at both the wide destination EEW and the narrow source
            // EEW, which is a reserved source-operand combination.
            return Err(illegal(insn));
        }
        validate_wider_destination_overlap(insn, destination, vs2, vs2_emul)?;
    }

    if vector_vs1 {
        let vs1 = RegisterGroup::for_emul(insn.rs1, narrow_emul).ok_or_else(|| illegal(insn))?;
        if (destination_is_source && destination.overlaps(vs1)) || (wide_vs2 && vs2.overlaps(vs1)) {
            // The first case is the other destructive-accumulate source. The
            // second would read a shared register through wide vs2 and narrow
            // vs1 in a `.w` form. Both use two EEWs for one source register.
            return Err(illegal(insn));
        }
        validate_wider_destination_overlap(insn, destination, vs1, narrow_emul)?;
    }
    Ok(())
}

fn validate_extension(cpu: &RiscVCpu, insn: &Insn, factor: u8) -> Result<(), Trap> {
    let destination_emul = current_lmul(cpu, insn)?;
    let source_emul = destination_emul.narrow(factor);
    let destination =
        RegisterGroup::for_emul(insn.rd, destination_emul).ok_or_else(|| illegal(insn))?;
    let source = RegisterGroup::for_emul(insn.rs2, source_emul).ok_or_else(|| illegal(insn))?;
    validate_wider_destination_overlap(insn, destination, source, source_emul)
}

fn validate_reduction_source_group(cpu: &RiscVCpu, insn: &Insn) -> Result<(), Trap> {
    // Reduction scalar operands in vd/vs1 may use any register regardless of
    // LMUL. The vector source in vs2 remains an LMUL-sized group and must be
    // aligned, in bounds, and no larger than eight registers.
    RegisterGroup::for_emul(insn.rs2, current_lmul(cpu, insn)?).ok_or_else(|| illegal(insn))?;
    Ok(())
}

fn validate_reduction(cpu: &RiscVCpu, insn: &Insn) -> Result<(), Trap> {
    // Reductions are architecturally non-restartable. Their traps are always
    // reported at element zero, so a guest-supplied nonzero vstart is illegal.
    if cpu.vstart != 0 {
        return Err(illegal(insn));
    }
    validate_reduction_source_group(cpu, insn)
}

fn validate_same_width_integer_alu(
    cpu: &RiscVCpu,
    insn: &Insn,
    vector_vector_funct3: u8,
) -> Result<(), Trap> {
    // Every same-width vector operand names the LMUL-sized register group.
    // Scalar/immediate forms retain only vd and vs2 as vector groups.
    same_width_group(cpu, insn, insn.rd)?;
    same_width_group(cpu, insn, insn.rs2)?;
    if insn.funct3 == vector_vector_funct3 {
        same_width_group(cpu, insn, insn.rs1)?;
    }
    Ok(())
}

fn validate_same_width_unary(cpu: &RiscVCpu, insn: &Insn) -> Result<(), Trap> {
    same_width_group(cpu, insn, insn.rd)?;
    same_width_group(cpu, insn, insn.rs2)?;
    Ok(())
}

fn validate_mask_result(cpu: &RiscVCpu, insn: &Insn, vector_vector_funct3: u8) -> Result<(), Trap> {
    let destination = RegisterGroup {
        first: insn.rd,
        count: 1,
    };
    let vs2 = same_width_group(cpu, insn, insn.rs2)?;
    if destination.overlaps(vs2) && destination.first != vs2.first {
        return Err(illegal(insn));
    }

    if insn.funct3 == vector_vector_funct3 {
        let vs1 = same_width_group(cpu, insn, insn.rs1)?;
        if destination.overlaps(vs1) && destination.first != vs1.first {
            return Err(illegal(insn));
        }
    }
    Ok(())
}

fn encoded_memory_width(insn: &Insn) -> Result<u8, Trap> {
    match insn.funct3 {
        0 => Ok(1),
        5 => Ok(2),
        6 => Ok(4),
        7 => Ok(8),
        _ => Err(illegal(insn)),
    }
}

fn memory_emul(cpu: &RiscVCpu, insn: &Insn) -> Result<Emul, Trap> {
    let sew = u8::try_from(cpu.sew_bytes()).map_err(|_| illegal(insn))?;
    if !matches!(sew, 1 | 2 | 4 | 8) {
        return Err(illegal(insn));
    }
    Ok(current_lmul(cpu, insn)?.scale(encoded_memory_width(insn)?, sew))
}

fn validate_segment_data_groups(
    insn: &Insn,
    emul: Emul,
    fields: u8,
) -> Result<Vec<RegisterGroup>, Trap> {
    if u16::from(emul.numerator) * u16::from(fields) > 8 * u16::from(emul.denominator) {
        return Err(illegal(insn));
    }

    let first = RegisterGroup::for_emul(insn.rd, emul).ok_or_else(|| illegal(insn))?;
    let mut groups = Vec::with_capacity(usize::from(fields));
    for field in 0..fields {
        let register = insn
            .rd
            .checked_add(field.saturating_mul(first.count))
            .ok_or_else(|| illegal(insn))?;
        groups.push(RegisterGroup::for_emul(register, emul).ok_or_else(|| illegal(insn))?);
    }
    Ok(groups)
}

fn validate_indexed_memory_overlap(
    insn: &Insn,
    data_groups: &[RegisterGroup],
    data_emul: Emul,
    index: RegisterGroup,
    index_emul: Emul,
    is_load: bool,
) -> Result<(), Trap> {
    let same_eew = data_emul.numerator * index_emul.denominator
        == index_emul.numerator * data_emul.denominator;
    for data in data_groups {
        if !data.overlaps(index) || same_eew {
            continue;
        }

        // An indexed store reads both groups, so sharing a register at two
        // EEWs is always reserved. Loads use the ordinary destination/source
        // overlap rules for the data destination and index source.
        if !is_load {
            return Err(illegal(insn));
        }
        let data_is_narrower = data_emul.numerator * index_emul.denominator
            < index_emul.numerator * data_emul.denominator;
        let legal = if data_is_narrower {
            data.first == index.first
        } else {
            index_emul.is_at_least_one() && data.last() == index.last()
        };
        if !legal {
            return Err(illegal(insn));
        }
    }
    Ok(())
}

fn validate_vector_memory(cpu: &RiscVCpu, insn: &Insn) -> Result<(), Trap> {
    match insn.op {
        Op::Vle | Op::Vse | Op::Vlse | Op::Vsse | Op::Vleff => {
            RegisterGroup::for_emul(insn.rd, memory_emul(cpu, insn)?)
                .ok_or_else(|| illegal(insn))?;
        }
        Op::Vlxei | Op::Vsxei => {
            let data_emul = current_lmul(cpu, insn)?;
            let data = same_width_group(cpu, insn, insn.rd)?;
            let index_emul = memory_emul(cpu, insn)?;
            let index =
                RegisterGroup::for_emul(insn.rs2, index_emul).ok_or_else(|| illegal(insn))?;
            validate_indexed_memory_overlap(
                insn,
                &[data],
                data_emul,
                index,
                index_emul,
                insn.op == Op::Vlxei,
            )?;
        }
        Op::Vlseg | Op::Vsseg => {
            let fields = ((insn.raw >> 29) & 7) as u8 + 1;
            let indexed = (insn.raw >> 26) & 3 & 1 != 0;
            let data_emul = if indexed {
                current_lmul(cpu, insn)?
            } else {
                memory_emul(cpu, insn)?
            };
            let data = validate_segment_data_groups(insn, data_emul, fields)?;
            if indexed {
                let index_emul = memory_emul(cpu, insn)?;
                let index =
                    RegisterGroup::for_emul(insn.rs2, index_emul).ok_or_else(|| illegal(insn))?;
                if insn.op == Op::Vlseg && data.iter().any(|group| group.overlaps(index)) {
                    // Indexed segment loads prohibit every destination/index
                    // overlap so a fault can be restarted without having
                    // overwritten an index needed by a later segment.
                    return Err(illegal(insn));
                }
                validate_indexed_memory_overlap(
                    insn,
                    &data,
                    data_emul,
                    index,
                    index_emul,
                    insn.op == Op::Vlseg,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn writes_nonmask_vector_destination(op: Op) -> bool {
    !matches!(
        op,
        // Stores and scalar-result operations do not write a vector group.
        Op::Vse
            | Op::Vsse
            | Op::Vsxei
            | Op::Vsseg
            | Op::Vsm
            | Op::Vsre
            | Op::VmvXS
            | Op::VfmvFS
            | Op::Vcpop
            | Op::Vfirst
            // These operations deliberately produce a single mask register.
            | Op::Vmseq
            | Op::Vmsne
            | Op::Vmsltu
            | Op::Vmslt
            | Op::Vmsleu
            | Op::Vmsle
            | Op::Vmsgtu
            | Op::Vmsgt
            | Op::Vmfeq
            | Op::Vmfne
            | Op::Vmflt
            | Op::Vmfle
            | Op::Vmfgt
            | Op::Vmfge
            | Op::Vmand
            | Op::Vmnand
            | Op::Vmandn
            | Op::Vmxor
            | Op::Vmor
            | Op::Vmnor
            | Op::Vmorn
            | Op::Vmxnor
            | Op::Vmsbf
            | Op::Vmsof
            | Op::Vmsif
            | Op::Vmadc
            | Op::Vmsbc
            // Reduction results are scalar values held in one vector register.
            | Op::Vredsum
            | Op::Vredand
            | Op::Vredor
            | Op::Vredxor
            | Op::Vredminu
            | Op::Vredmin
            | Op::Vredmaxu
            | Op::Vredmax
            | Op::Vfredusum
            | Op::Vfredosum
            | Op::Vfredmin
            | Op::Vfredmax
            | Op::Vwredsumu
            | Op::Vwredsum
            | Op::Vfwredusum
            | Op::Vfwredosum
    )
}

fn validate_gather(cpu: &RiscVCpu, insn: &Insn) -> Result<(), Trap> {
    let destination = same_width_group(cpu, insn, insn.rd)?;
    let data = same_width_group(cpu, insn, insn.rs2)?;
    if destination.overlaps(data) {
        return Err(illegal(insn));
    }

    let index = match insn.op {
        Op::Vrgatherei16 => {
            let index_emul = match cpu.sew_bytes() {
                1 => current_lmul(cpu, insn)?.widen(),
                2 => current_lmul(cpu, insn)?,
                4 => current_lmul(cpu, insn)?.narrow(2),
                8 => current_lmul(cpu, insn)?.narrow(4),
                _ => return Err(illegal(insn)),
            };
            RegisterGroup::for_emul(insn.rs1, index_emul).ok_or_else(|| illegal(insn))?
        }
        Op::Vrgather if insn.funct3 == 0b000 => same_width_group(cpu, insn, insn.rs1)?,
        Op::Vrgather => return Ok(()),
        _ => unreachable!("gather validator called for non-gather operation"),
    };

    if destination.overlaps(index)
        || (matches!(insn.op, Op::Vrgatherei16) && cpu.sew_bytes() != 2 && data.overlaps(index))
    {
        return Err(illegal(insn));
    }
    Ok(())
}

fn validate_iota(cpu: &RiscVCpu, insn: &Insn, vm: bool) -> Result<(), Trap> {
    if cpu.vstart != 0 {
        return Err(illegal(insn));
    }

    let destination = same_width_group(cpu, insn, insn.rd)?;
    let source_mask = RegisterGroup {
        first: insn.rs2,
        count: 1,
    };
    let execution_mask = RegisterGroup { first: 0, count: 1 };
    if destination.overlaps(source_mask) || (!vm && destination.overlaps(execution_mask)) {
        return Err(illegal(insn));
    }
    Ok(())
}

pub(super) fn is_vector_fp_encoding(insn: &Insn) -> bool {
    // OPFVV and OPFVF are the complete floating-point classes under OP-V.
    // Classifying the encoding, rather than maintaining an operation whitelist,
    // also covers exact operations and future decoded members of these classes.
    insn.raw & 0x7f == 0x57 && matches!(insn.funct3, 0b001 | 0b101)
}

fn fp_operands_supported_at_sew8(insn: &Insn) -> bool {
    // Zvfh defines these conversions at SEW=8 because their only floating-
    // point operand is the double-width, 16-bit side. Every other decoded
    // OPFVV/OPFVF instruction would consume or produce an unsupported FP8
    // operand and is reserved.
    matches!(
        insn.op,
        Op::VfwcvtFXu
            | Op::VfwcvtFX
            | Op::VfncvtXuF
            | Op::VfncvtXF
            | Op::VfncvtRtzXuF
            | Op::VfncvtRtzXF
    )
}

pub(super) fn validate(cpu: &RiscVCpu, insn: &Insn, vm: bool) -> Result<(), Trap> {
    // All vector floating-point instructions consult frm, including operations
    // whose numeric result is independent of rounding and instructions with a
    // fixed RTZ/ROD behavior. Architectural frm encodings 5, 6, and 7 are
    // reserved; frm=7 is not a second level of dynamic selection.
    let vector_fp = is_vector_fp_encoding(insn);
    if vector_fp && cpu.frm() > 4 {
        return Err(illegal(insn));
    }
    if vector_fp && cpu.sew_bytes() == 1 && !fp_operands_supported_at_sew8(insn) {
        return Err(illegal(insn));
    }
    if !vm && insn.rd == 0 && writes_nonmask_vector_destination(insn.op) {
        return Err(illegal(insn));
    }

    validate_vector_memory(cpu, insn)?;

    match insn.op {
        Op::VmvXS | Op::VmvSX | Op::VfmvFS | Op::VfmvSF if !vm => {
            return Err(illegal(insn));
        }
        Op::Vmerge if vm => {
            // vmv.v.v/vx/vi share the vmerge encoding. The vm=1 move forms
            // reserve vs2 and require that field to encode v0.
            if insn.rs2 != 0 {
                return Err(illegal(insn));
            }
        }
        Op::Vmsbf | Op::Vmsif | Op::Vmsof => {
            if cpu.vstart != 0 || insn.rd == insn.rs2 || (!vm && insn.rd == 0) {
                return Err(illegal(insn));
            }
        }
        Op::Vid => {
            // VMUNARY0 reserves the source field for vid.v and requires it to
            // encode v0 even though the operation does not consume a source.
            if insn.rs2 != 0 {
                return Err(illegal(insn));
            }
            same_width_group(cpu, insn, insn.rd)?;
        }
        Op::Viota => validate_iota(cpu, insn, vm)?,
        Op::Vadc | Op::Vsbc => {
            if vm || insn.rd == 0 {
                return Err(illegal(insn));
            }
            validate_same_width_integer_alu(cpu, insn, 0b000)?;
        }
        Op::Vmadc | Op::Vmsbc => validate_mask_result(cpu, insn, 0b000)?,
        Op::Vslideup | Op::Vslide1up | Op::Vfslide1up => {
            validate_slide_up(cpu, insn)?;
        }
        Op::Vslidedown | Op::Vslide1down | Op::Vfslide1down => {
            validate_same_width_unary(cpu, insn)?;
        }
        Op::Vrgather | Op::Vrgatherei16 => validate_gather(cpu, insn)?,
        Op::Vadd
        | Op::Vsub
        | Op::Vrsub
        | Op::Vand
        | Op::Vor
        | Op::Vxor
        | Op::Vminu
        | Op::Vmin
        | Op::Vmaxu
        | Op::Vmax
        | Op::Vsll
        | Op::Vsrl
        | Op::Vsra
        | Op::Vmerge
        | Op::Vsaddu
        | Op::Vsadd
        | Op::Vssubu
        | Op::Vssub
        | Op::Vssrl
        | Op::Vssra
        | Op::Vsmul => validate_same_width_integer_alu(cpu, insn, 0b000)?,
        Op::Vmul
        | Op::Vmulh
        | Op::Vmulhu
        | Op::Vmulhsu
        | Op::Vdivu
        | Op::Vdiv
        | Op::Vremu
        | Op::Vrem => validate_same_width_integer_alu(cpu, insn, 0b010)?,
        Op::Vaaddu | Op::Vaadd | Op::Vasubu | Op::Vasub => {
            validate_same_width_integer_alu(cpu, insn, 0b010)?;
        }
        Op::Vmseq
        | Op::Vmsne
        | Op::Vmsltu
        | Op::Vmslt
        | Op::Vmsleu
        | Op::Vmsle
        | Op::Vmsgtu
        | Op::Vmsgt => validate_mask_result(cpu, insn, 0b000)?,
        Op::Vmfeq | Op::Vmfne | Op::Vmflt | Op::Vmfle | Op::Vmfgt | Op::Vmfge => {
            validate_mask_result(cpu, insn, 0b001)?;
        }
        Op::Vfadd
        | Op::Vfsub
        | Op::Vfmul
        | Op::Vfdiv
        | Op::Vfmin
        | Op::Vfmax
        | Op::Vfsgnj
        | Op::Vfsgnjn
        | Op::Vfsgnjx
        | Op::Vfmacc
        | Op::Vfnmacc
        | Op::Vfmsac
        | Op::Vfnmsac
        | Op::Vfmadd
        | Op::Vfnmadd
        | Op::Vfmsub
        | Op::Vfnmsub => validate_same_width_integer_alu(cpu, insn, 0b001)?,
        Op::Vfrsub
        | Op::Vfrdiv
        | Op::Vfsqrt
        | Op::Vfclass
        | Op::Vfrsqrt7
        | Op::Vfrec7
        | Op::VfcvtXuF
        | Op::VfcvtXF
        | Op::VfcvtFXu
        | Op::VfcvtFX
        | Op::VfcvtRtzXuF
        | Op::VfcvtRtzXF => validate_same_width_unary(cpu, insn)?,
        Op::Vnsrl
        | Op::Vnsra
        | Op::Vnclipu
        | Op::Vnclip
        | Op::VfncvtXuF
        | Op::VfncvtXF
        | Op::VfncvtFXu
        | Op::VfncvtFX
        | Op::VfncvtFF
        | Op::VfncvtRodFF
        | Op::VfncvtRtzXuF
        | Op::VfncvtRtzXF => validate_narrowing(cpu, insn)?,
        Op::Vwaddu | Op::Vwadd | Op::Vwsubu | Op::Vwsub => {
            validate_widening_data(cpu, insn, false, insn.funct3 == 0b010, false)?;
        }
        Op::VwadduW | Op::VwaddW | Op::VwsubuW | Op::VwsubW => {
            validate_widening_data(cpu, insn, true, insn.funct3 == 0b010, false)?;
        }
        Op::Vwmulu
        | Op::Vwmulsu
        | Op::Vwmul
        | Op::Vwmaccu
        | Op::Vwmacc
        | Op::Vwmaccsu
        | Op::Vwmaccus => {
            let accumulate = matches!(
                insn.op,
                Op::Vwmaccu | Op::Vwmacc | Op::Vwmaccsu | Op::Vwmaccus
            );
            validate_widening_data(cpu, insn, false, insn.funct3 == 0b010, accumulate)?;
        }
        Op::Vfwadd | Op::Vfwsub | Op::Vfwmul => {
            validate_widening_data(cpu, insn, false, insn.funct3 == 0b001, false)?;
        }
        Op::VfwaddW | Op::VfwsubW => {
            validate_widening_data(cpu, insn, true, insn.funct3 == 0b001, false)?;
        }
        Op::Vfwmacc | Op::Vfwnmacc | Op::Vfwmsac | Op::Vfwnmsac => {
            validate_widening_data(cpu, insn, false, insn.funct3 == 0b001, true)?;
        }
        Op::VfwcvtXuF
        | Op::VfwcvtXF
        | Op::VfwcvtFXu
        | Op::VfwcvtFX
        | Op::VfwcvtFF
        | Op::VfwcvtRtzXuF
        | Op::VfwcvtRtzXF => validate_widening_data(cpu, insn, false, false, false)?,
        Op::VzextVf2 | Op::VsextVf2 => validate_extension(cpu, insn, 2)?,
        Op::VzextVf4 | Op::VsextVf4 => validate_extension(cpu, insn, 4)?,
        Op::VzextVf8 | Op::VsextVf8 => validate_extension(cpu, insn, 8)?,
        Op::Vredsum
        | Op::Vredand
        | Op::Vredor
        | Op::Vredxor
        | Op::Vredminu
        | Op::Vredmin
        | Op::Vredmaxu
        | Op::Vredmax
        | Op::Vfredusum
        | Op::Vfredosum
        | Op::Vfredmin
        | Op::Vfredmax
        | Op::Vwredsumu
        | Op::Vwredsum
        | Op::Vfwredusum
        | Op::Vfwredosum => validate_reduction(cpu, insn)?,
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::{FlatMemory, Isa, RiscVConfig, RiscVExit, Xlen, decode};

    const E8_M1: u64 = 0x00;
    const E16_MF8: u64 = 0x0d;
    const E32_M1: u64 = 0x10;
    const E32_M2: u64 = 0x11;
    const E32_M4: u64 = 0x12;
    const E32_M8: u64 = 0x13;
    const E32_MF4: u64 = 0x16;
    const E32_MF2: u64 = 0x17;
    const E64_M8: u64 = 0x1b;
    const E64_MF2: u64 = 0x1f;

    fn op_v(funct6: u32, vm: u32, vs2: u32, src: u32, funct3: u32, vd: u32) -> u32 {
        (funct6 << 26) | (vm << 25) | (vs2 << 20) | (src << 15) | (funct3 << 12) | (vd << 7) | 0x57
    }

    fn decoded(raw: u32) -> Insn {
        let insn = decode(raw, Xlen::Rv64, &Isa::rv64gc());
        assert_ne!(insn.op, Op::Illegal, "test encoding {raw:08x} is illegal");
        insn
    }

    fn cpu(vtype: u64, vl: u64, vstart: u64, frm: u8) -> RiscVCpu {
        let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(FlatMemory::new(0, 0x2000)));
        cpu.csr_write(0x300, 0b01 << 13).unwrap(); // mstatus.FS=Initial
        cpu.set_vl_vtype(vl, vtype);
        cpu.set_vstart(vstart);
        cpu.set_fcsr(u32::from(frm) << 5);
        for register in 0..32u8 {
            cpu.set_x(register, 0x1020_3040_5060_7080 ^ u64::from(register));
            cpu.set_f(register, 0xffff_ffff_3f80_0000 + u64::from(register));
            cpu.set_vreg(register, &[register.wrapping_mul(7); 16]);
        }
        cpu
    }

    fn architectural_state(
        cpu: &RiscVCpu,
    ) -> (
        [u64; 32],
        [u64; 32],
        [[u8; 16]; 32],
        u32,
        u64,
        u64,
        u64,
        u64,
    ) {
        (
            std::array::from_fn(|index| cpu.x(index as u8)),
            std::array::from_fn(|index| cpu.f(index as u8)),
            std::array::from_fn(|index| cpu.vreg(index as u8)),
            cpu.fcsr(),
            cpu.vl(),
            cpu.vtype(),
            cpu.vstart(),
            cpu.vcsr(),
        )
    }

    fn assert_illegal(raw: u32, vtype: u64, vl: u64, vstart: u64, frm: u8) {
        let insn = decoded(raw);
        let mut cpu = cpu(vtype, vl, vstart, frm);
        let before = architectural_state(&cpu);
        assert_eq!(
            cpu.execute_insn(&insn, 0x1000),
            Err(Trap::illegal(raw)),
            "reserved encoding {raw:08x} ({:?}) must trap",
            insn.op
        );
        assert_eq!(
            architectural_state(&cpu),
            before,
            "reserved encoding {raw:08x} modified state before trapping"
        );
    }

    fn assert_legal(raw: u32, vtype: u64, vl: u64, vstart: u64, frm: u8) {
        let insn = decoded(raw);
        let mut cpu = cpu(vtype, vl, vstart, frm);
        assert_eq!(
            cpu.execute_insn(&insn, 0x1000),
            Ok(RiscVExit::Continue),
            "legal encoding {raw:08x} ({:?}) trapped",
            insn.op
        );
    }

    #[test]
    fn mask_prefix_constraints_are_checked_before_execution() {
        for selector in [0b00001, 0b00010, 0b00011] {
            // Unmasked vd == vs2 is reserved.
            assert_illegal(op_v(0b010100, 1, 2, selector, 0b010, 2), E8_M1, 8, 0, 0);
            // A masked prefix instruction cannot write v0.
            assert_illegal(op_v(0b010100, 0, 2, selector, 0b010, 0), E8_M1, 8, 0, 0);
            // Prefix operations are not restartable.
            assert_illegal(op_v(0b010100, 1, 2, selector, 0b010, 1), E8_M1, 8, 1, 0);
            assert_legal(op_v(0b010100, 1, 2, selector, 0b010, 1), E8_M1, 8, 0, 0);
            assert_legal(op_v(0b010100, 0, 2, selector, 0b010, 1), E8_M1, 8, 0, 0);
        }
    }

    #[test]
    fn vid_requires_reserved_vs2_field_to_name_v0() {
        let vid = |vm, vs2| op_v(0b010100, vm, vs2, 0b10001, 0b010, 1);

        assert_illegal(vid(1, 16), E8_M1, 4, 0, 0);
        assert_illegal(vid(0, 3), E8_M1, 4, 0, 0);
        assert_legal(vid(1, 0), E8_M1, 4, 0, 0);
        assert_legal(vid(0, 0), E8_M1, 4, 0, 0);

        // vid writes a normal LMUL-sized data group even though it has no
        // vector data source.
        assert_illegal(vid(1, 0) | (1 << 7), E32_M2, 4, 0, 0);
    }

    #[test]
    fn vmv_forms_require_reserved_vs2_field_to_name_v0() {
        for funct3 in [0b000, 0b100, 0b011] {
            assert_illegal(op_v(0b010111, 1, 7, 4, funct3, 2), E8_M1, 4, 0, 0);
            assert_legal(op_v(0b010111, 1, 0, 4, funct3, 2), E8_M1, 4, 0, 0);
        }
    }

    #[test]
    fn scalar_move_forms_reserve_masked_encodings() {
        let forms = [
            (0b010, 2, 0, 1), // vmv.x.s x1,v2
            (0b110, 0, 3, 2), // vmv.s.x v2,x3
            (0b001, 2, 0, 1), // vfmv.f.s f1,v2
            (0b101, 0, 3, 2), // vfmv.s.f v2,f3
        ];
        for (funct3, vs2, src, vd) in forms {
            assert_illegal(op_v(0b010000, 0, vs2, src, funct3, vd), E32_M1, 4, 0, 0);
            assert_legal(op_v(0b010000, 1, vs2, src, funct3, vd), E32_M1, 4, 0, 0);
        }
    }

    #[test]
    fn vrgatherei16_validates_exact_index_emul_and_source_aliasing() {
        let gather = |vd, data, index| op_v(0b001110, 1, data, index, 0b000, vd);

        // At SEW=8, LMUL=2, the 16-bit index operand has EMUL=4. Its
        // register group must start at a multiple of four and remain in v0-v31.
        assert_illegal(gather(0, 2, 6), 0x01, 4, 0, 0);
        assert_legal(gather(0, 2, 8), 0x01, 4, 0, 0);
        assert_legal(gather(0, 8, 28), 0x01, 4, 0, 0);
        assert_illegal(gather(0, 8, 30), 0x01, 4, 0, 0);

        // A source register cannot be read through both the 8-bit data group
        // and the 16-bit index group. At SEW=16 their EEWs match, so an exact
        // group alias remains legal.
        assert_illegal(gather(0, 2, 2), E8_M1, 4, 0, 0);
        assert_legal(gather(0, 2, 2), 0x09, 4, 0, 0); // e16,m2
    }

    #[test]
    fn averaging_integer_groups_must_be_aligned() {
        for funct6 in [0b001000, 0b001001, 0b001010, 0b001011] {
            let form = |vd, vs2, src, funct3| op_v(funct6, 1, vs2, src, funct3, vd);

            assert_illegal(form(1, 2, 4, 0b010), E32_M2, 2, 0, 0);
            assert_illegal(form(0, 3, 4, 0b010), E32_M2, 2, 0, 0);
            assert_illegal(form(0, 2, 5, 0b010), E32_M2, 2, 0, 0);
            assert_legal(form(0, 2, 4, 0b010), E32_M2, 2, 0, 0);

            // The vx form's rs1 field names a scalar integer register.
            assert_legal(form(0, 2, 5, 0b110), E32_M2, 2, 0, 0);
        }
    }

    #[test]
    fn viota_enforces_nonrestartable_and_operand_overlap_rules() {
        let iota = |vm, vd, source| op_v(0b010100, vm, source, 0b10000, 0b010, vd);

        assert_illegal(iota(0, 0, 2), E8_M1, 4, 0, 0);
        assert_illegal(iota(1, 2, 2), E8_M1, 4, 0, 0);
        // Under LMUL=2, vd=v2 occupies v2-v3 and therefore overlaps source v3.
        assert_illegal(iota(1, 2, 3), E32_M2, 4, 0, 0);
        assert_illegal(iota(1, 2, 4), E8_M1, 4, 1, 0);
        assert_legal(iota(0, 2, 4), E8_M1, 4, 0, 0);
        assert_legal(iota(1, 2, 4), E8_M1, 4, 0, 0);
    }

    #[test]
    fn same_width_integer_groups_must_be_aligned() {
        // e32,m2 makes vd, vs2, and the vv-form vs1 two-register groups.
        let vadd = |vd, vs2, src, funct3| op_v(0b000000, 1, vs2, src, funct3, vd);
        assert_illegal(vadd(1, 2, 4, 0b000), E32_M2, 2, 0, 0);
        assert_illegal(vadd(0, 3, 4, 0b000), E32_M2, 2, 0, 0);
        assert_illegal(vadd(0, 2, 5, 0b000), E32_M2, 2, 0, 0);
        assert_legal(vadd(0, 2, 4, 0b000), E32_M2, 2, 0, 0);

        // Scalar and immediate fields are not vector groups.
        assert_legal(vadd(0, 2, 5, 0b100), E32_M2, 2, 0, 0);
        assert_legal(vadd(0, 2, 5, 0b011), E32_M2, 2, 0, 0);
    }

    #[test]
    fn remaining_same_width_families_validate_every_vector_group() {
        for (funct6, funct3) in [
            (0b100101, 0b010), // vmul.vv
            (0b100000, 0b010), // vdivu.vv
            (0b100000, 0b000), // vsaddu.vv
            (0b101010, 0b000), // vssrl.vv
            (0b100111, 0b000), // vsmul.vv
            (0b000000, 0b001), // vfadd.vv
        ] {
            assert_illegal(op_v(funct6, 1, 2, 4, funct3, 1), E32_M2, 2, 0, 0);
            assert_illegal(op_v(funct6, 1, 3, 4, funct3, 0), E32_M2, 2, 0, 0);
            assert_illegal(op_v(funct6, 1, 2, 5, funct3, 0), E32_M2, 2, 0, 0);
            assert_legal(op_v(funct6, 1, 2, 4, funct3, 0), E32_M2, 2, 0, 0);
        }

        for funct3 in [0b100, 0b110, 0b101] {
            assert_illegal(op_v(0b001111, 1, 2, 3, funct3, 1), E32_M2, 2, 0, 0);
            assert_illegal(op_v(0b001111, 1, 3, 3, funct3, 2), E32_M2, 2, 0, 0);
            assert_legal(op_v(0b001111, 1, 2, 3, funct3, 2), E32_M2, 2, 0, 0);
        }
    }

    #[test]
    fn mask_results_validate_sources_and_lowest_register_overlap() {
        for (funct6, funct3) in [
            (0b011000, 0b000), // vmseq.vv
            (0b010001, 0b000), // vmadc.vv
            (0b011000, 0b001), // vmfeq.vv
        ] {
            assert_illegal(op_v(funct6, 1, 2, 4, funct3, 3), E32_M2, 2, 0, 0);
            assert_illegal(op_v(funct6, 1, 2, 5, funct3, 0), E32_M2, 2, 0, 0);
            assert_legal(op_v(funct6, 1, 2, 4, funct3, 2), E32_M2, 2, 0, 0);
        }
    }

    #[test]
    fn masked_nonmask_destinations_cannot_overlap_v0() {
        assert_illegal(op_v(0b000000, 0, 2, 4, 0b000, 0), E32_M2, 2, 0, 0);
        assert_illegal(op_v(0b000000, 0, 2, 4, 0b001, 0), E32_M2, 2, 0, 0);

        // Mask-producing comparisons and scalar reductions are the explicit
        // architectural exceptions to the masked-destination rule.
        assert_legal(op_v(0b011000, 0, 2, 4, 0b000, 0), E32_M2, 2, 0, 0);
        assert_legal(op_v(0b000000, 0, 2, 3, 0b010, 0), E32_M2, 2, 0, 0);
    }

    #[test]
    fn carry_and_borrow_require_vm_zero_and_nonzero_destination() {
        let forms = [
            (0b010000, 0b000), // vadc.vvm
            (0b010000, 0b100), // vadc.vxm
            (0b010000, 0b011), // vadc.vim
            (0b010010, 0b000), // vsbc.vvm
            (0b010010, 0b100), // vsbc.vxm
        ];
        for (funct6, funct3) in forms {
            assert_illegal(op_v(funct6, 1, 2, 3, funct3, 1), E8_M1, 8, 0, 0);
            assert_illegal(op_v(funct6, 0, 2, 3, funct3, 0), E8_M1, 8, 0, 0);
            assert_legal(op_v(funct6, 0, 2, 3, funct3, 1), E8_M1, 8, 0, 0);
        }
    }

    #[test]
    fn slide_up_rejects_overlap_and_misaligned_groups_but_down_allows_overlap() {
        const E8_M2: u64 = 0x01;
        let up_forms = [
            (0b001110, 0b100, E8_M2),  // vslideup.vx
            (0b001110, 0b011, E8_M2),  // vslideup.vi
            (0b001110, 0b110, E8_M2),  // vslide1up.vx
            (0b001110, 0b101, E32_M2), // vfslide1up.vf
        ];
        for (funct6, funct3, vtype) in up_forms {
            assert_illegal(op_v(funct6, 1, 2, 3, funct3, 2), vtype, 4, 0, 0);
            assert_illegal(op_v(funct6, 1, 4, 3, funct3, 1), vtype, 4, 0, 0);
            assert_illegal(op_v(funct6, 1, 3, 3, funct3, 4), vtype, 4, 0, 0);
            assert_legal(op_v(funct6, 1, 4, 3, funct3, 2), vtype, 4, 0, 0);
        }

        // Downward slides explicitly permit source/destination overlap.
        for (funct3, vtype) in [
            (0b100, E8_M2),
            (0b011, E8_M2),
            (0b110, E8_M2),
            (0b101, E32_M2),
        ] {
            assert_legal(op_v(0b001111, 1, 2, 3, funct3, 2), vtype, 4, 0, 0);
        }
    }

    fn narrowing_encodings(vd: u32, vs2: u32, vector_shift: u32) -> Vec<u32> {
        let mut encodings = Vec::new();
        for funct6 in [0b101100, 0b101101, 0b101110, 0b101111] {
            encodings.push(op_v(funct6, 1, vs2, vector_shift, 0b000, vd));
            encodings.push(op_v(funct6, 1, vs2, 5, 0b100, vd));
            encodings.push(op_v(funct6, 1, vs2, 3, 0b011, vd));
        }
        for selector in 0b10000..=0b10111 {
            encodings.push(op_v(0b010010, 1, vs2, selector, 0b001, vd));
        }
        encodings
    }

    #[test]
    fn narrowing_overlap_uses_exact_rational_emul() {
        // LMUL >= 1: same-lowest-register overlap is legal, upper-part overlap
        // is reserved, and a disjoint aligned group is legal.
        for (vtype, same, partial, source, disjoint, vector_shift) in [
            (E32_M1, 2, 3, 2, 4, 6),
            (0x11, 4, 6, 4, 0, 16), // e32,m2: vd=6 overlaps upper half of v4-v7
            (0x12, 8, 12, 8, 0, 16), // e32,m4: vd=12 overlaps upper half of v8-v15
        ] {
            for raw in narrowing_encodings(same, source, vector_shift) {
                assert_legal(raw, vtype, 1, 0, 0);
            }
            for raw in narrowing_encodings(partial, source, vector_shift) {
                assert_illegal(raw, vtype, 1, 0, 0);
            }
            for raw in narrowing_encodings(disjoint, source, vector_shift) {
                assert_legal(raw, vtype, 1, 0, 0);
            }
        }

        // m8 would require an illegal wide source EMUL of 16 registers.
        for raw in narrowing_encodings(0, 0, 16) {
            assert_illegal(raw, 0x13, 1, 0, 0);
        }

        // Fractional LMULs occupy one named register. Odd register numbers are
        // valid, and widening mf8/mf4/mf2 does not invent a two-register group.
        for vtype in [0x15, 0x16, 0x17] {
            for raw in narrowing_encodings(1, 1, 4) {
                assert_legal(raw, vtype, 1, 0, 0);
            }
            for raw in narrowing_encodings(1, 3, 4) {
                assert_legal(raw, vtype, 1, 0, 0);
            }
        }
    }

    #[test]
    fn widening_rejects_low_part_and_fractional_source_overlap() {
        // e32,m1: vd=v0 is a two-register wide destination. A narrow source
        // in v1 overlaps its high part and is legal; a source in v0 overlaps
        // its low part and is reserved.
        assert_legal(op_v(0b110000, 1, 1, 2, 0b010, 0), E32_M1, 1, 0, 0);
        assert_illegal(op_v(0b110000, 1, 0, 2, 0b010, 0), E32_M1, 1, 0, 0);

        // e32,mf2: the narrow source has EMUL=1/2. Although both operands
        // name v1, widening overlap is forbidden when source EMUL is below 1.
        assert_illegal(op_v(0b110000, 1, 1, 2, 0b010, 1), E32_MF2, 1, 0, 0);
    }

    #[test]
    fn widening_arithmetic_covers_integer_fp_and_conversion_families() {
        let narrow_binary = [
            // Integer widening add/subtract and multiply.
            (0b110000, 0b010),
            (0b110001, 0b010),
            (0b110010, 0b010),
            (0b110011, 0b010),
            (0b111000, 0b010),
            (0b111010, 0b010),
            (0b111011, 0b010),
            // Floating-point widening add/subtract and multiply.
            (0b110000, 0b001),
            (0b110010, 0b001),
            (0b111000, 0b001),
        ];
        for (funct6, funct3) in narrow_binary {
            // vd=v0 occupies {v0,v1}. Both narrow vector sources are subject
            // to the same low-part/high-part overlap rule.
            assert_illegal(op_v(funct6, 1, 0, 2, funct3, 0), E32_M1, 1, 0, 0);
            assert_illegal(op_v(funct6, 1, 2, 0, funct3, 0), E32_M1, 1, 0, 0);
            assert_legal(op_v(funct6, 1, 1, 1, funct3, 0), E32_M1, 1, 0, 0);
        }

        for (funct6, funct3) in [
            (0b110000, 0b110),
            (0b110001, 0b110),
            (0b110010, 0b110),
            (0b110011, 0b110),
            (0b111000, 0b110),
            (0b111010, 0b110),
            (0b111011, 0b110),
            (0b110000, 0b101),
            (0b110010, 0b101),
            (0b111000, 0b101),
        ] {
            // Scalar rs1 is not a vector operand; only the narrow vs2 group
            // participates in overlap validation.
            assert_illegal(op_v(funct6, 1, 0, 0, funct3, 0), E32_M1, 1, 0, 0);
            assert_legal(op_v(funct6, 1, 1, 0, funct3, 0), E32_M1, 1, 0, 0);
        }

        // Destructive widening MAC/FMA instructions also read vd at the wide
        // EEW. Any overlap with a narrow vector source would therefore read
        // the same register at two EEWs and is reserved, including high-part
        // overlap that is legal for non-destructive widening operations.
        for (funct6, funct3) in [
            (0b111100, 0b010),
            (0b111101, 0b010),
            (0b111111, 0b010),
            (0b111100, 0b001),
            (0b111101, 0b001),
            (0b111110, 0b001),
            (0b111111, 0b001),
        ] {
            assert_illegal(op_v(funct6, 1, 0, 2, funct3, 0), E32_M1, 1, 0, 0);
            assert_illegal(op_v(funct6, 1, 1, 2, funct3, 0), E32_M1, 1, 0, 0);
            assert_illegal(op_v(funct6, 1, 2, 1, funct3, 0), E32_M1, 1, 0, 0);
            assert_legal(op_v(funct6, 1, 2, 3, funct3, 0), E32_M1, 1, 0, 0);
        }

        for (funct6, funct3) in [
            (0b111100, 0b110),
            (0b111101, 0b110),
            (0b111111, 0b110),
            (0b111100, 0b101),
            (0b111101, 0b101),
            (0b111110, 0b101),
            (0b111111, 0b101),
        ] {
            assert_illegal(op_v(funct6, 1, 1, 0, funct3, 0), E32_M1, 1, 0, 0);
            assert_legal(op_v(funct6, 1, 2, 0, funct3, 0), E32_M1, 1, 0, 0);
        }

        // The vx-only vwmaccus form validates vs2 but must not treat scalar
        // rs1 as a vector-register operand. Its wide accumulator still makes
        // every destination/vs2 overlap reserved.
        assert_illegal(op_v(0b111110, 1, 0, 0, 0b110, 0), E32_M1, 1, 0, 0);
        assert_illegal(op_v(0b111110, 1, 1, 0, 0b110, 0), E32_M1, 1, 0, 0);
        assert_legal(op_v(0b111110, 1, 2, 0, 0b110, 0), E32_M1, 1, 0, 0);

        // Every widening FP/integer conversion is unary and validates its
        // narrow vs2 source before the element loop.
        for selector in 0b01000..=0b01111 {
            if selector == 0b01101 {
                continue; // reserved VFUNARY0 selector
            }
            assert_illegal(op_v(0b010010, 1, 0, selector, 0b001, 0), E32_M1, 1, 0, 0);
            assert_legal(op_v(0b010010, 1, 1, selector, 0b001, 0), E32_M1, 1, 0, 0);
        }
    }

    #[test]
    fn widening_wide_source_forms_allow_same_width_alias() {
        for (funct6, funct3) in [
            (0b110100, 0b010),
            (0b110101, 0b010),
            (0b110110, 0b010),
            (0b110111, 0b010),
            (0b110100, 0b001),
            (0b110110, 0b001),
        ] {
            // Wide vs2 may fully alias the wide destination. The narrow vv
            // source must be disjoint from that wide source because a source
            // register cannot be read at both wide and narrow EEWs.
            assert_legal(op_v(funct6, 1, 0, 2, funct3, 0), E32_M1, 1, 0, 0);
            assert_illegal(op_v(funct6, 1, 0, 0, funct3, 0), E32_M1, 1, 0, 0);
            assert_illegal(op_v(funct6, 1, 0, 1, funct3, 0), E32_M1, 1, 0, 0);

            // With wide vs2 disjoint, narrow vs1 may use the destination's
            // high part under the normal widening overlap rule.
            assert_legal(op_v(funct6, 1, 4, 1, funct3, 0), E32_M1, 1, 0, 0);
        }

        // Scalar .wx/.wf forms have no vector vs1 operand.
        assert_legal(op_v(0b110100, 1, 0, 0, 0b110, 0), E32_M1, 1, 0, 0);
        assert_legal(op_v(0b110100, 1, 0, 0, 0b101, 0), E32_M1, 1, 0, 0);
    }

    #[test]
    fn widening_group_boundaries_use_exact_rational_emul() {
        let vwadd_vv = |vd, vs2| op_v(0b110000, 1, vs2, 8, 0b010, vd);

        for (vtype, high_source) in [(E32_M1, 1), (E32_M2, 2), (E32_M4, 4)] {
            assert_legal(vwadd_vv(0, high_source), vtype, 1, 0, 0);
            assert_illegal(vwadd_vv(0, 0), vtype, 1, 0, 0);
        }

        // A widening result at LMUL=8 would require the reserved EMUL=16.
        assert_illegal(vwadd_vv(0, 8), E32_M8, 1, 0, 0);

        // Fractional narrow sources have EMUL below 1, so any named-register
        // overlap is reserved even though each operand occupies one register.
        for vtype in [E16_MF8, E32_MF4, E32_MF2] {
            assert_illegal(vwadd_vv(1, 1), vtype, 1, 0, 0);
            assert_legal(vwadd_vv(1, 2), vtype, 1, 0, 0);
        }

        // Destination and source group alignment is validated independently.
        assert_illegal(vwadd_vv(1, 2), E32_M1, 1, 0, 0);
        assert_illegal(vwadd_vv(4, 1), E32_M2, 1, 0, 0);
    }

    #[test]
    fn vector_extensions_validate_scaled_source_emul() {
        let extension = |selector, vd, vs2| op_v(0b010010, 1, vs2, selector, 0b010, vd);
        for (selector, vtype, high_source) in [
            (0b00110, E32_M2, 1), // vzext.vf2: source EMUL=1
            (0b00111, E32_M2, 1), // vsext.vf2
            (0b00100, E32_M4, 3), // vzext.vf4: source EMUL=1
            (0b00101, E32_M4, 3), // vsext.vf4
            (0b00010, E64_M8, 7), // vzext.vf8: source EMUL=1
            (0b00011, E64_M8, 7), // vsext.vf8
        ] {
            assert_legal(extension(selector, 0, high_source), vtype, 1, 0, 0);
            assert_illegal(extension(selector, 0, 0), vtype, 1, 0, 0);
        }

        // mf2 divided by the vf8 factor produces source EMUL=1/16,
        // below this ELEN=64 implementation's minimum legal group of 1/8.
        assert_illegal(extension(0b00010, 0, 1), E64_MF2, 1, 0, 0);
    }

    #[test]
    fn widening_reductions_allow_any_scalar_destination_register() {
        for (funct6, funct3) in [
            (0b110000, 0b000),
            (0b110001, 0b000),
            (0b110001, 0b001),
            (0b110011, 0b001),
        ] {
            // Reduction scalar sources and destinations are not LMUL groups;
            // any vector register may hold them even when it lies within vs2.
            assert_legal(op_v(funct6, 1, 0, 3, funct3, 1), E32_M2, 1, 0, 0);
            assert_legal(op_v(funct6, 1, 0, 3, funct3, 0), E32_M2, 1, 0, 0);

            // vs2 itself remains an LMUL-sized vector group.
            assert_illegal(op_v(funct6, 1, 1, 3, funct3, 4), E32_M2, 1, 0, 0);
        }
    }

    #[test]
    fn every_reduction_rejects_nonzero_vstart_and_validates_vector_source() {
        let forms = [
            (0b000000, 0b010), // vredsum.vs
            (0b000001, 0b001), // vfredusum.vs
            (0b110000, 0b000), // vwredsumu.vs
            (0b110001, 0b001), // vfwredusum.vs
        ];
        for (funct6, funct3) in forms {
            let legal = op_v(funct6, 1, 2, 3, funct3, 1);
            assert_illegal(legal, E32_M2, 2, 1, 0);
            assert_legal(legal, E32_M2, 2, 0, 0);

            let misaligned_vs2 = op_v(funct6, 1, 1, 3, funct3, 1);
            assert_illegal(misaligned_vs2, E32_M2, 2, 0, 0);
        }
    }

    #[test]
    fn vector_fp_validation_rejects_unsupported_eew8_without_overrejecting_conversions() {
        // Single-width and widening arithmetic would consume 8-bit floating-
        // point operands, for which RAX exposes no supported IEEE format.
        assert_illegal(op_v(0b000000, 1, 2, 3, 0b001, 1), E8_M1, 1, 0, 0);
        assert_illegal(op_v(0b110000, 1, 2, 3, 0b001, 0), E8_M1, 1, 0, 0);

        // At SEW=8, Zvfh defines the integer-to-FP widening conversions and
        // FP-to-integer narrowing conversions because their FP operand is
        // 16 bits. The inverse directions still use an FP8 operand and trap.
        for selector in [0b01010, 0b01011] {
            assert_legal(op_v(0b010010, 1, 2, selector, 0b001, 0), E8_M1, 1, 0, 0);
        }
        for selector in [0b01000, 0b01001, 0b01100, 0b01110, 0b01111] {
            assert_illegal(op_v(0b010010, 1, 2, selector, 0b001, 0), E8_M1, 1, 0, 0);
        }
        // The entry validator must not preempt the separately owned narrowing
        // semantic path for its defined FP16-to-integer8 variants.
        for selector in [0b10000, 0b10001, 0b10110, 0b10111] {
            assert_legal(op_v(0b010010, 1, 2, selector, 0b001, 1), E8_M1, 1, 0, 0);
        }
        for selector in [0b10010, 0b10011, 0b10100, 0b10101] {
            assert_illegal(op_v(0b010010, 1, 2, selector, 0b001, 1), E8_M1, 1, 0, 0);
        }

        // Integer data paths remain legal at SEW=8.
        assert_legal(op_v(0b000000, 1, 2, 3, 0b000, 1), E8_M1, 1, 0, 0);
    }

    #[test]
    fn vfncvt_fp16_to_unsigned_integer8_rounds_saturates_and_accrues_flags() {
        let raw = op_v(0b010010, 1, 2, 0b10000, 0b001, 1); // vfncvt.xu.f.w v1,v2
        let insn = decoded(raw);
        let mut cpu = cpu(E8_M1, 4, 0, 0);
        let mut source = [0u8; 16];
        for (lane, bits) in [0x3e00u16, 0xbc00, 0x5c00, 0x7e00].into_iter().enumerate() {
            source[lane * 2..lane * 2 + 2].copy_from_slice(&bits.to_le_bytes());
        }
        cpu.set_vreg(2, &source);

        assert_eq!(cpu.execute_insn(&insn, 0x1000), Ok(RiscVExit::Continue));

        assert_eq!(&cpu.vreg(1)[0..4], &[2, 0, u8::MAX, u8::MAX]);
        assert_eq!(
            cpu.fcsr(),
            crate::isa::riscv::float::fflags::NX | crate::isa::riscv::float::fflags::NV
        );
        assert_eq!(cpu.vstart(), 0);
    }

    #[test]
    fn narrowing_rejects_misaligned_groups_and_reserved_lmul() {
        // e32,m2 has a two-register destination and a four-register wide source.
        for raw in narrowing_encodings(1, 4, 16) {
            assert_illegal(raw, 0x11, 1, 0, 0);
        }
        for raw in narrowing_encodings(0, 2, 16) {
            assert_illegal(raw, 0x11, 1, 0, 0);
        }
        // vlmul=100 is reserved even when injected directly through the test API.
        for raw in narrowing_encodings(0, 0, 4) {
            assert_illegal(raw, 0x14, 1, 0, 0);
        }
    }

    fn decoded_vector_fp_encodings() -> Vec<Insn> {
        let isa = Isa::rv64gc();
        let mut encodings = Vec::new();
        for funct6 in 0..64 {
            for funct3 in [0b001, 0b101] {
                for src in 0..32 {
                    // Keep vd/vs2 disjoint and aligned for widening/narrowing
                    // groups. The src field is still exhaustively enumerated
                    // because it is either an operand or a unary selector.
                    let raw = op_v(funct6, 1, 12, src, funct3, 8);
                    let insn = decode(raw, Xlen::Rv64, &isa);
                    if insn.op != Op::Illegal {
                        encodings.push(insn);
                    }
                }
            }
        }
        // vfmv.s.f uses vs2=0 as an additional encoding constraint.
        encodings.push(decoded(op_v(0b010000, 1, 0, 3, 0b101, 8)));
        encodings
    }

    #[test]
    fn every_decoded_opfvv_and_opfvf_encoding_validates_frm() {
        let encodings = decoded_vector_fp_encodings();
        assert!(
            encodings.len() > 100,
            "decoder enumeration unexpectedly found too few FP encodings"
        );

        let mut decoded_ops = Vec::new();
        let mut otherwise_legal_ops = Vec::new();

        for insn in encodings {
            assert!(is_vector_fp_encoding(&insn), "missed {:?}", insn.op);
            if !decoded_ops.contains(&insn.op) {
                decoded_ops.push(insn.op);
            }

            let legal_for_all_frm = (0..=4).all(|frm| {
                let cpu = cpu(E32_M1, 4, 0, frm);
                validate(&cpu, &insn, true) == Ok(())
            });
            if legal_for_all_frm && !otherwise_legal_ops.contains(&insn.op) {
                otherwise_legal_ops.push(insn.op);
            }

            for frm in 5..=7 {
                let cpu = cpu(E32_M1, 0, 8, frm);
                assert_eq!(
                    validate(&cpu, &insn, true),
                    Err(Trap::illegal(insn.raw)),
                    "reserved frm={frm} accepted for {:?} ({:08x})",
                    insn.op,
                    insn.raw
                );
            }
        }

        for op in decoded_ops {
            assert!(
                otherwise_legal_ops.contains(&op),
                "decoder enumeration found no register-valid encoding for {op:?}"
            );
        }

        let vector_load = decoded((1 << 25) | (10 << 15) | (6 << 12) | (1 << 7) | 0x07);
        assert!(!is_vector_fp_encoding(&vector_load));
    }

    #[test]
    fn reserved_frm_traps_before_vl_and_vstart_short_circuits() {
        let representatives = [
            op_v(0b000000, 1, 2, 3, 0b001, 1),       // vfadd.vv
            op_v(0b000100, 1, 2, 3, 0b001, 1),       // vfmin.vv (exact)
            op_v(0b001000, 1, 2, 3, 0b001, 1),       // vfsgnj.vv (exact)
            op_v(0b011000, 1, 2, 3, 0b001, 1),       // vmfeq.vv
            op_v(0b010011, 1, 2, 0b10000, 0b001, 1), // vfclass.v
            op_v(0b010000, 1, 2, 0, 0b001, 1),       // vfmv.f.s
            op_v(0b010000, 1, 0, 3, 0b101, 1),       // vfmv.s.f
            op_v(0b010011, 1, 2, 0b00100, 0b001, 1), // vfrsqrt7.v
            op_v(0b010010, 1, 2, 0b00110, 0b001, 1), // vfcvt.rtz.xu.f.v
            op_v(0b001110, 1, 2, 3, 0b101, 1),       // vfslide1up.vf
            op_v(0b000001, 1, 2, 3, 0b001, 1),       // vfredusum.vs
            op_v(0b110000, 1, 2, 3, 0b001, 1),       // vfwadd.vv
        ];

        for raw in representatives {
            for frm in 5..=7 {
                assert_illegal(raw, E32_M1, 0, 0, frm);
                assert_illegal(raw, E32_M1, 4, 4, frm);
            }
        }
    }
}
