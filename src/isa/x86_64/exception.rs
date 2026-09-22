//! IA-32e interrupt- and exception-gate validation and delivery.
//!
//! Delivery is kept outside `cpu.rs` because it is a complete architectural
//! operation: every descriptor, stack pointer, and frame address is validated
//! before visible register state is committed.

use crate::error::{Error, Result};
use crate::isa::x86_64::cpu::{X86_64Vcpu, log_if_transition};
use crate::isa::x86_64::execute::system::is_canonical_48;
use crate::isa::x86_64::flags;
use crate::vm::vcpu::Segment;

const EFER_LMA: u64 = 1 << 10;
const GATE_INTERRUPT_16: u8 = 0x6;
const GATE_TRAP_16: u8 = 0x7;
const GATE_INTERRUPT: u8 = 0xE;
const GATE_TRAP: u8 = 0xF;

type DeliveryResult<T> = std::result::Result<T, DeliveryFailure>;

#[derive(Debug)]
enum DeliveryFailure {
    Architectural {
        vector: u8,
        error_code: u64,
        cr2: Option<u64>,
        detail: String,
    },
    Other(Error),
}

impl std::fmt::Display for DeliveryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Architectural { detail, .. } => formatter.write_str(detail),
            Self::Other(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl From<Error> for DeliveryFailure {
    fn from(error: Error) -> Self {
        match error {
            Error::PageFault { vaddr, error_code } => Self::Architectural {
                vector: 14,
                error_code,
                cr2: Some(vaddr),
                detail: format!("#PF({error_code:#x}) during event delivery at {vaddr:#018x}"),
            },
            Error::GeneralProtection { error_code } => Self::Architectural {
                vector: 13,
                error_code,
                cr2: None,
                detail: format!("#GP({error_code:#x}) during event delivery"),
            },
            other => Self::Other(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventSource {
    /// INT n, INT3, or INTO. Gate DPL applies and nested-fault EXT is zero.
    Software,
    /// Processor-detected exceptions, including INT1. Gate DPL is ignored and
    /// selector/IDT error-code EXT is zero.
    Exception,
    /// NMI and maskable external interrupts. Gate DPL is ignored and nested
    /// selector/IDT error-code EXT is one.
    External,
}

impl EventSource {
    #[inline]
    fn ext(self) -> u32 {
        u32::from(self == Self::External)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdtGate64 {
    offset: u64,
    selector: u16,
    ist: u8,
    dpl: u8,
    gate_type: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdtGateLegacy {
    offset: u32,
    selector: u16,
    dpl: u8,
    gate_type: u8,
    width: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CodeTarget64 {
    segment: SegmentFields,
    accessed_descriptor: u64,
    descriptor_addr: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SegmentFields {
    base: u64,
    limit: u32,
    type_: u8,
    dpl: u8,
    l: bool,
    db: bool,
    g: bool,
    avl: bool,
}

#[inline]
fn idt_error_code(vector: u8, source: EventSource) -> u32 {
    (u32::from(vector) << 3) | 2 | source.ext()
}

#[inline]
fn selector_error_code(selector: u16, source: EventSource) -> u32 {
    u32::from(selector & 0xFFFC) | source.ext()
}

fn delivery_fault(kind: &str, error_code: u32, detail: impl std::fmt::Display) -> DeliveryFailure {
    let vector = match kind {
        "#TS" => 10,
        "#NP" => 11,
        "#SS" => 12,
        "#GP" => 13,
        _ => unreachable!("internal event-delivery fault kind {kind}"),
    };
    DeliveryFailure::Architectural {
        vector,
        error_code: u64::from(error_code),
        cr2: None,
        detail: format!("{kind}({error_code:#x}) during IA-32e event delivery: {detail}"),
    }
}

fn decode_gate64(
    vector: u8,
    entry: [u8; 16],
    source: EventSource,
    cpl: u8,
) -> DeliveryResult<IdtGate64> {
    let error_code = idt_error_code(vector, source);
    let selector = u16::from_le_bytes([entry[2], entry[3]]);
    let reserved_ist = entry[4] & 0xF8;
    let type_attr = entry[5];
    let gate_type = type_attr & 0x0F;
    let system = type_attr & 0x10 == 0;
    if reserved_ist != 0
        || entry[12..16] != [0; 4]
        || !system
        || !matches!(gate_type, GATE_INTERRUPT | GATE_TRAP)
    {
        return Err(delivery_fault(
            "#GP",
            error_code,
            format_args!(
                "IDT entry {vector} has reserved/type bits (ist={:#x}, type_attr={type_attr:#x}, reserved={:02x?})",
                entry[4],
                &entry[12..16]
            ),
        ));
    }
    if type_attr & 0x80 == 0 {
        return Err(delivery_fault(
            "#NP",
            error_code,
            format_args!("IDT entry {vector} not present (type_attr={type_attr:#x})"),
        ));
    }
    let dpl = (type_attr >> 5) & 3;
    if source == EventSource::Software && dpl < cpl {
        return Err(delivery_fault(
            "#GP",
            error_code,
            format_args!("software interrupt CPL {cpl} exceeds IDT entry {vector} DPL {dpl}"),
        ));
    }
    if selector & 0xFFFC == 0 {
        return Err(delivery_fault(
            "#GP",
            source.ext(),
            format_args!("IDT entry {vector} contains a null code selector"),
        ));
    }

    let offset = u64::from(u16::from_le_bytes([entry[0], entry[1]]))
        | (u64::from(u16::from_le_bytes([entry[6], entry[7]])) << 16)
        | (u64::from(u32::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11],
        ])) << 32);
    if !is_canonical_48(offset) {
        return Err(delivery_fault(
            "#GP",
            source.ext(),
            format_args!("IDT entry {vector} handler {offset:#018x} is non-canonical"),
        ));
    }

    Ok(IdtGate64 {
        offset,
        selector,
        ist: entry[4] & 7,
        dpl,
        gate_type,
    })
}

fn decode_gate_legacy(
    vector: u8,
    entry: [u8; 8],
    source: EventSource,
    cpl: u8,
) -> DeliveryResult<IdtGateLegacy> {
    let error_code = idt_error_code(vector, source);
    let selector = u16::from_le_bytes([entry[2], entry[3]]);
    let type_attr = entry[5];
    let gate_type = type_attr & 0x0F;
    let system = type_attr & 0x10 == 0;
    if entry[4] != 0
        || !system
        || !matches!(
            gate_type,
            GATE_INTERRUPT_16 | GATE_TRAP_16 | GATE_INTERRUPT | GATE_TRAP
        )
    {
        return Err(delivery_fault(
            "#GP",
            error_code,
            format_args!(
                "legacy IDT entry {vector} has reserved/type bits (reserved={:#x}, type_attr={type_attr:#x})",
                entry[4]
            ),
        ));
    }
    if type_attr & 0x80 == 0 {
        return Err(delivery_fault(
            "#NP",
            error_code,
            format_args!("IDT entry {vector} not present (type_attr={type_attr:#x})"),
        ));
    }
    let dpl = (type_attr >> 5) & 3;
    if source == EventSource::Software && dpl < cpl {
        return Err(delivery_fault(
            "#GP",
            error_code,
            format_args!("software interrupt CPL {cpl} exceeds IDT entry {vector} DPL {dpl}"),
        ));
    }
    if selector & 0xFFFC == 0 {
        return Err(delivery_fault(
            "#GP",
            source.ext(),
            format_args!("legacy IDT entry {vector} contains a null code selector"),
        ));
    }

    let width = if gate_type & 8 != 0 { 4 } else { 2 };
    let mut offset = u32::from(u16::from_le_bytes([entry[0], entry[1]]));
    if width == 4 {
        offset |= u32::from(u16::from_le_bytes([entry[6], entry[7]])) << 16;
    }
    Ok(IdtGateLegacy {
        offset,
        selector,
        dpl,
        gate_type,
        width,
    })
}

#[inline]
fn descriptor_base(raw: u64) -> u64 {
    ((raw >> 16) & 0xFFFF) | (((raw >> 32) & 0xFF) << 16) | (((raw >> 56) & 0xFF) << 24)
}

#[inline]
fn descriptor_limit(raw: u64) -> u32 {
    let raw_limit = ((raw & 0xFFFF) | (((raw >> 48) & 0x0F) << 16)) as u32;
    if raw >> 55 & 1 != 0 {
        (raw_limit << 12) | 0xFFF
    } else {
        raw_limit
    }
}

fn decode_code_target64(
    selector: u16,
    raw: u64,
    descriptor_addr: u64,
    old_cpl: u8,
    source: EventSource,
) -> DeliveryResult<(CodeTarget64, u8)> {
    let error_code = selector_error_code(selector, source);
    let type_ = ((raw >> 40) & 0xF) as u8;
    let code = raw >> 44 & 1 != 0 && type_ & 0x8 != 0;
    let dpl = ((raw >> 45) & 3) as u8;
    let conforming = type_ & 0x4 != 0;
    if !code || dpl > old_cpl {
        return Err(delivery_fault(
            "#GP",
            error_code,
            format_args!("selector {selector:#06x} is not an accessible code segment"),
        ));
    }
    if raw >> 47 & 1 == 0 {
        return Err(delivery_fault(
            "#NP",
            error_code,
            format_args!("code selector {selector:#06x} is not present"),
        ));
    }
    let l = raw >> 53 & 1 != 0;
    let db = raw >> 54 & 1 != 0;
    if !l || db {
        return Err(delivery_fault(
            "#GP",
            error_code,
            format_args!("selector {selector:#06x} is not a 64-bit L=1,D=0 code segment"),
        ));
    }
    let target_cpl = if conforming { old_cpl } else { dpl };
    Ok((
        CodeTarget64 {
            segment: SegmentFields {
                base: descriptor_base(raw),
                limit: descriptor_limit(raw),
                type_: type_ | 1,
                dpl,
                l,
                db,
                g: raw >> 55 & 1 != 0,
                avl: raw >> 52 & 1 != 0,
            },
            accessed_descriptor: raw | (1 << 40),
            descriptor_addr,
        },
        target_cpl,
    ))
}

fn decode_code_target_legacy(
    selector: u16,
    raw: u64,
    old_cpl: u8,
    source: EventSource,
    offset: u32,
) -> DeliveryResult<(SegmentFields, u64, u8)> {
    let error_code = selector_error_code(selector, source);
    let type_ = ((raw >> 40) & 0xF) as u8;
    let code = raw >> 44 & 1 != 0 && type_ & 0x8 != 0;
    let dpl = ((raw >> 45) & 3) as u8;
    let conforming = type_ & 0x4 != 0;
    if !code || dpl > old_cpl || raw >> 53 & 1 != 0 {
        return Err(delivery_fault(
            "#GP",
            error_code,
            format_args!("selector {selector:#06x} is not an accessible legacy code segment"),
        ));
    }
    if raw >> 47 & 1 == 0 {
        return Err(delivery_fault(
            "#NP",
            error_code,
            format_args!("code selector {selector:#06x} is not present"),
        ));
    }
    let limit = descriptor_limit(raw);
    if offset > limit {
        return Err(delivery_fault(
            "#GP",
            source.ext(),
            format_args!("handler offset {offset:#010x} exceeds code-segment limit {limit:#010x}"),
        ));
    }
    let target_cpl = if conforming { old_cpl } else { dpl };
    Ok((
        SegmentFields {
            base: descriptor_base(raw),
            limit,
            type_: type_ | 1,
            dpl,
            l: false,
            db: raw >> 54 & 1 != 0,
            g: raw >> 55 & 1 != 0,
            avl: raw >> 52 & 1 != 0,
        },
        raw | (1 << 40),
        target_cpl,
    ))
}

fn legacy_stack_range_valid(segment: &Segment, offset: u64, width: u8) -> bool {
    let upper = if segment.db {
        u64::from(u32::MAX)
    } else {
        u64::from(u16::MAX)
    };
    let Some(last) = offset.checked_add(u64::from(width) - 1) else {
        return false;
    };
    if last > upper {
        return false;
    }
    let expand_down = segment.type_ & 0x4 != 0;
    if expand_down {
        offset > u64::from(segment.limit)
    } else {
        last <= u64::from(segment.limit)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExceptionClass {
    Benign,
    Contributory,
    PageFault,
}

fn exception_class(vector: u8) -> ExceptionClass {
    match vector {
        0 | 10..=13 => ExceptionClass::Contributory,
        14 => ExceptionClass::PageFault,
        _ => ExceptionClass::Benign,
    }
}

fn becomes_double_fault(first: u8, second: u8) -> bool {
    matches!(
        (exception_class(first), exception_class(second)),
        (
            ExceptionClass::Contributory | ExceptionClass::PageFault,
            ExceptionClass::Contributory | ExceptionClass::PageFault
        )
    )
}

impl X86_64Vcpu {
    pub fn inject_exception(&mut self, vector: u8, error_code: Option<u64>) -> Result<()> {
        let pc = self.regs.rip;
        self.deliver_event(vector, error_code, EventSource::Exception, None)
            .map_err(|error| {
                // A failed #UD delivery must not be mistaken for an ordinary
                // sparse guest access and "repaired" with fabricated IDT bytes.
                if vector == 6 {
                    Error::InvalidInstruction {
                        pc,
                        diagnosis: error.to_string(),
                    }
                } else {
                    error
                }
            })
    }

    pub(super) fn inject_software_interrupt(
        &mut self,
        vector: u8,
        error_code: Option<u64>,
        fault_rip: u64,
    ) -> Result<()> {
        self.deliver_event(vector, error_code, EventSource::Software, Some(fault_rip))
    }

    pub(super) fn inject_external_event(
        &mut self,
        vector: u8,
        error_code: Option<u64>,
    ) -> Result<()> {
        self.deliver_event(vector, error_code, EventSource::External, None)
    }

    fn deliver_event(
        &mut self,
        vector: u8,
        error_code: Option<u64>,
        source: EventSource,
        software_fault_rip: Option<u64>,
    ) -> Result<()> {
        let original_vector = vector;
        let mut current_vector = vector;
        let mut current_error = error_code;
        let mut current_source = source;
        let mut chain = Vec::new();
        let mut first_attempt = true;
        let externally_caused = source == EventSource::External;

        loop {
            match self.deliver_event_once(current_vector, current_error, current_source) {
                Ok(()) => return Ok(()),
                Err(DeliveryFailure::Other(error)) => return Err(error),
                Err(DeliveryFailure::Architectural {
                    vector: nested_vector,
                    error_code: nested_error,
                    cr2,
                    detail,
                }) => {
                    chain.push(detail);
                    if current_vector == 8 {
                        return Err(Error::Emulator(format!(
                            "triple fault while delivering vector {original_vector}; original IDT entry {original_vector} not present or valid: {}",
                            chain.join("; ")
                        )));
                    }
                    if first_attempt {
                        if let Some(rip) = software_fault_rip {
                            // A protection fault discovered while evaluating a
                            // software interrupt is fault-class, not the INT's
                            // post-instruction trap return address.
                            self.regs.rip = rip;
                        }
                    }
                    first_attempt = false;
                    if let Some(vaddr) = cr2 {
                        self.sregs.cr2 = vaddr;
                    }
                    if becomes_double_fault(current_vector, nested_vector) {
                        current_vector = 8;
                        current_error = Some(0);
                    } else {
                        current_vector = nested_vector;
                        current_error = Some(nested_error);
                    }
                    current_source = if externally_caused {
                        EventSource::External
                    } else {
                        EventSource::Exception
                    };
                }
            }
        }
    }

    fn deliver_event_once(
        &mut self,
        vector: u8,
        error_code: Option<u64>,
        source: EventSource,
    ) -> DeliveryResult<()> {
        if self.sregs.cr0 & 1 == 0 {
            return self.deliver_real_mode_event(vector, source);
        }
        if self.sregs.efer & EFER_LMA == 0 {
            return self.deliver_legacy_protected_event(vector, error_code, source);
        }

        let entry_offset = u64::from(vector) * 16;
        if entry_offset
            .checked_add(15)
            .is_none_or(|last| last > u64::from(self.sregs.idt.limit))
        {
            return Err(delivery_fault(
                "#GP",
                idt_error_code(vector, source),
                format_args!(
                    "IDT entry {vector} exceeds IDTR limit {:#x}",
                    self.sregs.idt.limit
                ),
            ));
        }
        let Some(entry_addr) = self.sregs.idt.base.checked_add(entry_offset) else {
            return Err(delivery_fault(
                "#GP",
                idt_error_code(vector, source),
                "IDT address overflow",
            ));
        };
        if !is_canonical_48(entry_addr) || !is_canonical_48(entry_addr + 15) {
            return Err(delivery_fault(
                "#GP",
                idt_error_code(vector, source),
                format_args!("IDT entry address {entry_addr:#018x} is non-canonical"),
            ));
        }

        let mut entry = [0_u8; 16];
        self.mmu
            .read_supervisor(entry_addr, &mut entry, &self.sregs)?;
        let old_cpl = (self.sregs.cs.selector & 3) as u8;
        let gate = decode_gate64(vector, entry, source, old_cpl)?;

        let ti = gate.selector & 4 != 0;
        if ti && (self.sregs.ldt.selector & 0xFFFC == 0 || self.sregs.ldt.unusable) {
            return Err(delivery_fault(
                "#GP",
                selector_error_code(gate.selector, source),
                "gate selects an unusable LDT",
            ));
        }
        let (table_base, table_limit) = if ti {
            (self.sregs.ldt.base, u64::from(self.sregs.ldt.limit))
        } else {
            (self.sregs.gdt.base, u64::from(self.sregs.gdt.limit))
        };
        let descriptor_offset = u64::from(gate.selector >> 3) * 8;
        if descriptor_offset
            .checked_add(7)
            .is_none_or(|last| last > table_limit)
        {
            return Err(delivery_fault(
                "#GP",
                selector_error_code(gate.selector, source),
                format_args!(
                    "code selector {:#06x} exceeds descriptor-table limit",
                    gate.selector
                ),
            ));
        }
        let Some(descriptor_addr) = table_base.checked_add(descriptor_offset) else {
            return Err(delivery_fault(
                "#GP",
                selector_error_code(gate.selector, source),
                "code-descriptor address overflow",
            ));
        };
        if !is_canonical_48(descriptor_addr) || !is_canonical_48(descriptor_addr + 7) {
            return Err(delivery_fault(
                "#GP",
                selector_error_code(gate.selector, source),
                format_args!("code-descriptor address {descriptor_addr:#018x} is non-canonical"),
            ));
        }
        let raw = self.mmu.read_u64_supervisor(descriptor_addr, &self.sregs)?;
        let (target, target_cpl) =
            decode_code_target64(gate.selector, raw, descriptor_addr, old_cpl, source)?;

        self.materialize_flags();
        let old_ss = self.sregs.ss.selector;
        let old_rsp = self.regs.rsp;
        let old_rflags = self.regs.rflags;
        let old_cs = self.sregs.cs.selector;
        let old_rip = self.regs.rip;

        let stack_switch = gate.ist != 0 || target_cpl < old_cpl;
        let mut frame_rsp = if stack_switch {
            let tr_error = selector_error_code(self.sregs.tr.selector, source);
            if self.sregs.tr.selector & 0xFFFC == 0
                || self.sregs.tr.unusable
                || !self.sregs.tr.present
                || !matches!(self.sregs.tr.type_ & 0xF, 9 | 11)
            {
                return Err(delivery_fault(
                    "#TS",
                    tr_error,
                    "stack switch requires a present 64-bit TSS",
                ));
            }
            let tss_offset = if gate.ist == 0 {
                4 + u64::from(target_cpl) * 8
            } else {
                0x24 + (u64::from(gate.ist) - 1) * 8
            };
            if tss_offset + 7 > u64::from(self.sregs.tr.limit) {
                return Err(delivery_fault(
                    "#TS",
                    tr_error,
                    format_args!("TSS stack pointer at offset {tss_offset:#x} exceeds its limit"),
                ));
            }
            let Some(tss_addr) = self.sregs.tr.base.checked_add(tss_offset) else {
                return Err(delivery_fault("#TS", tr_error, "TSS address overflow"));
            };
            if !is_canonical_48(tss_addr) || !is_canonical_48(tss_addr + 7) {
                return Err(delivery_fault(
                    "#TS",
                    tr_error,
                    format_args!("TSS stack-pointer address {tss_addr:#018x} is non-canonical"),
                ));
            }
            let rsp = self.mmu.read_u64_supervisor(tss_addr, &self.sregs)?;
            if !is_canonical_48(rsp) {
                return Err(delivery_fault(
                    "#SS",
                    source.ext(),
                    format_args!("TSS supplied non-canonical RSP {rsp:#018x}"),
                ));
            }
            rsp & !0xF
        } else {
            old_rsp
        };

        let mut frame = [0_u64; 6];
        let mut frame_len = 5;
        frame[..5].copy_from_slice(&[
            u64::from(old_ss),
            old_rsp,
            old_rflags,
            u64::from(old_cs),
            old_rip,
        ]);
        if let Some(code) = error_code {
            frame[5] = code;
            frame_len = 6;
        }
        let final_rsp = frame_rsp.wrapping_sub((frame_len as u64) * 8);
        if !is_canonical_48(frame_rsp) || !is_canonical_48(final_rsp) {
            return Err(delivery_fault(
                "#SS",
                source.ext(),
                format_args!("event frame [{final_rsp:#018x}, {frame_rsp:#018x}) is non-canonical"),
            ));
        }

        // Loading CS marks the descriptor accessed. Complete this store and all
        // frame stores before exposing the new architectural register state.
        if target.accessed_descriptor != raw {
            self.mmu.write_u64_supervisor(
                target.descriptor_addr,
                target.accessed_descriptor,
                &self.sregs,
            )?;
        }
        for value in frame.into_iter().take(frame_len) {
            frame_rsp = frame_rsp.wrapping_sub(8);
            self.mmu
                .write_u64_supervisor(frame_rsp, value, &self.sregs)?;
        }

        let fields = target.segment;
        self.sregs.cs = Segment {
            base: fields.base,
            limit: fields.limit,
            selector: (gate.selector & !3) | u16::from(target_cpl),
            type_: fields.type_,
            present: true,
            dpl: fields.dpl,
            db: fields.db,
            s: true,
            l: fields.l,
            g: fields.g,
            avl: fields.avl,
            unusable: false,
        };
        if stack_switch {
            self.sregs.ss = Segment {
                selector: u16::from(target_cpl),
                dpl: target_cpl,
                present: true,
                unusable: false,
                ..Segment::default()
            };
        }
        self.regs.rsp = frame_rsp;
        self.regs.rip = gate.offset;

        let old_if = old_rflags & flags::bits::IF != 0;
        let mut clear = flags::bits::TF | flags::bits::NT | flags::bits::RF | flags::bits::VM;
        if gate.gate_type == GATE_INTERRUPT {
            clear |= flags::bits::IF;
        }
        self.regs.rflags &= !clear;
        if gate.gate_type == GATE_INTERRUPT {
            log_if_transition(
                gate.offset,
                old_if,
                false,
                &format!("INT_GATE(vec={vector})"),
            );
        }
        self.interrupt_inhibit = false;
        Ok(())
    }

    fn deliver_legacy_protected_event(
        &mut self,
        vector: u8,
        error_code: Option<u64>,
        source: EventSource,
    ) -> DeliveryResult<()> {
        let entry_offset = u64::from(vector) * 8;
        if entry_offset
            .checked_add(7)
            .is_none_or(|last| last > u64::from(self.sregs.idt.limit))
        {
            return Err(delivery_fault(
                "#GP",
                idt_error_code(vector, source),
                format_args!(
                    "legacy IDT entry {vector} exceeds IDTR limit {:#x}",
                    self.sregs.idt.limit
                ),
            ));
        }
        let Some(entry_addr) = self.sregs.idt.base.checked_add(entry_offset) else {
            return Err(delivery_fault(
                "#GP",
                idt_error_code(vector, source),
                "legacy IDT address overflow",
            ));
        };
        let mut entry = [0_u8; 8];
        self.mmu
            .read_supervisor(entry_addr, &mut entry, &self.sregs)?;

        let virtual_8086 = self.regs.rflags & flags::bits::VM != 0;
        let old_cpl = if virtual_8086 {
            3
        } else {
            (self.sregs.cs.selector & 3) as u8
        };
        let gate = decode_gate_legacy(vector, entry, source, old_cpl)?;
        let descriptor_error = selector_error_code(gate.selector, source);
        let ti = gate.selector & 4 != 0;
        if ti && (self.sregs.ldt.selector & 0xFFFC == 0 || self.sregs.ldt.unusable) {
            return Err(delivery_fault(
                "#GP",
                descriptor_error,
                "legacy gate selects an unusable LDT",
            ));
        }
        let (table_base, table_limit) = if ti {
            (self.sregs.ldt.base, u64::from(self.sregs.ldt.limit))
        } else {
            (self.sregs.gdt.base, u64::from(self.sregs.gdt.limit))
        };
        let descriptor_offset = u64::from(gate.selector >> 3) * 8;
        if descriptor_offset
            .checked_add(7)
            .is_none_or(|last| last > table_limit)
        {
            return Err(delivery_fault(
                "#GP",
                descriptor_error,
                format_args!(
                    "code selector {:#06x} exceeds descriptor-table limit",
                    gate.selector
                ),
            ));
        }
        let Some(descriptor_addr) = table_base.checked_add(descriptor_offset) else {
            return Err(delivery_fault(
                "#GP",
                descriptor_error,
                "legacy code-descriptor address overflow",
            ));
        };
        let raw = self.mmu.read_u64_supervisor(descriptor_addr, &self.sregs)?;
        let (code_fields, accessed_code, target_cpl) =
            decode_code_target_legacy(gate.selector, raw, old_cpl, source, gate.offset)?;

        if virtual_8086 && target_cpl == 3 {
            return Err(delivery_fault(
                "#GP",
                descriptor_error,
                "virtual-8086 event target must enter a more privileged code segment",
            ));
        }
        let stack_switch = target_cpl < old_cpl || virtual_8086;
        let old_ss = self.sregs.ss.selector;
        let old_sp = if self.sregs.ss.db {
            self.regs.rsp & u64::from(u32::MAX)
        } else {
            self.regs.rsp & u64::from(u16::MAX)
        };
        let mut stack_segment = self.sregs.ss.clone();
        let mut frame_sp = old_sp;
        let mut accessed_stack = None;

        if stack_switch {
            let tr_error = selector_error_code(self.sregs.tr.selector, source);
            let tr_type = self.sregs.tr.type_ & 0xF;
            if self.sregs.tr.selector & 0xFFFC == 0
                || self.sregs.tr.unusable
                || !self.sregs.tr.present
                || self.sregs.tr.s
                || !matches!(tr_type, 1 | 3 | 9 | 11)
            {
                return Err(delivery_fault(
                    "#TS",
                    tr_error,
                    "privilege switch requires a present 16- or 32-bit TSS",
                ));
            }
            let tss32 = matches!(tr_type, 9 | 11);
            let (sp_offset, ss_offset, field_width) = if tss32 {
                (
                    4 + u64::from(target_cpl) * 8,
                    8 + u64::from(target_cpl) * 8,
                    4,
                )
            } else {
                (
                    2 + u64::from(target_cpl) * 4,
                    4 + u64::from(target_cpl) * 4,
                    2,
                )
            };
            if ss_offset + 1 > u64::from(self.sregs.tr.limit)
                || sp_offset + field_width - 1 > u64::from(self.sregs.tr.limit)
            {
                return Err(delivery_fault(
                    "#TS",
                    tr_error,
                    "TSS privilege-stack fields exceed the TSS limit",
                ));
            }
            let Some(sp_addr) = self.sregs.tr.base.checked_add(sp_offset) else {
                return Err(delivery_fault(
                    "#TS",
                    tr_error,
                    "TSS stack-pointer address overflow",
                ));
            };
            let Some(ss_addr) = self.sregs.tr.base.checked_add(ss_offset) else {
                return Err(delivery_fault(
                    "#TS",
                    tr_error,
                    "TSS stack-selector address overflow",
                ));
            };
            let mut sp_bytes = [0_u8; 4];
            self.mmu.read_supervisor(
                sp_addr,
                &mut sp_bytes[..field_width as usize],
                &self.sregs,
            )?;
            frame_sp = if tss32 {
                u64::from(u32::from_le_bytes(sp_bytes))
            } else {
                u64::from(u16::from_le_bytes([sp_bytes[0], sp_bytes[1]]))
            };
            let mut ss_bytes = [0_u8; 2];
            self.mmu
                .read_supervisor(ss_addr, &mut ss_bytes, &self.sregs)?;
            let new_ss = u16::from_le_bytes(ss_bytes);
            let ss_error = selector_error_code(new_ss, source);
            if new_ss & 0xFFFC == 0 || (new_ss & 3) as u8 != target_cpl {
                return Err(delivery_fault(
                    "#TS",
                    ss_error,
                    "TSS supplied a null or wrong-RPL stack selector",
                ));
            }
            let ss_ti = new_ss & 4 != 0;
            if ss_ti && (self.sregs.ldt.selector & 0xFFFC == 0 || self.sregs.ldt.unusable) {
                return Err(delivery_fault(
                    "#TS",
                    ss_error,
                    "TSS stack selector uses an unusable LDT",
                ));
            }
            let (ss_table_base, ss_table_limit) = if ss_ti {
                (self.sregs.ldt.base, u64::from(self.sregs.ldt.limit))
            } else {
                (self.sregs.gdt.base, u64::from(self.sregs.gdt.limit))
            };
            let ss_descriptor_offset = u64::from(new_ss >> 3) * 8;
            if ss_descriptor_offset
                .checked_add(7)
                .is_none_or(|last| last > ss_table_limit)
            {
                return Err(delivery_fault(
                    "#TS",
                    ss_error,
                    "TSS stack selector exceeds its descriptor-table limit",
                ));
            }
            let Some(ss_descriptor_addr) = ss_table_base.checked_add(ss_descriptor_offset) else {
                return Err(delivery_fault(
                    "#TS",
                    ss_error,
                    "stack-descriptor address overflow",
                ));
            };
            let ss_raw = self
                .mmu
                .read_u64_supervisor(ss_descriptor_addr, &self.sregs)?;
            let ss_type = ((ss_raw >> 40) & 0xF) as u8;
            let ss_dpl = ((ss_raw >> 45) & 3) as u8;
            if ss_raw >> 44 & 1 == 0
                || ss_type & 0x8 != 0
                || ss_type & 0x2 == 0
                || ss_dpl != target_cpl
            {
                return Err(delivery_fault(
                    "#TS",
                    ss_error,
                    "TSS stack selector does not reference a writable data segment at target CPL",
                ));
            }
            if ss_raw >> 47 & 1 == 0 {
                return Err(delivery_fault(
                    "#SS",
                    ss_error,
                    "TSS stack segment is not present",
                ));
            }
            stack_segment = Segment {
                base: descriptor_base(ss_raw),
                limit: descriptor_limit(ss_raw),
                selector: new_ss,
                type_: ss_type | 1,
                present: true,
                dpl: ss_dpl,
                db: ss_raw >> 54 & 1 != 0,
                s: true,
                l: false,
                g: ss_raw >> 55 & 1 != 0,
                avl: ss_raw >> 52 & 1 != 0,
                unusable: false,
            };
            if !stack_segment.db {
                frame_sp &= u64::from(u16::MAX);
            }
            accessed_stack = Some((ss_descriptor_addr, ss_raw, ss_raw | (1 << 40)));
        }

        self.materialize_flags();
        let old_flags = self.regs.rflags;
        let old_cs = self.sregs.cs.selector;
        let old_ip = self.regs.rip;
        let mut frame = Vec::with_capacity(10);
        if virtual_8086 {
            frame.extend_from_slice(&[
                u64::from(self.sregs.gs.selector),
                u64::from(self.sregs.fs.selector),
                u64::from(self.sregs.ds.selector),
                u64::from(self.sregs.es.selector),
            ]);
        }
        if stack_switch {
            frame.extend_from_slice(&[u64::from(old_ss), old_sp]);
        }
        frame.extend_from_slice(&[old_flags, u64::from(old_cs), old_ip]);
        if let Some(code) = error_code {
            frame.push(code);
        }

        let stack_mask = if stack_segment.db {
            u64::from(u32::MAX)
        } else {
            u64::from(u16::MAX)
        };
        let mut writes = Vec::with_capacity(frame.len());
        for value in frame {
            frame_sp = frame_sp.wrapping_sub(u64::from(gate.width)) & stack_mask;
            if !legacy_stack_range_valid(&stack_segment, frame_sp, gate.width) {
                return Err(delivery_fault(
                    "#SS",
                    source.ext(),
                    format_args!(
                        "legacy event frame at stack offset {frame_sp:#010x} exceeds segment limit {:#010x}",
                        stack_segment.limit
                    ),
                ));
            }
            let linear = stack_segment.base.wrapping_add(frame_sp) & u64::from(u32::MAX);
            writes.push((linear, value));
        }

        if accessed_code != raw {
            self.mmu
                .write_u64_supervisor(descriptor_addr, accessed_code, &self.sregs)?;
        }
        if let Some((address, old, accessed)) = accessed_stack {
            if old != accessed {
                self.mmu
                    .write_u64_supervisor(address, accessed, &self.sregs)?;
            }
        }
        for (linear, value) in writes {
            let bytes = value.to_le_bytes();
            self.mmu
                .write_supervisor(linear, &bytes[..gate.width as usize], &self.sregs)?;
        }

        self.sregs.cs = Segment {
            base: code_fields.base,
            limit: code_fields.limit,
            selector: (gate.selector & !3) | u16::from(target_cpl),
            type_: code_fields.type_,
            present: true,
            dpl: code_fields.dpl,
            db: code_fields.db,
            s: true,
            l: false,
            g: code_fields.g,
            avl: code_fields.avl,
            unusable: false,
        };
        let stack_db = stack_segment.db;
        if stack_switch {
            self.sregs.ss = stack_segment;
        }
        if virtual_8086 {
            for segment in [
                &mut self.sregs.es,
                &mut self.sregs.ds,
                &mut self.sregs.fs,
                &mut self.sregs.gs,
            ] {
                *segment = Segment {
                    unusable: true,
                    ..Segment::default()
                };
            }
        }
        self.regs.rsp = if stack_db {
            frame_sp
        } else {
            (self.regs.rsp & !u64::from(u16::MAX)) | frame_sp
        };
        self.regs.rip = u64::from(gate.offset);

        let old_if = old_flags & flags::bits::IF != 0;
        let mut clear = flags::bits::TF | flags::bits::NT | flags::bits::RF | flags::bits::VM;
        if matches!(gate.gate_type, GATE_INTERRUPT_16 | GATE_INTERRUPT) {
            clear |= flags::bits::IF;
        }
        self.regs.rflags &= !clear;
        if matches!(gate.gate_type, GATE_INTERRUPT_16 | GATE_INTERRUPT) {
            log_if_transition(
                u64::from(gate.offset),
                old_if,
                false,
                &format!("LEGACY_INT_GATE(vec={vector})"),
            );
        }
        self.interrupt_inhibit = false;
        Ok(())
    }

    fn deliver_real_mode_event(&mut self, vector: u8, source: EventSource) -> DeliveryResult<()> {
        let entry_offset = u64::from(vector) * 4;
        if entry_offset
            .checked_add(3)
            .is_none_or(|last| last > u64::from(self.sregs.idt.limit))
        {
            return Err(delivery_fault(
                "#GP",
                source.ext(),
                format_args!(
                    "real-mode IDT entry {vector} exceeds IDTR limit {:#x}",
                    self.sregs.idt.limit
                ),
            ));
        }
        let Some(entry_addr) = self.sregs.idt.base.checked_add(entry_offset) else {
            return Err(delivery_fault(
                "#GP",
                source.ext(),
                "real-mode IDT address overflow",
            ));
        };
        let mut entry = [0_u8; 4];
        self.mmu
            .read_supervisor(entry_addr, &mut entry, &self.sregs)?;
        let offset = u16::from_le_bytes([entry[0], entry[1]]);
        let selector = u16::from_le_bytes([entry[2], entry[3]]);

        self.materialize_flags();
        let old_flags = self.regs.rflags as u16;
        let old_cs = self.sregs.cs.selector;
        let old_ip = self.regs.rip as u16;
        self.push16(old_flags)?;
        self.push16(old_cs)?;
        self.push16(old_ip)?;

        let old_if = self.regs.rflags & flags::bits::IF != 0;
        self.regs.rflags &= !(flags::bits::IF | flags::bits::TF | flags::bits::AC);
        log_if_transition(
            u64::from(offset),
            old_if,
            false,
            &format!("REAL_MODE_INT(vec={vector})"),
        );
        self.set_sreg(1, selector);
        self.regs.rip = u64::from(offset);
        self.interrupt_inhibit = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(type_attr: u8) -> [u8; 16] {
        let mut entry = [0_u8; 16];
        entry[2..4].copy_from_slice(&8_u16.to_le_bytes());
        entry[5] = type_attr;
        entry[6..8].copy_from_slice(&1_u16.to_le_bytes());
        entry
    }

    #[test]
    fn gate_validation_rejects_every_reserved_surface_before_presence() {
        for mutate in [
            |e: &mut [u8; 16]| e[4] = 8,
            |e: &mut [u8; 16]| e[12] = 1,
            |e: &mut [u8; 16]| e[5] = 0x9E,
            |e: &mut [u8; 16]| e[5] = 0x8C,
        ] {
            let mut entry = gate(0x8E);
            mutate(&mut entry);
            let error = decode_gate64(13, entry, EventSource::External, 0)
                .unwrap_err()
                .to_string();
            assert!(error.contains("#GP(0x6b)"), "{error}");
        }
    }

    #[test]
    fn software_gate_dpl_is_checked_but_external_delivery_ignores_it() {
        let entry = gate(0x8E);
        let error = decode_gate64(0x80, entry, EventSource::Software, 3)
            .unwrap_err()
            .to_string();
        assert!(error.contains("#GP(0x402)"), "{error}");
        assert!(decode_gate64(0x80, entry, EventSource::External, 3).is_ok());
    }

    #[test]
    fn gate_target_must_be_canonical_and_present() {
        let mut absent = gate(0x0E);
        let error = decode_gate64(3, absent, EventSource::Software, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("IDT entry 3 not present"), "{error}");

        absent[5] = 0x8E;
        absent[10] = 0x80;
        let error = decode_gate64(3, absent, EventSource::Software, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("non-canonical"), "{error}");
    }

    #[test]
    fn nested_exception_matrix_matches_contributory_and_page_fault_rules() {
        for first in [0_u8, 10, 11, 12, 13, 14] {
            for second in [0_u8, 10, 11, 12, 13, 14] {
                assert!(becomes_double_fault(first, second), "{first} + {second}");
            }
        }
        for benign in [1_u8, 2, 3, 4, 5, 6, 7, 9, 16, 32, 255] {
            assert!(!becomes_double_fault(benign, 13));
            assert!(!becomes_double_fault(13, benign));
        }
    }

    #[test]
    fn legacy_gate_decode_distinguishes_16_and_32_bit_forms_and_reserved_bits() {
        let mut entry = [0_u8; 8];
        entry[0..2].copy_from_slice(&0x5678_u16.to_le_bytes());
        entry[2..4].copy_from_slice(&8_u16.to_le_bytes());
        entry[5] = 0x8E;
        entry[6..8].copy_from_slice(&0x1234_u16.to_le_bytes());
        let gate = decode_gate_legacy(0x20, entry, EventSource::External, 3).unwrap();
        assert_eq!(gate.offset, 0x1234_5678);
        assert_eq!(gate.width, 4);

        entry[5] = 0xE7;
        let gate = decode_gate_legacy(0x20, entry, EventSource::Software, 3).unwrap();
        assert_eq!(gate.offset, 0x5678, "16-bit gates ignore offset[31:16]");
        assert_eq!(gate.width, 2);

        entry[4] = 1;
        let error = decode_gate_legacy(0x20, entry, EventSource::External, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("#GP(0x103)"), "{error}");
    }

    #[test]
    fn legacy_software_gate_checks_dpl_and_presence_in_architectural_order() {
        let mut entry = [0_u8; 8];
        entry[2..4].copy_from_slice(&8_u16.to_le_bytes());
        entry[5] = 0x0E;
        let error = decode_gate_legacy(0x80, entry, EventSource::Software, 3)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not present"), "{error}");

        entry[5] = 0x8E;
        let error = decode_gate_legacy(0x80, entry, EventSource::Software, 3)
            .unwrap_err()
            .to_string();
        assert!(error.contains("CPL 3 exceeds"), "{error}");
        assert!(decode_gate_legacy(0x80, entry, EventSource::External, 3).is_ok());
    }
}
