//! Actual metadata decoder plus device-effect-free native MMIO planning.
use rax::{devices, isa};
#[path = "../../../src/isa/x86_64/inspection.rs"]
mod guest_translation;
#[path = "../../../src/backend/hvf/interrupt_shadow.rs"]
mod interrupt_shadow;
#[path = "../../../src/backend/hvf/mmio.rs"]
mod mmio;
#[path = "../../../src/backend/hvf/native_step.rs"]
mod native_step;
#[path = "../../../src/backend/hvf/output.rs"]
mod output;
#[path = "../../../src/backend/hvf/retirement.rs"]
mod retirement;
use guest_translation::{Paging, PhysicalMemory};
use mmio::{Action, Context, ExitRecord, Extension, Input, RegisterPart, prepare};
use std::collections::BTreeMap;

#[path = "hvf_mmio/alu_read.rs"]
mod alu_read_tests;
#[path = "hvf_mmio/bit_test.rs"]
mod bit_test_tests;
#[path = "hvf_mmio/cmov.rs"]
mod cmov_tests;
#[path = "hvf_mmio/cmpxchg8b.rs"]
mod cmpxchg8b_tests;
#[path = "hvf_mmio/divide.rs"]
mod divide_tests;
#[path = "hvf_mmio/double_shifts.rs"]
mod double_shift_tests;
#[path = "hvf_mmio/exit_address.rs"]
mod exit_address_tests;
#[path = "hvf_mmio/guest_debug.rs"]
mod guest_debug_tests;
#[path = "hvf_mmio/movbe.rs"]
mod movbe_tests;
#[path = "hvf_mmio/movsxd.rs"]
mod movsxd_tests;
#[path = "hvf_mmio/rmw.rs"]
mod rmw_tests;
#[path = "hvf_mmio/shifts.rs"]
mod shift_tests;
#[path = "hvf_mmio/vector_bit_test.rs"]
mod vector_bit_test_tests;
#[path = "hvf_mmio/vector_logic.rs"]
mod vector_logic_tests;
#[path = "hvf_mmio/xlat.rs"]
mod xlat_tests;
#[path = "hvf_mmio/xmm_lanes.rs"]
mod xmm_lane_tests;
#[derive(Default)]
struct Ram {
    bytes: BTreeMap<u64, u8>,
    reads: Vec<(u64, usize)>,
    identity_tables: bool,
}

#[test]
fn plans_retain_validated_linear_aliases_for_data_breakpoint_matching() {
    let alias = 0xcee0_0000u64;
    for (code, bit_offset) in [
        (&[0x48, 0x8b, 0x07][..], false),
        (&[0x48, 0x89, 0x07][..], false),
        (&[0x48, 0x03, 0x07][..], false),
        (&[0x48, 0x01, 0x07][..], false),
        (&[0x48, 0x0f, 0xab, 0x07][..], true),
    ] {
        let (mut context, mut ram, mut exit) = fixture(code);
        context.registers[7] = alias;
        context.registers[0] = if bit_offset { 64 } else { 2 };
        let offset = if bit_offset { 8 } else { 0 };
        exit.linear = alias + offset;
        exit.physical = 0xfee0_0000 + offset;
        exit.qualification = if code[1] == 0x89 {
            0x182
        } else if code[1] == 0x01 || bit_offset {
            0x183
        } else {
            0x181
        };
        ram.identity_tables = false;
        for (address, value) in [
            (0x0100_0000, 0x0100_1003u64),
            (0x0100_1000, 0x0200_0003),
            (0x0100_1018, 0x0200_1003),
            (0x0200_0000, 0x83),
            (0x0200_1000 + ((alias >> 21) & 511) * 8, 0xfee0_0083),
        ] {
            ram.bytes(address, &value.to_le_bytes());
        }
        let plan = prepare(&context, &mut ram, exit).unwrap();
        assert_eq!(plan.linear, alias + offset);
        assert_eq!(plan.physical, 0xfee0_0000 + offset);
        assert_ne!(plan.linear, plan.physical);
    }
}
impl Ram {
    // Sparse identity page tables keep code/EA fixtures in a valid IA32e
    // paging context without allocating a complete guest machine.
    fn identity_entry(&self, address: u64) -> Option<u64> {
        if !self.identity_tables || address & 7 != 0 {
            return None;
        }
        if address == 0x0100_0000 {
            return Some(0x0100_1003);
        }
        if (0x0100_1000..0x0100_2000).contains(&address) {
            return Some(0x0200_0003 + ((address - 0x0100_1000) / 8) * 4096);
        }
        if (0x0200_0000..0x0220_0000).contains(&address) {
            let pdpt = (address - 0x0200_0000) / 4096;
            let pde = (address & 4095) / 8;
            return Some((pdpt << 30) | (pde << 21) | 0x83);
        }
        None
    }
    fn bytes(&mut self, address: u64, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.bytes.insert(address + i as u64, *b);
        }
    }
}
impl PhysicalMemory for Ram {
    fn contains_ram(&self, address: u64, size: usize) -> bool {
        (0..size).all(|i| {
            self.bytes.contains_key(&(address + i as u64))
                || self.identity_entry((address + i as u64) & !7).is_some()
        })
    }
    fn read_physical(&mut self, address: u64, data: &mut [u8]) -> Result<(), String> {
        self.reads.push((address, data.len()));
        if data.len() == 8 {
            if let Some(value) = self.identity_entry(address) {
                data.copy_from_slice(&value.to_le_bytes());
                return Ok(());
            }
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b = *self
                .bytes
                .get(&(address + i as u64))
                .ok_or("unmapped physical RAM")?;
        }
        Ok(())
    }
}
fn fixture(code: &[u8]) -> (Context, Ram, ExitRecord) {
    let mut registers = [0x1234_5678_9abc_def0; 16];
    registers[7] = 0xfee0_0000;
    let c = Context {
        registers,
        segments: [0; 6],
        code_bits: 64,
        rip: 0x1000,
        rflags: 2,
        bit_count: mmio::BitCountDecoding::default(),
        paging: Paging {
            cr0: (1 << 31) | 1,
            cr3: 0x0100_0000,
            cr4: 1 << 5,
            efer: (1 << 10) | (1 << 8),
            physical_bits: 40,
            pdpte: [0; 4],
        },
    };
    let mut r = Ram {
        identity_tables: true,
        ..Ram::default()
    };
    r.bytes(c.rip, code);
    (
        c,
        r,
        ExitRecord {
            qualification: 0x181,
            linear: 0xfee0_0000,
            physical: 0xfee0_0000,
            vectoring_information: 0,
        },
    )
}

#[test]
fn legacy_xmm_moves_plan_the_guest_width_and_xmm_lane() {
    for (code, size, index, read) in [
        (&[0x66, 0x0f, 0x6e, 0x07][..], 4, 0, true),
        (&[0x66, 0x44, 0x0f, 0x7e, 0x3f], 4, 15, false),
        (&[0x66, 0x4c, 0x0f, 0x6e, 0x3f], 8, 15, true),
        (&[0x66, 0x48, 0x0f, 0x7e, 0x07], 8, 0, false),
        (&[0xf3, 0x44, 0x0f, 0x7e, 0x3f], 8, 15, true),
        (&[0x66, 0x0f, 0xd6, 0x07], 8, 0, false),
        (&[0xf3, 0x44, 0x0f, 0x6f, 0x7f, 3], 16, 15, true),
        (&[0xf3, 0x0f, 0x7f, 0x47, 3], 16, 0, false),
    ] {
        let (context, mut ram, mut record) = fixture(code);
        record.qualification = if read { 0x181 } else { 0x182 };
        if size == 16 {
            record.linear += 3;
            record.physical += 3;
        }
        let plan = prepare(&context, &mut ram, record).unwrap();
        let transfer = match plan.action {
            Action::XmmRead {
                input,
                zero_upper: false,
            } if read => input,
            Action::XmmWrite(transfer) if !read => transfer,
            _ => panic!("wrong plan direction for {code:02x?}"),
        };
        assert_eq!(plan.physical, record.physical);
        assert_eq!((transfer.index, transfer.size), (index, size));
        assert_eq!(transfer.length, code.len() as u64);
        assert_eq!(transfer.length, plan.length);
        assert!(
            ram.reads
                .iter()
                .all(|&(address, _)| address != record.physical)
        );
        record.qualification ^= 3;
        assert!(prepare(&context, &mut ram, record).is_err());
    }
}

#[test]
fn xmm_reply_is_published_and_retired_once() {
    #[derive(Default)]
    struct Host {
        xmm: Vec<(u8, [u8; 16], bool)>,
        retired: Vec<u64>,
        fail_write: bool,
    }
    impl mmio::CompletionAccess for Host {
        type Error = &'static str;
        fn write_gpr(&mut self, _index: usize, _value: u64) -> Result<(), Self::Error> {
            panic!("XMM MMIO changes no GPR")
        }
        fn write_rflags(&mut self, _flags: u64) -> Result<(), Self::Error> {
            panic!("XMM MMIO changes no flags")
        }
        fn write_xmm(
            &mut self,
            index: u8,
            value: [u8; 16],
            zero_upper: bool,
        ) -> Result<(), String> {
            if self.fail_write {
                return Err("write failed".into());
            }
            self.xmm.push((index, value, zero_upper));
            Ok(())
        }
        fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
            assert_eq!(self.xmm.len(), 1);
            self.retired.push(length);
            Ok(())
        }
    }

    for zero_upper in [false, true] {
        for size in [4, 8, 16] {
            for (reply_size, fail_write) in [(size, false), (size - 1, false), (size, true)] {
                let mut pending = mmio::InputState::default();
                pending
                    .begin_xmm(
                        mmio::XmmTransfer {
                            index: 15,
                            size,
                            length: 5,
                        },
                        zero_upper,
                    )
                    .unwrap();
                let mut host = Host {
                    fail_write,
                    ..Host::default()
                };
                assert_eq!(pending.descriptor(), Some((size, None)));
                assert!(pending.validate_checkpoint().is_ok());
                let reply = &0x1100_ffee_ddcc_bbaa_8877_6655_4433_2211u128.to_le_bytes()
                    [..usize::from(reply_size)];
                pending.complete(&mut host, reply);
                if reply_size != size || fail_write {
                    assert!(pending.ready().is_err());
                    assert!(pending.validate_checkpoint().is_ok());
                    assert!(host.xmm.is_empty() && host.retired.is_empty());
                    pending.complete(&mut host, &[0; 8]);
                    assert!(host.xmm.is_empty() && host.retired.is_empty());
                    continue;
                }
                let mut expected = [0; 16];
                expected[..reply.len()].copy_from_slice(reply);
                assert_eq!(host.xmm, [(15, expected, zero_upper)]);
                assert_eq!(host.retired, [5]);
                assert!(pending.ready().is_ok());
                pending.complete(&mut host, reply);
                assert_eq!(host.retired, [5]);
            }
        }
    }
}

#[test]
fn ymm_mmio_reply_updates_both_halves_and_retires_once() {
    #[derive(Default)]
    struct Host {
        write: Option<(u8, [u8; 32])>,
        retirement: Option<u64>,
    }
    impl mmio::CompletionAccess for Host {
        type Error = &'static str;

        fn write_gpr(&mut self, _register: usize, _value: u64) -> Result<(), Self::Error> {
            panic!("vector completion must not change a GPR");
        }

        fn write_rflags(&mut self, _flags: u64) -> Result<(), Self::Error> {
            panic!("vector completion must not change RFLAGS");
        }

        fn write_ymm(&mut self, index: u8, value: [u8; 32]) -> Result<(), String> {
            assert!(self.write.replace((index, value)).is_none());
            Ok(())
        }

        fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
            assert!(self.write.is_some());
            assert!(self.retirement.replace(length).is_none());
            Ok(())
        }
    }

    let response: [u8; 33] = std::array::from_fn(|index| (index * 3) as u8);
    for size in [31, 32, 33] {
        let mut host = Host::default();
        let mut pending = mmio::InputState::default();
        pending
            .begin_ymm(mmio::YmmTransfer {
                index: 15,
                length: 5,
            })
            .unwrap();
        assert_eq!(pending.descriptor(), Some((32, None)));
        assert!(pending.validate_checkpoint().is_ok());
        pending.complete(&mut host, &response[..size]);
        pending.complete(&mut host, &response[..32]);
        if size == 32 {
            assert_eq!(host.write, Some((15, response[..32].try_into().unwrap())));
            assert_eq!(host.retirement, Some(5));
        } else {
            assert!(pending.ready().is_err());
            assert!(pending.validate_checkpoint().is_ok());
            assert!(host.write.is_none());
            assert!(host.retirement.is_none());
        }
    }
}

#[test]
fn load_register_parts_and_zero_extension_are_exact() {
    for (code, index, bits, shift) in [
        (&[0x8a, 0x07][..], 0, 8, 0),
        (&[0x66, 0x8b, 0x07], 0, 16, 0),
        (&[0x8b, 0x07], 0, 32, 0),
        (&[0x48, 0x8b, 0x07], 0, 64, 0),
        (&[0x8a, 0x27], 0, 8, 8),
        (&[0x44, 0x8a, 0x07], 8, 8, 0),
        (&[0x4c, 0x8b, 0x3f], 15, 64, 0),
    ] {
        let (c, mut r, record) = fixture(code);
        let before = r.bytes.clone();
        let p = prepare(&c, &mut r, record).unwrap();
        assert_eq!(p.length, code.len() as u64);
        assert_eq!(p.physical, record.physical);
        assert_eq!(r.bytes, before);
        let Action::Read(input) = p.action else {
            panic!("wrong direction")
        };
        assert_eq!(input.destination, RegisterPart { index, bits, shift });
        assert_eq!(input.extension, Extension::Plain);
        let data = 0xa5a5_a5a5_a5a5_a5a5u64.to_le_bytes();
        let value = input.value(&data[..bits as usize / 8]).unwrap();
        let old = c.registers[index];
        let expected = match (bits, shift) {
            (8, 0) => (old & !0xff) | 0xa5,
            (8, 8) => (old & !0xff00) | 0xa500,
            (16, 0) => (old & !0xffff) | 0xa5a5,
            (32, 0) => 0xa5a5_a5a5,
            _ => 0xa5a5_a5a5_a5a5_a5a5,
        };
        assert_eq!(value, expected);
    }
}

#[test]
fn stores_capture_actual_register_bytes_and_signed_immediates() {
    for (code, size, value) in [
        (&[0x88, 0x07][..], 1, 0xf0),
        (&[0x66, 0x89, 0x07], 2, 0xdef0),
        (&[0x89, 0x07], 4, 0x9abc_def0),
        (&[0x48, 0x89, 0x07], 8, 0x1234_5678_9abc_def0),
        (&[0x88, 0x27], 1, 0xde),
        (&[0x44, 0x88, 0x07], 1, 0xf0),
        (&[0x48, 0xc7, 0x07, 0xff, 0xff, 0xff, 0xff], 8, u64::MAX),
        (&[0xc6, 0x07, 0xa5], 1, 0xa5),
    ] {
        let (c, mut r, mut record) = fixture(code);
        record.qualification = 0x182;
        let p = prepare(&c, &mut r, record).unwrap();
        let Action::Write(data) = p.action else {
            panic!("wrong direction")
        };
        assert_eq!(data, value.to_le_bytes()[..size]);
        assert_eq!(p.length, code.len() as u64);
    }
}

#[test]
fn setcc_mmio_stores_one_byte_from_the_captured_flags() {
    use isa::x86_64::flags::bits::{CF, OF, PF, SF, ZF};
    for code_bits in [16, 32, 64] {
        for pattern in 0..32 {
            let [of, cf, zf, sf, pf] = std::array::from_fn(|bit| pattern & (1 << bit) != 0);
            let rflags = 2
                | if of { OF } else { 0 }
                | if cf { CF } else { 0 }
                | if zf { ZF } else { 0 }
                | if sf { SF } else { 0 }
                | if pf { PF } else { 0 };
            let expected = [of, cf, zf, cf || zf, sf, pf, sf != of, zf || sf != of];
            for cc in 0..16 {
                let code = [0x0f, 0x90 | cc, 0x07]; // [BX] in 16-bit, [E/RDI] otherwise.
                let (mut context, mut ram, mut exit) = fixture(&code);
                context.code_bits = code_bits;
                context.rflags = rflags;
                exit.qualification = 0x182;
                if code_bits == 16 {
                    context.segments[3] = exit.linear - 0x200;
                    context.registers[3] = 0x200;
                }
                let holds = expected[usize::from(cc >> 1)];
                let byte = u8::from(holds ^ (cc & 1 != 0));
                let plan = prepare(&context, &mut ram, exit).unwrap_or_else(|error| {
                    panic!("{code_bits}-bit SETcc {cc}, {rflags:#x}: {error}")
                });
                assert_eq!(
                    (plan.physical, plan.linear, plan.length),
                    (exit.physical, exit.linear, 3)
                );
                assert!(matches!(plan.action, Action::Write(bytes) if bytes == [byte]));
            }
        }
    }
}

#[test]
fn setcc_requires_a_matching_unlocked_memory_write() {
    for (code, qualification, mismatch) in [
        (&[0x0f, 0x94, 0xc7][..], 0x182, 0), // SETE BH is register-only.
        (&[0xf0, 0x0f, 0x94, 0x07], 0x182, 0), // LOCK #UD.
        (&[0x0f, 0x94, 0x07], 0x181, 0),
        (&[0x0f, 0x94, 0x07], 0x183, 0),
        (&[0x0f, 0x94, 0x07], 0x182, 1),
    ] {
        let (context, mut ram, mut exit) = fixture(code);
        exit.qualification = qualification;
        exit.linear += mismatch;
        assert!(prepare(&context, &mut ram, exit).is_err());
    }
}

#[test]
fn signed_and_unsigned_load_extensions_match_primary_subregister_rules() {
    for (code, size, bits, signed) in [
        (&[0x0f, 0xbe, 0x07][..], 1, 32, true),
        (&[0x48, 0x0f, 0xbe, 0x07], 1, 64, true),
        (&[0x0f, 0xbf, 0x07], 2, 32, true),
        (&[0x66, 0x0f, 0xbe, 0x07], 1, 16, true),
        (&[0x48, 0x0f, 0xb6, 0x07], 1, 64, false),
        (&[0x0f, 0xb7, 0x07], 2, 32, false),
    ] {
        let (c, mut r, record) = fixture(code);
        let p = prepare(&c, &mut r, record).unwrap();
        let Action::Read(input) = p.action else {
            panic!("wrong direction")
        };
        assert_eq!(input.size, size);
        assert_eq!(input.destination.bits, bits);
        let value = input.value(&vec![0x80; usize::from(size)]).unwrap();
        let low = if size == 1 { 0x80 } else { 0x8080 };
        let sign = if size == 1 {
            0xffff_ffff_ffff_ff80
        } else {
            0xffff_ffff_ffff_8080
        };
        let expected = if signed { sign } else { low };
        let expected = if bits == 16 {
            (c.registers[0] & !0xffff) | (expected & 0xffff)
        } else if bits == 32 {
            expected & 0xffff_ffff
        } else {
            expected
        };
        assert_eq!(value, expected);
    }
}

#[test]
fn malformed_ept_or_unrepresented_instruction_never_becomes_device_io() {
    for qual in [0, 1, 2, 3, 4, 0x180, 0x185, 0x187, 0x81, 0x101] {
        let (c, mut r, mut e) = fixture(&[0x8a, 7]);
        e.qualification = qual;
        assert!(prepare(&c, &mut r, e).is_err());
        assert!(r.reads.is_empty());
    }
    // Both direction bits are valid for an RMW exit. Decode is required to
    // distinguish it from an invalid MOV exit; inspection has no device effect.
    let (c, mut r, mut e) = fixture(&[0x8a, 7]);
    e.qualification = 0x183;
    let before = r.bytes.clone();
    assert!(prepare(&c, &mut r, e).is_err());
    assert_eq!(r.bytes, before);
    for code in [
        &[0x01, 0x07][..],
        &[0x87, 0x07],
        &[0xf0, 0x01, 0x07],
        &[0xa4],
        &[0x8c, 0x07],
        &[0x0f, 0x58, 0x07], // ADDPS remains outside the MMIO move profile.
    ] {
        let (c, mut r, e) = fixture(code);
        assert!(prepare(&c, &mut r, e).is_err());
    }
}

#[test]
fn gla_direction_ram_and_truncation_mismatches_stop_before_device_effects() {
    let (c, mut r, mut e) = fixture(&[0x8a, 7]);
    e.linear += 1;
    assert!(prepare(&c, &mut r, e).is_err());
    let (c, mut r, mut e) = fixture(&[0x8a, 7]);
    e.qualification = 0x182;
    assert!(prepare(&c, &mut r, e).is_err());
    let (c, mut r, e) = fixture(&[0x8a, 7]);
    r.bytes(e.physical, &[0]);
    assert!(prepare(&c, &mut r, e).is_err());
    for code in [&[0x8a][..], &[0x66], &[0x48, 0xc7, 7, 0]] {
        let (c, mut r, e) = fixture(code);
        assert!(prepare(&c, &mut r, e).is_err());
    }
}

#[test]
fn load_framing_and_register_alias_frontiers_are_explicit() {
    for name in ["xmm0", "rip", "eflags", "r16", "r31d", "r0", "r7b", ""] {
        assert!(RegisterPart::parse(name).is_none());
    }
    let input = Input {
        destination: RegisterPart::parse("rax").unwrap(),
        original: 0,
        size: 8,
        extension: Extension::Plain,
        length: 3,
    };
    for count in 0..16 {
        if count != 8 {
            assert!(input.value(&vec![0; count]).is_err());
        }
    }
    assert_eq!(input.value(&u64::MAX.to_le_bytes()), Ok(u64::MAX));
}

#[derive(Default)]
struct CompletionHost {
    value: u64,
    index: usize,
    length: u64,
    flags: u64,
    fail: Option<&'static str>,
    calls: Vec<&'static str>,
}
impl mmio::CompletionAccess for CompletionHost {
    type Error = &'static str;
    fn write_gpr(&mut self, index: usize, value: u64) -> Result<(), Self::Error> {
        self.calls.push("gpr");
        if self.fail == Some("gpr") {
            return Err("gpr");
        }
        self.index = index;
        self.value = value;
        Ok(())
    }
    fn write_rflags(&mut self, flags: u64) -> Result<(), Self::Error> {
        self.calls.push("writeflags");
        if self.fail == Some("writeflags") {
            return Err("writeflags");
        }
        self.flags = flags;
        Ok(())
    }
    fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
        self.calls.push("finish");
        if self.fail == Some("finish") {
            return Err("finish");
        }
        self.length = length;
        Ok(())
    }
}
impl mmio::RetirementAccess for CompletionHost {
    type Error = &'static str;
    fn rflags(&mut self) -> Result<u64, Self::Error> {
        self.calls.push("flags");
        if self.fail == Some("flags") {
            Err("flags")
        } else {
            Ok(self.flags)
        }
    }
    fn advance_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
        self.calls.push("advance");
        if self.fail == Some("advance") {
            return Err("advance");
        }
        self.length = length;
        Ok(())
    }
    fn write_rflags(&mut self, flags: u64) -> Result<(), Self::Error> {
        self.calls.push("writeflags");
        if self.fail == Some("writeflags") {
            return Err("writeflags");
        }
        self.flags = flags;
        Ok(())
    }
}
fn pending() -> Input {
    Input {
        destination: RegisterPart::parse("ah").unwrap(),
        original: 0x1234_5678_9abc_def0,
        size: 1,
        extension: Extension::Plain,
        length: 2,
    }
}

#[test]
fn typed_completion_commits_only_the_captured_destination_once() {
    let mut state = mmio::InputState::default();
    state.begin(pending()).unwrap();
    assert!(state.pending());
    assert!(state.ready().is_err());
    assert!(state.begin(pending()).is_err());
    let mut h = CompletionHost::default();
    state.complete(&mut h, &[0xa5]);
    assert_eq!((h.index, h.value, h.length), (0, 0x1234_5678_9abc_a5f0, 2));
    assert_eq!(h.calls, ["gpr", "finish"]);
    assert!(!state.pending());
    assert_eq!(state.ready(), Ok(()));
    state.complete(&mut h, &[0]);
    assert!(state.ready().is_err());
    assert_eq!(h.calls, ["gpr", "finish"]);
}

#[test]
fn malformed_input_and_both_host_failure_stages_are_terminal() {
    for data in [vec![], vec![1, 2]] {
        let mut state = mmio::InputState::default();
        state.begin(pending()).unwrap();
        let mut h = CompletionHost::default();
        state.complete(&mut h, &data);
        assert!(state.ready().is_err());
        assert!(h.calls.is_empty());
        state.complete(&mut h, &[3]);
        assert!(h.calls.is_empty());
    }
    for fail in ["gpr", "finish"] {
        let mut state = mmio::InputState::default();
        state.begin(pending()).unwrap();
        let mut h = CompletionHost {
            fail: Some(fail),
            ..CompletionHost::default()
        };
        state.complete(&mut h, &[0xa5]);
        assert_eq!(h.length, 0);
        assert_eq!(
            h.value,
            if fail == "gpr" {
                0
            } else {
                0x1234_5678_9abc_a5f0
            }
        );
        let error = state.ready().unwrap_err().to_owned();
        let calls = h.calls.clone();
        h.fail = None;
        for _ in 0..3 {
            assert_eq!(state.ready(), Err(error.as_str()));
            state.complete(&mut h, &[0]);
        }
        assert_eq!(h.calls, calls);
    }
}

#[test]
fn mmio_retirement_clears_only_rf_and_propagates_each_host_failure() {
    for flags in [2, 0x202, 0x1_0002, 0x1_0202, u64::MAX] {
        let mut h = CompletionHost {
            flags,
            ..CompletionHost::default()
        };
        mmio::retire(&mut h, 3).unwrap();
        assert_eq!(h.flags, flags & !(1 << 16));
        assert_eq!(h.length, 3);
        assert_eq!(
            h.calls.last(),
            Some(if flags & (1 << 16) != 0 {
                &"writeflags"
            } else {
                &"advance"
            })
        );
    }
    for fail in ["flags", "advance", "writeflags"] {
        let mut h = CompletionHost {
            flags: 0x1_0202,
            fail: Some(fail),
            ..CompletionHost::default()
        };
        assert_eq!(mmio::retire(&mut h, 3), Err(fail));
        assert_eq!(h.calls.last(), Some(&fail));
        assert_eq!(h.length, if fail == "writeflags" { 3 } else { 0 });
        assert_eq!(h.flags, 0x1_0202);
    }
}

fn paged_fixture(code: &[u8], next_data_page: u64) -> (Context, Ram, ExitRecord) {
    let (mut c, mut r, mut e) = fixture(&[]);
    c.rip = 0xffe;
    c.registers[7] = 0x2fff;
    c.paging.cr0 = 1 << 31;
    c.paging.cr3 = 0x1000;
    c.paging.cr4 = 1 << 5;
    c.paging.efer = 1 << 10;
    for (addr, value) in [
        (0x1000, 0x2001u64),
        (0x2000, 0x3001),
        (0x3000, 0x4001),
        (0x4000, 0x8001),
        (0x4010, 0xa001),
        (0x4018, next_data_page | 1),
    ] {
        r.bytes(addr, &value.to_le_bytes());
    }
    if code.len() > 2 {
        r.bytes(0x4008, &0x9001u64.to_le_bytes());
        r.bytes(0x9000, &code[2..]);
    }
    r.bytes(0x8ffe, &code[..code.len().min(2)]);
    e.linear = 0x2fff;
    e.physical = 0xafff;
    (c, r, e)
}

#[test]
fn incremental_fetch_does_not_touch_an_unneeded_next_code_page() {
    let (c, mut r, e) = paged_fixture(&[0x8a, 7], 0xb000);
    let p = prepare(&c, &mut r, e).unwrap();
    assert_eq!(p.length, 2);
    assert!(!r.reads.iter().any(|&(a, _)| a == 0x4008));
}

#[test]
fn complete_data_range_must_be_physically_contiguous_before_any_device_access() {
    let (c, mut r, e) = paged_fixture(&[0x48, 0x8b, 7], 0xc000);
    assert!(
        prepare(&c, &mut r, e)
            .unwrap_err()
            .contains("noncontiguous")
    );
    let (c, mut r, e) = paged_fixture(&[0x48, 0x8b, 7], 0xb000);
    let p = prepare(&c, &mut r, e).unwrap();
    let Action::Read(input) = p.action else {
        panic!("wrong direction")
    };
    assert_eq!(input.size, 8);
    assert_eq!(p.physical, 0xafff);
}

#[test]
fn moffs_uses_every_active_segment_override_and_guest_address_width() {
    for bits in [16, 32, 64] {
        for (index, prefix) in [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65]
            .iter()
            .copied()
            .enumerate()
        {
            let mut code = vec![prefix, 0xa0];
            code.extend_from_slice(&0x1234u64.to_le_bytes()[..bits as usize / 8]);
            let (mut c, mut r, mut e) = fixture(&[]);
            c.code_bits = bits;
            c.segments = [0x10000, 0x20000, 0x30000, 0x40000, 0x50000, 0x60000];
            let code_linear = if bits == 64 {
                c.rip
            } else {
                c.segments[1] + c.rip
            };
            r.bytes(code_linear, &code);
            let base = if bits == 64 && index < 4 {
                0
            } else {
                c.segments[index]
            };
            e.linear = base + 0x1234;
            e.physical = e.linear;
            let p = prepare(&c, &mut r, e).unwrap();
            assert_eq!(p.length, code.len() as u64);
        }
    }
}

fn compare_guest_records(cases: &[u8], raw: &[u8]) -> (usize, usize) {
    fn word(b: &[u8], i: usize) -> u32 {
        u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
    }
    fn quad(b: &[u8], i: usize) -> u64 {
        u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
    }
    let count = cases.len() / 168;
    assert!(count > 0);
    assert_eq!(cases.len() % 168, 0);
    assert_eq!(raw.len(), 20 + count * 152);
    assert_eq!(&raw[..8], b"RAXMM001");
    assert_eq!(word(raw, 8) as usize, count);
    assert_eq!(&raw[12 + count * 152..], b"MM_DONE!");
    let (mut reads, mut writes) = (0, 0);
    for (i, case) in cases.chunks_exact(168).enumerate() {
        let length = word(case, 144) as usize;
        assert!((1..=15).contains(&length));
        let code = &case[148..148 + length];
        let writing = word(case, 164);
        assert!(writing <= 1);
        let (mut c, mut ram, mut e) = fixture(&[]);
        for (index, r) in c.registers.iter_mut().enumerate() {
            *r = quad(case, index * 8);
        }
        c.rip = 0x300000;
        c.rflags = quad(case, 136);
        c.paging.cr0 = (1 << 31) | 1;
        c.paging.cr3 = 0x1000;
        c.paging.cr4 = 1 << 5;
        c.paging.efer = (1 << 10) | (1 << 8);
        for (addr, value) in [(0x1000, 0x2001u64), (0x2000, 0x3001), (0x3008, 0x200081)] {
            ram.bytes(addr, &value.to_le_bytes());
        }
        ram.bytes(c.rip, code);
        e.linear = 0x200000;
        e.physical = e.linear;
        e.qualification = 0x180 | if writing == 1 { 2 } else { 1 };
        let before = ram.bytes.clone();
        let plan = prepare(&c, &mut ram, e)
            .unwrap_or_else(|error| panic!("case{i},code{code:02x?}:{error}"));
        assert_eq!(plan.length, length as u64);
        assert_eq!(plan.physical, e.physical);
        assert_eq!(ram.bytes, before);
        let mut expected = c.registers;
        let mut memory = quad(case, 128).to_le_bytes();
        match plan.action {
            Action::Read(input) => {
                assert_eq!(writing, 0);
                reads += 1;
                expected[input.destination.index] =
                    input.value(&memory[..usize::from(input.size)]).unwrap();
            }
            Action::Write(data) => {
                assert_eq!(writing, 1);
                writes += 1;
                memory[..data.len()].copy_from_slice(&data);
            }
            Action::Rmw(_) => panic!("MOV reference case produced an RMW plan"),
            Action::AluRead(_) => panic!("MOV reference case produced an ALU read plan"),
            Action::Divide(_) => panic!("MOV reference case produced a divide plan"),
            Action::XmmRead { .. }
            | Action::XmmWrite(_)
            | Action::XmmLaneRead { .. }
            | Action::XmmLaneWrite(_)
            | Action::VectorLogic { .. }
            | Action::VectorMaskBlend { .. }
            | Action::VectorBitTest { .. }
            | Action::UnaryVector(_)
            | Action::YmmRead(_)
            | Action::YmmWrite(_) => panic!("unexpected vector plan for GPR MOV"),
            Action::StringLoad(_) | Action::StringStore { .. } => {
                panic!("unexpected string plan for GPR MOV")
            }
        }
        let record = &raw[12 + i * 152..12 + (i + 1) * 152];
        let actual: [u64; 16] = std::array::from_fn(|index| quad(record, index * 8));
        assert_eq!(expected, actual, "registers case{i},code{code:02x?}");
        assert_eq!(memory, record[128..136], "memory case{i},code{code:02x?}");
        assert_eq!(quad(record, 136), c.rflags);
        assert_eq!(quad(record, 144), c.rflags);
    }
    (reads, writes)
}

#[test]
fn independent_guest_records_preserve_all_registers_memory_and_flags() {
    const CASES: &[u8] = include_bytes!("../../fixtures/hvf/mmio-v1/cases.bin");
    const RAW: &[u8] = include_bytes!("../../fixtures/hvf/mmio-v1/records.bin");
    assert_eq!(CASES.len(), 1204 * 168);
    assert_eq!(compare_guest_records(CASES, RAW), (912, 292));
}

#[test]
fn ept_faults_during_event_delivery_cannot_become_instruction_mmio() {
    for kind in 0..8 {
        for vector in 0..=255 {
            let (c, mut r, mut e) = fixture(&[0x8a, 7]);
            e.vectoring_information = 0x8000_0000 | (kind << 8) | vector;
            assert!(
                prepare(&c, &mut r, e)
                    .unwrap_err()
                    .contains("event delivery")
            );
            assert!(r.reads.is_empty());
        }
    }
}

#[test]
fn special_ept_accesses_are_rejected_while_undefined_permission_bits_are_ignored() {
    for bit in [12, 13, 15, 16] {
        for write in [false, true] {
            let code = if write {
                &[0x88, 7][..]
            } else {
                &[0x8a, 7][..]
            };
            let (c, mut ram, mut record) = fixture(code);
            record.qualification = 0x180 | if write { 2 } else { 1 } | (1 << bit);
            assert!(
                prepare(&c, &mut ram, record)
                    .unwrap_err()
                    .contains("ordinary scalar")
            );
            assert!(ram.reads.is_empty());
        }
    }
    for bit in [3, 4, 5, 6, 9, 10, 11, 14, 17, 32, 63] {
        let (c, mut ram, mut record) = fixture(&[0x8a, 7]);
        record.qualification |= 1 << bit;
        assert!(prepare(&c, &mut ram, record).is_ok());
    }
}

#[test]
fn scaled_displaced_and_wrapped_effective_addresses_match_the_exit() {
    let cases: &[(&[u8], u32, u64, u64, u64, u64)] = &[
        (
            &[0x48, 0x8b, 0x44, 0x8b, 0xf0],
            64,
            0x1000,
            0x4000_0000,
            0,
            0x1_0000_0ff0,
        ),
        (
            &[0x67, 0x48, 0x8b, 0x44, 0x8b, 0xf0],
            64,
            0xffff_ffff_ffff_f000,
            0x1234_5678_0000_0800,
            0,
            0xff0,
        ),
        (
            &[0x64, 0x48, 0x8b, 0x03],
            64,
            0x1234,
            0,
            0x1_0000_0000,
            0x1_0000_1234,
        ),
    ];
    for &(code, bits, base, index, fs, linear) in cases {
        let (mut c, mut ram, mut e) = fixture(code);
        c.code_bits = bits;
        c.registers[3] = base;
        c.registers[1] = index;
        c.segments[4] = fs;
        e.linear = linear;
        e.physical = linear;
        assert!(prepare(&c, &mut ram, e).is_ok(), "{code:02x?}");
    }
    let (mut c, mut ram, mut e) = fixture(&[0x8b, 0x44, 0x75, 0xfc]);
    c.code_bits = 32;
    c.registers[5] = 0xffff_0000;
    c.registers[6] = 0x8000;
    c.segments[2] = 0x2000;
    e.linear = 0x1ffc;
    e.physical = e.linear;
    assert!(prepare(&c, &mut ram, e).is_ok());
}

#[test]
fn rip_relative_and_addr32_eip_relative_addresses_include_the_complete_encoding() {
    for addr32 in [false, true] {
        let (mut c, mut ram, mut e) = fixture(&[]);
        c.rip = if addr32 { 0x1_0000_1000 } else { 0x1000 };
        let mut code = if addr32 {
            vec![0x67, 0x48, 0x8b, 0x05]
        } else {
            vec![0x48, 0x8b, 0x05]
        };
        code.extend_from_slice(&0x1234i32.to_le_bytes());
        ram.bytes(c.rip, &code);
        e.linear = c.rip + code.len() as u64 + 0x1234;
        if addr32 {
            e.linear &= 0xffff_ffff;
        }
        e.physical = e.linear;
        let p = prepare(&c, &mut ram, e).unwrap();
        assert_eq!(p.length, code.len() as u64);
    }
}

#[test]
fn rmw_exit_accepts_both_architectural_ept_qualification_encodings() {
    for code in [
        &[0xf0, 0x01, 0x07][..],
        &[0x87, 0x07][..],
        &[0xf0, 0x0f, 0xb1, 0x0f][..],
    ] {
        for qualification in [0x182, 0x183] {
            let (context, mut memory, mut record) = fixture(code);
            record.qualification = qualification;
            assert!(
                prepare(&context, &mut memory, record).is_ok(),
                "code={code:02x?},qualification={qualification:#x}"
            );
        }
    }
}

#[test]
fn movnti_writes_exactly_the_encoded_register_width() {
    let value = 0x0123_4567_89ab_cdefu64.to_le_bytes();
    for (code, expected) in [
        (&[0x0f, 0xc3, 0x07][..], &value[..4]),
        (&[0x48, 0x0f, 0xc3, 0x07], &value[..8]),
        (&[0x67, 0x44, 0x0f, 0xc3, 0x47, 0x04], &value[..4]),
        (&[0x4c, 0x0f, 0xc3, 0x47, 0x07], &value[..8]),
    ] {
        let (mut context, mut ram, mut exit) = fixture(code);
        context.registers[0] = u64::from_le_bytes(value);
        context.registers[8] = u64::from_le_bytes(value);
        let displacement = match code[code.len() - 2] {
            0x47 => u64::from(code[code.len() - 1]),
            _ => 0,
        };
        if code[0] == 0x67 {
            context.registers[7] |= 0x1234_0000_0000;
        }
        exit.linear += displacement;
        exit.physical += displacement;
        exit.qualification = 0x182;
        let plan = prepare(&context, &mut ram, exit).unwrap();
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
        assert_eq!(plan.length, code.len() as u64);
        let Action::Write(bytes) = plan.action else {
            panic!("MOVNTI must produce one write");
        };
        assert_eq!(bytes, expected);
        for qualification in [0x181, 0x183] {
            exit.qualification = qualification;
            assert!(prepare(&context, &mut ram, exit).is_err());
        }
    }
}

#[test]
fn movnti_metadata_describes_a_memory_only_store_in_each_code_size() {
    use isa::x86_64::instruction_metadata::{self, Flow, OperandKind};

    for (bits, code, width, register) in [
        (16, &[0x0f, 0xc3, 0x07][..], 32, "eax"),
        (32, &[0x0f, 0xc3, 0x07], 32, "eax"),
        (64, &[0x0f, 0xc3, 0x07], 32, "eax"),
        (64, &[0x4c, 0x0f, 0xc3, 0x07], 64, "r8"),
    ] {
        let instruction = instruction_metadata::decode(bits, 0x1000, code).unwrap();
        assert_eq!(instruction.mnemonic, "movnti");
        assert_eq!(instruction.flow, Flow::Next);
        assert!(instruction.operands_complete);
        assert_eq!(instruction.size as usize, code.len());
        let [memory, source] = instruction.operands.as_slice() else {
            panic!("MOVNTI must have two operands");
        };
        assert_eq!(memory.kind, OperandKind::Memory);
        assert_eq!(memory.address_bits, bits);
        assert_eq!(source.kind, OperandKind::Register);
        assert_eq!(source.reg, register);
        assert_eq!((memory.width_bits, source.width_bits), (width, width));
        assert!(!memory.read && memory.write && !memory.conditional);
        assert!(source.read && !source.write && !source.conditional);
        for end in 0..code.len() {
            assert!(instruction_metadata::decode(bits, 0x1000, &code[..end]).is_err());
        }
    }

    for code in [
        &[0x0f, 0xc3, 0xc7][..],   // register target
        &[0xf0, 0x0f, 0xc3, 0x07], // LOCK
        &[0x66, 0x0f, 0xc3, 0x07], // operand-size prefix
        &[0xf2, 0x0f, 0xc3, 0x07], // REPNE
        &[0xf3, 0x0f, 0xc3, 0x07], // REP
    ] {
        assert!(instruction_metadata::decode(64, 0x1000, code).is_err());
        let (context, mut ram, mut exit) = fixture(code);
        exit.qualification = 0x182;
        assert!(prepare(&context, &mut ram, exit).is_err());
    }
}

#[test]
fn vex_movd_memory_read_has_a_native_mmio_plan() {
    let (context, mut ram, exit) = fixture(&[0xc5, 0xf9, 0x6e, 0x07]);
    let plan = prepare(&context, &mut ram, exit)
        .expect("VEX scalar XMM MMIO read must have a validated plan");
    assert_eq!(plan.length, 4);
    assert_eq!(plan.linear, exit.linear);
    assert_eq!(plan.physical, exit.physical);
}

#[test]
fn vex_xmm_access_width_direction_and_upper_lane_policy() {
    for (code, size, index, read, bits) in [
        (&[0xc5, 0xf9, 0x6e, 0x07][..], 4, 0, true, 64),
        (&[0xc5, 0x79, 0x7e, 0x3f], 4, 15, false, 64),
        (&[0xc4, 0x61, 0xf9, 0x6e, 0x3f], 8, 15, true, 64),
        (&[0xc4, 0xe1, 0xf9, 0x7e, 0x07], 8, 0, false, 64),
        (&[0xc5, 0x7a, 0x7e, 0x3f], 8, 15, true, 64),
        (&[0xc5, 0xf9, 0xd6, 0x07], 8, 0, false, 64),
        (&[0xc5, 0x7a, 0x6f, 0x7f, 3], 16, 15, true, 64),
        (&[0xc5, 0xfa, 0x7f, 0x47, 3], 16, 0, false, 64),
        (&[0xc4, 0xe1, 0xf9, 0x6e, 0x07], 4, 0, true, 32),
        (&[0xc4, 0x01, 0xf9, 0x6e, 0x7c, 0xa5, 0x10], 8, 15, true, 64),
    ] {
        let (mut context, mut ram, mut exit) = fixture(code);
        context.code_bits = bits;
        if size == 16 {
            exit.linear += 3;
            exit.physical += 3;
        }
        context.registers[12] = 0x10;
        context.registers[13] = exit.linear - 0x50;
        exit.qualification = if read { 0x181 } else { 0x182 };
        let plan = prepare(&context, &mut ram, exit).unwrap();
        let input = match plan.action {
            Action::XmmRead {
                input,
                zero_upper: true,
            } if read => input,
            Action::XmmWrite(input) if !read => input,
            _ => panic!("wrong plan direction or upper-lane policy for {code:02x?}"),
        };
        assert_eq!((input.index, input.size), (index, size));
        assert_eq!(input.length, code.len() as u64);
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
        assert!(
            ram.reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
        let wrong_direction = ExitRecord {
            qualification: exit.qualification ^ 3,
            ..exit
        };
        assert!(prepare(&context, &mut ram, wrong_direction).is_err());
        let wrong_address = ExitRecord {
            physical: exit.physical + 1,
            ..exit
        };
        assert!(prepare(&context, &mut ram, wrong_address).is_err());
    }
}

#[test]
fn whole_ymm_moves_decode_and_plan_their_memory_operands() {
    use rax::isa::x86_64::instruction_metadata::{self, OperandKind};

    for (prefix, load, store, mnemonic, aligned) in [
        (2, 0x6f, 0x7f, "vmovdqu", false),
        (1, 0x6f, 0x7f, "vmovdqa", true),
        (0, 0x10, 0x11, "vmovups", false),
        (1, 0x10, 0x11, "vmovupd", false),
        (0, 0x28, 0x29, "vmovaps", true),
        (1, 0x28, 0x29, "vmovapd", true),
    ] {
        for (opcode, read) in [(load, true), (store, false)] {
            let vex2 = [0xc5, 0x7c | prefix, opcode, 0x3f];
            let vex3 = [0xc4, 0x61, 0xfc | prefix, opcode, 0x3f];
            for code in [vex2.as_slice(), vex3.as_slice()] {
                let instruction = instruction_metadata::decode(64, 0x1000, code).unwrap();
                assert_eq!(instruction.mnemonic, mnemonic);
                assert_eq!(instruction.size as usize, code.len());
                assert!(instruction.operands_complete);
                let [first, second] = instruction.operands.as_slice() else {
                    panic!("expected vector and memory operands: {code:02x?}");
                };
                let (register, memory) = if read {
                    (first, second)
                } else {
                    (second, first)
                };
                assert_eq!(
                    (register.kind, register.reg.as_str(), register.width_bits),
                    (OperandKind::Register, "ymm15", 256),
                );
                assert_eq!((memory.kind, memory.width_bits), (OperandKind::Memory, 256));
                assert_eq!(
                    (memory.read, memory.write, register.read, register.write),
                    (read, !read, !read, read)
                );
                for offset in [0, 1, 16, 31] {
                    let (mut context, mut ram, mut record) = fixture(code);
                    context.registers[7] += offset;
                    record.linear += offset;
                    record.physical += offset;
                    record.qualification = if read { 0x181 } else { 0x182 };
                    let result = prepare(&context, &mut ram, record);
                    if aligned && offset != 0 {
                        assert_eq!(result.unwrap_err(), "misaligned YMM MMIO transfer");
                        continue;
                    }
                    let plan = result.unwrap();
                    assert_eq!(
                        (plan.linear, plan.physical),
                        (record.linear, record.physical)
                    );
                    assert_eq!(plan.length, code.len() as u64);
                    let transfer = match plan.action {
                        Action::YmmRead(transfer) if read => transfer,
                        Action::YmmWrite(transfer) if !read => transfer,
                        _ => panic!("incorrect YMM transfer direction for {code:02x?}"),
                    };
                    assert_eq!((transfer.index, transfer.length), (15, code.len() as u64));
                    assert!(ram.reads.iter().all(|&(addr, _)| addr != record.physical));
                    record.qualification ^= 3;
                    assert!(prepare(&context, &mut ram, record).is_err());
                }
            }
        }
    }
}
#[test]
fn aligned_streaming_vector_stores_plan_exact_mmio_widths() {
    use rax::isa::x86_64::instruction_metadata;

    let cases = [
        (0, 0x2b, "movntps", "vmovntps"),
        (1, 0x2b, "movntpd", "vmovntpd"),
        (1, 0xe7, "movntdq", "vmovntdq"),
    ];
    for (prefix, opcode, legacy_name, vex_name) in cases {
        let legacy = [0x66, 0x44, 0x0f, opcode, 0x3f];
        for (code, name, size) in [
            (&legacy[usize::from(prefix == 0)..], legacy_name, 16),
            (&[0xc5, 0x78 | prefix, opcode, 0x3f], vex_name, 16),
            (&[0xc4, 0x61, 0xf8 | prefix, opcode, 0x3f], vex_name, 16),
            (&[0xc5, 0x7c | prefix, opcode, 0x3f], vex_name, 32),
            (&[0xc4, 0x61, 0xfc | prefix, opcode, 0x3f], vex_name, 32),
        ] {
            let (context, mut ram, mut record) = fixture(code);
            record.qualification = 0x182;
            let plan = prepare(&context, &mut ram, record).unwrap_or_else(|err| {
                panic!("{name} {code:02x?} must plan a {size}-byte store: {err}")
            });
            let instruction = instruction_metadata::decode(64, 0x1000, code).unwrap();
            assert_eq!(instruction.mnemonic, name);
            assert_eq!(plan.length, code.len() as u64);
            assert_eq!(
                (plan.linear, plan.physical),
                (record.linear, record.physical)
            );
            match plan.action {
                Action::XmmWrite(transfer) if size == 16 => {
                    assert_eq!(
                        (transfer.index, transfer.size, transfer.length),
                        (15, 16, plan.length)
                    );
                }
                Action::YmmWrite(transfer) if size == 32 => {
                    assert_eq!((transfer.index, transfer.length), (15, plan.length));
                }
                _ => panic!("unexpected streaming store action for {code:02x?}"),
            }
            assert!(
                ram.reads
                    .iter()
                    .all(|&(address, _)| address != record.physical)
            );
            let mut misaligned = context;
            let offset = u64::from(size / 2u8);
            misaligned.registers[7] += offset;
            let bad_address = ExitRecord {
                linear: record.linear + offset,
                physical: record.physical + offset,
                ..record
            };
            let expected = if size == 16 {
                "misaligned XMM MMIO transfer"
            } else {
                "misaligned YMM MMIO transfer"
            };
            assert_eq!(
                prepare(&misaligned, &mut ram, bad_address).unwrap_err(),
                expected
            );
            record.qualification = 0x181;
            assert!(prepare(&context, &mut ram, record).is_err());
        }
        let legacy_register = [0x66, 0x0f, opcode, 0xff];
        for code in [
            &legacy_register[usize::from(prefix == 0)..],
            &[0xc5, 0x78 | prefix, opcode, 0xff],
            &[0xc5, 0x70 | prefix, opcode, 0x3f],
        ] {
            assert!(instruction_metadata::decode(64, 0x1000, code).is_err());
            let (context, mut ram, mut record) = fixture(code);
            record.qualification = 0x182;
            assert!(prepare(&context, &mut ram, record).is_err());
        }
    }
}

#[test]
fn aligned_xmm_moves_use_the_full_operand_and_reject_misalignment() {
    use rax::isa::x86_64::instruction_metadata;
    for (bytes, mnemonic, lane, read, vex) in [
        (&[0x66, 0x0f, 0x6f, 0x07][..], "movdqa", 0, true, false),
        (&[0x66, 0x44, 0x0f, 0x7f, 0x3f], "movdqa", 15, false, false),
        (&[0xc5, 0x79, 0x6f, 0x3f], "vmovdqa", 15, true, true),
        (&[0xc4, 0xe1, 0x79, 0x7f, 0x07], "vmovdqa", 0, false, true),
    ] {
        let metadata = instruction_metadata::decode(64, 0x1000, bytes).unwrap();
        assert_eq!(
            (metadata.mnemonic.as_str(), metadata.size),
            (mnemonic, bytes.len() as u32)
        );
        let (mut context, mut ram, mut record) = fixture(bytes);
        record.qualification = if read { 0x181 } else { 0x182 };
        let plan = prepare(&context, &mut ram, record).unwrap();
        let transfer = match plan.action {
            Action::XmmRead { input, zero_upper } if read => {
                assert_eq!(zero_upper, vex);
                input
            }
            Action::XmmWrite(transfer) if !read => transfer,
            _ => panic!("wrong plan direction for {bytes:02x?}"),
        };
        assert_eq!(
            (transfer.index, transfer.size, transfer.length),
            (lane, 16, bytes.len() as u64)
        );
        assert_eq!(
            (plan.linear, plan.physical),
            (record.linear, record.physical)
        );
        assert!(
            prepare(
                &context,
                &mut ram,
                ExitRecord {
                    qualification: record.qualification ^ 3,
                    ..record
                }
            )
            .is_err()
        );
        for offset in 1..16 {
            context.registers[7] = record.linear + offset;
            let unaligned = ExitRecord {
                linear: record.linear + offset,
                physical: record.physical + offset,
                ..record
            };
            assert_eq!(
                prepare(&context, &mut ram, unaligned).unwrap_err(),
                "misaligned XMM MMIO transfer"
            );
        }
        assert!(
            ram.reads
                .iter()
                .all(|&(address, _)| address < record.physical || address >= record.physical + 31)
        );
    }
}

#[test]
fn movdqu_metadata_identifies_both_xmm_registers_and_operand_roles() {
    use rax::isa::x86_64::instruction_metadata::{self, OperandKind};
    for (code, name, destination, source) in [
        (
            &[0xf3, 0x45, 0x0f, 0x6f, 0xc7][..],
            "movdqu",
            "xmm8",
            "xmm15",
        ),
        (&[0xf3, 0x45, 0x0f, 0x7f, 0xc7], "movdqu", "xmm15", "xmm8"),
        (&[0xc4, 0x41, 0xfa, 0x6f, 0xc7], "vmovdqu", "xmm8", "xmm15"),
        (&[0xc4, 0x41, 0xfa, 0x7f, 0xc7], "vmovdqu", "xmm15", "xmm8"),
    ] {
        let instruction = instruction_metadata::decode(64, 0x1000, code).unwrap();
        assert_eq!(instruction.mnemonic, name);
        assert_eq!(instruction.size as usize, code.len());
        let [dst, src] = instruction.operands.as_slice() else {
            panic!("expected two operands for {code:02x?}");
        };
        assert_eq!(
            (dst.kind, dst.reg.as_str(), dst.width_bits),
            (OperandKind::Register, destination, 128)
        );
        assert_eq!(
            (src.kind, src.reg.as_str(), src.width_bits),
            (OperandKind::Register, source, 128)
        );
        assert!(dst.write && !dst.read && src.read && !src.write);
        let (context, mut ram, exit) = fixture(code);
        assert!(prepare(&context, &mut ram, exit).is_err());
    }
    for invalid in [
        &[0xf0, 0xf3, 0x0f, 0x6f, 0x07][..], // LOCK MOVDQU
        &[0xc5, 0xf2, 0x6f, 0x07],           // reserved VEX.vvvv
    ] {
        assert!(instruction_metadata::decode(64, 0x1000, invalid).is_err());
    }
}

#[test]
fn vex_scalar_xmm_refuses_reserved_encodings_and_register_operands() {
    for code in [
        &[0xc5, 0xfd, 0x6e, 0x07][..],   // L=1
        &[0xc5, 0xf1, 0x6e, 0x07],       // reserved vvvv
        &[0xc4, 0xe2, 0xf9, 0x6e, 0x07], // another opcode map
        &[0xf0, 0xc5, 0xf9, 0x6e, 0x07],
        &[0xf2, 0xc5, 0xf9, 0x6e, 0x07],
        &[0xf3, 0xc5, 0xf9, 0x6e, 0x07],
        &[0x66, 0xc5, 0xf9, 0x6e, 0x07],
        &[0x40, 0x67, 0xc5, 0xf9, 0x6e, 0x07],
        &[0xc5, 0xf9, 0x6e, 0xc7], // register-only
        &[0xc4, 0xe1, 0xf9],       // truncated
    ] {
        let (context, mut ram, exit) = fixture(code);
        assert!(prepare(&context, &mut ram, exit).is_err(), "{code:02x?}");
        assert!(
            ram.reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }
}

#[test]
fn string_load_and_store_plan_the_current_element() {
    for (code, index, access) in [
        (&[0xac][..], 6, 0x181),             // LODSB
        (&[0x48, 0xab][..], 7, 0x182),       // STOSQ
        (&[0xf3, 0x67, 0xad][..], 6, 0x181), // REP LODSD with ESI
        (&[0xf3, 0x66, 0xab][..], 7, 0x182), // REP STOSW
    ] {
        let (mut context, mut ram, mut exit) = fixture(code);
        context.registers[index] = exit.linear;
        context.registers[1] = 2;
        exit.qualification = access;
        let plan = prepare(&context, &mut ram, exit)
            .expect("single-memory string operation must plan its current MMIO element");
        assert_eq!(plan.physical, exit.physical);
        assert_eq!(plan.linear, exit.linear);
        assert_eq!(plan.length, code.len() as u64);
    }
}

#[test]
fn packed_float_xmm_moves_keep_direction_alignment_and_register_width() {
    use rax::isa::x86_64::instruction_metadata::{self, OperandKind};
    for (double, aligned, legacy_name, vex_name) in [
        (false, false, "movups", "vmovups"),
        (true, false, "movupd", "vmovupd"),
        (false, true, "movaps", "vmovaps"),
        (true, true, "movapd", "vmovapd"),
    ] {
        for read in [true, false] {
            let opcode = if aligned { 0x28 } else { 0x10 } | u8::from(!read);
            for (prefix, mnemonic, vex) in [
                (vec![0x44, 0x0f], legacy_name, false),
                (vec![0xc5, 0x78 | u8::from(double)], vex_name, true),
                (vec![0xc4, 0x61, 0xf8 | u8::from(double)], vex_name, true),
            ] {
                // The legacy packed-double prefix precedes any REX.
                let mut bytes = prefix;
                if double && !vex {
                    bytes.insert(0, 0x66);
                }
                bytes.extend_from_slice(&[opcode, 0x3f]); // XMM15 and [RDI].
                let meta = instruction_metadata::decode(64, 0x1000, &bytes).unwrap();
                let (dst, src) = (&meta.operands[0], &meta.operands[1]);
                let (reg, mem) = if read { (dst, src) } else { (src, dst) };
                assert_eq!(meta.mnemonic, mnemonic);
                assert_eq!(meta.size, bytes.len() as u32);
                assert_eq!(
                    (reg.kind, reg.reg.as_str(), reg.width_bits),
                    (OperandKind::Register, "xmm15", 128)
                );
                assert_eq!(
                    (mem.kind, mem.width_bits, mem.read, mem.write),
                    (OperandKind::Memory, 128, read, !read)
                );

                let (mut context, mut ram, mut exit) = fixture(&bytes);
                exit.qualification = if read { 0x181 } else { 0x182 };
                for offset in [0, 1, 15] {
                    context.registers[7] = exit.linear + offset;
                    let plan = prepare(
                        &context,
                        &mut ram,
                        ExitRecord {
                            linear: exit.linear + offset,
                            physical: exit.physical + offset,
                            ..exit
                        },
                    );
                    if aligned && offset != 0 {
                        assert_eq!(plan.unwrap_err(), "misaligned XMM MMIO transfer");
                        continue;
                    }
                    let plan = plan.unwrap();
                    let transfer = match plan.action {
                        Action::XmmRead { input, zero_upper } if read => {
                            assert_eq!(zero_upper, vex);
                            input
                        }
                        Action::XmmWrite(transfer) if !read => transfer,
                        action => panic!("unexpected {mnemonic} MMIO action: {action:?}"),
                    };
                    assert_eq!(
                        (transfer.index, transfer.size, transfer.length),
                        (15, 16, bytes.len() as u64)
                    );
                    assert_eq!(plan.physical, exit.physical + offset);
                }
                assert!(
                    ram.reads
                        .iter()
                        .all(|&(address, _)| address < exit.physical
                            || address >= exit.physical + 31)
                );
            }
        }
    }
    for bytes in [
        &[0xc5, 0xfc, 0x58, 0x07][..], // YMM VADDPS.
        &[0xc5, 0xf1, 0x28, 0x07],     // Reserved VEX.vvvv.
    ] {
        let (context, mut ram, record) = fixture(bytes);
        assert!(prepare(&context, &mut ram, record).is_err(), "{bytes:02x?}");
    }
}

#[test]
fn scalar_float_xmm_memory_moves_keep_the_exact_lane_and_width() {
    use rax::isa::x86_64::instruction_metadata::{self, OperandKind};

    for (legacy_prefix, vex_prefix, size, legacy_name, vex_name) in [
        (0xf3, 2, 4, "movss", "vmovss"),
        (0xf2, 3, 8, "movsd", "vmovsd"),
    ] {
        for read in [true, false] {
            for (mut bytes, mnemonic, vex) in [
                (vec![legacy_prefix, 0x44, 0x0f], legacy_name, false),
                (vec![0xc5, 0x78 | vex_prefix], vex_name, true),
                (vec![0xc4, 0x61, 0xf8 | vex_prefix], vex_name, true),
            ] {
                bytes.extend_from_slice(&[0x10 | u8::from(!read), 0x7f, 3]); // XMM15, [RDI+3].
                let insn = instruction_metadata::decode(64, 0x1000, &bytes).unwrap();
                assert_eq!(insn.mnemonic, mnemonic);
                let [destination, source] = insn.operands.as_slice() else {
                    panic!("expected two operands in {insn:?}");
                };
                let (xmm, memory) = if read {
                    (destination, source)
                } else {
                    (source, destination)
                };
                assert_eq!(
                    (
                        xmm.kind,
                        xmm.reg.as_str(),
                        xmm.width_bits,
                        xmm.read,
                        xmm.write
                    ),
                    (OperandKind::Register, "xmm15", 128, !read, read)
                );
                assert_eq!(
                    (memory.kind, memory.width_bits, memory.read, memory.write),
                    (OperandKind::Memory, u32::from(size) * 8, read, !read)
                );

                let (context, mut ram, mut exit) = fixture(&bytes);
                exit.linear += 3;
                exit.physical += 3;
                exit.qualification = if read { 0x181 } else { 0x182 };
                let plan = prepare(&context, &mut ram, exit).unwrap();
                assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
                let transfer = match plan.action {
                    Action::XmmRead { input, zero_upper } if read => {
                        assert_eq!(zero_upper, vex);
                        input
                    }
                    Action::XmmWrite(input) if !read => input,
                    action => panic!("unexpected {mnemonic} MMIO action: {action:?}"),
                };
                assert_eq!(
                    (transfer.index, transfer.size, transfer.length),
                    (15, size, bytes.len() as u64)
                );
                assert!(
                    ram.reads
                        .iter()
                        .all(|&(address, _)| address < exit.physical)
                );
                exit.qualification ^= 3;
                assert!(prepare(&context, &mut ram, exit).is_err());
            }

            let bytes = [legacy_prefix, 0x44, 0x0f, 0x10 | u8::from(!read), 0xf8];
            let meta = instruction_metadata::decode(64, 0x1000, &bytes).unwrap();
            assert_eq!(meta.mnemonic, legacy_name);
            assert_eq!(meta.operands.len(), 2);
            for (operand, (name, write)) in meta.operands.iter().zip([
                (if read { "xmm15" } else { "xmm0" }, true),
                (if read { "xmm0" } else { "xmm15" }, false),
            ]) {
                assert_eq!(
                    (operand.reg.as_str(), operand.read, operand.write),
                    (name, true, write)
                );
            }
        }
    }

    for code in [
        &[0xa5][..],               // MOVSD with two implicit memory operands.
        &[0xf3, 0xa5],             // REP MOVSD.
        &[0xf3, 0x0f, 0x10, 0xc0], // MOVSS register merge.
        &[0xc5, 0xea, 0x10, 0xc7], // VMOVSS three-register merge.
        &[0xc5, 0xf2, 0x10, 0x07], // Reserved memory VEX.vvvv.
        &[0xc5, 0xfe, 0x10, 0x07], // Noncanonical scalar VEX.L.
        &[0xf2, 0x0f, 0x58, 0x07], // ADDSD has arithmetic side effects.
    ] {
        let (context, mut ram, exit) = fixture(code);
        assert!(prepare(&context, &mut ram, exit).is_err(), "{code:02x?}");
        assert!(
            ram.reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }
}
