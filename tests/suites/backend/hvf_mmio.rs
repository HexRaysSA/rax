//! Actual metadata decoder plus device-effect-free native MMIO planning.
use rax::{devices, isa};
#[path = "../../../src/backend/hvf/guest_translation.rs"]
mod guest_translation;
#[path = "../../../src/backend/hvf/mmio.rs"]
mod mmio;
use guest_translation::{Paging, PhysicalMemory};
use mmio::{Action, Context, ExitRecord, Extension, Input, RegisterPart, prepare};
use std::collections::BTreeMap;

#[path = "hvf_mmio/alu_read.rs"]
mod alu_read_tests;
#[path = "hvf_mmio/rmw.rs"]
mod rmw_tests;
#[derive(Default)]
struct Ram {
    bytes: BTreeMap<u64, u8>,
    reads: Vec<(u64, usize)>,
    identity_tables: bool,
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
        &[0x48, 0x63, 0x07],
        &[0x8c, 0x07],
        &[0x0f, 0x10, 0x07],
    ] {
        let (c, mut r, e) = fixture(code);
        assert!(prepare(&c, &mut r, e).is_err());
    }
    let (mut c, mut r, e) = fixture(&[0x8a, 7]);
    c.rflags |= 1 << 8;
    assert!(prepare(&c, &mut r, e).is_err());
    assert!(r.reads.is_empty());
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

#[test]
fn independent_guest_records_preserve_all_registers_memory_and_flags() {
    const CASES: &[u8] = include_bytes!("../../fixtures/hvf/mmio-v1/cases.bin");
    const RAW: &[u8] = include_bytes!("../../fixtures/hvf/mmio-v1/records.bin");
    fn word(b: &[u8], i: usize) -> u32 {
        u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
    }
    fn quad(b: &[u8], i: usize) -> u64 {
        u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
    }
    let count = CASES.len() / 168;
    assert_eq!(count, 1204);
    assert_eq!(CASES.len() % 168, 0);
    assert_eq!(RAW.len(), 20 + count * 152);
    assert_eq!(&RAW[..8], b"RAXMM001");
    assert_eq!(word(RAW, 8) as usize, count);
    assert_eq!(&RAW[12 + count * 152..], b"MM_DONE!");
    let (mut reads, mut writes) = (0, 0);
    for (i, case) in CASES.chunks_exact(168).enumerate() {
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
        }
        let record = &RAW[12 + i * 152..12 + (i + 1) * 152];
        let actual: [u64; 16] = std::array::from_fn(|index| quad(record, index * 8));
        assert_eq!(expected, actual, "registers case{i},code{code:02x?}");
        assert_eq!(memory, record[128..136], "memory case{i},code{code:02x?}");
        assert_eq!(quad(record, 136), c.rflags);
        assert_eq!(quad(record, 144), c.rflags);
    }
    assert_eq!((reads, writes), (912, 292));
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
