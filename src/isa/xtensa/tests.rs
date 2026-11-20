//! Unit tests of the Xtensa core on a flat RAM bus.

use super::*;

/// 1 MB of RAM at 0x4000_0000.
pub(crate) struct Ram {
    pub base: u32,
    pub mem: Vec<u8>,
}

impl Ram {
    pub fn new() -> Self {
        Ram {
            base: 0x4000_0000,
            mem: vec![0; 1 << 20],
        }
    }

    fn off(&self, addr: u32, len: u32) -> Result<usize, ()> {
        let off = addr.wrapping_sub(self.base);
        if off
            .checked_add(len)
            .is_some_and(|end| end as usize <= self.mem.len())
        {
            Ok(off as usize)
        } else {
            Err(())
        }
    }

    pub fn load(&mut self, addr: u32, bytes: &[u8]) {
        let off = self.off(addr, bytes.len() as u32).unwrap();
        self.mem[off..off + bytes.len()].copy_from_slice(bytes);
    }
}

impl XtensaBus for Ram {
    fn fetch(&mut self, addr: u32) -> Result<u32, ()> {
        let off = self.off(addr, 1)?;
        let mut b = [0u8; 4];
        for (i, v) in b.iter_mut().enumerate() {
            *v = self.mem.get(off + i).copied().unwrap_or(0);
        }
        Ok(u32::from_le_bytes(b))
    }
    fn read8(&mut self, addr: u32) -> Result<u8, ()> {
        Ok(self.mem[self.off(addr, 1)?])
    }
    fn read16(&mut self, addr: u32) -> Result<u16, ()> {
        let o = self.off(addr, 2)?;
        Ok(u16::from_le_bytes([self.mem[o], self.mem[o + 1]]))
    }
    fn read32(&mut self, addr: u32) -> Result<u32, ()> {
        let o = self.off(addr, 4)?;
        Ok(u32::from_le_bytes(self.mem[o..o + 4].try_into().unwrap()))
    }
    fn write8(&mut self, addr: u32, v: u8) -> Result<(), ()> {
        let o = self.off(addr, 1)?;
        self.mem[o] = v;
        Ok(())
    }
    fn write16(&mut self, addr: u32, v: u16) -> Result<(), ()> {
        let o = self.off(addr, 2)?;
        self.mem[o..o + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, addr: u32, v: u32) -> Result<(), ()> {
        let o = self.off(addr, 4)?;
        self.mem[o..o + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
}

/// Instruction bytes from the words objdump prints (24-bit words as 3 bytes,
/// 16-bit words as 2 bytes, little-endian).
fn code(words: &[(u32, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(len, w) in words {
        out.extend_from_slice(&w.to_le_bytes()[..len as usize]);
    }
    out
}

fn cpu_at(pc: u32) -> XtensaCpu {
    let mut cpu = XtensaCpu::new(XtensaConfig::esp32s3(), 0xcdcd);
    cpu.pc = pc;
    // PS: UM, WOE, INTLEVEL 0, EXCM clear.
    cpu.sr[regs::sr::PS] = regs::ps::UM | regs::ps::WOE;
    cpu
}

#[test]
fn decodes_known_words() {
    let cases: &[(u32, &str)] = &[
        (0xe32e70, "rur.threadptr"),
        (0xf3e730, "wur.threadptr"),
        (0xfa3230, "const.s"),
        (0x028323, "lsip"),
        (0x00056c, "movi.n"),
        (0xfc7317, "bbci"),
        (0x491344, "mula.da.hl.ldinc"),
        (0x1a7504, "mula.dd.lh.lddec"),
        (0x802804, "ldinc"),
        (0x9a2140, "trunc.s"),
        (0x1134b0, "slli"),
        (0x453240, "extui"),
        (0x09d430, "l32e"),
        (0x4080e0, "rotw"),
        (0x006520, "rsil"),
        (0x00f72d, "break.n"),
        (0x029376, "loopnez"),
        (0x00340b, "addi.n"),
        (0x004136, "entry"),
        (0x00f01d, "retw.n"),
        (0x0020f0, "nop"),
    ];
    for &(w, m) in cases {
        let insn = decode(w);
        assert_eq!(insn.op.map(|o| o.mnemonic()), Some(m), "{w:#08x}");
    }
}

#[test]
fn arithmetic_and_loop() {
    // movi a3, 10; movi a4, 0; loop a3, end; addi a4, a4, 3; end: nop
    let mut ram = Ram::new();
    let prog = code(&[
        (3, 0x0aa032), // movi a3, 10
        (3, 0x00a042), // movi a4, 0
        (3, 0x028376), // loop a3, end (lend = pc + 4 + 2)
        (3, 0x03c442), // addi a4, a4, 3
        (3, 0x0020f0), // nop
    ]);
    ram.load(0x4000_1000, &prog);
    let mut cpu = cpu_at(0x4000_1000);
    for _ in 0..40 {
        if cpu.pc == 0x4000_1000 + 12 + 3 {
            break;
        }
        assert_eq!(cpu.step(&mut ram), None);
    }
    assert_eq!(cpu.pc, 0x4000_100f);
    assert_eq!(cpu.a(4), 30);
    assert_eq!(cpu.sr[regs::sr::LCOUNT], 0);
}

/// The generated decoder agrees with GNU objdump on every word of the inventory.
#[test]
fn decode_matches_objdump() {
    let data = include_str!("testdata/objdump_words.txt");
    let mut checked = 0;
    let mut mismatches = Vec::new();
    for line in data
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (word, mnemonic) = line.split_once(' ').unwrap();
        let value = u32::from_str_radix(word, 16).unwrap();
        let insn = decode(value);
        assert_eq!(insn.len() as usize * 2, word.len(), "{line}: length");
        let ours = insn.op.map(|o| o.mnemonic()).unwrap_or("(none)");
        if ours != mnemonic {
            mismatches.push(format!("{word}: objdump {mnemonic}, rax {ours}"));
        }
        checked += 1;
    }
    assert!(checked > 4000, "{checked} words checked");
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches[..mismatches.len().min(40)].join("\n")
    );
}

/// Runs `n` instructions of `prog` loaded at 0x4000_1000, with a stack at 0x4008_0000.
fn run_prog(prog: &[u8], n: usize, setup: impl FnOnce(&mut XtensaCpu)) -> (XtensaCpu, Ram) {
    let mut ram = Ram::new();
    ram.load(0x4000_1000, prog);
    let mut cpu = cpu_at(0x4000_1000);
    cpu.sr[regs::sr::WINDOWSTART] = 1;
    cpu.set_a(1, 0x4008_0000);
    setup(&mut cpu);
    for _ in 0..n {
        assert_eq!(cpu.step(&mut ram), None);
    }
    (cpu, ram)
}

// start: movi a10, 5; call8 func; mov.n a3, a10; j .
// func:  entry a1, 32; addi a2, a2, 37; retw.n
const CALLS: &[u8] = &[
    0xa2, 0xa0, 0x05, 0xa5, 0x00, 0x00, 0x3d, 0x0a, 0x06, 0xff, 0xff, 0x00, 0x36, 0x41, 0x00, 0x22,
    0xc2, 0x25, 0x1d, 0xf0,
];

#[test]
fn windowed_call_entry_retw() {
    let (cpu, _) = run_prog(CALLS, 6, |_| {});
    assert_eq!(cpu.pc, 0x4000_1008);
    assert_eq!(cpu.a(3), 42);
    assert_eq!(
        cpu.a(8),
        0x8000_1006,
        "return address with the window increment"
    );
    assert_eq!(cpu.a(9), 0x4008_0000 - 32, "stack pointer of the callee");
    assert_eq!(cpu.sr[regs::sr::WINDOWBASE], 0);
    assert_eq!(cpu.sr[regs::sr::WINDOWSTART], 1);
}

#[test]
fn window_overflow_on_call() {
    // The frame two groups up is live: `movi a10` names a10, which belongs to it.
    let (cpu, _) = run_prog(CALLS, 1, |cpu| cpu.sr[regs::sr::WINDOWSTART] = 0b101);
    assert_eq!(
        cpu.pc, 0x4000_0100,
        "OF12 vector: the next live frame is far"
    );
    assert_eq!(cpu.sr[regs::sr::EPC1], 0x4000_1000);
    assert_eq!(cpu.sr[regs::sr::WINDOWBASE], 2);
    let ps = cpu.sr[regs::sr::PS];
    assert_eq!((ps & regs::ps::OWB) >> regs::ps::OWB_SHIFT, 0);
    assert_ne!(ps & regs::ps::EXCM, 0);
}

// movi a2, 7; float.s f1, a2, 1; movi a3, 3; float.s f2, a3, 0; mul.s f3, f1, f2;
// madd.s f3, f1, f1; trunc.s a4, f3, 2; olt.s b1, f2, f1; movi a5, 0; movt a5, a2, b1;
// rfr a6, f3; j .
const FP: &[u8] = &[
    0x22, 0xa0, 0x07, 0x10, 0x12, 0xca, 0x32, 0xa0, 0x03, 0x00, 0x23, 0xca, 0x20, 0x31, 0x2a, 0x10,
    0x31, 0x4a, 0x20, 0x43, 0x9a, 0x10, 0x12, 0x4b, 0x52, 0xa0, 0x00, 0x10, 0x52, 0xd3, 0x40, 0x63,
    0xfa, 0x06, 0xff, 0xff,
];

#[test]
fn single_precision_fpu() {
    let (cpu, _) = run_prog(FP, 11, |_| {});
    assert_eq!(f32::from_bits(cpu.fr[1]), 3.5);
    assert_eq!(f32::from_bits(cpu.fr[2]), 3.0);
    assert_eq!(f32::from_bits(cpu.fr[3]), 22.75);
    assert_eq!(cpu.a(4), 91);
    assert_eq!(cpu.a(5), 7, "olt.s set b1");
    assert_eq!(cpu.a(6), 22.75f32.to_bits());
}

#[test]
fn fpu_disabled_raises_coprocessor_exception() {
    let mut ram = Ram::new();
    ram.load(0x4000_1000, FP);
    let mut cpu = cpu_at(0x4000_1000);
    cpu.sr[regs::sr::CPENABLE] = 0;
    cpu.step(&mut ram);
    cpu.step(&mut ram);
    assert_eq!(
        cpu.sr[regs::sr::EXCCAUSE],
        regs::cause::COPROCESSOR0_DISABLED
    );
    assert_eq!(cpu.sr[regs::sr::EPC1], 0x4000_1003);
    assert_eq!(cpu.pc, 0x4000_0340, "user exception vector (PS.UM)");
}

// movi a2, 0x123; movi a3, -77; mul.aa.ll a2, a3; mula.aa.ll a2, a2; rsr.acclo a4; rsr.acchi a5;
// movi a6, 100; wsr.scompare1 a6; s32i a6, a1, 0; movi a7, 200; s32c1i a7, a1, 0; l32i a8, a1, 0;
// movi a9, 5; s32c1i a9, a1, 0; movi a10, 0; loopnez a10, 1f; movi a11, 1; 1: nsau a12, a2;
// clamps a13, a3, 7; j .
const MISC: &[u8] = &[
    0x22, 0xa1, 0x23, 0x32, 0xaf, 0xb3, 0x34, 0x02, 0x74, 0x24, 0x02, 0x78, 0x40, 0x10, 0x03, 0x50,
    0x11, 0x03, 0x62, 0xa0, 0x64, 0x60, 0x0c, 0x13, 0x62, 0x61, 0x00, 0x72, 0xa0, 0xc8, 0x72, 0xe1,
    0x00, 0x82, 0x21, 0x00, 0x92, 0xa0, 0x05, 0x92, 0xe1, 0x00, 0xa2, 0xa0, 0x00, 0x76, 0x9a, 0x02,
    0xb2, 0xa0, 0x01, 0xc0, 0xf2, 0x40, 0x00, 0xd3, 0x33, 0x06, 0xff, 0xff,
];

#[test]
fn mac16_atomics_loops_and_bit_operations() {
    let (cpu, _) = run_prog(MISC, 18, |cpu| cpu.set_a(1, 0x4008_0000));
    assert_eq!(cpu.a(4), (291i32 * -77 + 291 * 291) as u32, "accumulator");
    assert_eq!(cpu.a(5), 0);
    assert_eq!(cpu.a(7), 100, "s32c1i returns the old word");
    assert_eq!(cpu.a(8), 200, "and stored on a match");
    assert_eq!(cpu.a(9), 200, "no store without a match");
    assert_eq!(cpu.a(11), 0, "loopnez with a zero count skips the body");
    assert_eq!(cpu.a(12), 23);
    assert_eq!(cpu.a(13) as i32, -77);
    assert_eq!(cpu.pc, 0x4000_1039);
}

#[test]
fn interrupts_take_their_level_vectors() {
    let nops: Vec<u8> = (0..16).flat_map(|_| [0xf0, 0x20, 0x00]).collect();
    // Level 1: general exception path, user vector.
    let (mut cpu, mut ram) = run_prog(&nops, 1, |cpu| {
        cpu.sr[regs::sr::INTENABLE] = (1 << 1) | (1 << 23) | (1 << 24)
    });
    let vectors: Vec<u8> = (0..0x400 / 3).flat_map(|_| [0xf0, 0x20, 0x00]).collect();
    ram.load(0x4000_0000, &vectors);
    cpu.set_irq_lines(1 << 1);
    assert_eq!(cpu.run(&mut ram, 1), Exit::Budget);
    assert_eq!(cpu.sr[regs::sr::EXCCAUSE], regs::cause::LEVEL1_INTERRUPT);
    assert_eq!(cpu.sr[regs::sr::EPC1], 0x4000_1003);
    // The handler runs at the user vector with PS.EXCM set; level 1 is now masked.
    assert_eq!(cpu.pc, 0x4000_0340 + 3);
    // PS.EXCM masks up to EXCM_LEVEL (3): interrupt 23 (level 3) waits.
    cpu.set_irq_lines((1 << 1) | (1 << 23));
    let pc_before = cpu.pc;
    assert_eq!(cpu.run(&mut ram, 1), Exit::Budget);
    assert_eq!(cpu.pc, pc_before + 3);
    // Level 4 (interrupt 24) preempts it: EPC4/EPS4 and the level-4 vector.
    let ps_before = cpu.sr[regs::sr::PS];
    let pc_before = cpu.pc;
    cpu.set_irq_lines((1 << 1) | (1 << 23) | (1 << 24));
    assert_eq!(cpu.run(&mut ram, 1), Exit::Budget);
    assert_eq!(cpu.sr[regs::sr::EPC1 + 3], pc_before);
    assert_eq!(cpu.sr[regs::sr::EPS2 + 2], ps_before);
    assert_eq!(cpu.pc, 0x4000_0200 + 3);
    assert_eq!(cpu.sr[regs::sr::PS] & regs::ps::INTLEVEL, 4);
}
