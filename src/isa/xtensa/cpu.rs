//! Xtensa processor state, run loop, exceptions, interrupts and register windows.

use super::config::{IntType, XtensaConfig};
use super::decode::{DecodeCache, Insn};
use super::generated::opcodes::{OPCODE_COUNT, Opcode};
use super::regs::{cause, ps, sr};

/// Memory and processor interface the core runs against. Addresses are virtual
/// (the core has no MMU, only region protection).
pub trait XtensaBus {
    /// The four bytes at `addr`, little-endian. Bytes past the end of a region
    /// read as 0; it fails only when `addr` itself can't be fetched.
    fn fetch(&mut self, addr: u32) -> Result<u32, ()>;
    fn read8(&mut self, addr: u32) -> Result<u8, ()>;
    fn read16(&mut self, addr: u32) -> Result<u16, ()>;
    fn read32(&mut self, addr: u32) -> Result<u32, ()>;
    fn write8(&mut self, addr: u32, value: u8) -> Result<(), ()>;
    fn write16(&mut self, addr: u32, value: u16) -> Result<(), ()>;
    fn write32(&mut self, addr: u32, value: u32) -> Result<(), ()>;
    /// External register interface (`RER`/`WER`).
    fn eri_read(&mut self, _addr: u32) -> u32 {
        0
    }
    fn eri_write(&mut self, _addr: u32, _value: u32) {}
    /// Called before each instruction with the instruction count. Returns the
    /// external interrupt lines when they changed.
    #[inline]
    fn sync(&mut self, _icount: u64) -> Option<u32> {
        None
    }
}

/// Why [`XtensaCpu::run`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// The instruction budget ran out.
    Budget,
    /// The core waits for an interrupt (`WAITI`) and none is pending.
    Waiti,
    /// The PC reached an address marked with [`XtensaCpu::set_hook`].
    Hook,
    /// `BREAK s, t` or `BREAK.N s` (t = 0). The PC is on the next instruction.
    Break { s: u32, t: u32 },
    /// An exception whose cause is in [`XtensaCpu::stop_on_cause`]. Nothing was
    /// changed yet: [`XtensaCpu::raise`] takes it.
    Exception { cause: u32, vaddr: Option<u32> },
    /// `SIMCALL`. The PC is on the next instruction.
    Simcall,
}

/// Outcome of one instruction that leaves the straight-line flow.
pub(crate) enum Trap {
    /// General exception (EXCCAUSE value) with an optional EXCVADDR.
    Exception(u32, Option<u32>),
    /// The instruction set PC and the state itself (window exceptions).
    Vectored,
    /// Stop the run loop after this instruction.
    Exit(Exit),
}

/// Executed-instruction counters.
pub struct Profile {
    pub executed: Box<[u64; OPCODE_COUNT]>,
    /// Instructions that raised IllegalInstruction for lack of semantics.
    pub unimplemented: Box<[u64; OPCODE_COUNT]>,
    pub undecoded: u64,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            executed: Box::new([0; OPCODE_COUNT]),
            unimplemented: Box::new([0; OPCODE_COUNT]),
            undecoded: 0,
        }
    }
}

/// An Xtensa core.
pub struct XtensaCpu {
    pub cfg: XtensaConfig,
    /// Physical AR registers.
    pub ar: [u32; 64],
    pub pc: u32,
    /// Special registers, by number.
    pub sr: [u32; 256],
    /// User registers, by number.
    pub ur: [u32; 256],
    /// FP registers (single-precision bit patterns).
    pub fr: [u32; 16],
    /// Waiting for an interrupt after `WAITI`.
    pub waiting: bool,
    /// Instructions executed.
    pub icount: u64,
    /// Exception causes (bit n = cause n) that stop the run loop before they are taken.
    pub stop_on_cause: u64,
    pub profile: Option<Box<Profile>>,
    /// Region protection attributes (8 regions of 512 MB), for `WITLB`/`WDTLB`.
    pub region_attr: [u32; 8],
    pub(crate) npc: u32,
    pub(crate) jumped: bool,
    level_mask: [u32; 8],
    edge_mask: u32,
    extern_level_mask: u32,
    software_mask: u32,
    nmi_mask: u32,
    ext_lines: u32,
    /// Cycles until CCOUNT next matches a CCOMPARE register (1..=2^32).
    to_ccompare: u64,
    cache: DecodeCache,
    pub(crate) kinds: &'static [super::exec::Kind; OPCODE_COUNT],
    /// Hook addresses, sorted, and their range.
    hooks: Vec<u32>,
    hook_min: u32,
    hook_max: u32,
}

#[inline]
fn bit(n: u32) -> u32 {
    1u32.wrapping_shl(n)
}

impl XtensaCpu {
    pub fn new(cfg: XtensaConfig, prid: u32) -> Self {
        let mut level_mask = [0; 8];
        for (level, m) in level_mask.iter_mut().enumerate() {
            *m = cfg.level_mask(level as u32);
        }
        let mut cpu = XtensaCpu {
            edge_mask: cfg.type_mask(IntType::ExternEdge),
            extern_level_mask: cfg.type_mask(IntType::ExternLevel),
            software_mask: cfg.type_mask(IntType::Software),
            nmi_mask: cfg.type_mask(IntType::Nmi),
            level_mask,
            cfg,
            ar: [0; 64],
            pc: 0,
            sr: [0; 256],
            ur: [0; 256],
            fr: [0; 16],
            waiting: false,
            icount: 0,
            stop_on_cause: 0,
            profile: None,
            region_attr: [2; 8],
            npc: 0,
            jumped: false,
            ext_lines: 0,
            to_ccompare: 1 << 32,
            cache: DecodeCache::new(),
            kinds: super::exec::kinds(),
            hooks: Vec::new(),
            hook_min: u32::MAX,
            hook_max: 0,
        };
        cpu.sr[sr::PRID] = prid;
        cpu.reset();
        cpu
    }

    /// Processor reset: PC at the reset vector, interrupts off, window at 0.
    pub fn reset(&mut self) {
        let prid = self.sr[sr::PRID];
        self.sr = [0; 256];
        self.sr[sr::PRID] = prid;
        self.sr[sr::PS] = 0x1f; // INTLEVEL 15, EXCM
        self.sr[sr::VECBASE] = self.cfg.vecbase_reset;
        self.sr[sr::ATOMCTL] = self.cfg.atomctl_reset;
        self.sr[sr::MEMCTL] = self.cfg.memctl_reset;
        self.sr[sr::CPENABLE] = self.cfg.cpenable_reset;
        self.sr[sr::CONFIGID0] = self.cfg.configid0;
        self.sr[sr::CONFIGID1] = self.cfg.configid1;
        self.ur = [0; 256];
        self.pc = self.cfg.reset_vector;
        self.waiting = false;
        self.region_attr = [2; 8];
        self.recompute_ccompare();
    }

    // ---- registers ----

    #[inline]
    fn ar_index(&self, n: u32) -> usize {
        ((self.sr[sr::WINDOWBASE] << 2).wrapping_add(n) as usize) & (self.cfg.nareg - 1)
    }

    /// Register `a<n>` of the current window.
    #[inline]
    pub fn a(&self, n: u32) -> u32 {
        self.ar[self.ar_index(n)]
    }

    #[inline]
    pub fn set_a(&mut self, n: u32, value: u32) {
        let i = self.ar_index(n);
        self.ar[i] = value;
    }

    pub fn ps(&self) -> u32 {
        self.sr[sr::PS]
    }

    fn nwindows(&self) -> u32 {
        (self.cfg.nareg / 4) as u32
    }

    fn wb_bound(&self, wb: u32) -> u32 {
        wb & (self.nwindows() - 1)
    }

    // ---- hooks ----

    /// Makes the run loop stop with [`Exit::Hook`] when the PC reaches `addr`,
    /// before the instruction there executes.
    pub fn set_hook(&mut self, addr: u32) {
        if let Err(i) = self.hooks.binary_search(&addr) {
            self.hooks.insert(i, addr);
        }
        self.hook_min = self.hook_min.min(addr);
        self.hook_max = self.hook_max.max(addr);
    }

    #[inline]
    fn hooked(&self, pc: u32) -> bool {
        pc >= self.hook_min && pc <= self.hook_max && self.hooks.binary_search(&pc).is_ok()
    }

    /// Returns from the function whose first instruction is at the PC, before its
    /// ENTRY runs, with `value` as its result.
    pub fn return_from_function(&mut self, value: u32) {
        let callinc = (self.sr[sr::PS] & ps::CALLINC) >> ps::CALLINC_SHIFT;
        if callinc == 0 {
            self.set_a(2, value);
            self.pc = self.a(0);
        } else {
            let ra = self.a(callinc * 4);
            self.set_a(callinc * 4 + 2, value);
            self.pc = (ra & 0x3fff_ffff) | (self.pc & 0xc000_0000);
        }
    }

    // ---- timers ----

    /// Sets the external interrupt lines (bit n = processor interrupt n).
    /// Level-type interrupts follow the lines; edge-type ones latch rising edges.
    pub fn set_irq_lines(&mut self, lines: u32) {
        let rising = lines & !self.ext_lines;
        self.ext_lines = lines;
        let int = &mut self.sr[sr::INTERRUPT];
        *int = (*int & !self.extern_level_mask) | (lines & self.extern_level_mask);
        *int |= rising & (self.edge_mask | self.nmi_mask);
    }

    pub(crate) fn recompute_ccompare(&mut self) {
        let ccount = self.sr[sr::CCOUNT];
        self.to_ccompare = (0..3)
            .map(|i| {
                let d = self.sr[sr::CCOMPARE0 + i].wrapping_sub(ccount);
                if d == 0 { 1 << 32 } else { u64::from(d) }
            })
            .min()
            .unwrap_or(1 << 32);
    }

    /// Cycles until the next CCOMPARE match.
    pub fn cycles_to_ccompare(&self) -> u64 {
        self.to_ccompare
    }

    /// Advances CCOUNT by `cycles` (one per executed instruction, or idle time),
    /// raising the timer interrupts of the CCOMPARE registers it reaches.
    #[inline]
    pub fn advance_ccount(&mut self, cycles: u64) {
        let mut left = cycles;
        while left >= self.to_ccompare {
            left -= self.to_ccompare;
            self.sr[sr::CCOUNT] = self.sr[sr::CCOUNT].wrapping_add(self.to_ccompare as u32);
            let ccount = self.sr[sr::CCOUNT];
            for i in 0..3 {
                if self.sr[sr::CCOMPARE0 + i] == ccount {
                    self.sr[sr::INTERRUPT] |= bit(u32::from(self.cfg.timer_int[i]));
                }
            }
            self.to_ccompare = 1 << 32;
            self.recompute_ccompare();
        }
        self.sr[sr::CCOUNT] = self.sr[sr::CCOUNT].wrapping_add(left as u32);
        self.to_ccompare -= left;
    }

    // ---- interrupts and exceptions ----

    fn current_int_level(&self) -> u32 {
        let ps = self.sr[sr::PS];
        let level = ps & ps::INTLEVEL;
        if ps & ps::EXCM != 0 {
            level.max(self.cfg.excm_level)
        } else {
            level
        }
    }

    /// Highest level among the pending enabled interrupts, if it can be taken now.
    #[inline]
    pub fn pending_level(&self) -> Option<u32> {
        let mut pending = self.sr[sr::INTERRUPT] & (self.sr[sr::INTENABLE] | self.nmi_mask);
        if pending == 0 {
            return None;
        }
        let mut level = 0;
        while pending != 0 {
            let i = pending.trailing_zeros();
            level = level.max(u32::from(self.cfg.int_level[i as usize]));
            pending &= pending - 1;
        }
        (level > self.current_int_level() || level == self.cfg.nmi_level).then_some(level)
    }

    fn vector(&self, ofs: u32) -> u32 {
        self.sr[sr::VECBASE].wrapping_add(ofs)
    }

    fn take_interrupt(&mut self, level: u32) {
        self.waiting = false;
        if level > 1 {
            self.sr[sr::EPC1 + level as usize - 1] = self.pc;
            self.sr[sr::EPS2 + level as usize - 2] = self.sr[sr::PS];
            self.sr[sr::PS] = (self.sr[sr::PS] & !ps::INTLEVEL) | level | ps::EXCM;
            self.pc = self.vector(self.cfg.level_vecofs[level as usize]);
            if level == self.cfg.nmi_level {
                self.sr[sr::INTERRUPT] &= !self.nmi_mask;
            }
        } else {
            self.sr[sr::EXCCAUSE] = cause::LEVEL1_INTERRUPT;
            self.enter_general_exception();
        }
    }

    fn enter_general_exception(&mut self) {
        let ps = self.sr[sr::PS];
        let vec = if ps & ps::EXCM != 0 {
            self.sr[sr::DEPC] = self.pc;
            self.cfg.double_vecofs
        } else {
            self.sr[sr::EPC1] = self.pc;
            if ps & ps::UM != 0 {
                self.cfg.user_vecofs
            } else {
                self.cfg.kernel_vecofs
            }
        };
        self.sr[sr::PS] |= ps::EXCM;
        self.pc = self.vector(vec);
    }

    /// Takes a general exception at the current PC.
    pub fn raise(&mut self, cause: u32, vaddr: Option<u32>) {
        self.sr[sr::EXCCAUSE] = cause;
        if let Some(v) = vaddr {
            self.sr[sr::EXCVADDR] = v;
        }
        self.enter_general_exception();
    }

    // ---- windows ----

    fn windowstart_replicated(&self) -> u32 {
        let ws = self.sr[sr::WINDOWSTART];
        ws | (ws << self.nwindows())
    }

    /// Groups of four registers above the current window that are free (0..=3).
    fn free_window_groups(&self) -> u32 {
        let ws = self.windowstart_replicated() >> (self.sr[sr::WINDOWBASE] + 1);
        (ws | 0x8).trailing_zeros()
    }

    /// Overflow exception for an instruction that names register group `group`:
    /// rotates to the frame in the way and vectors to its spill handler.
    fn window_overflow(&mut self) {
        let wb = self.sr[sr::WINDOWBASE];
        let ws = self.windowstart_replicated() >> (wb + 1);
        let n = ws.trailing_zeros() + 1;
        self.sr[sr::WINDOWBASE] = self.wb_bound(wb + n);
        self.sr[sr::PS] = (self.sr[sr::PS] & !ps::OWB) | (wb << ps::OWB_SHIFT) | ps::EXCM;
        self.sr[sr::EPC1] = self.pc;
        let k = match (ws >> n).trailing_zeros() {
            0 => 0,
            1 => 2,
            _ => 4,
        };
        self.pc = self.vector(self.cfg.window_vecofs[k]);
    }

    /// Underflow exception for a `RETW` returning by `n` frames.
    pub(crate) fn window_underflow(&mut self, n: u32) {
        let wb = self.sr[sr::WINDOWBASE];
        self.sr[sr::WINDOWBASE] = self.wb_bound(wb.wrapping_sub(n));
        self.sr[sr::PS] = (self.sr[sr::PS] & !ps::OWB) | (wb << ps::OWB_SHIFT) | ps::EXCM;
        self.sr[sr::EPC1] = self.pc;
        let k = match n {
            1 => 1,
            2 => 3,
            _ => 5,
        };
        self.pc = self.vector(self.cfg.window_vecofs[k]);
    }

    pub(crate) fn windowstart_bit(&self, wb: u32) -> u32 {
        bit(self.wb_bound(wb))
    }

    pub(crate) fn rotate_window(&mut self, delta: u32) {
        self.sr[sr::WINDOWBASE] = self.wb_bound(self.sr[sr::WINDOWBASE].wrapping_add(delta));
    }

    /// Window overflow checking is on (PS.WOE set, PS.EXCM clear).
    #[inline]
    pub(crate) fn cwoe(&self) -> bool {
        self.sr[sr::PS] & (ps::WOE | ps::EXCM) == ps::WOE
    }

    // ---- run loop ----

    /// Runs at most `budget` instructions.
    pub fn run<B: XtensaBus>(&mut self, bus: &mut B, budget: u64) -> Exit {
        let mut done = 0;
        while done < budget {
            if let Some(lines) = bus.sync(self.icount) {
                self.set_irq_lines(lines);
            }
            if self.sr[sr::INTERRUPT] != 0
                && let Some(level) = self.pending_level()
            {
                self.take_interrupt(level);
            }
            if self.waiting {
                return Exit::Waiti;
            }
            if self.hooked(self.pc) {
                return Exit::Hook;
            }
            match self.step_insn(bus) {
                Ok(()) => {}
                Err(exit) => {
                    done += 1;
                    return exit;
                }
            }
            done += 1;
        }
        Exit::Budget
    }

    /// Executes one instruction, ignoring hooks and pending interrupts.
    pub fn step<B: XtensaBus>(&mut self, bus: &mut B) -> Option<Exit> {
        self.step_insn(bus).err()
    }

    #[inline]
    fn step_insn<B: XtensaBus>(&mut self, bus: &mut B) -> Result<(), Exit> {
        let pc = self.pc;
        let fetched = match bus.fetch(pc) {
            Ok(w) => w,
            Err(()) => return self.exception(cause::INSTRUCTION_FETCH_ERROR, Some(pc)),
        };
        let insn = self.cache.decode(pc, fetched);
        let result = self.execute(bus, insn);
        self.icount += 1;
        self.advance_ccount(1);
        result
    }

    fn exception(&mut self, cause: u32, vaddr: Option<u32>) -> Result<(), Exit> {
        if cause < 64 && self.stop_on_cause & (1 << cause) != 0 {
            return Err(Exit::Exception { cause, vaddr });
        }
        self.raise(cause, vaddr);
        Ok(())
    }

    #[inline]
    fn execute<B: XtensaBus>(&mut self, bus: &mut B, insn: Insn) -> Result<(), Exit> {
        let Some(op) = insn.op else {
            if let Some(p) = self.profile.as_mut() {
                p.undecoded += 1;
            }
            return self.exception(cause::ILLEGAL_INSTRUCTION, None);
        };
        if let Some(p) = self.profile.as_mut() {
            p.executed[op as usize] += 1;
        }
        if self.cwoe() {
            let mut group = u32::from(insn.ar_group);
            if op == Opcode::ENTRY {
                group = group.max((self.sr[sr::PS] & ps::CALLINC) >> ps::CALLINC_SHIFT);
            }
            if group > 0 && group > self.free_window_groups() {
                self.window_overflow();
                return Ok(());
            }
        }
        self.npc = self.pc.wrapping_add(insn.len());
        self.jumped = false;
        match self.exec(bus, op, insn.word) {
            Ok(()) => {
                self.finish();
                Ok(())
            }
            Err(Trap::Vectored) => Ok(()),
            Err(Trap::Exception(cause, vaddr)) => {
                if cause == cause::ILLEGAL_INSTRUCTION
                    && let Some(p) = self.profile.as_mut()
                {
                    p.unimplemented[op as usize] += 1;
                }
                self.exception(cause, vaddr)
            }
            Err(Trap::Exit(exit)) => {
                self.finish();
                Err(exit)
            }
        }
    }

    /// Moves to the next instruction, with the zero-overhead loop back-edge.
    #[inline]
    fn finish(&mut self) {
        if !self.jumped
            && self.npc == self.sr[sr::LEND]
            && self.sr[sr::LCOUNT] != 0
            && self.sr[sr::PS] & ps::EXCM == 0
        {
            self.sr[sr::LCOUNT] -= 1;
            self.npc = self.sr[sr::LBEG];
        }
        self.pc = self.npc;
    }

    #[inline]
    pub(crate) fn jump(&mut self, target: u32) {
        self.npc = target;
        self.jumped = true;
    }
}
