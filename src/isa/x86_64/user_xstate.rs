//! Kernel-side transfer of user extended state (the XSAVE-managed x87, SSE,
//! AVX, AVX-512, and APX registers) to and from memory images.
//!
//! An operating system saves a thread's extended state into a signal frame
//! with `XSAVE` and reloads it at `sigreturn` with `XRSTOR` or `FXRSTOR`,
//! executed by the kernel on user memory. A user-mode embedder performs the
//! same transfers on byte images:
//!
//! - [`X86_64Vcpu::xsave_image`] yields the bytes `XSAVE` stores in the
//!   standard (non-compacted) format for the requested components, and which
//!   byte ranges the instruction writes (it leaves the others untouched).
//! - [`X86_64Vcpu::xrstor_image`] and [`X86_64Vcpu::fxrstor_image`] load an
//!   image, refusing it exactly where the instruction would raise #GP.
//! - [`X86_64Vcpu::init_user_xstate`] puts every enabled component in its
//!   initial configuration, as an `XRSTOR` of init state does.
//!
//! Layouts and checks follow Intel SDM Vol. 1 §§10.5.1 (`FXSAVE` area),
//! 13.4 (XSAVE area), 13.6 (initial configurations), and 13.8 (`XRSTOR`),
//! and match the instruction implementations in
//! `decode/dispatch/twobyte/{xsave.rs, dispatch/group7.rs}`.

use super::X86_64Vcpu;
use super::execute;
use super::mxcsr_value_is_valid;

/// Size of the legacy (`FXSAVE`) region.
pub const XSAVE_LEGACY_SIZE: usize = 512;
/// Offset of the XSAVE header.
pub const XSAVE_HEADER_OFFSET: usize = 512;
/// Offset of the first extended component.
pub const XSAVE_EXTENDED_OFFSET: usize = 576;

/// Extended components the CPU implements: `(component, standard offset,
/// size)` from CPUID.(EAX=0DH,ECX=i):EBX/EAX.
const EXTENDED: [(u8, usize, usize); 5] = [
    (2, 576, 256),
    (19, 960, 128),
    (5, 1088, 64),
    (6, 1152, 512),
    (7, 1664, 1024),
];

/// A standard-format XSAVE image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XsaveImage {
    /// The image; bytes `XSAVE` does not store are zero.
    pub bytes: Vec<u8>,
    /// Half-open byte ranges `XSAVE` stores, in ascending order.
    pub written: Vec<(usize, usize)>,
}

/// Why an image cannot be loaded: the instruction would raise #GP(0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrstorError {
    /// The image is shorter than the layout its header selects.
    Truncated,
    /// The XSAVE header is invalid for XCR0 (SDM Vol. 1 §13.8.1).
    Header,
    /// The selected MXCSR value sets reserved bits.
    Mxcsr,
}

impl X86_64Vcpu {
    /// Size of the standard-format image for every component enabled in
    /// XCR0: CPUID.(EAX=0DH,ECX=0):EBX.
    pub fn xsave_standard_size(&self) -> usize {
        self.cpuid(0xD, 0).1 as usize
    }

    /// The bytes `XSAVE` (the 64-bit form, `XSAVE64`) stores for the
    /// components in `rfbm & XCR0`, in the standard format. XSTATE_BV
    /// reports every saved component as modified, as the instruction does
    /// when it does not track the init optimization. Per SDM Vol. 1 §13.7,
    /// the only header field `XSAVE` stores is XSTATE_BV; the reserved bytes
    /// of the legacy region (5, the six bytes after each ST register,
    /// 416-511) are not stored either.
    pub fn xsave_image(&self, rfbm: u64) -> XsaveImage {
        let rfbm = rfbm & self.xcr0;
        let mut bytes = vec![0u8; self.xsave_standard_size()];
        let mut written = Vec::new();
        let mut xstate_bv = 0u64;
        if rfbm & 1 != 0 {
            self.put_x87(&mut bytes);
            written.extend([(0, 5), (6, 24)]);
            written.extend((0..8).map(|i| (32 + i * 16, 42 + i * 16)));
            xstate_bv |= 1;
        }
        if rfbm & 2 != 0 {
            self.put_sse(&mut bytes);
            written.extend([(24, 32), (160, 416)]);
            xstate_bv |= 2;
        }
        for (component, offset, size) in EXTENDED {
            if rfbm & (1 << component) != 0 {
                self.put_extended(component, &mut bytes[offset..offset + size]);
                written.push((offset, offset + size));
                xstate_bv |= 1 << component;
            }
        }
        bytes[XSAVE_HEADER_OFFSET..XSAVE_HEADER_OFFSET + 8]
            .copy_from_slice(&xstate_bv.to_le_bytes());
        written.push((XSAVE_HEADER_OFFSET, XSAVE_HEADER_OFFSET + 8));
        written.sort_unstable();
        XsaveImage { bytes, written }
    }

    /// Loads `image` as `XRSTOR` with requested-feature bitmap `rfbm`
    /// would, in the standard or compacted format its header selects.
    /// Components in `rfbm & XCR0` whose XSTATE_BV bit is clear are
    /// initialized. On error nothing is changed.
    pub fn xrstor_image(&mut self, image: &[u8], rfbm: u64) -> Result<(), XrstorError> {
        let rfbm = rfbm & self.xcr0;
        let header = image
            .get(XSAVE_HEADER_OFFSET..XSAVE_EXTENDED_OFFSET)
            .ok_or(XrstorError::Truncated)?;
        let word = |i: usize| u64::from_le_bytes(header[i..i + 8].try_into().unwrap());
        let xstate_bv = word(0);
        let xcomp_bv = word(8);
        let compacted = xcomp_bv & (1 << 63) != 0;
        let format = xcomp_bv & !(1 << 63);
        let malformed = if compacted {
            format & !self.xcr0 != 0 || xstate_bv & !xcomp_bv != 0
        } else {
            xstate_bv & !self.xcr0 != 0 || xcomp_bv != 0
        };
        // Standard XRSTOR checks header bytes 23:8; the compacted form
        // requires bytes 63:16 to be zero as well.
        let reserved = if compacted {
            &header[16..]
        } else {
            &header[16..24]
        };
        if malformed || reserved.iter().any(|&b| b != 0) {
            return Err(XrstorError::Header);
        }
        // Component offsets: fixed in the standard format, packed in
        // XCOMP_BV order in the compacted one (no component requires
        // 64-byte alignment: CPUID.(EAX=0DH,ECX=i):ECX[1] = 0).
        let mut offsets = Vec::new();
        let mut next = XSAVE_EXTENDED_OFFSET;
        let mut ordered = EXTENDED;
        ordered.sort_unstable_by_key(|&(c, _, _)| c);
        for (component, offset, size) in ordered {
            if compacted {
                if format & (1 << component) != 0 {
                    offsets.push((component, next, size));
                    next += size;
                }
            } else {
                offsets.push((component, offset, size));
            }
        }
        let loads = |c: u8| rfbm & (1 << c) != 0 && xstate_bv & (1 << c) != 0;
        for &(component, offset, size) in &offsets {
            if loads(component) && image.len() < offset + size {
                return Err(XrstorError::Truncated);
            }
        }
        // MXCSR (SDM Vol. 1 §13.8.1): the standard form loads it whenever
        // SSE or AVX is requested; the compacted form only for requested
        // SSE state, and uses the init value if XSTATE_BV[1] is clear.
        let mxcsr = if compacted {
            if rfbm & 2 == 0 {
                None
            } else if xstate_bv & 2 == 0 {
                Some(0x1F80)
            } else {
                Some(u32::from_le_bytes(image[24..28].try_into().unwrap()))
            }
        } else if rfbm & 6 != 0 {
            Some(u32::from_le_bytes(image[24..28].try_into().unwrap()))
        } else {
            None
        };
        if mxcsr.is_some_and(|v| !mxcsr_value_is_valid(v)) {
            return Err(XrstorError::Mxcsr);
        }

        if rfbm & 1 != 0 {
            if xstate_bv & 1 != 0 {
                self.get_x87(image);
            } else {
                self.init_component(0);
            }
        }
        if let Some(value) = mxcsr {
            self.mxcsr = value;
        }
        if rfbm & 2 != 0 {
            if xstate_bv & 2 != 0 {
                self.get_xmm(image);
            } else {
                for xmm in &mut self.regs.xmm {
                    *xmm = [0, 0];
                }
            }
        }
        for (component, _, _) in ordered {
            if rfbm & (1 << component) == 0 {
                continue;
            }
            match offsets.iter().find(|&&(c, _, _)| c == component) {
                Some(&(_, offset, size)) if xstate_bv & (1 << component) != 0 => {
                    self.get_extended(component, &image[offset..offset + size]);
                }
                _ => self.init_component(component),
            }
        }
        Ok(())
    }

    /// Loads the 512-byte legacy region as `FXRSTOR64` would: x87 state,
    /// MXCSR, and XMM0-15. On error nothing is changed.
    pub fn fxrstor_image(&mut self, image: &[u8]) -> Result<(), XrstorError> {
        let image = image
            .get(..XSAVE_LEGACY_SIZE)
            .ok_or(XrstorError::Truncated)?;
        let mxcsr = u32::from_le_bytes(image[24..28].try_into().unwrap());
        if !mxcsr_value_is_valid(mxcsr) {
            return Err(XrstorError::Mxcsr);
        }
        self.get_x87(image);
        self.mxcsr = mxcsr;
        self.get_xmm(image);
        Ok(())
    }

    /// Puts every component in `mask & XCR0` in its initial configuration
    /// (SDM Vol. 1 §13.6): FCW = 037FH, FSW = 0, FTW = FFFFH, x87 pointers
    /// and ST0-ST7 zero, MXCSR = 1F80H, and every vector, opmask, and APX
    /// register zero.
    pub fn init_user_xstate(&mut self, mask: u64) {
        let mask = mask & self.xcr0;
        if mask & 1 != 0 {
            self.init_component(0);
        }
        if mask & 2 != 0 {
            self.mxcsr = 0x1F80;
            for xmm in &mut self.regs.xmm {
                *xmm = [0, 0];
            }
        }
        for (component, _, _) in EXTENDED {
            if mask & (1 << component) != 0 {
                self.init_component(component);
            }
        }
    }

    fn init_component(&mut self, component: u8) {
        match component {
            0 => {
                self.fpu.init();
                self.fpu.st = [0.0; 8];
            }
            2 => self.regs.ymm_high = [[0; 2]; 16],
            5 => self.regs.k = [0; 8],
            6 => self.regs.zmm_high = [[0; 4]; 16],
            7 => self.regs.zmm_ext = [[0; 8]; 16],
            19 => {
                for i in 0..16 {
                    self.set_reg(16 + i, 0, 8);
                }
            }
            _ => {}
        }
    }

    /// x87 portion of the legacy region: FCW, FSW, abridged FTW, FOP, FIP,
    /// FDP (64-bit forms), and ST0-ST7 in 80-bit format.
    fn put_x87(&self, b: &mut [u8]) {
        b[0..2].copy_from_slice(&self.fpu.control_word.to_le_bytes());
        b[2..4].copy_from_slice(&self.fpu.status_word.to_le_bytes());
        let mut abridged = 0u8;
        for i in 0..8 {
            if (self.fpu.tag_word >> (i * 2)) & 3 != 3 {
                abridged |= 1 << i;
            }
        }
        b[4] = abridged;
        b[6..8].copy_from_slice(&self.fpu.last_opcode.to_le_bytes());
        b[8..16].copy_from_slice(&self.fpu.instr_ptr.to_le_bytes());
        b[16..24].copy_from_slice(&self.fpu.data_ptr.to_le_bytes());
        for i in 0..8 {
            let at = 32 + i * 16;
            b[at..at + 10].copy_from_slice(&execute::fpu::f64_to_f80_pub(self.fpu.get_st(i as u8)));
        }
    }

    /// SSE portion: MXCSR, MXCSR_MASK, and XMM0-15.
    fn put_sse(&self, b: &mut [u8]) {
        b[24..28].copy_from_slice(&self.mxcsr.to_le_bytes());
        b[28..32].copy_from_slice(&0xFFFFu32.to_le_bytes());
        for (i, xmm) in self.regs.xmm.iter().enumerate() {
            let at = 160 + i * 16;
            b[at..at + 8].copy_from_slice(&xmm[0].to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&xmm[1].to_le_bytes());
        }
    }

    fn put_extended(&self, component: u8, out: &mut [u8]) {
        let mut words: Vec<u64> = Vec::with_capacity(out.len() / 8);
        match component {
            2 => self.regs.ymm_high.iter().for_each(|r| words.extend(r)),
            5 => words.extend(self.regs.k),
            6 => self.regs.zmm_high.iter().for_each(|r| words.extend(r)),
            7 => self.regs.zmm_ext.iter().for_each(|r| words.extend(r)),
            19 => words.extend((0..16).map(|i| self.get_reg(16 + i, 8))),
            _ => unreachable!("EXTENDED lists only implemented components"),
        }
        for (chunk, w) in out.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }

    fn get_x87(&mut self, b: &[u8]) {
        let half = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let quad = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        self.fpu.control_word = half(0);
        self.fpu.status_word = half(2);
        self.fpu.top = ((self.fpu.status_word >> 11) & 7) as u8;
        self.fpu.tag_word = 0;
        for i in 0..8 {
            if b[4] & (1 << i) == 0 {
                self.fpu.tag_word |= 3 << (i * 2);
            }
        }
        self.fpu.last_opcode = half(6);
        self.fpu.instr_ptr = quad(8);
        self.fpu.data_ptr = quad(16);
        for i in 0..8 {
            let at = 32 + i * 16;
            // Stack order; the abridged tag word above says which
            // registers are empty, so set_st (which retags) is not used.
            let idx = self.fpu.st_index(i as u8);
            self.fpu.st[idx] = execute::fpu::f80_to_f64_pub(&b[at..at + 10]);
        }
    }

    fn get_xmm(&mut self, b: &[u8]) {
        for i in 0..16 {
            let at = 160 + i * 16;
            self.regs.xmm[i] = [
                u64::from_le_bytes(b[at..at + 8].try_into().unwrap()),
                u64::from_le_bytes(b[at + 8..at + 16].try_into().unwrap()),
            ];
        }
    }

    fn get_extended(&mut self, component: u8, data: &[u8]) {
        let words: Vec<u64> = data
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        match component {
            2 => {
                for (i, r) in self.regs.ymm_high.iter_mut().enumerate() {
                    r.copy_from_slice(&words[i * 2..i * 2 + 2]);
                }
            }
            5 => self.regs.k.copy_from_slice(&words[..8]),
            6 => {
                for (i, r) in self.regs.zmm_high.iter_mut().enumerate() {
                    r.copy_from_slice(&words[i * 4..i * 4 + 4]);
                }
            }
            7 => {
                for (i, r) in self.regs.zmm_ext.iter_mut().enumerate() {
                    r.copy_from_slice(&words[i * 8..i * 8 + 8]);
                }
            }
            19 => {
                for (i, &w) in words.iter().take(16).enumerate() {
                    self.set_reg(16 + i as u8, w, 8);
                }
            }
            _ => unreachable!("EXTENDED lists only implemented components"),
        }
    }
}
