//! Core configuration: the options and constants that differ between Xtensa cores.

/// Interrupt types of the interrupt option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntType {
    ExternLevel,
    ExternEdge,
    Timer,
    Software,
    Nmi,
    Profiling,
}

/// The configuration of an Xtensa core with the windowed register, interrupt,
/// high-priority interrupt, timer and exception (XEA2) options.
#[derive(Clone, Debug)]
pub struct XtensaConfig {
    pub name: &'static str,
    /// Physical AR registers (multiple of 16, at most 64).
    pub nareg: usize,
    pub reset_vector: u32,
    pub vecbase_reset: u32,
    pub user_vecofs: u32,
    pub kernel_vecofs: u32,
    pub double_vecofs: u32,
    /// Window overflow/underflow vectors: OF4, UF4, OF8, UF8, OF12, UF12.
    pub window_vecofs: [u32; 6],
    /// Vector offset of interrupt levels 2..=7 (index = level).
    pub level_vecofs: [u32; 8],
    pub excm_level: u32,
    /// Highest maskable level.
    pub nlevel: u32,
    pub nmi_level: u32,
    pub int_level: [u8; 32],
    pub int_type: [IntType; 32],
    /// The interrupt raised by each CCOMPARE register.
    pub timer_int: [u8; 3],
    pub atomctl_reset: u32,
    pub memctl_reset: u32,
    pub cpenable_reset: u32,
    pub configid0: u32,
    pub configid1: u32,
}

impl XtensaConfig {
    /// The LX7 cores of the ESP32-S3.
    pub fn esp32s3() -> Self {
        use IntType::*;
        const LEVEL: [u8; 32] = [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 1, 7, 3, 5, 1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 3, 4,
            3, 4, 5,
        ];
        let mut int_type = [ExternLevel; 32];
        for i in [10, 22, 28, 30] {
            int_type[i] = ExternEdge;
        }
        for i in [6, 15, 16] {
            int_type[i] = Timer;
        }
        for i in [7, 29] {
            int_type[i] = Software;
        }
        int_type[11] = Profiling;
        int_type[14] = Nmi;
        XtensaConfig {
            name: "esp32s3",
            nareg: 64,
            reset_vector: 0x4000_0400,
            vecbase_reset: 0x4000_0000,
            user_vecofs: 0x340,
            kernel_vecofs: 0x300,
            double_vecofs: 0x3c0,
            window_vecofs: [0x000, 0x040, 0x080, 0x0c0, 0x100, 0x140],
            level_vecofs: [0, 0, 0x180, 0x1c0, 0x200, 0x240, 0x280, 0x2c0],
            excm_level: 3,
            nlevel: 6,
            nmi_level: 7,
            int_level: LEVEL,
            int_type,
            timer_int: [6, 15, 16],
            atomctl_reset: 0x28,
            memctl_reset: 1,
            cpenable_reset: 0xff,
            configid0: 0xc2f0_fffe,
            configid1: 0x2309_0f1f,
        }
    }

    /// Mask of the interrupts of the given type.
    pub fn type_mask(&self, ty: IntType) -> u32 {
        (0..32)
            .filter(|&i| self.int_type[i] == ty)
            .fold(0, |m, i| m | (1 << i))
    }

    /// Mask of the interrupts at the given level.
    pub fn level_mask(&self, level: u32) -> u32 {
        (0..32)
            .filter(|&i| u32::from(self.int_level[i]) == level)
            .fold(0, |m, i| m | (1 << i))
    }
}
