//! Special and user register numbers, PS fields and exception causes.

/// Special register numbers (`RSR`/`WSR`/`XSR` operand).
pub mod sr {
    pub const LBEG: usize = 0;
    pub const LEND: usize = 1;
    pub const LCOUNT: usize = 2;
    pub const SAR: usize = 3;
    pub const BR: usize = 4;
    pub const LITBASE: usize = 5;
    pub const SCOMPARE1: usize = 12;
    pub const ACCLO: usize = 16;
    pub const ACCHI: usize = 17;
    pub const M0: usize = 32;
    pub const WINDOWBASE: usize = 72;
    pub const WINDOWSTART: usize = 73;
    pub const MMID: usize = 89;
    pub const ERACCESS: usize = 95;
    pub const IBREAKENABLE: usize = 96;
    pub const MEMCTL: usize = 97;
    pub const ATOMCTL: usize = 99;
    pub const DDR: usize = 104;
    pub const IBREAKA0: usize = 128;
    pub const DBREAKA0: usize = 144;
    pub const DBREAKC0: usize = 160;
    pub const CONFIGID0: usize = 176;
    pub const EPC1: usize = 177;
    pub const DEPC: usize = 192;
    pub const EPS2: usize = 194;
    pub const CONFIGID1: usize = 208;
    pub const EXCSAVE1: usize = 209;
    pub const CPENABLE: usize = 224;
    pub const INTERRUPT: usize = 226;
    pub const INTCLEAR: usize = 227;
    pub const INTENABLE: usize = 228;
    pub const PS: usize = 230;
    pub const VECBASE: usize = 231;
    pub const EXCCAUSE: usize = 232;
    pub const DEBUGCAUSE: usize = 233;
    pub const CCOUNT: usize = 234;
    pub const PRID: usize = 235;
    pub const ICOUNT: usize = 236;
    pub const ICOUNTLEVEL: usize = 237;
    pub const EXCVADDR: usize = 238;
    pub const CCOMPARE0: usize = 240;
    pub const MISC0: usize = 244;
}

/// User register numbers (`RUR`/`WUR` operand).
pub mod ur {
    pub const ACCX_0: usize = 0;
    pub const ACCX_1: usize = 1;
    pub const QACC_H_0: usize = 2;
    pub const QACC_L_4: usize = 11;
    pub const GPIO_OUT: usize = 12;
    pub const SAR_BYTE: usize = 13;
    pub const FFT_BIT_WIDTH: usize = 14;
    pub const UA_STATE_0: usize = 15;
    pub const UA_STATE_3: usize = 18;
    pub const THREADPTR: usize = 231;
    pub const FCR: usize = 232;
    pub const FSR: usize = 233;
}

/// PS register fields.
pub mod ps {
    pub const INTLEVEL: u32 = 0xf;
    pub const EXCM: u32 = 1 << 4;
    pub const UM: u32 = 1 << 5;
    pub const RING: u32 = 3 << 6;
    pub const OWB_SHIFT: u32 = 8;
    pub const OWB: u32 = 0xf << OWB_SHIFT;
    pub const CALLINC_SHIFT: u32 = 16;
    pub const CALLINC: u32 = 3 << CALLINC_SHIFT;
    pub const WOE: u32 = 1 << 18;
    /// Bits that exist in PS.
    pub const MASK: u32 = INTLEVEL | EXCM | UM | RING | OWB | CALLINC | WOE;
}

/// EXCCAUSE values.
pub mod cause {
    pub const ILLEGAL_INSTRUCTION: u32 = 0;
    pub const SYSCALL: u32 = 1;
    pub const INSTRUCTION_FETCH_ERROR: u32 = 2;
    pub const LOAD_STORE_ERROR: u32 = 3;
    pub const LEVEL1_INTERRUPT: u32 = 4;
    pub const ALLOCA: u32 = 5;
    pub const INTEGER_DIVIDE_BY_ZERO: u32 = 6;
    pub const PRIVILEGED: u32 = 8;
    pub const LOAD_STORE_ALIGNMENT: u32 = 9;
    pub const COPROCESSOR0_DISABLED: u32 = 32;
}
