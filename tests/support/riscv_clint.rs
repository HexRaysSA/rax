//! LLVM-assembled bytes from tests/fixtures/riscv/vmm_clint.S.
pub fn program(count: u8, wait: bool) -> Vec<u8> {
    let mut words = [
        0xf14024f3u32,
        0x00000297u32,
        0x0ec28293u32,
        0x30529073u32,
        0x08800293u32,
        0x30429073u32,
        0x00349293u32,
        0x02004337u32,
        0x006282b3u32,
        0x0002b023u32,
        0x10001437u32,
        0x00341413u32,
        0x00100293u32,
        0x0654202fu32,
        0x00400913u32,
        0x00000793u32,
        0x02049e63u32,
        0x00010737u32,
        0x00042283u32,
        0x01228863u32,
        0xfff70713u32,
        0xfe071ae3u32,
        0x0fc0006fu32,
        0x00000293u32,
        0x02000337u32,
        0x00100393u32,
        0x00732023u32,
        0x00430313u32,
        0x00128293u32,
        0xff22cae3u32,
        0x00742423u32,
        0x00078663u32,
        0x00442283u32,
        0xfe028ce3u32,
        0x00800293u32,
        0x3002a073u32,
        0x04049c63u32,
        0x00010737u32,
        0x00000293u32,
        0x10001337u32,
        0x00331313u32,
        0x10030313u32,
        0x00032383u32,
        0x00300693u32,
        0x02d39663u32,
        0x00430313u32,
        0x00128293u32,
        0xff22c6e3u32,
        0x001005b7u32,
        0x00005337u32,
        0x55530313u32,
        0x0065a023u32,
        0x05d00893u32,
        0x00000513u32,
        0x00000073u32,
        0xfff70713u32,
        0xfa071ce3u32,
        0x0700006fu32,
        0x10500073u32,
        0xffdff06fu32,
        0x34202e73u32,
        0x7ffe7e13u32,
        0x00300e93u32,
        0x03de0463u32,
        0x00700e93u32,
        0x05de1863u32,
        0x00349f13u32,
        0x02004eb7u32,
        0x01df0f33u32,
        0xfff00f93u32,
        0x01ff3023u32,
        0x00200f93u32,
        0x0180006fu32,
        0x00249f13u32,
        0x02000eb7u32,
        0x01df0f33u32,
        0x000f2023u32,
        0x00100f93u32,
        0x00249f13u32,
        0x10001eb7u32,
        0x003e9e93u32,
        0x100e8e93u32,
        0x01df0f33u32,
        0x47ff202fu32,
        0x30200073u32,
        0x05d00893u32,
        0x00100513u32,
        0x00000073u32,
        0xff5ff06fu32,
    ];
    words[14] = (u32::from(count) << 20) | (18 << 7) | 0x13;
    words[15] = (u32::from(wait) << 20) | (15 << 7) | 0x13;
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// LLVM-assembled future prefix plus the common guest with its zero-deadline
/// store replaced by NOP, exactly as CLINT_TIMER_PRESET selects in assembly.
pub fn future_program(count: u8, wait: bool) -> Vec<u8> {
    let mut body = program(count, wait);
    assert_eq!(&body[36..40], &0x0002b023u32.to_le_bytes());
    body[36..40].copy_from_slice(&0x00000013u32.to_le_bytes());
    let prefix = [
        0xf1402e73u32,
        0x003e1e13,
        0x02004eb7,
        0x01de0e33,
        0xc0102ef3,
        0x040e8e93,
        0x01de3023,
    ];
    let mut code = prefix
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    code.extend(body);
    code
}
