//! Shared bare-metal reset witness assembled from vmm_startup.S with LLVM 23.
pub const COUNT_WORD: usize = 9;
pub const WAIT_WORD: usize = 10;
const WORDS: &[u32] = &[
    0xf14022f3, 0x0aa29c63, 0x00010d93, 0x00128313, 0x00030f93, 0x10001437, 0x00341413, 0x00100393,
    0x0674202f, 0x00400813, 0x00000793, 0x00078c63, 0x100014b7, 0x00349493, 0x20048493, 0x0004ae03,
    0xfe0e0ee3, 0x00100e93, 0x10040413, 0x07d4202f, 0x06029263, 0x00010f37, 0x00042e03, 0x010e0863,
    0xffff0f13, 0xfe0f1ae3, 0x0540006f, 0x0230000f, 0x00080f13, 0x100005b7, 0x05200313, 0x00658023,
    0x05600313, 0x00658023, 0x03080313, 0x00658023, 0x00a00313, 0x00658023, 0x001005b7, 0x00005337,
    0x55530313, 0x0065a023, 0x05d00893, 0x00000513, 0x00000073, 0x10500073, 0xffdff06f, 0x00001fb7,
    0xbadf8f93, 0x05d00893, 0x00100513, 0x00000073, 0xfedff06f,
];
pub fn program(count: u8, wait: bool) -> Vec<u8> {
    let mut words = WORDS.to_vec();
    words[COUNT_WORD] = u32::from(count) << 20 | 16 << 7 | 0x13;
    words[WAIT_WORD] = u32::from(wait) << 20 | 15 << 7 | 0x13;
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}
pub fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
pub fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
pub fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
pub fn elf(code: &[u8], entry: u64, load: u64) -> Vec<u8> {
    let mut bytes = vec![0; 4096 + code.len()];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 243);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, entry);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 1);
    put16(&mut bytes, 58, 64);
    put32(&mut bytes, 64, 1);
    put32(&mut bytes, 68, 7);
    put64(&mut bytes, 72, 4096);
    put64(&mut bytes, 80, load);
    put64(&mut bytes, 88, load);
    put64(&mut bytes, 96, code.len() as u64);
    put64(&mut bytes, 104, code.len() as u64);
    put64(&mut bytes, 112, 4096);
    bytes[4096..].copy_from_slice(code);
    bytes
}
