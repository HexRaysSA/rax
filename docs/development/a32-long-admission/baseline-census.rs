use rax::isa::arm::decoder::{Aarch32Decoder, Mnemonic, ThumbDecoder};
fn main() {
    let mut cases = 0u64;
    let mut mismatches = 0u64;
    let mut legal = 0u64;
    for (base, mnemonic) in [
        (0xf280_0e00u32, Mnemonic::VMULL),
        (0xf290_0900, Mnemonic::VQDMLAL),
        (0xf290_0b00, Mnemonic::VQDMLSL),
        (0xf290_0d00, Mnemonic::VQDMULL),
        (0xf2a0_0900, Mnemonic::VQDMLAL),
        (0xf2a0_0b00, Mnemonic::VQDMLSL),
        (0xf2a0_0d00, Mnemonic::VQDMULL),
    ] {
        for thumb in [false, true] {
            for u in 0..2 {
                for d in 0..32 {
                    for n in 0..32 {
                        for m in 0..32 {
                            let raw = base
                                | (u << 24)
                                | ((d >> 4) << 22)
                                | ((d & 15) << 12)
                                | ((n >> 4) << 7)
                                | ((n & 15) << 16)
                                | ((m >> 4) << 5)
                                | (m & 15);
                            let raw = if thumb {
                                (raw & 0x00ff_ffff) | 0xef00_0000 | (u << 28)
                            } else {
                                raw
                            };
                            let decoded = if thumb {
                                ThumbDecoder::decode_32bit(raw).unwrap()
                            } else {
                                Aarch32Decoder::decode(raw).unwrap()
                            };
                            let valid = u == 0 && d & 1 == 0;
                            let expected = if valid { mnemonic } else { Mnemonic::UNDEFINED };
                            cases += 1;
                            if valid {
                                legal += 1;
                            }
                            if decoded.mnemonic != expected {
                                mismatches += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    println!("{{\"cases\":{cases},\"legal_expected\":{legal},\"mismatches\":{mismatches}}}");
}
