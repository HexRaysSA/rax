//! MAC16 option: 16x16 multiplies into the 40-bit accumulator, with the M0..M3
//! operand registers and their loads.
//!
//! Every MAC16 opcode is described by its mnemonic (`mula.da.hl.ldinc`): the
//! accumulator operation, where each operand comes from (`a`: AR, `d`: M), which
//! half of each is used, and an optional load into an M register.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acc {
    Set,
    Add,
    Sub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Src {
    A,
    M,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Load {
    None,
    Inc,
    Dec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mac16 {
    /// None for the plain loads (`ldinc`, `lddec`).
    pub acc: Option<Acc>,
    pub unsigned: bool,
    pub src1: Src,
    pub src2: Src,
    pub hi1: bool,
    pub hi2: bool,
    pub load: Load,
}

/// The MAC16 description of a mnemonic, if it is a MAC16 opcode.
pub fn parse(mnemonic: &str) -> Option<Mac16> {
    let plain_load = |load| Mac16 {
        acc: None,
        unsigned: false,
        src1: Src::A,
        src2: Src::A,
        hi1: false,
        hi2: false,
        load,
    };
    match mnemonic {
        "ldinc" => return Some(plain_load(Load::Inc)),
        "lddec" => return Some(plain_load(Load::Dec)),
        _ => {}
    }
    let mut parts = mnemonic.split('.');
    let (acc, unsigned) = match parts.next()? {
        "mul" => (Acc::Set, false),
        "umul" => (Acc::Set, true),
        "mula" => (Acc::Add, false),
        "muls" => (Acc::Sub, false),
        _ => return None,
    };
    let srcs = parts.next()?.as_bytes();
    let halves = parts.next()?.as_bytes();
    if srcs.len() != 2 || halves.len() != 2 {
        return None;
    }
    let src = |c: u8| match c {
        b'a' => Some(Src::A),
        b'd' => Some(Src::M),
        _ => None,
    };
    let half = |c: u8| match c {
        b'h' => Some(true),
        b'l' => Some(false),
        _ => None,
    };
    let load = match parts.next() {
        None => Load::None,
        Some("ldinc") => Load::Inc,
        Some("lddec") => Load::Dec,
        Some(_) => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some(Mac16 {
        acc: Some(acc),
        unsigned,
        src1: src(srcs[0])?,
        src2: src(srcs[1])?,
        hi1: half(halves[0])?,
        hi2: half(halves[1])?,
        load,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::xtensa::generated::opcodes::MNEMONICS;

    #[test]
    fn every_mac16_mnemonic_parses() {
        let mac: Vec<_> = MNEMONICS
            .iter()
            .filter(|m| {
                (m.starts_with("mul.") && **m != "mul.s")
                    || m.starts_with("umul.")
                    || m.starts_with("mula.")
                    || m.starts_with("muls.")
                    || **m == "ldinc"
                    || **m == "lddec"
            })
            .collect();
        assert_eq!(mac.len(), 70);
        for m in mac {
            assert!(parse(m).is_some(), "{m}");
        }
        let d = parse("mula.da.hl.ldinc").unwrap();
        assert_eq!(d.acc, Some(Acc::Add));
        assert_eq!(
            (d.src1, d.src2, d.hi1, d.hi2, d.load),
            (Src::M, Src::A, true, false, Load::Inc)
        );
    }
}
