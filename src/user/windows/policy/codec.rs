//! Software-policy block encoding recovered from the installed client/server.
//!
//! Each 64-bit block has two big-endian 32-bit words. Thirty-two descriptor
//! rounds and eleven direction-specific rounds update alternating words.
//! Arithmetic wraps at 32 bits; the four 16-bit key parts are little-endian.

use std::num::Wrapping;

type Word = Wrapping<u32>;

#[derive(Clone, Copy)]
pub(super) enum Direction {
    Request,
    Reply,
}

struct Key {
    halves: [Word; 4],
    words: [Word; 2],
}

impl Key {
    fn new(value: u64) -> Self {
        Self {
            halves: [0, 16, 32, 48].map(|shift| Wrapping((value >> shift) as u16 as u32)),
            words: [Wrapping(value as u32), Wrapping((value >> 32) as u32)],
        }
    }
}

fn right(value: Word, count: u32) -> Word {
    Wrapping(value.0.rotate_right(count))
}

fn left(value: Word, count: u32) -> Word {
    Wrapping(value.0.rotate_left(count))
}

fn variable(selector: u8, index: usize, args: &[u8], key: &Key, x: Word) -> Word {
    let [a, b, c] = [args[0], args[1], args[2]].map(u32::from);
    let k = key.halves[index % 4];
    let j = key.halves[(index % 4 + a as usize % 3 + 1) % 4];
    let w = key.words[((index >> 1) + 1) % 2];
    let (s15, s7, s31, t15, t31) = (b % 15 + 1, b % 7 + 1, b % 31 + 1, c % 15 + 1, c % 31 + 1);
    match selector {
        0 => k * (x ^ j) + (x >> s15 as usize),
        1 => k * (x - j) - (x >> s15 as usize),
        2 => k * (x ^ j) ^ (x >> s15 as usize),
        3 => k * (x ^ j) + right(x, s15),
        4 => k * (x ^ j) - right(x, s15),
        5 => k * (x ^ j) ^ right(x, s15),
        6 => k * left(x ^ j, s7) + (x >> t15 as usize),
        7 => k * left(x ^ w, s7) - (x >> t15 as usize),
        8 => k * left(x - j, s7) ^ (x >> t15 as usize),
        9 => k * left(x ^ j, s7) + right(x, t31),
        10 => k * left(x ^ j, s7) - right(x, t31),
        11 => k * left(x ^ j, s7) ^ right(x, t31),
        12 => k * right(x + w, s31) + right(x, t31),
        13 => k * right(w - x, s31) + right(x, t31),
        14 => k * right(x ^ w, s31) + right(x, t31),
        15 => k * right(x + w, s31) - right(x, t31),
        16 => k * right(w - x, s31) - right(x, t31),
        17 => k * right(x ^ w, s31) - right(x, t31),
        // The native selector table intentionally aliases entries 18 and 23.
        18 | 23 => k * right(x - w, s31) ^ right(x, t31),
        19 => k * right(w - x, s31) ^ right(x, t31),
        20 => k * right(x ^ w, s31) ^ right(x, t31),
        21 => k * right(x - w, s31) + right(x, t31),
        22 => k * right(x - w, s31) - right(x, t31),
        24..=26 => {
            let other = key.halves[(index % 4 + b as usize % 3 + 1) % 4];
            let shifted = right(if selector == 24 { !x } else { x }, a % 15 + 1);
            other
                * match selector {
                    24 => shifted + k,
                    25 => shifted - k,
                    _ => shifted ^ k,
                }
        }
        27 => key.words[(index + 1) % 2] - (x ^ key.words[index % 2]),
        28 => x ^ key.words[0] ^ key.words[1],
        29 => (x - k) ^ w,
        30 => x - w - k,
        // A descriptor byte >=31 disables that round, including 0xff.
        _ => Wrapping(0),
    }
}

fn fixed(direction: Direction, index: usize, key: &Key, x: Word) -> Word {
    let [k0, k1, k2, k3] = key.halves;
    let [low, high] = key.words;
    match (direction, index) {
        (Direction::Request, 0) => k0 * left(x - k2, 3) ^ (x >> 15),
        (Direction::Request, 1) => k1 * (x - k2) - (x >> 13),
        (Direction::Request, 2) => k2 * right(low - x, 9) ^ right(x, 11),
        (Direction::Request, 3) => x - low - k3,
        (Direction::Request, 4) => k0 * (x ^ k1) - right(x, 7),
        (Direction::Request, 5) => k1 * left(x ^ k3, 4) - right(x, 16),
        (Direction::Request, 6) => k2 * right(low - x, 10) + right(x, 4),
        (Direction::Request, 7) => k3 * right(x - low, 4) ^ right(x, 9),
        (Direction::Request, 8) => k0 * left(x ^ high, 8) - left(x, 2),
        (Direction::Request, 9) => k1 * right(high - x, 11) - right(x, 12),
        (Direction::Request, 10) => k2 * (x ^ k1) ^ (x >> 8),
        (Direction::Reply, 0) => k3 * (right(!x, 5) + k0),
        (Direction::Reply, 1) => k1 * (x ^ k3) ^ (x >> 10),
        (Direction::Reply, 2) => k2 * right(x ^ low, 12) ^ right(x, 10),
        (Direction::Reply, 3) => k3 * right(x - low, 14) - left(x, 8),
        (Direction::Reply, 4) => k0 * right(x + high, 15) + left(x, 2),
        (Direction::Reply, 5) => k1 * (x ^ k2) ^ right(x, 6),
        (Direction::Reply, 6) => high - (x ^ low),
        (Direction::Reply, 7) => k3 * left(x ^ k1, 6) - left(x, 2),
        (Direction::Reply, 8) => k0 * (x - k2) - (x >> 13),
        (Direction::Reply, 9) => k1 * right(x + high, 9) - left(x, 2),
        (Direction::Reply, 10) => k2 * left(x - low, 5) + right(x, 22),
        _ => unreachable!("fixed policy round index is bounded to eleven rounds"),
    }
}

/// Transform aligned blocks. Callers bound allocation before reaching the codec.
pub(super) fn transform(
    bytes: &[u8],
    context: &[u8; 160],
    key: u64,
    direction: Direction,
    decrypt: bool,
) -> Option<Vec<u8>> {
    if bytes.len() % 8 != 0 {
        return None;
    }
    let key = Key::new(key);
    let mut result = Vec::with_capacity(bytes.len());
    let (mut previous_plain, mut previous_cipher) =
        ([Wrapping(0); 2], [Wrapping(0), Wrapping(u32::MAX)]);
    for block in bytes.chunks_exact(8) {
        let first = Wrapping(u32::from_be_bytes(block[..4].try_into().ok()?));
        let second = Wrapping(u32::from_be_bytes(block[4..].try_into().ok()?));
        let (mut a, mut b) = if decrypt {
            let a = first ^ previous_plain[0];
            (
                a,
                second ^ previous_plain[1] ^ a ^ key.words[0] ^ key.words[1],
            )
        } else {
            (first ^ previous_cipher[0], second ^ previous_cipher[1])
        };
        for step in 0..43 {
            let round = if decrypt { 42 - step } else { step };
            let index = if round < 32 { round } else { round - 32 };
            let input = if index % 2 == 0 { b } else { a };
            let value = if round < 32 {
                variable(
                    context[128 + index],
                    index,
                    &context[4 * index..4 * index + 4],
                    &key,
                    input,
                )
            } else {
                fixed(direction, index, &key, input)
            };
            if index % 2 == 0 {
                a ^= value;
            } else {
                b ^= value;
            }
        }
        let (plain, cipher) = if decrypt {
            (
                [a ^ previous_cipher[0], b ^ previous_cipher[1]],
                [first, second],
            )
        } else {
            (
                [first, second],
                [
                    a ^ previous_plain[0],
                    b ^ a ^ key.words[0] ^ key.words[1] ^ previous_plain[1],
                ],
            )
        };
        for value in if decrypt { plain } else { cipher } {
            result.extend_from_slice(&value.0.to_be_bytes());
        }
        previous_plain = plain;
        previous_cipher = cipher;
    }
    Some(result)
}
