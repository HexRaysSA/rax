//! Images: the files foreign code comes in.
//!
//! An image here is a static ELF executable for the processor: 64-bit,
//! little-endian, of type `ET_EXEC`, which says for each of its segments
//! where in the processor's memory it belongs. Nothing in it is relocated
//! and nothing is linked to it, so a module that names a byte range of the
//! file names code at one address, whatever process the image is in.

use rax_smir_portable::ir::ForeignIsa;
use sha2::{Digest, Sha256};

use crate::Refusal;

/// The header of the file, of a program header, and what they hold that is
/// read here (System V ABI, "ELF header" and "Program header").
const HEADER_BYTES: usize = 64;
const PROGRAM_BYTES: usize = 56;
const EXECUTABLE: u16 = 2;
const LOAD: u32 = 1;
const MACHINE_X86_64: u16 = 62;
const MACHINE_AARCH64: u16 = 183;

/// What a segment's memory allows, as its header's flags say it.
pub(crate) const MAY_EXECUTE: u32 = 1;
pub(crate) const MAY_WRITE: u32 = 2;
pub(crate) const MAY_READ: u32 = 4;

/// A part of the file that belongs in memory: `in_file` bytes at `offset`
/// of the file are the first of `in_memory` bytes at `address`, the rest of
/// which are zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Segment {
    pub offset: u64,
    pub address: u64,
    pub in_file: u64,
    pub in_memory: u64,
    pub flags: u32,
}

/// An image: its identity, which is the SHA-256 of the file, and its
/// segments in the order of the file's headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Image {
    pub identity: [u8; 32],
    pub segments: Vec<Segment>,
}

fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn long(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

impl Image {
    /// Read the headers of `file`, which must be an image for `isa`.
    pub(crate) fn read(isa: ForeignIsa, file: &[u8]) -> Result<Self, Refusal> {
        if file.len() < HEADER_BYTES || file[..4] != *b"\x7fELF" {
            return Err(Refusal::Format("no ELF file"));
        }
        // The class, the byte order, and the version of the format.
        if file[4..7] != [2, 1, 1] {
            return Err(Refusal::Format("no 64-bit little-endian ELF file"));
        }
        let machine = match isa {
            ForeignIsa::X86_64 => MACHINE_X86_64,
            ForeignIsa::Aarch64 => MACHINE_AARCH64,
        };
        if half(file, 18) != machine {
            return Err(Refusal::Machine);
        }
        if half(file, 16) != EXECUTABLE {
            return Err(Refusal::Format(
                "no static executable: the image would have to be relocated",
            ));
        }
        let (headers_at, each, count) = (
            long(file, 32),
            usize::from(half(file, 54)),
            usize::from(half(file, 56)),
        );
        if count != 0 && each < PROGRAM_BYTES {
            return Err(Refusal::Format("program headers of no known size"));
        }
        let mut segments = Vec::new();
        for index in 0..count {
            let header = usize::try_from(headers_at)
                .ok()
                .and_then(|at| at.checked_add(index * each))
                .and_then(|at| file.get(at..)?.get(..PROGRAM_BYTES))
                .ok_or(Refusal::Format("program headers beyond the file"))?;
            if word(header, 0) != LOAD {
                continue;
            }
            let segment = Segment {
                flags: word(header, 4),
                offset: long(header, 8),
                address: long(header, 16),
                in_file: long(header, 32),
                in_memory: long(header, 40),
            };
            let within = segment
                .offset
                .checked_add(segment.in_file)
                .is_some_and(|end| end <= file.len() as u64);
            if !within || segment.in_file > segment.in_memory {
                return Err(Refusal::Format("a segment beyond the file"));
            }
            if segment.address.checked_add(segment.in_memory).is_none() {
                return Err(Refusal::Format("a segment beyond the address space"));
            }
            if segment.in_memory != 0 {
                segments.push(segment);
            }
        }
        if segments.is_empty() {
            return Err(Refusal::Format("nothing to load"));
        }
        Ok(Self {
            identity: Sha256::digest(file).into(),
            segments,
        })
    }

    /// The address of the code that is `size` bytes at `offset` of the
    /// file: bytes of the file that one segment has in memory, which may be
    /// executed.
    pub(crate) fn code(&self, offset: u64, size: u64) -> Option<u64> {
        let end = offset.checked_add(size)?;
        if size == 0 {
            return None;
        }
        self.segments
            .iter()
            .find(|segment| {
                segment.flags & MAY_EXECUTE != 0
                    && segment.offset <= offset
                    && end <= segment.offset + segment.in_file
            })
            .map(|segment| segment.address + (offset - segment.offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file with one header and the program headers given: for each, its
    /// type, flags, offset, address, and sizes in the file and in memory.
    fn file(machine: u16, kind: u16, programs: &[(u32, u32, u64, u64, u64, u64)]) -> Vec<u8> {
        let mut bytes = vec![0; HEADER_BYTES];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&kind.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[32..40].copy_from_slice(&(HEADER_BYTES as u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PROGRAM_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(programs.len() as u16).to_le_bytes());
        for (kind, flags, offset, address, in_file, in_memory) in programs {
            bytes.extend(kind.to_le_bytes());
            bytes.extend(flags.to_le_bytes());
            bytes.extend(offset.to_le_bytes());
            bytes.extend(address.to_le_bytes());
            bytes.extend(address.to_le_bytes());
            bytes.extend(in_file.to_le_bytes());
            bytes.extend(in_memory.to_le_bytes());
            bytes.extend(4096_u64.to_le_bytes());
        }
        bytes.resize(0x400, 0xCC);
        bytes
    }

    #[test]
    fn code_is_named_by_where_it_is_in_the_file() {
        let bytes = file(
            MACHINE_X86_64,
            EXECUTABLE,
            &[
                (LOAD, MAY_READ, 0, 0x20_0000, 0x200, 0x200),
                (6, MAY_READ, 0x40, 0x20_0040, 0x70, 0x70),
                (LOAD, MAY_READ | MAY_EXECUTE, 0x200, 0x20_1200, 0x100, 0x100),
                (LOAD, MAY_READ | MAY_WRITE, 0x300, 0x20_2300, 0x10, 0x1000),
            ],
        );
        let image = Image::read(ForeignIsa::X86_64, &bytes).unwrap();
        assert_eq!(image.identity, <[u8; 32]>::from(Sha256::digest(&bytes)));
        assert_eq!(image.segments.len(), 3);
        // Bytes of the segment that may be executed, and no others: not what
        // only lies in the file, not data, not a range that leaves the
        // segment, and not nothing.
        assert_eq!(image.code(0x200, 0x100), Some(0x20_1200));
        assert_eq!(image.code(0x2F0, 0x10), Some(0x20_12F0));
        assert_eq!(image.code(0x2F0, 0x11), None);
        assert_eq!(image.code(0x100, 0x10), None);
        assert_eq!(image.code(0x300, 0x10), None);
        assert_eq!(image.code(0x200, 0), None);
        assert_eq!(image.code(u64::MAX, 2), None);
    }

    #[test]
    fn what_is_no_image_for_the_processor_is_refused() {
        let load = (LOAD, MAY_READ | MAY_EXECUTE, 0x200, 0x20_1200, 0x100, 0x100);
        let refused = |isa, bytes: &[u8]| Image::read(isa, bytes).unwrap_err();
        assert_eq!(
            refused(ForeignIsa::X86_64, b"#!/bin/sh\n"),
            Refusal::Format("no ELF file")
        );
        let good = file(MACHINE_AARCH64, EXECUTABLE, &[load]);
        assert!(Image::read(ForeignIsa::Aarch64, &good).is_ok());
        assert_eq!(refused(ForeignIsa::X86_64, &good), Refusal::Machine);
        // A 32-bit file; one that is position-independent; one with no
        // segment; segments that are not all in the file.
        let mut narrow = good.clone();
        narrow[4] = 1;
        assert!(matches!(
            refused(ForeignIsa::Aarch64, &narrow),
            Refusal::Format(_)
        ));
        let shared = file(MACHINE_AARCH64, 3, &[load]);
        assert_eq!(
            refused(ForeignIsa::Aarch64, &shared),
            Refusal::Format("no static executable: the image would have to be relocated")
        );
        let empty = file(MACHINE_AARCH64, EXECUTABLE, &[]);
        assert_eq!(
            refused(ForeignIsa::Aarch64, &empty),
            Refusal::Format("nothing to load")
        );
        for beyond in [
            (LOAD, MAY_READ, 0x3F0, 0x20_0000, 0x11, 0x11),
            (LOAD, MAY_READ, u64::MAX, 0x20_0000, 2, 2),
            (LOAD, MAY_READ, 0x200, 0x20_0000, 0x20, 0x10),
        ] {
            let bytes = file(MACHINE_AARCH64, EXECUTABLE, &[beyond]);
            assert_eq!(
                refused(ForeignIsa::Aarch64, &bytes),
                Refusal::Format("a segment beyond the file")
            );
        }
        let mut cut = good.clone();
        cut.truncate(HEADER_BYTES + 8);
        assert_eq!(
            refused(ForeignIsa::Aarch64, &cut),
            Refusal::Format("program headers beyond the file")
        );
    }
}
