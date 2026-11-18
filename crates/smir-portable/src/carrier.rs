//! Native files that carry a portable payload: finding the payload in an
//! ELF, Mach-O or PE file, and wrapping one in such a file.
//!
//! A carrier has one locator, 64 bytes that say where in the file the
//! payload is, how long it is and what its SHA-256 is. Where the locator
//! itself is, is fixed for each format: an ELF note, the start of a Mach-O
//! section, the start of a PE section. Nothing is found by searching the
//! file for a magic number, and nothing here maps or runs any of the file.
//!
//! Finding a payload says nothing about what it is: the bytes go on to
//! framing, verification and admission like any others.

use sha2::{Digest, Sha256};

use crate::{Error, ErrorClass};

/// Size of a locator.
pub const LOCATOR_BYTES: usize = 64;
const MAGIC: &[u8; 8] = b"RAXSMIR\0";
/// Most program headers, load commands or sections looked at.
const MAX_ENTRIES: u64 = 4096;

/// A native file format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// ELF, 64-bit little-endian.
    Elf,
    /// Mach-O, 64-bit little-endian, one architecture.
    MachO,
    /// PE32+.
    Pe,
}

/// The machine a carrier's native code is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine {
    X86_64,
    Aarch64,
}

/// A payload found in a carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found<'file> {
    pub carrier: Carrier,
    pub machine: Machine,
    /// The payload's bytes, which are `length` bytes of the file at `offset`.
    pub payload: &'file [u8],
    pub offset: u64,
    /// The payload's SHA-256, which the locator gave and the bytes have.
    pub sha256: [u8; 32],
}

fn refused(code: &'static str) -> Error {
    Error::new(ErrorClass::Framing, code, String::new())
}

fn require(condition: bool, code: &'static str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(refused(code))
    }
}

/// A file, read with every range checked.
struct Reader<'file>(&'file [u8]);

impl<'file> Reader<'file> {
    fn take(&self, offset: u64, size: u64) -> Result<&'file [u8], Error> {
        let length = self.0.len() as u64;
        require(
            offset <= length && size <= length - offset,
            "CARRIER_BOUNDS",
        )?;
        Ok(&self.0[offset as usize..(offset + size) as usize])
    }

    fn integer(&self, offset: u64, width: u64) -> Result<u64, Error> {
        let mut bytes = [0_u8; 8];
        bytes[..width as usize].copy_from_slice(self.take(offset, width)?);
        Ok(u64::from_le_bytes(bytes))
    }
}

/// Where the locators of a file are, and the parts of the file the native
/// loader would map: each from, to, and whether only for reading.
#[derive(Default)]
struct Layout {
    locators: Vec<u64>,
    regions: Vec<(u64, u64, bool)>,
}

fn sum(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right)
        .ok_or_else(|| refused("CARRIER_BOUNDS"))
}

fn elf(reader: &Reader) -> Result<(Machine, Layout), Error> {
    require(reader.take(0, 7)? == b"\x7fELF\x02\x01\x01", "ELF_PROFILE")?;
    let machine = match (reader.integer(16, 2)?, reader.integer(18, 2)?) {
        (2 | 3, 62) => Machine::X86_64,
        (2 | 3, 183) => Machine::Aarch64,
        _ => return Err(refused("ELF_MACHINE")),
    };
    require(
        reader.integer(52, 2)? == 64 && reader.integer(54, 2)? == 56,
        "ELF_HEADER",
    )?;
    let count = reader.integer(56, 2)?;
    require(count != 0xffff && count <= MAX_ENTRIES, "ELF_HEADER_COUNT")?;
    let table = reader.integer(32, 8)?;
    reader.take(table, count * 56)?;
    let mut layout = Layout::default();
    for index in 0..count {
        let at = table + index * 56;
        let kind = reader.integer(at, 4)?;
        let flags = reader.integer(at + 4, 4)?;
        let start = reader.integer(at + 8, 8)?;
        let size = reader.integer(at + 32, 8)?;
        reader.take(start, size)?;
        let end = start + size;
        if kind == 1 {
            layout.regions.push((start, end, flags == 4));
        }
        if kind != 4 {
            continue;
        }
        require(flags == 4, "CARRIER_PERMISSIONS")?;
        let mut cursor = start;
        while cursor < end {
            require(end - cursor >= 12, "ELF_NOTE_HEADER")?;
            let name_size = reader.integer(cursor, 4)?;
            let descriptor_size = reader.integer(cursor + 4, 4)?;
            let note_type = reader.integer(cursor + 8, 4)?;
            let name_at = cursor + 12;
            let descriptor_at = (name_at + name_size + 3) & !3;
            let next = (descriptor_at + descriptor_size + 3) & !3;
            require(next <= end, "ELF_NOTE_BOUNDS")?;
            let name = reader.take(name_at, name_size)?;
            let padded = |from: u64, to: u64| -> Result<bool, Error> {
                Ok(reader.take(from, to - from)?.iter().all(|byte| *byte == 0))
            };
            require(
                padded(name_at + name_size, descriptor_at)?
                    && padded(descriptor_at + descriptor_size, next)?,
                "ELF_NOTE_PADDING",
            )?;
            if name == MAGIC {
                require(
                    note_type == 1 && descriptor_size == LOCATOR_BYTES as u64,
                    "ELF_NOTE_TYPE",
                )?;
                layout.locators.push(descriptor_at);
            }
            cursor = next;
        }
    }
    Ok((machine, layout))
}

/// A name of sixteen bytes, without the zeros that fill it.
fn name16<'file>(reader: &Reader<'file>, at: u64) -> Result<&'file [u8], Error> {
    let bytes = reader.take(at, 16)?;
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    Ok(&bytes[..end])
}

fn macho(reader: &Reader) -> Result<(Machine, Layout), Error> {
    require(reader.integer(0, 4)? == 0xfeed_facf, "MACHO_PROFILE")?;
    let machine = match (reader.integer(4, 4)?, reader.integer(12, 4)?) {
        (0x0100_0007, 2 | 6) => Machine::X86_64,
        (0x0100_000c, 2 | 6) => Machine::Aarch64,
        _ => return Err(refused("MACHO_MACHINE")),
    };
    let count = reader.integer(16, 4)?;
    let command_bytes = reader.integer(20, 4)?;
    require(count <= MAX_ENTRIES, "MACHO_COMMAND_COUNT")?;
    reader.take(32, command_bytes)?;
    let commands_end = 32 + command_bytes;
    let mut cursor = 32;
    let mut layout = Layout::default();
    for _ in 0..count {
        let kind = reader.integer(cursor, 4)?;
        let size = reader.integer(cursor + 4, 4)?;
        require(
            size >= 8 && size % 8 == 0 && cursor + size <= commands_end,
            "MACHO_COMMAND_SIZE",
        )?;
        if kind == 0x19 {
            require(size >= 72, "MACHO_SEGMENT_SIZE")?;
            let sections = reader.integer(cursor + 64, 4)?;
            require(size == 72 + 80 * sections, "MACHO_SECTION_COUNT")?;
            let file_offset = reader.integer(cursor + 40, 8)?;
            let file_size = reader.integer(cursor + 48, 8)?;
            reader.take(file_offset, file_size)?;
            let read_only =
                reader.integer(cursor + 56, 4)? == 1 && reader.integer(cursor + 60, 4)? == 1;
            layout
                .regions
                .push((file_offset, file_offset + file_size, read_only));
            for index in 0..sections {
                let at = cursor + 72 + index * 80;
                if name16(reader, at)? != b"__module" || name16(reader, at + 16)? != b"__SMIR" {
                    continue;
                }
                require(
                    name16(reader, cursor + 8)? == b"__SMIR",
                    "MACHO_SEGMENT_NAME",
                )?;
                let start = reader.integer(at + 48, 4)?;
                let length = reader.integer(at + 40, 8)?;
                require(
                    file_offset <= start && sum(start, length)? <= file_offset + file_size,
                    "MACHO_SECTION_BOUNDS",
                )?;
                require(
                    length >= LOCATOR_BYTES as u64 && reader.integer(at + 64, 4)? == 0,
                    "MACHO_SECTION_FLAGS",
                )?;
                require(read_only, "CARRIER_PERMISSIONS")?;
                layout.locators.push(start);
            }
        }
        cursor += size;
    }
    require(cursor == commands_end, "MACHO_COMMAND_END")?;
    Ok((machine, layout))
}

fn pe(reader: &Reader) -> Result<(Machine, Layout), Error> {
    require(reader.take(0, 2)? == b"MZ", "PE_PROFILE")?;
    let header = reader.integer(60, 4)?;
    require(reader.take(header, 4)? == b"PE\0\0", "PE_SIGNATURE")?;
    let machine = match reader.integer(header + 4, 2)? {
        0x8664 => Machine::X86_64,
        0xaa64 => Machine::Aarch64,
        _ => return Err(refused("PE_MACHINE")),
    };
    let count = reader.integer(header + 6, 2)?;
    let optional_size = reader.integer(header + 20, 2)?;
    require(count <= MAX_ENTRIES && optional_size >= 112, "PE_HEADER")?;
    reader.take(header + 24, optional_size)?;
    require(
        reader.integer(header + 24, 2)? == 0x20b,
        "PE_OPTIONAL_HEADER",
    )?;
    let table = header + 24 + optional_size;
    reader.take(table, count * 40)?;
    let mut layout = Layout::default();
    for index in 0..count {
        let at = table + index * 40;
        let name = reader.take(at, 8)?;
        let size = reader.integer(at + 16, 4)?;
        let offset = reader.integer(at + 20, 4)?;
        let flags = reader.integer(at + 36, 4)?;
        reader.take(offset, size)?;
        // Readable, and neither executable, writable nor discardable.
        let read_only = flags & 0x4000_0000 != 0 && flags & 0xa200_0000 == 0;
        layout.regions.push((offset, offset + size, read_only));
        if name == b".smir\0\0\0" {
            require(
                size >= LOCATOR_BYTES as u64 && read_only && flags & 0x40 != 0,
                "CARRIER_PERMISSIONS",
            )?;
            layout.locators.push(offset);
        }
    }
    Ok((machine, layout))
}

/// The format of a file, by how it begins; none if it begins like no
/// carrier, as a payload on its own does.
pub fn kind(file: &[u8]) -> Option<Carrier> {
    if file.starts_with(b"\x7fELF") {
        Some(Carrier::Elf)
    } else if file.starts_with(&0xfeed_facf_u32.to_le_bytes()) {
        Some(Carrier::MachO)
    } else if file.starts_with(b"MZ") {
        Some(Carrier::Pe)
    } else {
        None
    }
}

/// Find the payload of a carrier of the given format.
///
/// The file must have exactly one locator, where its format puts it. The
/// payload must lie inside a part of the file that the native loader maps
/// for reading only, and inside no part it maps for anything else; it must
/// not overlap the locator, and its SHA-256 must be what the locator says.
pub fn find(file: &[u8], carrier: Carrier) -> Result<Found<'_>, Error> {
    let reader = Reader(file);
    let (machine, layout) = match carrier {
        Carrier::Elf => elf(&reader)?,
        Carrier::MachO => macho(&reader)?,
        Carrier::Pe => pe(&reader)?,
    };
    let [at] = layout.locators[..] else {
        return Err(refused("LOCATOR_AMBIGUOUS"));
    };
    let record = reader.take(at, LOCATOR_BYTES as u64)?;
    let field = |from: usize, width: usize| u64::from_le_bytes(pad(&record[from..from + width]));
    let (offset, length) = (field(16, 8), field(24, 8));
    let end = offset.saturating_add(length);
    require(
        layout
            .regions
            .iter()
            .any(|(from, to, read_only)| *from <= offset && end <= *to && *read_only),
        "PAYLOAD_NOT_READONLY",
    )?;
    require(
        layout
            .regions
            .iter()
            .all(|(from, to, read_only)| end <= *from || *to <= offset || *read_only),
        "PAYLOAD_ALIAS_PERMISSIONS",
    )?;
    require(&record[..8] == MAGIC && field(8, 2) == 1, "LOCATOR_VERSION")?;
    require(field(10, 2) == 0 && field(12, 4) == 0, "LOCATOR_RESERVED")?;
    require(
        length > 0
            && offset
                .checked_add(length)
                .is_some_and(|end| end <= file.len() as u64),
        "LOCATOR_BOUNDS",
    )?;
    require(
        end <= at || at + LOCATOR_BYTES as u64 <= offset,
        "LOCATOR_OVERLAP",
    )?;
    let payload = &file[offset as usize..end as usize];
    let sha256: [u8; 32] = Sha256::digest(payload).into();
    require(sha256[..] == record[32..], "LOCATOR_HASH")?;
    Ok(Found {
        carrier,
        machine,
        payload,
        offset,
        sha256,
    })
}

fn pad(bytes: &[u8]) -> [u8; 8] {
    let mut wide = [0_u8; 8];
    wide[..bytes.len()].copy_from_slice(bytes);
    wide
}

/// The payload of a file that is a carrier, or the file itself if it begins
/// like none. A file that begins like a carrier and has no payload that can
/// be found is refused: it is not taken for a payload.
pub fn payload(file: &[u8]) -> Result<&[u8], Error> {
    match kind(file) {
        Some(carrier) => Ok(find(file, carrier)?.payload),
        None => Ok(file),
    }
}

/// The locator of a payload at `offset` of its file.
pub fn locator(offset: u64, payload: &[u8]) -> [u8; LOCATOR_BYTES] {
    let mut record = [0_u8; LOCATOR_BYTES];
    record[..8].copy_from_slice(MAGIC);
    record[8..10].copy_from_slice(&1_u16.to_le_bytes());
    record[16..24].copy_from_slice(&offset.to_le_bytes());
    record[24..32].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    record[32..].copy_from_slice(&Sha256::digest(payload));
    record
}

/// What a native linker is given as the section that carries `payload`: a
/// locator that says how long the payload is and what its SHA-256 is, but
/// not yet where it is, and the payload. [`seal`] completes it in the
/// linked file.
pub fn section(payload: &[u8]) -> Vec<u8> {
    let mut content = locator(0, payload).to_vec();
    content.extend_from_slice(payload);
    content
}

/// Write into the locator of a linked file where its payload is: right
/// after the locator, as [`section`] put it. The file must be a Mach-O or a
/// PE file with exactly one locator; an ELF file's locator is in a note,
/// which nothing follows.
pub fn seal(file: &mut [u8], carrier: Carrier) -> Result<(), Error> {
    let layout = match carrier {
        Carrier::Elf => return Err(refused("CARRIER_SEAL")),
        Carrier::MachO => macho(&Reader(file))?.1,
        Carrier::Pe => pe(&Reader(file))?.1,
    };
    let [at] = layout.locators[..] else {
        return Err(refused("LOCATOR_AMBIGUOUS"));
    };
    let at = at as usize;
    require(file.len() - at >= LOCATOR_BYTES, "CARRIER_BOUNDS")?;
    put(file, at + 16, 8, (at + LOCATOR_BYTES) as u64);
    Ok(())
}

fn put(file: &mut [u8], at: usize, width: usize, value: u64) {
    file[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

/// A file of the given format that carries `payload` and nothing else: the
/// headers that say where the payload is, no code and no entry. Such a file
/// is for handing a payload to a runtime in the dress of a native file; the
/// system's loader has nothing to run in it.
pub fn wrap(payload: &[u8], carrier: Carrier, machine: Machine) -> Vec<u8> {
    match carrier {
        Carrier::Elf => {
            // The header, two program headers, the note, the payload.
            let (note_at, note_bytes) = (64 + 2 * 56, 12 + 8 + LOCATOR_BYTES);
            let payload_at = note_at + note_bytes;
            let mut file = vec![0_u8; payload_at];
            file[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            put(&mut file, 16, 2, 2);
            put(
                &mut file,
                18,
                2,
                match machine {
                    Machine::X86_64 => 62,
                    Machine::Aarch64 => 183,
                },
            );
            put(&mut file, 20, 4, 1);
            put(&mut file, 32, 8, 64);
            put(&mut file, 52, 2, 64);
            put(&mut file, 54, 2, 56);
            put(&mut file, 56, 2, 2);
            // Read-only: the whole file as what is loaded, and the note.
            for (index, (kind, start, size, alignment)) in [
                (1_u64, 0, payload_at + payload.len(), 8_u64),
                (4, note_at, note_bytes, 4),
            ]
            .into_iter()
            .enumerate()
            {
                let at = 64 + index * 56;
                put(&mut file, at, 4, kind);
                put(&mut file, at + 4, 4, 4);
                put(&mut file, at + 8, 8, start as u64);
                put(&mut file, at + 32, 8, size as u64);
                put(&mut file, at + 40, 8, size as u64);
                put(&mut file, at + 48, 8, alignment);
            }
            put(&mut file, note_at, 4, 8);
            put(&mut file, note_at + 4, 4, LOCATOR_BYTES as u64);
            put(&mut file, note_at + 8, 4, 1);
            file[note_at + 12..note_at + 20].copy_from_slice(MAGIC);
            file[note_at + 20..payload_at].copy_from_slice(&locator(payload_at as u64, payload));
            file.extend_from_slice(payload);
            file
        }
        Carrier::MachO => {
            // The header, one segment with one section: the locator, then
            // the payload.
            let section_at = 32 + 72 + 80;
            let payload_at = section_at + LOCATOR_BYTES;
            let section_bytes = (LOCATOR_BYTES + payload.len()) as u64;
            let mut file = vec![0_u8; payload_at];
            put(&mut file, 0, 4, 0xfeed_facf);
            put(
                &mut file,
                4,
                4,
                match machine {
                    Machine::X86_64 => 0x0100_0007,
                    Machine::Aarch64 => 0x0100_000c,
                },
            );
            put(&mut file, 12, 4, 2);
            put(&mut file, 16, 4, 1);
            put(&mut file, 20, 4, 72 + 80);
            put(&mut file, 32, 4, 0x19);
            put(&mut file, 36, 4, 72 + 80);
            file[40..46].copy_from_slice(b"__SMIR");
            put(&mut file, 32 + 32, 8, section_bytes);
            put(&mut file, 32 + 40, 8, section_at as u64);
            put(&mut file, 32 + 48, 8, section_bytes);
            put(&mut file, 32 + 56, 4, 1);
            put(&mut file, 32 + 60, 4, 1);
            put(&mut file, 32 + 64, 4, 1);
            let section = 32 + 72;
            file[section..section + 8].copy_from_slice(b"__module");
            file[section + 16..section + 22].copy_from_slice(b"__SMIR");
            put(&mut file, section + 40, 8, section_bytes);
            put(&mut file, section + 48, 4, section_at as u64);
            file[section_at..payload_at].copy_from_slice(&locator(payload_at as u64, payload));
            file.extend_from_slice(payload);
            file
        }
        Carrier::Pe => {
            // The DOS header, the PE header with an optional header of the
            // least size, one section: the locator, then the payload.
            let (header, optional) = (64, 112);
            let table = header + 24 + optional;
            let section_at = table + 40;
            let payload_at = section_at + LOCATOR_BYTES;
            let mut file = vec![0_u8; payload_at];
            file[..2].copy_from_slice(b"MZ");
            put(&mut file, 60, 4, header as u64);
            file[header..header + 4].copy_from_slice(b"PE\0\0");
            put(
                &mut file,
                header + 4,
                2,
                match machine {
                    Machine::X86_64 => 0x8664,
                    Machine::Aarch64 => 0xaa64,
                },
            );
            put(&mut file, header + 6, 2, 1);
            put(&mut file, header + 20, 2, optional as u64);
            put(&mut file, header + 24, 2, 0x20b);
            file[table..table + 5].copy_from_slice(b".smir");
            let section_bytes = (LOCATOR_BYTES + payload.len()) as u64;
            put(&mut file, table + 8, 4, section_bytes);
            put(&mut file, table + 16, 4, section_bytes);
            put(&mut file, table + 20, 4, section_at as u64);
            // Initialized data, readable.
            put(&mut file, table + 36, 4, 0x4000_0040);
            file[section_at..payload_at].copy_from_slice(&locator(payload_at as u64, payload));
            file.extend_from_slice(payload);
            file
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as Json;
    use std::path::Path;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    /// The fixtures of the specification, each with the payload it carries
    /// or the code it is refused with.
    #[test]
    fn the_specification_fixtures_are_found_or_refused_as_they_say() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/specifications/smir/portable/conformance/runtime/carriers");
        let mut names: Vec<_> = std::fs::read_dir(&directory)
            .expect("the fixtures are there")
            .map(|entry| entry.unwrap().path())
            .collect();
        names.sort();
        assert_eq!(names.len(), 14);
        let (mut accepted, mut refused) = (0, 0);
        for name in names {
            let fixture: Json = serde_json::from_slice(&std::fs::read(&name).unwrap()).unwrap();
            let document = &fixture["document"];
            let carrier = match document["carrier"].as_str().unwrap() {
                "elf" => Carrier::Elf,
                "macho" => Carrier::MachO,
                "pe" => Carrier::Pe,
                other => panic!("carrier {other}"),
            };
            let file = unhex(document["encoded_hex"].as_str().unwrap());
            let outcome = find(&file, carrier);
            if fixture["accept"].as_bool().unwrap() {
                let found = outcome.unwrap_or_else(|error| panic!("{}: {error}", name.display()));
                assert_eq!(
                    found.payload,
                    unhex(fixture["expected_payload_hex"].as_str().unwrap()),
                    "{}",
                    name.display()
                );
                // The format shows in how the file begins.
                assert_eq!(kind(&file), Some(carrier));
                accepted += 1;
            } else {
                assert_eq!(
                    outcome.unwrap_err().code(),
                    fixture["expected_code"].as_str().unwrap(),
                    "{}",
                    name.display()
                );
                refused += 1;
            }
        }
        assert_eq!((accepted, refused), (3, 11));
    }

    const PAYLOAD: &[u8] = b"a payload of some bytes, which need not be a module";

    #[test]
    fn a_wrapped_payload_is_found_again_in_every_format() {
        for carrier in [Carrier::Elf, Carrier::MachO, Carrier::Pe] {
            for machine in [Machine::X86_64, Machine::Aarch64] {
                let file = wrap(PAYLOAD, carrier, machine);
                assert_eq!(kind(&file), Some(carrier));
                let found = find(&file, carrier).unwrap();
                assert_eq!(
                    (found.carrier, found.machine, found.payload),
                    (carrier, machine, PAYLOAD)
                );
                assert_eq!(
                    &file[found.offset as usize..][..PAYLOAD.len()],
                    PAYLOAD,
                    "{carrier:?}"
                );
                assert_eq!(payload(&file).unwrap(), PAYLOAD);
            }
        }
        // What begins like no carrier is its own payload.
        assert_eq!(kind(PAYLOAD), None);
        assert_eq!(payload(PAYLOAD).unwrap(), PAYLOAD);
    }

    #[test]
    fn a_changed_carrier_is_refused() {
        for carrier in [Carrier::Elf, Carrier::MachO, Carrier::Pe] {
            let file = wrap(PAYLOAD, carrier, Machine::Aarch64);
            let code = |file: &[u8]| find(file, carrier).unwrap_err().code().to_owned();
            // One bit of the payload.
            let mut changed = file.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert_eq!(code(&changed), "LOCATOR_HASH", "{carrier:?}");
            // The end of the file.
            assert_eq!(
                code(&file[..file.len() - 1]),
                "CARRIER_BOUNDS",
                "{carrier:?}"
            );
            // The locator's magic, its revision, a reserved field, and a
            // length of nothing.
            let at = file.len() - PAYLOAD.len() - LOCATOR_BYTES;
            for (field, value, expected) in [
                (0, 0x52_u8 ^ 1, "LOCATOR_VERSION"),
                (8, 2, "LOCATOR_VERSION"),
                (10, 1, "LOCATOR_RESERVED"),
                (12, 1, "LOCATOR_RESERVED"),
            ] {
                let mut changed = file.clone();
                changed[at + field] = value;
                assert_eq!(code(&changed), expected, "{carrier:?} field {field}");
            }
            let mut empty = file.clone();
            empty[at + 24..at + 32].fill(0);
            assert_eq!(code(&empty), "LOCATOR_BOUNDS", "{carrier:?}");
            // A payload said to be where the locator is.
            let mut overlapping = file.clone();
            overlapping[at + 16..at + 24].copy_from_slice(&(at as u64).to_le_bytes());
            assert_eq!(code(&overlapping), "LOCATOR_OVERLAP", "{carrier:?}");
            // A file that begins like a carrier is not taken for a payload,
            // however little of a carrier it is.
            assert_eq!(
                payload(&file[..8]).unwrap_err().code(),
                "CARRIER_BOUNDS",
                "{carrier:?}"
            );
        }
        // Another format than the file has.
        let file = wrap(PAYLOAD, Carrier::Elf, Machine::X86_64);
        assert_eq!(find(&file, Carrier::Pe).unwrap_err().code(), "PE_PROFILE");
        assert_eq!(
            find(&file, Carrier::MachO).unwrap_err().code(),
            "MACHO_PROFILE"
        );
    }

    #[test]
    fn a_linked_section_is_sealed_where_it_ended_up() {
        // A file as a linker makes it: the section's content somewhere in
        // it, which the headers name; here the wrapped form's own layout,
        // with the locator not yet saying where the payload is.
        for carrier in [Carrier::MachO, Carrier::Pe] {
            let mut file = wrap(PAYLOAD, carrier, Machine::Aarch64);
            let at = file.len() - PAYLOAD.len() - LOCATOR_BYTES;
            file[at..].copy_from_slice(&section(PAYLOAD));
            assert_eq!(
                find(&file, carrier).unwrap_err().code(),
                "PAYLOAD_NOT_READONLY"
            );
            seal(&mut file, carrier).unwrap();
            assert_eq!(find(&file, carrier).unwrap().payload, PAYLOAD);
            assert_eq!(file, wrap(PAYLOAD, carrier, Machine::Aarch64));
        }
        let mut elf = wrap(PAYLOAD, Carrier::Elf, Machine::X86_64);
        assert_eq!(
            seal(&mut elf, Carrier::Elf).unwrap_err().code(),
            "CARRIER_SEAL"
        );
    }

    #[test]
    fn a_payload_the_loader_would_map_writable_is_refused() {
        // The ELF program header's flags, the Mach-O segment's protections,
        // the PE section's characteristics.
        let mut elf = wrap(PAYLOAD, Carrier::Elf, Machine::X86_64);
        elf[64 + 4] = 6;
        assert_eq!(
            find(&elf, Carrier::Elf).unwrap_err().code(),
            "PAYLOAD_NOT_READONLY"
        );
        let mut macho = wrap(PAYLOAD, Carrier::MachO, Machine::Aarch64);
        macho[32 + 60] = 3;
        assert_eq!(
            find(&macho, Carrier::MachO).unwrap_err().code(),
            "CARRIER_PERMISSIONS"
        );
        let mut pe = wrap(PAYLOAD, Carrier::Pe, Machine::X86_64);
        let characteristics = 64 + 24 + 112 + 36;
        pe[characteristics + 3] |= 0x80;
        assert_eq!(
            find(&pe, Carrier::Pe).unwrap_err().code(),
            "CARRIER_PERMISSIONS"
        );
    }
}
