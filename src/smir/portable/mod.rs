//! Experimental portable SMIR envelopes, legacy 0.1 and candidate 0.2.
//!
//! This decoder validates framing only. Section payloads are opaque and MUST
//! undergo semantic verification before linking or execution. No interpreter
//! admission API accepts this type. See `docs/specifications/smir/portable/`.

use std::fmt;

/// Isolated mathematical reference witness; not a portable execution engine.
pub mod execution;

pub const MAGIC: &[u8; 8] = b"SMIR\r\n\x1a\n";
pub const HEADER_SIZE: usize = 48;
pub const DIRECTORY_ENTRY_SIZE: usize = 24;
pub const NO_ENTRY: u32 = u32::MAX;

/// Loader resource limits, independent of the on-disk representation.
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    pub max_bytes: usize,
    pub max_sections: u32,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1 << 30,
            max_sections: 1024,
        }
    }
}

/// Stable draft diagnostic identifiers. These describe framing, not semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Magic,
    Version,
    Header,
    Limit,
    Directory,
    Section,
    RequiredSection,
    Padding,
}

impl DecodeError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncated => "SMIR-E001",
            Self::Magic => "SMIR-E002",
            Self::Version => "SMIR-E003",
            Self::Header => "SMIR-E004",
            Self::Limit => "SMIR-E005",
            Self::Directory => "SMIR-E006",
            Self::Section => "SMIR-E007",
            Self::RequiredSection => "SMIR-E008",
            Self::Padding => "SMIR-E009",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DecodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    Object,
    Image,
}

/// Borrowed section; unknown optional metadata is retained for round trips.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'a> {
    pub kind: u16,
    pub required: bool,
    pub bytes: &'a [u8],
}

/// Structurally decoded bytes. This is deliberately not a verified module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedEnvelope<'a> {
    pub kind: ModuleKind,
    pub entry_function: Option<u32>,
    pub sections: Vec<Section<'a>>,
}

/// Candidate 0.2/profile 2 framing, with all ten required section slots.
/// Payload grammars and semantic admission remain separate prerequisites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedCandidateEnvelope<'a> {
    pub kind: ModuleKind,
    pub entry_function: Option<u32>,
    pub sections: Vec<Section<'a>>,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn aligned(value: usize) -> Option<usize> {
    value.checked_add(7).map(|n| n & !7)
}

/// Decode the canonical draft envelope in O(bytes + sections) time and
/// O(sections) auxiliary space. Payloads are borrowed, never copied.
pub fn decode(bytes: &[u8], limits: DecodeLimits) -> Result<DecodedEnvelope<'_>, DecodeError> {
    decode_profile(bytes, limits, false)
}

/// Decode candidate framing only. Empty or otherwise invalid executable
/// payloads can pass this function and MUST NOT be linked or executed.
/// Time O(bytes + sections), auxiliary space O(sections), borrowed payloads.
pub fn decode_candidate(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<DecodedCandidateEnvelope<'_>, DecodeError> {
    let envelope = decode_profile(bytes, limits, true)?;
    Ok(DecodedCandidateEnvelope {
        kind: envelope.kind,
        entry_function: envelope.entry_function,
        sections: envelope.sections,
    })
}

fn decode_profile(
    bytes: &[u8],
    limits: DecodeLimits,
    candidate: bool,
) -> Result<DecodedEnvelope<'_>, DecodeError> {
    let revision = if candidate { 2 } else { 1 };
    let required_count = if candidate { 10 } else { 9 };
    if bytes.len() > limits.max_bytes {
        return Err(DecodeError::Limit);
    }
    if bytes.len() < HEADER_SIZE {
        return Err(DecodeError::Truncated);
    }
    if &bytes[..8] != MAGIC {
        return Err(DecodeError::Magic);
    }
    if u16_at(bytes, 8) != 0 || u16_at(bytes, 10) != revision {
        return Err(DecodeError::Version);
    }
    let kind = match u16_at(bytes, 12) {
        1 => ModuleKind::Object,
        2 => ModuleKind::Image,
        _ => return Err(DecodeError::Header),
    };
    let entry = u32_at(bytes, 40);
    if u16_at(bytes, 14) != 0
        || u32_at(bytes, 16) != u32::from(revision)
        || u64_at(bytes, 24) != bytes.len() as u64
        || u64_at(bytes, 32) != HEADER_SIZE as u64
        || u32_at(bytes, 44) != 0
        || (kind == ModuleKind::Object && entry != NO_ENTRY)
    {
        return Err(DecodeError::Header);
    }
    let count = u32_at(bytes, 20);
    if count > limits.max_sections {
        return Err(DecodeError::Limit);
    }
    let count = usize::try_from(count).map_err(|_| DecodeError::Limit)?;
    let directory_end = count
        .checked_mul(DIRECTORY_ENTRY_SIZE)
        .and_then(|n| HEADER_SIZE.checked_add(n))
        .ok_or(DecodeError::Directory)?;
    if directory_end > bytes.len() {
        return Err(DecodeError::Directory);
    }
    let mut sections = Vec::new();
    let mut previous_kind = 0;
    let mut cursor = directory_end;
    // The whole header and directory are bounded before fixed-offset reads.
    for index in 0..count {
        let record = HEADER_SIZE + index * DIRECTORY_ENTRY_SIZE;
        let section_kind = u16_at(bytes, record);
        let flags = u16_at(bytes, record + 2);
        if section_kind <= previous_kind || flags > 1 || u32_at(bytes, record + 4) != 0 {
            return Err(DecodeError::Directory);
        }
        let known =
            (1..=required_count).contains(&section_kind) || matches!(section_kind, 0x8000..=0x8002);
        if (!known && (section_kind < 0x8000 || flags != 0))
            || (section_kind < 0x8000 && flags != 1)
            || (section_kind >= 0x8000 && flags != 0)
        {
            return Err(DecodeError::RequiredSection);
        }
        let offset =
            usize::try_from(u64_at(bytes, record + 8)).map_err(|_| DecodeError::Section)?;
        let size = usize::try_from(u64_at(bytes, record + 16)).map_err(|_| DecodeError::Section)?;
        let start = aligned(cursor).ok_or(DecodeError::Section)?;
        let end = offset.checked_add(size).ok_or(DecodeError::Section)?;
        if offset != start || end > bytes.len() {
            return Err(DecodeError::Section);
        }
        if bytes[cursor..start].iter().any(|b| *b != 0) {
            return Err(DecodeError::Padding);
        }
        sections.push(Section {
            kind: section_kind,
            required: flags == 1,
            bytes: &bytes[offset..end],
        });
        previous_kind = section_kind;
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(DecodeError::Padding);
    }
    if candidate && sections.iter().filter(|s| s.kind < 0x8000).count() != 10 {
        return Err(DecodeError::RequiredSection);
    }
    Ok(DecodedEnvelope {
        kind,
        entry_function: (entry != NO_ENTRY).then_some(entry),
        sections,
    })
}

/// Independent, bounded ordered-record representation witness. No execution or
/// semantic admission APIs consume its values. Schema snapshots are explicit.
mod record_refinements;
pub mod records {
    pub use super::record_refinements::{CountBounds, Refinements, ScalarRule};
    use std::collections::{BTreeMap, BTreeSet};

    pub type Fields = Vec<(String, String)>;
    pub type Schema = BTreeMap<String, Definition>;

    #[derive(Clone, Debug, Default)]
    pub struct Definition {
        pub discriminator: Option<String>,
        pub fields: Fields,
        pub variants: BTreeMap<String, Fields>,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Limits {
        pub bytes: usize,
        pub nodes: usize,
        pub depth: usize,
        pub list: usize,
        pub string: usize,
    }

    impl Default for Limits {
        fn default() -> Self {
            Self {
                bytes: 16 * 1024 * 1024,
                nodes: 1_000_000,
                depth: 64,
                list: 65_536,
                string: 1024 * 1024,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Value {
        Unsigned(u64),
        Signed(i64),
        Boolean(bool),
        Bytes(Vec<u8>),
        Text(String),
        Vector(Vec<Value>),
        Option(Option<Box<Value>>),
        Record(BTreeMap<String, Value>),
    }

    /// Symbolic reference diagnostic, separate from published framing errors.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Error(pub &'static str);

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Error {}

    fn require(condition: bool, code: &'static str) -> Result<(), Error> {
        if condition { Ok(()) } else { Err(Error(code)) }
    }

    fn token(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 63
            && value.as_bytes()[0].is_ascii_lowercase()
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }

    fn integer(kind: &str) -> Option<(usize, bool)> {
        let width = match kind {
            "u8" | "i8" => 1,
            "u16" | "i16" => 2,
            "u32" | "i32" => 4,
            "u64" | "i64" => 8,
            _ => return None,
        };
        Some((width, kind.starts_with('i')))
    }

    fn primitive(kind: &str) -> bool {
        integer(kind).is_some()
            || matches!(
                kind,
                "bool" | "bytes" | "hex" | "digest32" | "utf8" | "token"
            )
    }

    pub struct Codec {
        schema: Schema,
        limits: Limits,
        refinements: Option<Refinements>,
    }

    impl Codec {
        pub fn new(schema: Schema, limits: Limits) -> Result<Self, Error> {
            require(limits.depth <= 128, "WIRE-CONFIG")?;
            require(!schema.is_empty(), "WIRE-SCHEMA")?;
            let codec = Self { schema, limits, refinements: None };
            for (name, record) in &codec.schema {
                require(token(name) && !primitive(name), "WIRE-SCHEMA")?;
                if let Some(discriminator) = &record.discriminator {
                    require(
                        token(discriminator)
                            && record.fields.is_empty()
                            && !record.variants.is_empty(),
                        "WIRE-SCHEMA",
                    )?;
                    for (tag, fields) in &record.variants {
                        require(token(tag), "WIRE-SCHEMA")?;
                        codec.audit(fields, Some(discriminator))?;
                    }
                } else {
                    require(record.variants.is_empty(), "WIRE-SCHEMA")?;
                    codec.audit(&record.fields, None)?;
                }
            }
            Ok(codec)
        }

        pub fn new_refined(schema: Schema, limits: Limits, refinements: Refinements) -> Result<Self, Error> {
            let mut codec = Self::new(schema, limits)?;
            refinements.audit(&codec.schema)?;
            codec.refinements = Some(refinements);
            Ok(codec)
        }

        fn vector_path(&self, path: &str) -> String {
            if self.refinements.is_some() { format!("{path}[]") } else { String::new() }
        }

        fn member_path(&self, prefix: &str, name: &str) -> String {
            if self.refinements.is_some() { format!("{prefix}.{name}") } else { String::new() }
        }

        fn kind(&self, mut name: &str) -> Result<(), Error> {
            for _ in 0..=128 {
                if let Some(child) = name
                    .strip_prefix("vec:")
                    .or_else(|| name.strip_prefix("opt:"))
                {
                    name = child;
                } else {
                    return require(
                        primitive(name) || self.schema.contains_key(name),
                        "WIRE-SCHEMA",
                    );
                }
            }
            Err(Error("WIRE-SCHEMA"))
        }

        fn audit(&self, fields: &Fields, discriminator: Option<&String>) -> Result<(), Error> {
            let mut names = BTreeSet::new();
            if let Some(name) = discriminator {
                names.insert(name);
            }
            for (name, kind) in fields {
                require(token(name) && names.insert(name), "WIRE-SCHEMA")?;
                self.kind(kind)?;
            }
            Ok(())
        }

        fn visit(&self, depth: usize, nodes: &mut usize) -> Result<(), Error> {
            require(
                depth <= self.limits.depth && *nodes < self.limits.nodes,
                "WIRE-LIMIT",
            )?;
            *nodes += 1;
            Ok(())
        }

        /// Worst-case O((schema + nodes) log(schema + nodes) + payload bytes)
        /// work, O(schema + nodes + payload bytes) space; all are bounded.
        pub fn decode(&self, kind: &str, bytes: &[u8]) -> Result<Value, Error> {
            self.kind(kind)?;
            require(bytes.len() <= self.limits.bytes, "WIRE-LIMIT")?;
            let mut input = Input {
                bytes,
                cursor: 0,
                nodes: 0,
            };
            let value = self.read(kind, &mut input, 0, "")?;
            require(input.cursor == bytes.len(), "WIRE-TRAILING")?;
            Ok(value)
        }

        fn read(&self, kind: &str, input: &mut Input<'_>, depth: usize, path: &str) -> Result<Value, Error> {
            let value = self.read_value(kind, input, depth, path)?;
            if let Some(rules) = &self.refinements { rules.scalar(path, &value)?; }
            Ok(value)
        }

        fn read_value(&self, kind: &str, input: &mut Input<'_>, depth: usize, path: &str) -> Result<Value, Error> {
            self.visit(depth, &mut input.nodes)?;
            if let Some(child) = kind.strip_prefix("vec:") {
                let count = input.number(4)?;
                require(
                    count <= self.limits.list as u64 && count <= self.limits.nodes as u64,
                    "WIRE-LIMIT",
                )?;
                if let Some(rules) = &self.refinements { rules.count(path, count as usize)?; }
                let child_path = self.vector_path(path);
                let mut values = Vec::new();
                for _ in 0..count {
                    values.push(self.read(child, input, depth + 1, &child_path)?);
                }
                return Ok(Value::Vector(values));
            }
            if let Some(child) = kind.strip_prefix("opt:") {
                let tag = input.number(1)?;
                require(tag <= 1, "WIRE-TAG")?;
                return Ok(Value::Option(if tag == 0 {
                    None
                } else {
                    Some(Box::new(self.read(child, input, depth + 1, path)?))
                }));
            }
            if let Some((width, signed)) = integer(kind) {
                let number = input.number(width)?;
                return Ok(if signed {
                    let shift = (8 - width) * 8;
                    Value::Signed(((number << shift) as i64) >> shift)
                } else {
                    Value::Unsigned(number)
                });
            }
            match kind {
                "bool" => {
                    let number = input.number(1)?;
                    require(number <= 1, "WIRE-RANGE")?;
                    Ok(Value::Boolean(number != 0))
                }
                "bytes" | "hex" | "digest32" => {
                    let count = if kind == "digest32" {
                        32
                    } else {
                        input.number(4)? as usize
                    };
                    Ok(Value::Bytes(input.take(count)?.to_vec()))
                }
                "token" | "utf8" => {
                    let count = input.number(if kind == "token" { 1 } else { 4 })? as usize;
                    require(count <= self.limits.string, "WIRE-LIMIT")?;
                    let text =
                        std::str::from_utf8(input.take(count)?).map_err(|_| Error("WIRE-TEXT"))?;
                    require(kind != "token" || token(text), "WIRE-TEXT")?;
                    Ok(Value::Text(text.to_owned()))
                }
                _ => {
                    let definition = &self.schema[kind];
                    let mut members = BTreeMap::new();
                    let mut prefix = if self.refinements.is_some() { kind.to_owned() } else { String::new() };
                    let fields = if let Some(discriminator) = &definition.discriminator {
                        let Value::Text(tag) = self.read("token", input, depth + 1, "")? else {
                            unreachable!()
                        };
                        let fields = definition.variants.get(&tag).ok_or(Error("WIRE-TAG"))?;
                        if self.refinements.is_some() { prefix = format!("{kind}.{tag}"); }
                        members.insert(discriminator.clone(), Value::Text(tag));
                        fields
                    } else {
                        &definition.fields
                    };
                    for (name, child) in fields {
                        members.insert(name.clone(), self.read(child, input, depth + 1, &self.member_path(&prefix, name))?);
                    }
                    Ok(Value::Record(members))
                }
            }
        }

        pub fn encode(&self, kind: &str, value: &Value) -> Result<Vec<u8>, Error> {
            self.kind(kind)?;
            let mut bytes = Vec::new();
            self.write(kind, value, &mut bytes, 0, &mut 0, "")?;
            Ok(bytes)
        }

        fn append(&self, bytes: &mut Vec<u8>, more: &[u8]) -> Result<(), Error> {
            require(more.len() <= self.limits.bytes - bytes.len(), "WIRE-LIMIT")?;
            bytes.extend_from_slice(more);
            Ok(())
        }

        fn write(&self, kind: &str, value: &Value, bytes: &mut Vec<u8>, depth: usize, nodes: &mut usize, path: &str) -> Result<(), Error> {
            if let Some(rules) = &self.refinements { rules.scalar(path, value)?; }
            self.write_value(kind, value, bytes, depth, nodes, path)
        }

        fn write_value(
            &self,
            kind: &str,
            value: &Value,
            bytes: &mut Vec<u8>,
            depth: usize,
            nodes: &mut usize,
            path: &str,
        ) -> Result<(), Error> {
            self.visit(depth, nodes)?;
            if let Some(child) = kind.strip_prefix("vec:") {
                let Value::Vector(values) = value else {
                    return Err(Error("WIRE-TYPE"));
                };
                require(
                    values.len() <= self.limits.list && values.len() <= u32::MAX as usize,
                    "WIRE-LIMIT",
                )?;
                if let Some(rules) = &self.refinements { rules.count(path, values.len())?; }
                self.append(bytes, &(values.len() as u32).to_le_bytes())?;
                let child_path = self.vector_path(path);
                for value in values {
                    self.write(child, value, bytes, depth + 1, nodes, &child_path)?;
                }
                return Ok(());
            }
            if let Some(child) = kind.strip_prefix("opt:") {
                let Value::Option(value) = value else {
                    return Err(Error("WIRE-TYPE"));
                };
                self.append(bytes, &[u8::from(value.is_some())])?;
                if let Some(value) = value {
                    self.write(child, value, bytes, depth + 1, nodes, path)?;
                }
                return Ok(());
            }
            if let Some((width, signed)) = integer(kind) {
                let number = match (signed, value) {
                    (true, Value::Signed(number)) => {
                        if width < 8 {
                            let limit = 1i64 << (width * 8 - 1);
                            require(*number >= -limit && *number < limit, "WIRE-RANGE")?;
                        }
                        number.to_le_bytes()
                    }
                    (false, Value::Unsigned(number)) => {
                        require(width == 8 || *number < (1u64 << (width * 8)), "WIRE-RANGE")?;
                        number.to_le_bytes()
                    }
                    _ => return Err(Error("WIRE-TYPE")),
                };
                return self.append(bytes, &number[..width]);
            }
            match (kind, value) {
                ("bool", Value::Boolean(value)) => self.append(bytes, &[u8::from(*value)]),
                ("bytes" | "hex" | "digest32", Value::Bytes(value)) => {
                    if kind == "digest32" {
                        require(value.len() == 32, "WIRE-RANGE")?;
                    } else {
                        require(value.len() <= u32::MAX as usize, "WIRE-LIMIT")?;
                        self.append(bytes, &(value.len() as u32).to_le_bytes())?;
                    }
                    self.append(bytes, value)
                }
                ("token" | "utf8", Value::Text(value)) => {
                    require(
                        value.len() <= self.limits.string && value.len() <= u32::MAX as usize,
                        "WIRE-LIMIT",
                    )?;
                    require(kind != "token" || token(value), "WIRE-TEXT")?;
                    if kind == "token" {
                        self.append(bytes, &[value.len() as u8])?;
                    } else {
                        self.append(bytes, &(value.len() as u32).to_le_bytes())?;
                    }
                    self.append(bytes, value.as_bytes())
                }
                (_, Value::Record(members)) if self.schema.contains_key(kind) => {
                    let definition = &self.schema[kind];
                    let mut prefix = if self.refinements.is_some() { kind.to_owned() } else { String::new() };
                    let fields = if let Some(discriminator) = &definition.discriminator {
                        let tag = members.get(discriminator).ok_or(Error("WIRE-TYPE"))?;
                        let Value::Text(name) = tag else {
                            return Err(Error("WIRE-TAG"));
                        };
                        let fields = definition.variants.get(name).ok_or(Error("WIRE-TAG"))?;
                        self.write("token", tag, bytes, depth + 1, nodes, "")?;
                        if self.refinements.is_some() { prefix = format!("{kind}.{name}"); }
                        fields
                    } else {
                        &definition.fields
                    };
                    require(
                        members.len()
                            == fields.len() + usize::from(definition.discriminator.is_some()),
                        "WIRE-TYPE",
                    )?;
                    for (name, child) in fields {
                        self.write(
                            child,
                            members.get(name).ok_or(Error("WIRE-TYPE"))?,
                            bytes,
                            depth + 1,
                            nodes,
                            &self.member_path(&prefix, name),
                        )?;
                    }
                    Ok(())
                }
                _ => Err(Error("WIRE-TYPE")),
            }
        }
    }

    struct Input<'a> {
        bytes: &'a [u8],
        cursor: usize,
        nodes: usize,
    }
    impl<'a> Input<'a> {
        fn take(&mut self, size: usize) -> Result<&'a [u8], Error> {
            require(size <= self.bytes.len() - self.cursor, "WIRE-TRUNCATED")?;
            let bytes = &self.bytes[self.cursor..self.cursor + size];
            self.cursor += size;
            Ok(bytes)
        }
        fn number(&mut self, width: usize) -> Result<u64, Error> {
            let mut array = [0; 8];
            array[..width].copy_from_slice(self.take(width)?);
            Ok(u64::from_le_bytes(array))
        }
    }
}

#[cfg(test)]
mod tests;
