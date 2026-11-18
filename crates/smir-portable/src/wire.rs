//! Bounded candidate0.2 representation and identity; no semantic proof.

use crate::frozen_format::{self, records};
use crate::limits::Budget;
use crate::{Error, ErrorClass, Limits};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub type RecordValue = records::Value;

pub(crate) const ROOT_NAMES: [&str; 10] = [
    "execution_types",
    "runtime_symbols",
    "execution_functions",
    "runtime_data",
    "runtime_relocations",
    "runtime_imports",
    "runtime_tls",
    "execution_exceptions",
    "runtime_capabilities",
    "abi_contract",
];

// Ordinary-function-address record revisions; envelope0.2/profile2 is unchanged.
const PAYLOAD_REVISIONS: [u32; 10] = [2, 2, 2, 1, 2, 1, 1, 1, 1, 3];

/// Immutable decoded syntax. This type does not grant executable admission.
pub struct ParsedObject {
    roots: BTreeMap<u16, RecordValue>,
    kind: frozen_format::ModuleKind,
    entry: Option<u32>,
    metadata: Vec<(u16, Vec<u8>)>,
    identity: [u8; 32],
    limits: Limits,
    payload_lengths: BTreeMap<u16, usize>,
    encoded_len: usize,
}

impl ParsedObject {
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn root(&self, section: u16) -> Result<&RecordValue, Error> {
        self.roots
            .get(&section)
            .ok_or_else(|| Error::semantic("P2_ROOT", "absent semantic root"))
    }
    pub(crate) fn entry(&self) -> Option<u32> {
        self.entry
    }
    pub(crate) fn image(&self) -> bool {
        self.kind == frozen_format::ModuleKind::Image
    }
    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }
    pub(crate) fn payload(&self, section: u16) -> Result<Vec<u8>, Error> {
        let mut budget = Budget::new(&self.limits);
        budget.reserve_bytes(self.payload_len(section)?)?;
        self.encode_payload(section)
    }
    pub(crate) fn payload_len(&self, section: u16) -> Result<usize, Error> {
        self.payload_lengths
            .get(&section)
            .copied()
            .ok_or_else(|| Error::semantic("P2_ROOT", "absent payload length"))
    }
    fn encode_payload(&self, section: u16) -> Result<Vec<u8>, Error> {
        let name = root_name(section)?;
        codec(self.limits, self.limits.max_record_nodes)?
            .encode(name, self.root(section)?)
            .map_err(wire_error)
    }
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn root_name(section: u16) -> Result<&'static str, Error> {
    section
        .checked_sub(1)
        .and_then(|index| ROOT_NAMES.get(usize::from(index)))
        .copied()
        .ok_or_else(|| Error::semantic("P2_ROOT", "unknown semantic section"))
}

fn configuration() -> Error {
    Error::new(
        ErrorClass::Wire,
        "WIRE-SCHEMA",
        "frozen schema configuration",
    )
}

fn fields(value: &Json) -> Result<records::Fields, Error> {
    let values = value.as_array().ok_or_else(configuration)?;
    values
        .iter()
        .map(|value| {
            let pair = value
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(configuration)?;
            Ok((
                pair[0].as_str().ok_or_else(configuration)?.to_owned(),
                pair[1].as_str().ok_or_else(configuration)?.to_owned(),
            ))
        })
        .collect()
}

fn schema() -> Result<&'static records::Schema, Error> {
    static SCHEMA: OnceLock<Result<records::Schema, Error>> = OnceLock::new();
    SCHEMA
        .get_or_init(|| {
            let sources = [
                include_str!(
                    "../../../docs/specifications/smir/portable/schema/execution/candidate.json"
                ),
                include_str!(
                    "../../../docs/specifications/smir/portable/schema/runtime/candidate.json"
                ),
                include_str!(
                    "../../../docs/specifications/smir/portable/schema/abi/candidate.json"
                ),
            ];
            let mut merged = BTreeMap::<String, Json>::new();
            for source in sources {
                let document: Json = serde_json::from_str(source).map_err(|_| configuration())?;
                for (name, definition) in document
                    .get("records")
                    .and_then(Json::as_object)
                    .ok_or_else(configuration)?
                {
                    if merged.get(name).is_some_and(|old| old != definition) {
                        return Err(configuration());
                    }
                    merged.insert(name.clone(), definition.clone());
                }
            }
            let mut result = records::Schema::new();
            for (name, definition) in merged {
                let mut parsed = records::Definition::default();
                if let Some(discriminator) = definition.get("discriminator") {
                    parsed.discriminator =
                        Some(discriminator.as_str().ok_or_else(configuration)?.to_owned());
                    for (tag, members) in definition
                        .get("variants")
                        .and_then(Json::as_object)
                        .ok_or_else(configuration)?
                    {
                        parsed.variants.insert(tag.clone(), fields(members)?);
                    }
                } else {
                    parsed.fields = fields(definition.get("fields").ok_or_else(configuration)?)?;
                }
                result.insert(name, parsed);
            }
            let manifest = result.get("module_manifest").ok_or_else(configuration)?;
            let symbols = result.get("runtime_symbols").ok_or_else(configuration)?;
            if manifest.fields.first() != Some(&("identity".to_owned(), "digest32".to_owned()))
                || symbols.fields.get(..2)
                    != Some(&[
                        ("payload_revision".to_owned(), "u32".to_owned()),
                        ("manifest".to_owned(), "module_manifest".to_owned()),
                    ])
            {
                return Err(configuration());
            }
            Ok(result)
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn codec(limits: Limits, nodes: usize) -> Result<records::Codec, Error> {
    records::Codec::new(
        schema()?.clone(),
        records::Limits {
            bytes: limits.max_payload_bytes,
            nodes,
            depth: limits.max_record_depth,
            list: limits.max_list_items,
            string: limits.max_string_bytes,
        },
    )
    .map_err(wire_error)
}

/// Decode a record of the schemas that stands by itself, outside any
/// object, such as the descriptor of a host function. Only the one
/// canonical encoding of a record is that record: `WIRE-CANONICAL` for any
/// other bytes that decode.
pub(crate) fn decode_record(
    kind: &str,
    bytes: &[u8],
    limits: Limits,
) -> Result<RecordValue, Error> {
    let codec = codec(limits, limits.max_record_nodes)?;
    let value = codec.decode(kind, bytes).map_err(wire_error)?;
    if codec.encode(kind, &value).map_err(wire_error)? != bytes {
        return Err(Error::new(
            ErrorClass::Wire,
            "WIRE-CANONICAL",
            "a record in other than its canonical encoding",
        ));
    }
    Ok(value)
}

fn wire_error(error: records::Error) -> Error {
    Error::new(
        if error.0 == "WIRE-LIMIT" {
            ErrorClass::Resource
        } else {
            ErrorClass::Wire
        },
        error.0,
        "ordered candidate payload",
    )
}

fn nodes(value: &RecordValue) -> Result<usize, Error> {
    let mut result = 1usize;
    let mut add = |child: &RecordValue| -> Result<(), Error> {
        result = result
            .checked_add(nodes(child)?)
            .ok_or_else(|| Error::resource("P2_NODE_LIMIT", "node count overflow"))?;
        Ok(())
    };
    match value {
        RecordValue::Record(members) => {
            for child in members.values() {
                add(child)?;
            }
        }
        RecordValue::Vector(members) => {
            for child in members {
                add(child)?;
            }
        }
        RecordValue::Option(Some(child)) => add(child)?,
        _ => {}
    }
    Ok(result)
}

fn member<'a>(value: &'a RecordValue, name: &str) -> Result<&'a RecordValue, Error> {
    let RecordValue::Record(members) = value else {
        return Err(configuration());
    };
    members.get(name).ok_or_else(configuration)
}

/// Decode all ten required roots and verify the exact normalized content hash.
/// Work O(schema+payload bytes+nodes), excluding ordered-map logarithmic factors;
/// space O(payload bytes+nodes). Semantic verification remains a separate gate.
pub fn decode_object(bytes: &[u8], limits: Limits) -> Result<ParsedObject, Error> {
    limits.check()?;
    let envelope = frozen_format::decode_candidate(
        bytes,
        frozen_format::DecodeLimits {
            max_bytes: limits.max_object_bytes,
            max_sections: 1024,
        },
    )
    .map_err(|error| {
        Error::new(
            if error == frozen_format::DecodeError::Limit {
                ErrorClass::Resource
            } else {
                ErrorClass::Framing
            },
            error.code(),
            "candidate envelope",
        )
    })?;
    let mut roots = BTreeMap::new();
    let mut metadata = Vec::new();
    let mut payload_lengths = BTreeMap::new();
    let mut remaining = limits.max_record_nodes;
    let mut digest = Sha256::new();
    digest.update(b"SMIR0.2\0");
    digest.update(2u32.to_le_bytes());
    for section in envelope.sections {
        if section.kind >= 0x8000 {
            metadata.push((section.kind, section.bytes.to_vec()));
            continue;
        }
        let expected_revision = PAYLOAD_REVISIONS[usize::from(section.kind - 1)];
        let actual_revision = match section.bytes.get(..4) {
            Some([a, b, c, d]) => Some(u32::from_le_bytes([*a, *b, *c, *d])),
            _ => None,
        };
        if actual_revision != Some(expected_revision) {
            return Err(Error::new(
                ErrorClass::Wire,
                "WIRE-REVISION",
                "payload revision before schema-dependent decoding",
            ));
        }
        let codec = codec(limits, remaining)?;
        let value = codec
            .decode(root_name(section.kind)?, section.bytes)
            .map_err(wire_error)?;
        remaining = remaining
            .checked_sub(nodes(&value)?)
            .ok_or_else(|| Error::resource("P2_NODE_LIMIT", "aggregate nodes"))?;
        if member(&value, "payload_revision")?
            != &RecordValue::Unsigned(u64::from(expected_revision))
        {
            return Err(Error::new(
                ErrorClass::Wire,
                "WIRE-REVISION",
                "payload revision",
            ));
        }
        if codec
            .encode(root_name(section.kind)?, &value)
            .map_err(wire_error)?
            != section.bytes
        {
            return Err(Error::new(
                ErrorClass::Wire,
                "WIRE-CANONICAL",
                "noncanonical payload",
            ));
        }
        digest.update(section.kind.to_le_bytes());
        digest.update((section.bytes.len() as u64).to_le_bytes());
        if section.kind == 2 {
            // schema() proved exactly revision:u32 then manifest.identity:digest32.
            let prefix = section.bytes.get(..4).ok_or_else(configuration)?;
            let suffix = section.bytes.get(36..).ok_or_else(configuration)?;
            digest.update(prefix);
            digest.update([0u8; 32]);
            digest.update(suffix);
        } else {
            digest.update(section.bytes);
        }
        roots.insert(section.kind, value);
        payload_lengths.insert(section.kind, section.bytes.len());
    }
    let identity: [u8; 32] = digest.finalize().into();
    let symbols = roots.get(&2).ok_or_else(configuration)?;
    let declared = member(member(symbols, "manifest")?, "identity")?;
    if declared != &RecordValue::Bytes(identity.to_vec()) {
        return Err(Error::new(
            ErrorClass::Wire,
            "WIRE-IDENTITY",
            "content identity mismatch",
        ));
    }
    Ok(ParsedObject {
        roots,
        kind: envelope.kind,
        entry: envelope.entry_function,
        metadata,
        identity,
        limits,
        payload_lengths,
        encoded_len: bytes.len(),
    })
}

/// Re-encode canonical records and framing, retaining optional metadata bytes.
/// Invalid inputs cannot be repaired here: only a successful decode makes a value.
pub fn canonical_bytes(object: &ParsedObject) -> Result<Vec<u8>, Error> {
    let mut budget = Budget::new(&object.limits);
    // Owned encoded payload buffers and the final output coexist. Preflight both
    // before any encoding allocation; immutable roots retain their exact lengths.
    budget.reserve_bytes(object.encoded_len)?;
    for length in object.payload_lengths.values() {
        budget.reserve_bytes(*length)?;
    }
    for (_, bytes) in &object.metadata {
        budget.reserve_bytes(bytes.len())?;
    }
    let mut payloads = Vec::new();
    for section in 1..=10 {
        payloads.push((section, true, object.encode_payload(section)?));
    }
    for (kind, bytes) in &object.metadata {
        payloads.push((*kind, false, bytes.clone()));
    }
    let directory = payloads
        .len()
        .checked_mul(24)
        .and_then(|n| n.checked_add(48))
        .ok_or_else(|| Error::resource("P2_OBJECT_LIMIT", "directory overflow"))?;
    let mut cursor = directory;
    let mut offsets = Vec::new();
    for (_, _, bytes) in &payloads {
        cursor = cursor
            .checked_add(7)
            .map(|n| n & !7)
            .ok_or_else(|| Error::resource("P2_OBJECT_LIMIT", "alignment overflow"))?;
        offsets.push(cursor);
        cursor = cursor
            .checked_add(bytes.len())
            .filter(|n| *n <= object.limits.max_object_bytes)
            .ok_or_else(|| Error::resource("P2_OBJECT_LIMIT", "canonical object limit"))?;
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(cursor)
        .map_err(|_| Error::resource("P2_ALLOCATION", "canonical output"))?;
    result.resize(cursor, 0);
    result[..8].copy_from_slice(frozen_format::MAGIC);
    result[10..12].copy_from_slice(&2u16.to_le_bytes());
    result[12..14].copy_from_slice(&(if object.image() { 2u16 } else { 1u16 }).to_le_bytes());
    result[16..20].copy_from_slice(&2u32.to_le_bytes());
    result[20..24].copy_from_slice(&(payloads.len() as u32).to_le_bytes());
    result[24..32].copy_from_slice(&(cursor as u64).to_le_bytes());
    result[32..40].copy_from_slice(&48u64.to_le_bytes());
    result[40..44].copy_from_slice(&object.entry.unwrap_or(u32::MAX).to_le_bytes());
    for (index, ((kind, required, bytes), offset)) in payloads.iter().zip(offsets).enumerate() {
        let directory = 48 + index * 24;
        result[directory..directory + 2].copy_from_slice(&kind.to_le_bytes());
        result[directory + 2..directory + 4].copy_from_slice(&u16::from(*required).to_le_bytes());
        result[directory + 8..directory + 16].copy_from_slice(&(offset as u64).to_le_bytes());
        result[directory + 16..directory + 24].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        result[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    Ok(result)
}
