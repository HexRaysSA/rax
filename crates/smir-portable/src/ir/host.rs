//! The descriptor a host registers one of its functions with.
//!
//! A module that imports a function of its host quotes the identity of a
//! descriptor: a record that names the function and says what it takes and
//! returns, as a root of types of its own and the function type in it. The
//! host that has the function registers it with the same record. The
//! identity is the SHA-256 of `SMIR-HOST-V1`, a zero byte and the record's
//! bytes, so a module and a host that agree on it agree on all of it.

use sha2::{Digest, Sha256};

use crate::context::{bytes, field, list, text, unsigned};
use crate::wire::decode_record;
use crate::{Error, Limits};

use super::lower::standalone_types;
use super::{HostImport, Module, Type};

/// What a descriptor says of a host function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDescriptor {
    pub namespace: String,
    pub name: String,
    pub version: u32,
    /// The descriptor's identity, which an import of the function quotes.
    pub identity: [u8; 32],
    /// The types of the parameters and of the results: integers and
    /// floats, each with whether it must be a defined value.
    params: Vec<(Type, bool)>,
    results: Vec<(Type, bool)>,
}

fn refused(what: &'static str) -> Error {
    Error::semantic("HOST_DESCRIPTOR", what)
}

fn number(value: &crate::RecordValue, name: &str) -> Result<u32, Error> {
    u32::try_from(unsigned(field(value, name)?)?).map_err(|_| refused("a number out of range"))
}

impl HostDescriptor {
    /// Decode a descriptor from the bytes of its record.
    ///
    /// # Errors
    ///
    /// A `WIRE-` code if the bytes are not the canonical encoding of such a
    /// record, and `HOST_DESCRIPTOR` if the record is of another revision,
    /// names nothing or something in the runtime's own namespace, has no
    /// version, or describes anything but a function of the portable
    /// calling convention over integers and floats.
    pub fn decode(record: &[u8]) -> Result<Self, Error> {
        let limits = Limits::default();
        let described = decode_record("runtime_host_descriptor", record, limits)?;
        let (namespace, name) = (
            text(field(&described, "namespace")?)?,
            text(field(&described, "name")?)?,
        );
        let version = number(&described, "version")?;
        if number(&described, "revision")? != 1
            || namespace.is_empty()
            || namespace.starts_with("smir.")
            || name.is_empty()
            || namespace.contains('\0')
            || name.contains('\0')
            || version == 0
        {
            return Err(refused("the function's name, version or revision"));
        }
        // The types are a root of their own, with nothing but types in it.
        let root = decode_record(
            "execution_types",
            bytes(field(&described, "types")?)?,
            limits,
        )?;
        if number(&root, "payload_revision")? != 2
            || !list(field(&root, "memory_layouts")?)?.is_empty()
        {
            return Err(refused("the root of types"));
        }
        let (types, by_id) = standalone_types(&root)?;
        let signature = by_id
            .get(&number(&described, "signature")?)
            .and_then(|id| match &types[id.index()] {
                Type::Function(signature) => Some(signature),
                _ => None,
            })
            .filter(|signature| signature.portable_cc && !signature.variadic)
            .ok_or_else(|| refused("the function type"))?;
        let values = |ids: &[super::TypeId], noundef: &[bool]| {
            ids.iter()
                .zip(noundef)
                .map(|(id, required)| match &types[id.index()] {
                    ty @ Type::Int { bits } if *bits <= 128 => Ok((ty.clone(), *required)),
                    ty @ Type::Float { .. } => Ok((ty.clone(), *required)),
                    _ => Err(refused("a value that is no integer and no float")),
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let mut digest = Sha256::new();
        digest.update(b"SMIR-HOST-V1\0");
        digest.update(record);
        Ok(Self {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            version,
            identity: digest.finalize().into(),
            params: values(&signature.params, &signature.param_noundef)?,
            results: values(&signature.results, &signature.result_noundef)?,
        })
    }

    /// Whether this is the descriptor of a function `module` imports: the
    /// one whose identity the import quotes, of the import's name and
    /// version, taking and returning what the module calls it with.
    pub fn describes(&self, module: &Module, import: &HostImport) -> bool {
        let signature = module.host_signature(import);
        let same = |described: &[(Type, bool)], ids: &[super::TypeId], noundef: &[bool]| {
            described.len() == ids.len()
                && described.iter().zip(ids.iter().zip(noundef)).all(
                    |((ty, required), (id, wanted))| ty == module.ty(*id) && required == wanted,
                )
        };
        self.identity == import.descriptor
            && (self.namespace.as_str(), self.name.as_str(), self.version)
                == (
                    import.namespace.as_str(),
                    import.name.as_str(),
                    import.version,
                )
            && same(&self.params, &signature.params, &signature.param_noundef)
            && same(&self.results, &signature.results, &signature.result_noundef)
    }

    /// How many bits each parameter and each result has.
    pub fn widths(&self) -> (Vec<u32>, Vec<u32>) {
        let bits = |values: &[(Type, bool)]| {
            values
                .iter()
                .map(|(ty, _)| match ty {
                    Type::Int { bits } => *bits,
                    Type::Float { format } => format.bits(),
                    _ => 0,
                })
                .collect()
        };
        (bits(&self.params), bits(&self.results))
    }
}
