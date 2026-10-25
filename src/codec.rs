//! Legacy wire-codec compatibility layer.
//!
//! rax's on-disk context and snapshot formats were originally produced by
//! bincode 1.x with fixed-width little-endian integers. `uklad`'s `legacy`
//! configuration emits the same bytes, so these helpers keep the existing
//! formats readable while removing the bincode dependency.

use uklad::config::legacy;

/// Serializes a value using the legacy fixed-width little-endian format.
pub fn serialize<T>(value: &T) -> Result<Vec<u8>, uklad::error::EncodeError>
where
    T: serde::Serialize + ?Sized,
{
    uklad::serde::encode_to_vec(value, legacy())
}

/// Deserializes a value from the legacy fixed-width little-endian format,
/// allowing trailing bytes.
pub fn deserialize<'a, T>(bytes: &'a [u8]) -> Result<T, uklad::error::DecodeError>
where
    T: serde::Deserialize<'a>,
{
    uklad::serde::borrow_decode_from_slice(bytes, legacy()).map(|(value, _)| value)
}

/// Deserializes a value and rejects trailing bytes.
pub fn deserialize_strict<'a, T>(bytes: &'a [u8]) -> Result<T, uklad::error::DecodeError>
where
    T: serde::Deserialize<'a>,
{
    let (value, read) = uklad::serde::borrow_decode_from_slice(bytes, legacy())?;
    if read == bytes.len() {
        Ok(value)
    } else {
        Err(uklad::error::DecodeError::Other("trailing bytes"))
    }
}

/// Serializes a value into a writer using the legacy format.
pub fn serialize_into<W, T>(mut writer: W, value: &T) -> Result<(), uklad::error::EncodeError>
where
    W: std::io::Write,
    T: serde::Serialize + ?Sized,
{
    uklad::serde::encode_into_std_write(value, &mut writer, legacy())?;
    Ok(())
}

/// Deserializes a value from a reader using the legacy format.
pub fn deserialize_from<R, T>(mut reader: R) -> Result<T, uklad::error::DecodeError>
where
    R: std::io::Read,
    T: serde::de::DeserializeOwned,
{
    uklad::serde::decode_from_std_read(&mut reader, legacy())
}
