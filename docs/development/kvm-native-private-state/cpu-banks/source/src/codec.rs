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

/// Serializes with an encoded-byte limit before growing the output buffer.
/// Time is linear in the encoded length; output storage is bounded by `limit`.
pub fn serialize_limited<T>(value: &T, limit: usize) -> Result<Vec<u8>, uklad::error::EncodeError>
where
    T: serde::Serialize + ?Sized,
{
    struct LimitedVec {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for LimitedVec {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            let end = self
                .bytes
                .len()
                .checked_add(buffer.len())
                .filter(|&end| end <= self.limit)
                .ok_or_else(|| std::io::Error::other("codec size limit exceeded"))?;
            if end > self.bytes.capacity() {
                let capacity = end
                    .max(self.bytes.capacity().saturating_mul(2))
                    .max(64)
                    .min(self.limit);
                self.bytes
                    .try_reserve_exact(capacity - self.bytes.len())
                    .map_err(std::io::Error::other)?;
            }
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = LimitedVec {
        bytes: Vec::new(),
        limit,
    };
    uklad::serde::encode_into_std_write(value, &mut writer, legacy())?;
    Ok(writer.bytes)
}

/// Strict legacy decoding with the decoder's byte budget enabled.
pub fn deserialize_limited<'a, T, const LIMIT: usize>(
    bytes: &'a [u8],
) -> Result<T, uklad::error::DecodeError>
where
    T: serde::Deserialize<'a>,
{
    let (value, read) =
        uklad::serde::borrow_decode_from_slice(bytes, legacy().with_limit::<LIMIT>())?;
    if read == bytes.len() {
        Ok(value)
    } else {
        Err(uklad::error::DecodeError::Other("trailing bytes"))
    }
}

/// Reads one legacy value with a byte budget, leaving subsequent values unread.
pub fn deserialize_from_limited<R, T, const LIMIT: usize>(
    mut reader: R,
) -> Result<T, uklad::error::DecodeError>
where
    R: std::io::Read,
    T: serde::de::DeserializeOwned,
{
    uklad::serde::decode_from_std_read(&mut reader, legacy().with_limit::<LIMIT>())
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    #[test]
    fn fixed_width_boundaries_keep_legacy_bytes_and_reject_overflow() {
        let value = 0x0123_4567_89ab_cdefu64;
        assert_eq!(serialize_limited(&value, 8).unwrap(), value.to_le_bytes());
        assert!(serialize_limited(&value, 7).is_err());
        assert!(serialize_limited(&(), 0).unwrap().is_empty());
        let bytes = serialize_limited(&vec![0xa5u8], 9).unwrap();
        assert_eq!(bytes, [1, 0, 0, 0, 0, 0, 0, 0, 0xa5]);
        assert!(serialize_limited(&vec![0xa5u8], 8).is_err());
    }
    #[test]
    fn strict_decoding_enforces_byte_budget_truncation_and_trailing_data() {
        let bytes = 0x0123_4567_89ab_cdefu64.to_le_bytes();
        assert_eq!(
            deserialize_limited::<u64, 8>(&bytes).unwrap(),
            0x0123_4567_89ab_cdef
        );
        assert!(deserialize_limited::<u64, 7>(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(deserialize_limited::<u64, 8>(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(deserialize_limited::<u64, 16>(&trailing).is_err());
        assert!(deserialize_limited::<Vec<u64>, 16>(&u64::MAX.to_le_bytes()).is_err());
    }
    #[test]
    fn streaming_value_limits_preserve_the_following_record() {
        let mut bytes = 0x1234_5678u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
        let mut reader = std::io::Cursor::new(bytes);
        assert_eq!(
            deserialize_from_limited::<_, u32, 4>(&mut reader).unwrap(),
            0x1234_5678
        );
        assert_eq!(reader.position(), 4);
        assert_eq!(
            deserialize_from_limited::<_, u64, 8>(&mut reader).unwrap(),
            0x0123_4567_89ab_cdef
        );
        assert_eq!(reader.position(), 12);
    }
}
