//! Validate the installed ARM64 build 29708 executable-policy reply.

use super::{EXECUTABLE_REPLY_CAPACITY, EXECUTABLE_REPLY_GROUP, invalid};
use std::io;

const GROUP_BYTES: usize = EXECUTABLE_REPLY_GROUP.len() * 4;
const HEADER_BYTES: usize = GROUP_BYTES + 8;
const QUERY_BYTES: usize = 456;
const FULL_REPLY_BYTES: usize = HEADER_BYTES + QUERY_BYTES;

// The measured policy record is an SDBQUERYRESULT with up to 16 executable
// references, 8 layer references and 16 database GUID slots.
const EXE_COUNT_MAX: usize = 16;
const EXE_FLAGS: usize = EXE_COUNT_MAX * 4;
const LAYERS: usize = EXE_FLAGS + EXE_COUNT_MAX * 4;
const EXE_COUNT: usize = LAYERS + 8 * 4 + 2 * 4;
const QUERY_FLAGS: usize = EXE_COUNT + 2 * 4 + 16;
const DATABASES: usize = QUERY_FLAGS + 2 * 4;
const BUILTIN_DATABASE: [u8; 16] = [0x11; 16];

/// A record can contain only the measured stock metadata or references to the
/// same built-in shim database used by the selected installed runtime.
pub(crate) struct ExecutableReply {
    bytes: [u8; FULL_REPLY_BYTES],
    len: usize,
}

impl ExecutableReply {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub(super) fn capture(
        storage: &[u8; EXECUTABLE_REPLY_CAPACITY],
        written: usize,
    ) -> io::Result<Self> {
        let bytes = storage
            .get(..written)
            .filter(|_| matches!(written, HEADER_BYTES | FULL_REPLY_BYTES))
            .ok_or_else(|| invalid("installed executable AppHelp reply has an unknown extent"))?;
        if storage[written..].iter().any(|&byte| byte != 0xa5) {
            return Err(invalid(
                "installed executable AppHelp reply exceeds its extent",
            ));
        }

        let policy = &bytes[HEADER_BYTES..];
        for (index, expected) in EXECUTABLE_REPLY_GROUP.into_iter().enumerate() {
            let actual = word(bytes, index * 4);
            if index == 9 && !policy.is_empty() && actual == 0x20 {
                continue;
            }
            if actual != expected {
                return Err(invalid("installed executable AppHelp group is unsupported"));
            }
        }
        if word(bytes, GROUP_BYTES) != 1 || word(bytes, GROUP_BYTES + 4) as usize != policy.len() {
            return Err(invalid(
                "installed executable AppHelp record has an invalid header",
            ));
        }
        if !policy.is_empty() {
            validate_builtin_policy(policy)?;
        }
        let mut capture = Self {
            bytes: [0; FULL_REPLY_BYTES],
            len: written,
        };
        capture.bytes[..written].copy_from_slice(bytes);
        Ok(capture)
    }
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn validate_builtin_policy(bytes: &[u8]) -> io::Result<()> {
    // All database references must use the built-in database slot. Its
    // TAGREFs are aligned byte offsets, below the selected database size cap.
    let count = word(bytes, EXE_COUNT) as usize;
    if !(1..=EXE_COUNT_MAX).contains(&count)
        || word(bytes, QUERY_FLAGS + 4) != 1
        || bytes[DATABASES..DATABASES + 16] != BUILTIN_DATABASE
        || bytes[DATABASES + 16..].iter().any(|&byte| byte != 0)
    {
        return Err(invalid(
            "installed executable AppHelp database reference is unsupported",
        ));
    }

    // This profile carries no explicit layers, AppHelp message, or last
    // executable GUID. Only the observed executable and query flags apply.
    if bytes[LAYERS..EXE_COUNT].iter().any(|&byte| byte != 0)
        || bytes[EXE_COUNT + 4..QUERY_FLAGS]
            .iter()
            .any(|&byte| byte != 0)
        || word(bytes, QUERY_FLAGS) & !0x0901 != 0
    {
        return Err(invalid(
            "installed executable AppHelp policy fields are unsupported",
        ));
    }
    for index in 0..EXE_COUNT_MAX {
        let tag = word(bytes, index * 4);
        let flags = word(bytes, EXE_FLAGS + index * 4);
        if index < count {
            if !(12..super::MAX_FILE_BYTES as u32).contains(&tag)
                || !tag.is_multiple_of(2)
                || flags & !0x0101_0000 != 0
            {
                return Err(invalid("installed executable AppHelp match is unsupported"));
            }
        } else if tag != 0 || flags != 0 {
            return Err(invalid(
                "installed executable AppHelp match exceeds its count",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
