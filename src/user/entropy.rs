//! Host entropy for process personalities that are not given a seed.
//!
//! `getrandom` covers Unix, Windows, and WASI. wasm32/wasm64 `unknown` and
//! `none` targets have no entropy source without a JavaScript host, so `fill`
//! reports `Unsupported` there and a personality needs a deterministic seed.
//! `Cargo.toml` gates the `getrandom` dependency on the same predicate, so
//! these targets build without a `getrandom_backend` cfg in `RUSTFLAGS`.

use std::io;

/// Fill `buf` from the host entropy source. A failure leaves `buf` unspecified.
#[cfg(not(all(target_family = "wasm", any(target_os = "unknown", target_os = "none"))))]
pub(crate) fn fill(buf: &mut [u8]) -> io::Result<()> {
    getrandom::fill(buf).map_err(io::Error::other)
}

/// Fill `buf` from the host entropy source. A failure leaves `buf` unspecified.
#[cfg(all(target_family = "wasm", any(target_os = "unknown", target_os = "none")))]
pub(crate) fn fill(_buf: &mut [u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host entropy is not available on this target",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(all(target_family = "wasm", any(target_os = "unknown", target_os = "none"))))]
    #[test]
    fn host_entropy_fills_the_whole_buffer() {
        // 32 zero bytes from a working source has probability 2^-256.
        let mut bytes = [0u8; 32];
        fill(&mut bytes).unwrap();
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[cfg(all(target_family = "wasm", any(target_os = "unknown", target_os = "none")))]
    #[test]
    fn host_entropy_is_unsupported() {
        let error = fill(&mut [0u8; 8]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
