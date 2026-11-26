//! OpenSSL's distribution configuration and public PEM trust data.

use std::{fs::File, io};

const CERTIFICATES: &str = "/etc/ssl/certs";
pub(super) const CERTIFICATE_ROOTS: &[&str] = &[
    CERTIFICATES,
    "/usr/share/ca-certificates",
    "/usr/local/share/ca-certificates",
];

#[cfg(target_os = "linux")]
pub(super) const CONFIG: &str = "/etc/ssl/openssl.cnf";

#[cfg(target_os = "linux")]
pub(super) const ALIASES: &[(&str, &str)] = &[
    ("/usr/lib/ssl/certs", CERTIFICATES),
    ("/usr/lib/ssl/openssl.cnf", CONFIG),
];

/// Only admit PEM certificate bundles. A neighboring key or a PEM file that
/// also contains a private key must never enter an installed runtime.
pub(super) fn accept_certificate(file: &File) -> io::Result<bool> {
    use io::Read;

    // This covers installed CA bundles while bounding the work of lookup.
    const MAX_PEM: u64 = 16 * 1024 * 1024;
    let mut pem = Vec::new();
    file.take(MAX_PEM + 1).read_to_end(&mut pem)?;
    Ok(pem.len() as u64 <= MAX_PEM && certificates_only(&pem))
}

fn certificates_only(pem: &[u8]) -> bool {
    let mut payload = None;
    let mut certificate = false;
    for line in pem.split(|&byte| byte == b'\n').map(<[u8]>::trim_ascii) {
        match line {
            b"" => {}
            b"-----BEGIN CERTIFICATE-----" if payload.is_none() => payload = Some(false),
            b"-----END CERTIFICATE-----" if payload == Some(true) => {
                payload = None;
                certificate = true;
            }
            data if payload.is_some()
                && data
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(byte)) =>
            {
                payload = Some(true);
            }
            _ => return false,
        }
    }
    certificate && payload.is_none()
}

#[cfg(test)]
mod tests {
    use super::certificates_only;

    #[test]
    fn certificate_store_rejects_keys_and_incomplete_bundles() {
        const CERT: &[u8] = b"-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n";
        assert!(certificates_only(CERT));
        assert!(certificates_only(&[CERT, b"\n", CERT].concat()));
        assert!(!certificates_only(
            CERT.strip_suffix(b"-----END CERTIFICATE-----\n").unwrap()
        ));
        for foreign in [
            b"-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----\n".as_slice(),
            b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
            b"unexpected content\n",
        ] {
            assert!(!certificates_only(foreign));
            assert!(!certificates_only(&[CERT, foreign].concat()));
        }
    }
}
