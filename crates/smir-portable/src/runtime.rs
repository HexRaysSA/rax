//! What this runtime is, for a launcher that has to choose one before it
//! hands a program over (chapter 10 of the specification, "Launch forms and
//! runtime selection").

use crate::limits::Budget;
use crate::metadata::imports::Catalogs;
use crate::{Error, Limits};
use sha2::{Digest, Sha256};

/// The executable profile of the objects this runtime runs.
pub const PROFILE: u32 = 2;

/// Counts the changes of this implementation that a launcher may have to
/// ask for: a program that needs what a revision brought names that
/// revision as the least it runs with.
pub const REVISION: u32 = 1;

/// A runtime as a launcher sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    pub profile: u32,
    pub revision: u32,
    /// What tells this implementation from another: see [`describe`].
    pub implementation: [u8; 32],
    /// The identity of the catalog of internal helpers, which an import of
    /// one quotes.
    pub helpers: [u8; 32],
    /// The identities of the catalogs of services, the first catalog first.
    pub services: Vec<[u8; 32]>,
}

/// Describe this runtime.
///
/// The implementation's identity is the SHA-256 of `RAX-SMIR-PORTABLE-RUNTIME`
/// and a zero byte, the crate's version and a zero byte, the revision as
/// four bytes, least significant first, the architecture and the operating
/// system it was built for, each with a zero byte after it, and the
/// identities of its catalogs. Two builds of one version for one machine
/// have the same identity: it names what was built, not the file.
pub fn describe() -> Result<Description, Error> {
    let catalogs = Catalogs::load(&mut Budget::new(&Limits::default()))?;
    let mut digest = Sha256::new();
    digest.update(b"RAX-SMIR-PORTABLE-RUNTIME\0");
    digest.update(env!("CARGO_PKG_VERSION"));
    digest.update([0]);
    digest.update(REVISION.to_le_bytes());
    for part in [std::env::consts::ARCH, std::env::consts::OS] {
        digest.update(part);
        digest.update([0]);
    }
    digest.update(catalogs.helper_digest());
    for services in catalogs.service_digests() {
        digest.update(services);
    }
    Ok(Description {
        profile: PROFILE,
        revision: REVISION,
        implementation: digest.finalize().into(),
        helpers: catalogs.helper_digest(),
        services: catalogs.service_digests().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runtime_is_described_by_what_it_was_built_of() {
        let described = describe().unwrap();
        assert_eq!(described, describe().unwrap());
        assert_eq!((described.profile, described.revision), (2, REVISION));
        // One catalog of helpers and two of services, each its own.
        assert_eq!(described.services.len(), 2);
        let mut identities = vec![described.implementation, described.helpers];
        identities.extend(&described.services);
        for (position, identity) in identities.iter().enumerate() {
            assert_ne!(*identity, [0; 32]);
            assert!(!identities[..position].contains(identity));
        }
    }
}
