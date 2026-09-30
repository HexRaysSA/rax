//! Lossless Windows file identity behind the two-word mapping key.
//!
//! `FILE_ID_INFO` contains a 64-bit volume serial and a 128-bit file ID.
//! Hashing or truncating those 192 bits can alias different mapped objects.
//! Live mappings instead retain an interned token; duplicate handles share
//! it, and the last owner removes its registry entry. Tokens never reuse a
//! number. Registry operations take O(log n) time and O(n) space for n live
//! file identities, independently of the number of duplicate mappings.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex, Weak};

use super::backing::SourceIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    volume: u64,
    file: [u8; 16],
}

struct Entry {
    number: u64,
    token: Weak<Identity>,
}

struct State {
    next: u64,
    entries: BTreeMap<Key, Entry>,
}

struct Registry(Mutex<State>);

impl Registry {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(State {
            next: 1,
            entries: BTreeMap::new(),
        })))
    }

    fn acquire(self: &Arc<Self>, key: Key) -> io::Result<Arc<Identity>> {
        let mut state = self.0.lock().unwrap();
        if let Some(token) = state.entries.get(&key).and_then(|e| e.token.upgrade()) {
            return Ok(token);
        }
        let next = state
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("mapped file identity space exhausted"))?;
        let token = Arc::new(Identity {
            registry: Arc::downgrade(self),
            key,
            number: state.next,
        });
        state.next = next;
        state.entries.insert(
            key,
            Entry {
                number: token.number,
                token: Arc::downgrade(&token),
            },
        );
        Ok(token)
    }
}

pub(super) struct Identity {
    registry: Weak<Registry>,
    key: Key,
    number: u64,
}

impl Identity {
    pub(super) fn source(&self) -> SourceIdentity {
        SourceIdentity {
            // u64::MAX is reserved for non-file objects by shared.rs.
            dev: u64::MAX - 1,
            ino: self.number,
        }
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            let mut state = registry.0.lock().unwrap();
            // Another thread may replace the expired Weak before this
            // destructor acquires the lock. Never remove its new token.
            if state
                .entries
                .get(&self.key)
                .is_some_and(|e| e.number == self.number)
            {
                state.entries.remove(&self.key);
            }
        }
    }
}

#[cfg(windows)]
pub(super) fn for_file(file: &std::fs::File) -> io::Result<Arc<Identity>> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::sync::LazyLock;

    #[repr(C)]
    #[derive(Default)]
    struct FileIdInfo {
        volume: u64,
        file: [u8; 16],
    }
    const _: () = assert!(std::mem::size_of::<FileIdInfo>() == 24);
    const FILE_ID_INFO: i32 = 18;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut c_void,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
    }

    let mut info = FileIdInfo::default();
    // SAFETY: the borrowed file owns a live handle for this call. The
    // initialized, exclusively borrowed repr(C) buffer has FILE_ID_INFO's
    // 24-byte layout and alignment. The API retains no pointer and does
    // not invoke Rust callbacks; failure is read before any other OS call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_ID_INFO,
            (&raw mut info).cast(),
            std::mem::size_of::<FileIdInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    static REGISTRY: LazyLock<Arc<Registry>> = LazyLock::new(Registry::new);
    REGISTRY.acquire(Key {
        volume: info.volume,
        file: info.file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(volume: u64, lo: u64, hi: u64) -> Key {
        let mut file = [0; 16];
        file[..8].copy_from_slice(&lo.to_le_bytes());
        file[8..].copy_from_slice(&hi.to_le_bytes());
        Key { volume, file }
    }

    #[test]
    fn full_volume_and_file_id_distinguish_live_objects() {
        let registry = Registry::new();
        let a = registry.acquire(key(1, 2, 3)).unwrap();
        let same = registry.acquire(key(1, 2, 3)).unwrap();
        assert!(Arc::ptr_eq(&a, &same));
        for k in [
            key(0, 2, 3),
            key(1 << 32 | 1, 2, 3),
            key(1, 0, 3),
            key(1, 2, 0),
        ] {
            let other = registry.acquire(k).unwrap();
            assert_ne!(a.source(), other.source());
        }
        assert_ne!(a.source(), SourceIdentity::default());
        assert_ne!(a.source().dev, u64::MAX);
    }

    #[test]
    fn last_owner_reaps_entry_and_reopen_does_not_reuse_token() {
        let registry = Registry::new();
        let k = key(1, 2, 3);
        let a = registry.acquire(k).unwrap();
        let id = a.source();
        let b = a.clone();
        drop(a);
        assert_eq!(registry.0.lock().unwrap().entries.len(), 1);
        drop(b);
        assert!(registry.0.lock().unwrap().entries.is_empty());
        assert_ne!(registry.acquire(k).unwrap().source(), id);
        assert!(registry.0.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn delayed_destructor_preserves_replacement_and_exhaustion_is_transactional() {
        let registry = Registry::new();
        let k = key(1, 2, 3);
        // Model the interval after the last strong reference expired and
        // before its destructor obtained the registry lock.
        let stale = Identity {
            registry: Arc::downgrade(&registry),
            key: k,
            number: 7,
        };
        {
            let mut state = registry.0.lock().unwrap();
            state.next = 8;
            state.entries.insert(
                k,
                Entry {
                    number: 7,
                    token: Weak::new(),
                },
            );
        }
        let replacement = registry.acquire(k).unwrap();
        drop(stale);
        assert!(Arc::ptr_eq(&registry.acquire(k).unwrap(), &replacement));
        registry.0.lock().unwrap().next = u64::MAX;
        assert!(registry.acquire(key(2, 2, 3)).is_err());
        assert!(Arc::ptr_eq(&registry.acquire(k).unwrap(), &replacement));
        assert_eq!(registry.0.lock().unwrap().entries.len(), 1);
        drop(replacement);
        assert!(registry.0.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn concurrent_duplicate_registration_has_one_live_identity() {
        let registry = Registry::new();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let registry = registry.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    registry.acquire(key(u64::MAX, u64::MAX, u64::MAX)).unwrap()
                })
            })
            .collect();
        let tokens: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(tokens.iter().all(|t| Arc::ptr_eq(t, &tokens[0])));
        assert_eq!(registry.0.lock().unwrap().entries.len(), 1);
        drop(tokens);
        assert!(registry.0.lock().unwrap().entries.is_empty());
    }
}
