//! Test-owned native data for controlled present-tree acquisition. Real fixed
//! roots keep separate read-only integration coverage. No system key is changed.
use super::{Hkey, OwnedKey, RegOpenKeyExW, io, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CURRENT_USER: Hkey = (-2_147_483_647isize) as Hkey;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegCreateKeyExW(
        key: Hkey,
        name: *const u16,
        reserved: u32,
        class: *mut u16,
        options: u32,
        access: u32,
        security: *const std::ffi::c_void,
        output: *mut Hkey,
        disposition: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        key: Hkey,
        name: *const u16,
        reserved: u32,
        kind: u32,
        data: *const u8,
        bytes: u32,
    ) -> i32;
    fn RegDeleteTreeW(key: Hkey, name: *const u16) -> i32;
}

pub(super) struct Tree {
    name: Vec<u16>,
    root: Option<OwnedKey>,
}

fn create(parent: Hkey, name: &[u16]) -> io::Result<(OwnedKey, u32)> {
    let mut handle = null_mut();
    let mut disposition = 0;
    // SAFETY: terminated owned name, initialized exclusive outputs and no
    // inherited handle. Volatile creation and full access are restricted to
    // the unique fixture leaf or descendants of its already owned root.
    let status = unsafe {
        RegCreateKeyExW(
            parent,
            name.as_ptr(),
            0,
            null_mut(),
            1,           // REG_OPTION_VOLATILE
            0x000f_003f, // KEY_ALL_ACCESS
            std::ptr::null(),
            &mut handle,
            &mut disposition,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok((OwnedKey(handle), disposition))
}

fn value(key: &OwnedKey, name: &str, kind: u32, bytes: &[u8]) -> io::Result<()> {
    let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: live exclusively owned fixture key, terminated name and bounded
    // initialized input bytes; the native call does not retain these pointers.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            kind,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(())
}

impl Tree {
    pub(super) fn new() -> Self {
        Self::acquire().expect("create private volatile native registry fixture")
    }

    fn acquire() -> io::Result<Self> {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        for _ in 0..16 {
            // A direct HKCU leaf is outside redirected Software branches. No
            // shared test parent or pre-existing path needs to be created.
            let name: Vec<_> = format!(
                "RaxRuntimeFixture-{}-{epoch}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )
            .encode_utf16()
            .chain(Some(0))
            .collect();
            let (root, disposition) = create(CURRENT_USER, &name)?;
            if disposition != 1 {
                // Existing keys are never written or selected for cleanup.
                drop(root);
                continue;
            }
            let fixture = Self {
                name,
                root: Some(root),
            };
            fixture.populate()?;
            return Ok(fixture);
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "native fixture name collision",
        ))
    }

    fn populate(&self) -> io::Result<()> {
        let root = self.root.as_ref().expect("owned fixture root");
        value(root, "", 3, &[0, 0xff, 1, 0])?;
        value(root, "Dword", 4, &0x1234_5678u32.to_le_bytes())?;
        for (path, text, kind) in [
            ("ChildΩ", "NativeΩ\0", 1),
            ("ChildΩ\\Grandchild", "A\0B\0\0", 7),
            ("Empty", "", 0),
        ] {
            let name: Vec<_> = path.encode_utf16().chain(Some(0)).collect();
            let (key, disposition) = create(root.0, &name)?;
            if disposition != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "fixture child already exists",
                ));
            }
            if kind != 0 {
                let bytes: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
                value(&key, "Text", kind, &bytes)?;
            }
        }
        Ok(())
    }

    pub(super) fn open(&self, suffix: &[u16], view: u32) -> io::Result<OwnedKey> {
        assert!(matches!(view, 0 | 0x100 | 0x200));
        assert!(!suffix.contains(&0));
        assert!(suffix.is_empty() || suffix.first() == Some(&92));
        let name: Vec<_> = self.name[..self.name.len() - 1]
            .iter()
            .chain(suffix)
            .copied()
            .chain(Some(0))
            .collect();
        let mut handle = null_mut();
        // SAFETY: this test's fixed private root plus its native-enumerated
        // suffix, terminated buffer, query/enumerate-only explicit view and
        // exclusive HKEY output. No guest callback invokes this helper.
        let status =
            unsafe { RegOpenKeyExW(CURRENT_USER, name.as_ptr(), 0, 9 | view, &mut handle) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        Ok(OwnedKey(handle))
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        drop(self.root.take());
        // SAFETY: disposition REG_CREATED_NEW_KEY established this exact
        // unique leaf as test-owned before any fixture mutation. Cleanup never
        // targets an existing key, parent, real fixed root or system hive.
        let status = unsafe { RegDeleteTreeW(CURRENT_USER, self.name.as_ptr()) };
        if status != 0 {
            if std::thread::panicking() {
                eprintln!("native registry fixture cleanup failed: {status}");
            } else {
                panic!("native registry fixture cleanup failed: {status}");
            }
        }
    }
}

#[test]
fn native_registry_fixture_removes_its_private_leaf_after_owned_readers_close() {
    let fixture = Tree::new();
    let name = fixture.name.clone();
    let reader = fixture.open(&[], 0).unwrap();
    let metadata = super::info(&reader).unwrap();
    assert_eq!(metadata.children, 2);
    assert_eq!(metadata.values, 2);
    drop(reader);
    drop(fixture);
    let mut handle = null_mut();
    // SAFETY: initialized predefined HKCU, the terminated owned fixture name,
    // read/query-only access and an exclusive initialized HKEY output. The
    // name lives through the synchronous Windows call; no callback or unwind.
    let status = unsafe { RegOpenKeyExW(CURRENT_USER, name.as_ptr(), 0, 9, &mut handle) };
    if !handle.is_null() {
        drop(OwnedKey(handle));
    }
    assert_eq!(
        status, 2,
        "the test-owned registry leaf must be absent after Drop"
    );
}
