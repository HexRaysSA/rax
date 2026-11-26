//! The existing machine-wide license record for an installed Xcode bundle.
use super::{Files, overlaps_executable};
use plist::Value;
use std::{
    fs::{self, Metadata, OpenOptions},
    io::{self, Cursor, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
};

const PREFERENCES: &str = "/Library/Preferences/com.apple.dt.Xcode.plist";
const MAX_PREFERENCES_BYTES: usize = 64 << 10;
const LICENSE_KEYS: [&str; 6] = [
    "IDELastBetaLicenseAgreedTo",
    "IDELastGMLicenseAgreedTo",
    "IDELastPTRLicenseAgreedTo",
    "IDEXcodeVersionForAgreedToBetaLicense",
    "IDEXcodeVersionForAgreedToGMLicense",
    "IDEXcodeVersionForAgreedToPTRLicense",
];

pub(super) fn select(files: Files, root: &Path, executable: Option<&str>) -> io::Result<Files> {
    if overlaps_executable(PREFERENCES, executable)
        || !files
            .default_runtime_entry_available(PREFERENCES, None)
            .map_err(io::Error::other)?
    {
        return Ok(files);
    }
    if let Some(bytes) = installed_snapshot(root) {
        files
            .with_file(PREFERENCES.into(), Arc::from(bytes))
            .map_err(io::Error::other)
    } else {
        Ok(files)
    }
}

fn trusted(metadata: &Metadata) -> bool {
    metadata.uid() == 0 && metadata.mode() & 0o022 == 0
}

fn installed_snapshot(root: &Path) -> Option<Vec<u8>> {
    for ancestor in ["Library", "Library/Preferences"] {
        let metadata = fs::symlink_metadata(root.join(ancestor)).ok()?;
        if !metadata.is_dir() || !trusted(&metadata) {
            return None;
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(PREFERENCES.trim_start_matches('/')))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || !trusted(&metadata) {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_PREFERENCES_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    license_record(&bytes)
}

fn license_record(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > MAX_PREFERENCES_BYTES {
        return None;
    }
    let mut record = Value::from_reader(Cursor::new(bytes))
        .ok()?
        .into_dictionary()?;
    record.retain(|key, value| {
        LICENSE_KEYS.contains(&key.as_str()) && matches!(value, Value::String(_))
    });
    if record.is_empty() {
        return None;
    }
    let mut snapshot = Vec::new();
    Value::Dictionary(record)
        .to_writer_binary(&mut snapshot)
        .ok()?;
    Some(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::supplied_fs::test_backing::TestFile;
    use plist::Dictionary;
    use std::os::unix::fs::symlink;

    fn encoded(record: Dictionary) -> Vec<u8> {
        let mut bytes = Vec::new();
        Value::Dictionary(record)
            .to_writer_binary(&mut bytes)
            .unwrap();
        bytes
    }

    #[test]
    fn license_snapshot_retains_only_existing_license_strings() {
        let expected = Dictionary::from_iter(
            LICENSE_KEYS[..5]
                .iter()
                .map(|&key| (key.to_owned(), Value::String(format!("installed {key}")))),
        );
        let mut record = expected.clone();
        record.insert(LICENSE_KEYS[5].into(), Value::Boolean(true));
        record.insert(
            "UnrelatedPreference".into(),
            Value::String("private".into()),
        );
        let snapshot = license_record(&encoded(record)).unwrap();
        assert_eq!(
            Value::from_reader(Cursor::new(snapshot)).unwrap(),
            Value::Dictionary(expected)
        );
        assert!(license_record(&encoded(Dictionary::new())).is_none());
        assert!(license_record(b"invalid plist").is_none());
        assert!(license_record(&vec![0; MAX_PREFERENCES_BYTES + 1]).is_none());
    }

    #[test]
    fn license_snapshot_preserves_caller_data_and_omits_symlink_sources() {
        let fixture = TestFile::new(b"", 0);
        let root = &fixture.dir;
        let installed = root.join(PREFERENCES.trim_start_matches('/'));
        fs::create_dir_all(installed.parent().unwrap()).unwrap();
        let record = Dictionary::from_iter([(LICENSE_KEYS[0], Value::String("accepted".into()))]);
        fs::write(&fixture.path, encoded(record)).unwrap();
        symlink(&fixture.path, installed).unwrap();
        assert!(installed_snapshot(root).is_none());

        let files = Files::default()
            .with_file(
                PREFERENCES.into(),
                Arc::from(b"caller preference".as_slice()),
            )
            .unwrap();
        let selected = select(files, root, None).unwrap();
        assert_eq!(&*selected.read(PREFERENCES).unwrap(), b"caller preference");
    }
}
