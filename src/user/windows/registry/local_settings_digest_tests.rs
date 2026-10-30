//! Fresh independent C acquisition compared with the complete installed model.
use super::*;
use crate::user::windows::nt::status::*;
use std::ffi::c_void;

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptHashCertificate2(
        algorithm: *const u16,
        flags: u32,
        reserved: *mut c_void,
        data: *const u8,
        length: u32,
        hash: *mut u8,
        hash_length: *mut u32,
    ) -> i32;
}

struct Wire {
    bytes: Vec<u8>,
    nodes: usize,
    values: usize,
}

impl Wire {
    fn append(&mut self, bytes: &[u8]) {
        assert!(self.bytes.len().checked_add(bytes.len()).unwrap() <= 64 << 20);
        self.bytes.extend_from_slice(bytes);
    }

    fn number(&mut self, value: u32) {
        self.append(&value.to_le_bytes());
    }

    fn blob(&mut self, bytes: &[u8]) {
        self.number(bytes.len().try_into().unwrap());
        self.append(bytes);
    }

    fn name(&mut self, name: &[u16]) {
        self.number((name.len() * 2).try_into().unwrap());
        for unit in name {
            self.append(&unit.to_le_bytes());
        }
    }

    fn node(&mut self, key: &Key) {
        self.nodes += 1;
        self.append(b"KEY1");
        self.name(&key.path);
        let access = key.captured_access().unwrap();
        self.number(access.maximum_access);
        self.number(access.system_security_status);
        let mut values: Vec<_> = key.values.values().collect();
        values.sort_by(|left, right| left.name.cmp(&right.name));
        self.number(values.len().try_into().unwrap());
        self.values += values.len();
        for value in values {
            self.name(&value.name);
            self.number(value.kind);
            self.blob(&value.data);
        }
        let entries = key.child_metadata().unwrap();
        self.number(entries.len().try_into().unwrap());
        let children = key.subkeys.as_ref().unwrap();
        let mut ordered = Vec::new();
        for child in entries {
            self.name(&child.name);
            self.append(&child.last_write.to_le_bytes());
            ordered.push((&child.name, children.get(&key.fold(&child.name)).unwrap()));
        }
        ordered.sort_by(|left, right| left.0.cmp(right.0));
        for (_, child) in ordered {
            self.node(child);
        }
    }

    fn digest(&self) -> String {
        let algorithm: Vec<_> = "SHA256\0".encode_utf16().collect();
        let mut hash = [0u8; 32];
        let mut length = 32;
        // SAFETY: terminated algorithm string, live bounded byte input, no
        // reserved context, exclusive initialized 32-byte output and length.
        let status = unsafe {
            CryptHashCertificate2(
                algorithm.as_ptr(),
                0,
                std::ptr::null_mut(),
                self.bytes.as_ptr(),
                self.bytes.len().try_into().unwrap(),
                hash.as_mut_ptr(),
                &mut length,
            )
        };
        assert_ne!(status, 0);
        assert_eq!(length, 32);
        hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[test]
fn installed_local_settings_complete_capture_matches_fresh_native_digest_and_retains_routes() {
    let context = crate::user::windows::wnf::snapshot().unwrap();
    let subject = context.primary_subject().unwrap().user.clone();
    let registry = crate::user::windows::registry::capture_primary_user(
        crate::user::windows::registry::snapshot().unwrap(),
        &subject,
    )
    .unwrap();
    compare_local_settings(registry, subject);
}

#[test]
fn installed_local_settings_subject_matches_native_without_unrelated_startup_roots() {
    let context = crate::user::windows::wnf::snapshot().unwrap();
    let subject = context.primary_subject().unwrap().user.clone();
    let registry = super::super::installed::local_settings_subject(&subject).unwrap();
    compare_local_settings(registry, subject);
}

fn compare_local_settings(registry: Registry, subject: Vec<u8>) {
    let mut wire = Wire {
        bytes: b"RAXLS1\0\0".to_vec(),
        nodes: 0,
        values: 0,
    };
    let mut retained = Vec::new();
    for view in [RegistryView::Native64, RegistryView::Wow32] {
        wire.number(view.flag());
        let root = registry
            .views
            .roots
            .get(&(ViewRoot::LocalSettings, view))
            .unwrap();
        let status = if root.is_some() {
            0
        } else if registry
            .views
            .missing_paths
            .contains(&(ViewRoot::LocalSettings, view))
        {
            STATUS_OBJECT_PATH_NOT_FOUND
        } else {
            STATUS_OBJECT_NAME_NOT_FOUND
        };
        wire.number(status);
        if let Some(root) = root {
            wire.node(root);
            retained.push((view, root.clone()));
        }
    }
    let digest = wire.digest();
    eprintln!(
        "native Local Settings: {} nodes, {} values, {} wire bytes",
        wire.nodes,
        wire.values,
        wire.bytes.len()
    );
    if let Some(path) = std::env::var_os("RAX_LOCAL_SETTINGS_CORPUS") {
        let fresh: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(fresh["schema"], "rax-native-local-settings-v1");
        assert_eq!(fresh["state"], "complete");
        let reports = fresh["reports"].as_array().unwrap();
        assert!(!reports.is_empty());
        let sid_hex: String = subject.iter().map(|byte| format!("{byte:02x}")).collect();
        for report in reports {
            let snapshot = &report["snapshot"];
            assert_eq!(snapshot["subject_sid_hex"], sid_hex);
            assert_eq!(snapshot["sha256"], digest, "{}", report["architecture"]);
            assert_eq!(
                snapshot["wire_bytes"].as_u64(),
                Some(wire.bytes.len() as u64)
            );
            assert_eq!(snapshot["nodes"].as_u64(), Some(wire.nodes as u64));
            assert_eq!(snapshot["values"].as_u64(), Some(wire.values as u64));
        }
        eprintln!(
            "independent native Local Settings SHA256 compared for {} process ABIs",
            reports.len()
        );
    }
    let primary_path = user_policy::user_hive_path(&subject).unwrap();
    let primary = registry.key(&primary_path);
    drop(registry);
    for (view, expected) in retained {
        let Lookup::Present(actual) = primary.as_ref().unwrap().relative_in_view(
            &"Software\\Classes\\Local Settings"
                .encode_utf16()
                .collect::<Vec<_>>(),
            view,
        ) else {
            panic!("retained creator route");
        };
        assert!(Arc::ptr_eq(&actual, &expected));
    }
}
