//! Native v8 observations constrain capture order, spelling and file roots.

use super::Harness;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::memory::{Mem, prot};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_SUCCESS,
};
use crate::user::windows::objects::{FileObj, Object};
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn native_file_attributes_captured_names_and_security_headers_precede_wow_output_probe() {
    for arch in WinArch::ALL {
        for name in ["NtQueryAttributesFile", "NtQueryFullAttributesFile"] {
            for role in [145, 146, 148, 151, 152] {
                let mut h = Harness::new(arch);
                let attrs = h.attrs();
                let output = h.base + PAGE_SIZE;
                let p = h.process.state_mut();
                let width = arch.ptr_size();
                match role {
                    145 => p.space.wptr(attrs + 2 * width, width, 1).unwrap(),
                    146 => p.space.wptr(attrs + 64 + width, width, 1).unwrap(),
                    148 => {
                        let descriptor = attrs + 512;
                        p.space.wr(descriptor, &[0; 40]).unwrap();
                        p.space.w8(descriptor, 1).unwrap();
                        p.space
                            .wptr(descriptor + if arch.is64() { 8 } else { 4 }, width, 1)
                            .unwrap();
                        p.space
                            .wptr(attrs + if arch.is64() { 32 } else { 16 }, width, descriptor)
                            .unwrap();
                    }
                    151 => p
                        .space
                        .wptr(attrs + if arch.is64() { 32 } else { 16 }, width, 1)
                        .unwrap(),
                    152 => p
                        .space
                        .wptr(attrs + if arch.is64() { 40 } else { 20 }, width, 1)
                        .unwrap(),
                    _ => unreachable!(),
                }
                p.vm.protect(output, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                let wrapper_fault = arch == WinArch::X86 && role != 148;
                assert_eq!(
                    h.query(name, attrs, output),
                    if wrapper_fault {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_GUARD_PAGE_VIOLATION
                    },
                    "{arch}/{name}/role{role}"
                );
                assert_eq!(
                    h.process.state().vm.query(output).unwrap().protect & prot::GUARD != 0,
                    wrapper_fault
                );
            }
        }
    }
}

#[test]
fn native_file_attributes_preserves_nt_spelling_and_distinguishes_absence() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        std::fs::create_dir(h.directory.0.join("directory")).unwrap();
        for (path, expected) in [
            ("\\??\\C:\\FIXTURE.BIN", STATUS_SUCCESS),
            ("\\DosDevices\\C:\\fixture.bin", STATUS_SUCCESS),
            ("\\??\\C:\\missing", STATUS_OBJECT_NAME_NOT_FOUND),
            (
                "\\??\\C:\\parent-missing\\child",
                STATUS_OBJECT_PATH_NOT_FOUND,
            ),
            ("\\??\\C:\\fixture.bin\\child", STATUS_OBJECT_PATH_NOT_FOUND),
            ("\\??\\C:\\fixture.bin\\", STATUS_NOT_A_DIRECTORY),
            ("\\??\\C:\\fixture.bin.", STATUS_OBJECT_NAME_NOT_FOUND),
            ("\\??\\C:\\fixture.bin ", STATUS_OBJECT_NAME_NOT_FOUND),
            ("\\??\\C:\\.\\fixture.bin", STATUS_OBJECT_PATH_NOT_FOUND),
            (
                "\\??\\C:\\directory\\..\\fixture.bin",
                STATUS_OBJECT_NAME_INVALID,
            ),
            ("\\??\\C:\\\\fixture.bin", STATUS_OBJECT_NAME_INVALID),
            ("\\??\\C:", STATUS_INVALID_PARAMETER),
            ("fixture.bin", STATUS_OBJECT_PATH_SYNTAX_BAD),
            ("", STATUS_OBJECT_PATH_SYNTAX_BAD),
        ] {
            h.name(path);
            assert_eq!(
                h.query("NtQueryAttributesFile", h.attrs(), h.base),
                expected,
                "{arch}/{path}"
            );
        }
    }
}

fn selection(h: &mut Harness) -> PathBuf {
    let directory = h.directory.0.join("runtime");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("fixture.dll"), b"native").unwrap();
    std::fs::write(directory.join("unselected.exe"), b"unselected").unwrap();
    let mut schema = [0u8; 28];
    schema[..4].copy_from_slice(&6u32.to_le_bytes());
    schema[4..8].copy_from_slice(&28u32.to_le_bytes());
    let p = h.process.state_mut();
    p.native = Some(crate::user::windows::native::NativeRuntime {
        directory: directory.canonicalize().unwrap(),
        guest_root: "C:\\Windows".into(),
        guest_directory: format!(
            "C:\\Windows\\{}",
            if p.arch == WinArch::X86 {
                "SysWOW64"
            } else {
                "System32"
            }
        ),
        version: p.cfg.version.clone(),
        apisets: crate::user::windows::loader::apiset_schema::ApiSetSchema::parse(&schema).unwrap(),
        registry: p.registry.clone(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        code_integrity: Err("controlled absent code integrity metadata".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
        code_integrity_policies: Err("code integrity policies not captured in this fixture".into()),
        gui: Default::default(),
    });
    Arc::make_mut(&mut p.cfg).host_filesystem = false;
    directory
}

#[test]
fn native_file_attributes_selected_runtime_does_not_grant_general_host_access() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let directory = selection(&mut h);
        for (path, expected) in [
            ("\\??\\C:\\WINDOWS\\SYSTEM32\\FIXTURE.dll", STATUS_SUCCESS),
            (
                "\\??\\C:\\Windows\\System32\\missing.dll",
                STATUS_OBJECT_NAME_NOT_FOUND,
            ),
            (
                "\\??\\C:\\Windows\\System32\\unselected.exe",
                STATUS_ACCESS_DENIED,
            ),
            ("\\??\\C:\\fixture.bin", STATUS_ACCESS_DENIED),
            (
                "\\??\\C:\\Windows\\System32\\fixture.dll\\",
                STATUS_NOT_A_DIRECTORY,
            ),
            (
                "\\??\\C:\\Windows\\System32\\..\\fixture.bin",
                STATUS_OBJECT_NAME_INVALID,
            ),
        ] {
            h.name(path);
            assert_eq!(
                h.query("NtQueryFullAttributesFile", h.attrs(), h.base),
                expected,
                "{arch}/{path}"
            );
        }
        #[cfg(unix)]
        {
            use crate::user::windows::nt::status::STATUS_REPARSE_POINT_ENCOUNTERED;
            std::os::unix::fs::symlink(directory.join("fixture.dll"), directory.join("alias.dll"))
                .unwrap();
            std::os::unix::fs::symlink(
                h.directory.0.join("fixture.bin"),
                directory.join("escape.dll"),
            )
            .unwrap();
            for (name, flags, expected) in [
                ("alias", 0x840, STATUS_SUCCESS),
                ("alias", 0x1840, STATUS_REPARSE_POINT_ENCOUNTERED),
                ("escape", 0x840, STATUS_ACCESS_DENIED),
                ("escape", 0x1840, STATUS_ACCESS_DENIED),
            ] {
                h.name(&format!("\\??\\C:\\Windows\\System32\\{name}.dll"));
                let attrs = h.attrs();
                h.process
                    .state()
                    .space
                    .w32(attrs + 3 * arch.ptr_size(), flags)
                    .unwrap();
                assert_eq!(
                    h.query("NtQueryAttributesFile", attrs, h.base),
                    expected,
                    "{arch}/{name}/{flags:#x}"
                );
            }
        }
        #[cfg(not(unix))]
        let _ = directory;
    }
}

#[test]
fn native_file_attributes_root_handles_retain_identity_and_native_name_rules() {
    for arch in WinArch::ALL {
        for directory in [false, true] {
            let mut h = Harness::new(arch);
            let host = if directory {
                h.directory.0.clone()
            } else {
                h.directory.0.join("fixture.bin")
            };
            let metadata = std::fs::metadata(&host).unwrap();
            let id = FileIdentity::of(&host, &metadata).unwrap();
            let p = h.process.state_mut();
            let object = p.objects.create(Object::File(FileObj {
                host: None,
                host_path: host,
                path: if directory {
                    "C:\\".into()
                } else {
                    "C:\\fixture.bin".into()
                },
                access: 0,
                share: 7,
                lifetime: Arc::new(FileLifetime::new(id)),
                null: false,
                append: false,
                delete_on_close: false,
                directory,
                overlapped: false,
            }));
            let root = p.objects.open_access(object, false, 0).unwrap();
            for (name, expected) in [
                ("", STATUS_SUCCESS),
                (
                    "fixture.bin",
                    if directory {
                        STATUS_SUCCESS
                    } else {
                        STATUS_OBJECT_PATH_NOT_FOUND
                    },
                ),
                ("\\??\\C:\\fixture.bin", STATUS_INVALID_PARAMETER),
            ] {
                h.name(name);
                let attrs = h.attrs();
                h.process
                    .state()
                    .space
                    .wptr(attrs + arch.ptr_size(), arch.ptr_size(), u64::from(root))
                    .unwrap();
                assert_eq!(
                    h.query("NtQueryAttributesFile", attrs, h.base),
                    expected,
                    "{arch}/{directory}/{name}"
                );
            }
            h.process
                .state_mut()
                .objects
                .close(u64::from(root))
                .unwrap();
            h.name("");
            let attrs = h.attrs();
            h.process
                .state()
                .space
                .wptr(attrs + arch.ptr_size(), arch.ptr_size(), u64::from(root))
                .unwrap();
            assert_eq!(
                h.query("NtQueryAttributesFile", attrs, h.base),
                STATUS_INVALID_HANDLE
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn native_file_attributes_mapped_root_alias_is_not_a_guest_reparse_component() {
    use crate::user::windows::nt::status::STATUS_REPARSE_POINT_ENCOUNTERED;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let alias = h.directory.0.join("mapped-root");
        std::os::unix::fs::symlink(&h.directory.0, &alias).unwrap();
        std::os::unix::fs::symlink(
            h.directory.0.join("fixture.bin"),
            h.directory.0.join("leaf-link.bin"),
        )
        .unwrap();
        Arc::make_mut(&mut h.process.state_mut().cfg)
            .drives
            .set('C', &alias);
        for (name, expected) in [
            ("fixture.bin", STATUS_SUCCESS),
            ("leaf-link.bin", STATUS_REPARSE_POINT_ENCOUNTERED),
        ] {
            h.name(&format!("\\??\\C:\\{name}"));
            let attrs = h.attrs();
            h.process
                .state()
                .space
                .w32(attrs + 3 * arch.ptr_size(), 0x1840)
                .unwrap();
            assert_eq!(
                h.query("NtQueryAttributesFile", attrs, h.base),
                expected,
                "{arch}/{name}"
            );
        }
    }
}

#[test]
fn native_file_attributes_empty_name_queries_retained_file_after_path_replacement() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let path = h.directory.0.join("fixture.bin");
        let file = std::fs::File::open(&path).unwrap();
        let identity = FileIdentity::of(&path, &file.metadata().unwrap()).unwrap();
        let p = h.process.state_mut();
        let object = p.objects.create(Object::File(FileObj {
            host: Some(file),
            host_path: path.clone(),
            path: "C:\\fixture.bin".into(),
            access: 0,
            share: 7,
            lifetime: Arc::new(FileLifetime::new(identity)),
            null: false,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        }));
        let handle = p.objects.open_access(object, false, 0).unwrap();
        std::fs::rename(&path, h.directory.0.join("renamed.bin")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        h.name("");
        let attrs = h.attrs();
        h.process
            .state()
            .space
            .wptr(attrs + arch.ptr_size(), arch.ptr_size(), u64::from(handle))
            .unwrap();
        assert_eq!(
            h.query("NtQueryFullAttributesFile", attrs, h.base),
            STATUS_SUCCESS
        );
        assert_eq!(h.process.state().space.u64(h.base + 40).unwrap(), 5);
        h.process
            .state_mut()
            .objects
            .close(u64::from(handle))
            .unwrap();
    }
}
