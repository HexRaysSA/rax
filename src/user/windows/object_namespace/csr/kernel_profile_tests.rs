use super::{CsrMetadata, CsrServer};
use crate::user::windows::arch::WinArch;
use crate::user::windows::object_namespace::data::{DataRegion, DataSection};
use std::sync::Arc;

const PROFILE_29698: &str = include_str!(
    "../../../../../docs/specifications/windows/native-csr-kernel-profiles/profile-29698-v1.json"
);
const PROFILE_29704: &str = include_str!(
    "../../../../../docs/specifications/windows/native-csr-kernel-profiles/profile-29704-v1.json"
);

fn captured_profile(raw: &str) -> (Arc<DataSection>, CsrMetadata) {
    let capture: serde_json::Value = serde_json::from_str(raw).unwrap();
    let row = capture["metadata_samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["architecture"] == "arm64" && row["kind"] == "metadata2")
        .unwrap();
    let geometry = &capture["shared_section"][0];
    let native_prefix = row["selected_prefix_hex"].as_str().unwrap();
    let mut prefix: Vec<_> = (0..native_prefix.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&native_prefix[at..at + 2], 16).unwrap())
        .collect();
    // Only the independently captured header participates in this constructor
    // test. Padding the unused bytes is not replay of the whole native view.
    prefix.resize(
        geometry["regions"][0]["bytes"].as_u64().unwrap() as usize,
        0,
    );
    let section = DataSection::selected(
        0x20004,
        crate::user::windows::nt::status::STATUS_PRIVILEGE_NOT_HELD,
        false,
        geometry["view_bytes"].as_u64().unwrap(),
        vec![
            DataRegion {
                offset: geometry["regions"][0]["offset"].as_u64().unwrap(),
                size: geometry["regions"][0]["bytes"].as_u64().unwrap(),
                bytes: Some(prefix.into()),
            },
            DataRegion {
                offset: geometry["regions"][1]["offset"].as_u64().unwrap(),
                size: geometry["regions"][1]["bytes"].as_u64().unwrap(),
                bytes: None,
            },
        ],
    )
    .unwrap();
    let metadata = CsrMetadata {
        arch: WinArch::Arm64,
        kernel: (
            row["kernel"][0].as_u64().unwrap() as u32,
            row["kernel"][1].as_u64().unwrap() as u32,
            row["kernel"][2].as_u64().unwrap() as u32,
        ),
        session: row["session"].as_u64().unwrap() as u32,
        server_base: row["server_base"].as_u64().unwrap(),
        statics_offset: row["statics_offset"].as_u64().unwrap(),
        server_pid: row["server_pid"].as_u64().unwrap() as u32,
    };
    (section, metadata)
}

#[test]
fn csr_kernel_profile_selects_independently_captured_29698_metadata_and_geometry() {
    let (section, metadata) = captured_profile(PROFILE_29698);
    assert_eq!(metadata.kernel, (10, 0, 29698));
    assert_eq!(metadata.session, 0);
    assert_eq!(metadata.statics_offset, 0x750);
    let expected_base = metadata.server_base;
    let expected_pid = metadata.server_pid;
    let server = CsrServer::selected(section.clone(), metadata).unwrap();
    assert!(Arc::ptr_eq(&section, &server.section()));
    assert_eq!(server.metadata.server_base, expected_base);
    assert_eq!(server.metadata.server_pid, expected_pid);
    assert_eq!(server.metadata.kernel, (10, 0, 29698));
}

#[test]
fn csr_kernel_profile_selects_independently_captured_29704_session1_metadata_and_geometry() {
    let (section, metadata) = captured_profile(PROFILE_29704);
    assert_eq!(metadata.kernel, (10, 0, 29704));
    assert_eq!(metadata.session, 1);
    assert_eq!(metadata.statics_offset, 0x750);
    assert_eq!(
        String::from_utf16(&metadata.port_path()).unwrap(),
        r"\Sessions\1\Windows\ApiPort"
    );
    let expected_base = metadata.server_base;
    let expected_pid = metadata.server_pid;
    let server = CsrServer::selected(section.clone(), metadata).unwrap();
    assert!(Arc::ptr_eq(&section, &server.section()));
    assert_eq!(server.metadata.server_base, expected_base);
    assert_eq!(server.metadata.server_pid, expected_pid);
    assert_eq!(server.metadata.kernel, (10, 0, 29704));
}

#[test]
fn csr_kernel_profile_29704_refuses_adjacent_builds_and_changed_native_identity() {
    let (section, metadata) = captured_profile(PROFILE_29704);
    for (major, minor, build, arch, pid, statics_offset) in [
        (10, 0, 29703, WinArch::Arm64, metadata.server_pid, 0x750),
        (10, 0, 29705, WinArch::Arm64, metadata.server_pid, 0x750),
        (11, 0, 29704, WinArch::Arm64, metadata.server_pid, 0x750),
        (10, 1, 29704, WinArch::Arm64, metadata.server_pid, 0x750),
        (10, 0, 29704, WinArch::X64, metadata.server_pid, 0x750),
        (10, 0, 29704, WinArch::X86, metadata.server_pid, 0x750),
        (10, 0, 29704, WinArch::Arm64, 0, 0x750),
        (10, 0, 29704, WinArch::Arm64, metadata.server_pid, 0x751),
    ] {
        let changed = CsrMetadata {
            arch,
            kernel: (major, minor, build),
            server_pid: pid,
            statics_offset,
            ..metadata.clone()
        };
        assert!(CsrServer::selected(section.clone(), changed).is_err());
    }
}

#[test]
fn csr_kernel_profile_refuses_adjacent_builds_and_foreign_architecture() {
    let (section, metadata) = captured_profile(PROFILE_29698);
    for (major, minor, build, session, arch) in [
        (10, 0, 29697, 0, WinArch::Arm64),
        (10, 0, 29699, 0, WinArch::Arm64),
        (11, 0, 29698, 0, WinArch::Arm64),
        (10, 1, 29698, 0, WinArch::Arm64),
        (10, 0, 29698, 0, WinArch::X64),
        (10, 0, 29698, 0, WinArch::X86),
    ] {
        let changed = CsrMetadata {
            arch,
            kernel: (major, minor, build),
            session,
            ..metadata.clone()
        };
        assert!(CsrServer::selected(section.clone(), changed).is_err());
    }
}
