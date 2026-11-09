//! File-view reservations retain the existing conservative charge policy.
use super::*;
use crate::user::windows::object_namespace::FileSection;

#[test]
fn memory_usage_file_views_charge_commitment_without_pagefile_shared_bytes() {
    for arch in WinArch::ALL {
        let (mut process, _) = fixture(arch, "NtMapViewOfSection", 0x28);
        let p = process.state_mut();
        let initial = p.vm.memory_usage().unwrap();
        let file = FileCase::new(8192);
        let section = FileSection::create(
            file.writer.as_ref().unwrap(),
            file.lifetime.clone(),
            0,
            prot::READWRITE,
            None,
        )
        .unwrap();
        assert_eq!(p.vm.memory_usage().unwrap(), initial);
        p.vm.map_file_section(section.clone(), 0x4000_0000, 0, 8192, prot::READWRITE)
            .unwrap();
        let first = p.vm.memory_usage().unwrap();
        assert_eq!(first.committed_bytes, initial.committed_bytes + 8192);
        assert_eq!(first.shared_committed_bytes, initial.shared_committed_bytes);
        assert_eq!(
            first.peak_commitment_bytes,
            initial.peak_commitment_bytes.max(first.committed_bytes)
        );
        // Conflicting address admission must not publish a speculative peak.
        assert!(
            p.vm.map_file_section(section.clone(), 0x4000_0000, 0, 8192, prot::READWRITE)
                .is_err()
        );
        assert_eq!(p.vm.memory_usage().unwrap(), first);
        p.vm.map_file_section(section, 0x4100_0000, 0, 8192, prot::WRITECOPY)
            .unwrap();
        let second = p.vm.memory_usage().unwrap();
        assert_eq!(second.committed_bytes, initial.committed_bytes + 16384);
        assert_eq!(
            second.shared_committed_bytes,
            initial.shared_committed_bytes
        );
        p.vm.release(0x4000_0000).unwrap();
        p.vm.release(0x4100_0000).unwrap();
        let retired = p.vm.memory_usage().unwrap();
        assert_eq!(retired.committed_bytes, initial.committed_bytes);
        assert_eq!(retired.peak_commitment_bytes, second.peak_commitment_bytes);
    }
}
