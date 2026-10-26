use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess, thread};

fn process() -> WindowsProcess {
    let mut config = WindowsConfig::embedded("C:\\wow64-state.exe", vec![], vec![], 4096).unwrap();
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(
        config,
        include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe").to_vec(),
    )
    .unwrap()
}

fn profile(software: bool) -> Profile {
    Profile {
        machine: if software { 0xaa64 } else { 0x8664 },
        flags: if software { 2 } else { 1 },
        information_offset: if software { 0x490 } else { 0x488 },
    }
}

fn child(p: &mut Proc) -> u32 {
    thread::create(p, p.modules.exe().entry, 0, 0x10000, false).unwrap()
}

fn inventory(
    p: &Proc,
) -> Vec<(
    u64,
    u64,
    crate::user::windows::memory::AllocKind,
    std::collections::BTreeMap<u64, crate::user::windows::memory::PageState>,
)> {
    p.vm.allocations()
        .map(|a| (a.base, a.size, a.kind, a.pages.clone()))
        .collect()
}

#[test]
fn wow64_startup_29695_profile_matches_native_threads_and_rejects_unknown_kernels() {
    let capture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/specifications/windows/native-wow64-startup-information/local-29695-v1.json"
    )).unwrap();
    let mut count = 0;
    for sample in capture["samples"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|sample| sample["kind"] == "information")
    {
        for row in sample["rows"].as_array().unwrap() {
            let version = super::super::WinVersion {
                major: 10,
                minor: 0,
                build: row["build"].as_u64().unwrap() as u32,
                ..Default::default()
            };
            let selected =
                Profile::kernel(&version, row["native_machine"].as_u64().unwrap() as u16).unwrap();
            assert_eq!(
                u64::from(selected.flags),
                row["information_words"][1].as_u64().unwrap()
            );
            assert_eq!(
                selected.information_offset,
                row["information_minus_peb32"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(selected.machine),
                row["information_native_machine"].as_u64().unwrap()
            );
            count += 1;
        }
    }
    assert_eq!(count, 4);
    for (major, minor, build, machine) in [
        (10, 0, 29682, 0xaa64),
        (10, 0, 29684, 0xaa64),
        (10, 0, 29694, 0xaa64),
        (10, 0, 29696, 0xaa64),
        (10, 1, 29695, 0xaa64),
        (11, 0, 29695, 0xaa64),
        (10, 0, 29695, 0x8664),
        (10, 0, 29695, 0x14c),
    ] {
        let version = super::super::WinVersion {
            major,
            minor,
            build,
            ..Default::default()
        };
        assert!(matches!(
            Profile::kernel(&version, machine),
            Err(STATUS_NOT_SUPPORTED)
        ));
    }
}

#[test]
fn wow64_startup_native_profiles_have_owned_information_and_work_sections() {
    for software in [false, true] {
        let mut process = process();
        let p = process.state_mut();
        initialize_profile(p, profile(software)).unwrap();
        let information = p.wow64.as_ref().unwrap().information;
        assert_eq!(information, p.peb + if software { 0x490 } else { 0x488 });
        assert_eq!(p.space.u32(information).unwrap(), 4096);
        assert_eq!(
            p.space.u32(information + 4).unwrap(),
            if software { 2 } else { 1 }
        );
        assert_eq!(p.space.u32(information + 8).unwrap(), 0);
        assert_eq!(
            p.space.u16(information + 32).unwrap(),
            if software { 0xaa64 } else { 0x8664 }
        );
        assert_eq!(p.space.u16(information + 34).unwrap(), 0x14c);
        let handle = p.space.u64(information + 16).unwrap();
        let work = p.space.u64(information + 24).unwrap();
        if software {
            assert_ne!(handle, 0);
            assert_ne!(work, 0);
            assert_eq!(p.objects.access(handle), Some(0xf001f));
            let shared = match p.objects.get(handle).unwrap() {
                Object::Mapping {
                    size,
                    protect,
                    attributes,
                    shared: Some(shared),
                    ..
                } => {
                    assert_eq!((*size, *protect, *attributes), (16384, 4, 0x08000000));
                    shared.clone()
                }
                _ => panic!("startup section must have ordinary owned section semantics"),
            };
            assert_eq!(p.space.u32(work).unwrap(), 16328);
            assert_eq!(p.space.u32(work + 4).unwrap(), 408);
            assert_eq!(p.space.bytes(work + 8, 40).unwrap(), [0; 40]);
            let mut next = p.space.u32(work).unwrap();
            let mut seen = std::collections::BTreeSet::new();
            while next != 0 {
                assert!(next >= 48 && u64::from(next) + 40 <= 16384);
                assert_eq!((next - 48) % 40, 0);
                assert!(seen.insert(next), "free-list cycle");
                next = p.space.u32(work + u64::from(next)).unwrap();
            }
            assert_eq!(seen.len(), 408);
            let alias = p.vm.map_shared_view(shared, None, 0, 16384).unwrap();
            p.space.w32(alias.base + 12, 17).unwrap();
            assert_eq!(p.space.u32(work + 12).unwrap(), 17);
            p.objects.close(handle).unwrap();
            assert_eq!(p.space.u32(work + 12).unwrap(), 17);
            p.vm.release(alias.base).unwrap();
        } else {
            assert_eq!((handle, work), (0, 0));
        }
    }
}

#[test]
fn wow64_startup_threads_share_information_and_keep_application_tls_separate() {
    let mut process = process();
    let p = process.state_mut();
    initialize_profile(p, profile(true)).unwrap();
    let information = p.wow64.as_ref().unwrap().information;
    let native_peb = p.wow64.as_ref().unwrap().native_peb;
    let first = child(p);
    let second = child(p);
    for id in [first, second] {
        let thread = &p.threads[&id];
        let native = thread.teb - 8192;
        assert_eq!(p.space.u32(thread.teb + 0xfdc).unwrap() as i32, -8192);
        assert_eq!(p.space.u32(native + 0x180c).unwrap(), 8192);
        assert_eq!(p.space.u64(native).unwrap(), thread.teb);
        assert_eq!(p.space.u64(native + 0x30).unwrap(), native);
        assert_eq!(p.space.u64(native + 0x40).unwrap(), u64::from(p.pid));
        assert_eq!(p.space.u64(native + 0x48).unwrap(), u64::from(id));
        assert_eq!(p.space.u64(native + 0x60).unwrap(), native_peb);
        assert_eq!(p.space.u64(native + 0x14d0).unwrap(), information);
        assert_eq!(p.space.u32(thread.teb + 0xe38).unwrap(), 0);
        p.space.w32(thread.teb + 0xe38, 0x12345678).unwrap();
        assert_eq!(p.space.u64(native + 0x14d0).unwrap(), information);
    }
    let first = p.threads.remove(&first).unwrap();
    let base = first.teb - 8192;
    p.space.w32(first.teb + 0xfdc, 0x7fffffff).unwrap();
    p.space.w64(base + 0x30, 0).unwrap();
    thread::destroy(p, first, 0);
    for page in [base, base + 4096, base + 8192] {
        assert_eq!(p.vm.query(page).unwrap().state, mem::RESERVE);
    }
    let second = &p.threads[&second];
    assert_eq!(
        p.space.u64(second.teb - 8192 + 0x14d0).unwrap(),
        information
    );
    assert_eq!(p.space.u32(information).unwrap(), 4096);
}

#[test]
fn wow64_startup_active_teb_claim_survives_guest_decommit_and_scheduler_extraction() {
    let mut process = process();
    let p = process.state_mut();
    initialize_profile(p, profile(false)).unwrap();
    let first_id = child(p);
    let first = p.threads.remove(&first_id).unwrap();
    let base = first.teb - 8192;
    p.vm.decommit(base, 12288).unwrap();
    let second_id = child(p);
    assert_ne!(first.teb, p.threads[&second_id].teb);
    let second_teb = p.threads[&second_id].teb;
    p.space.w32(second_teb + 0xe38, 0x5a5a5a5a).unwrap();
    thread::destroy(p, first, 0);
    assert_eq!(p.space.u32(second_teb + 0xe38).unwrap(), 0x5a5a5a5a);
}

#[test]
fn wow64_startup_teb_teardown_preserves_replacement_allocation() {
    let mut process = process();
    let p = process.state_mut();
    initialize_profile(p, profile(false)).unwrap();
    let id = child(p);
    let thread = p.threads.remove(&id).unwrap();
    let teb = thread.teb;
    p.vm.release(crate::user::windows::layout::SYSTEM_AREA)
        .unwrap();
    p.vm.allocate(
        Some(crate::user::windows::layout::SYSTEM_AREA),
        crate::user::windows::layout::SYSTEM_AREA_END - crate::user::windows::layout::SYSTEM_AREA,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    p.space.w32(teb, 0xcafebabe).unwrap();
    thread::destroy(p, thread, 0);
    assert_eq!(p.space.u32(teb).unwrap(), 0xcafebabe);
    assert!(thread::teb::Allocation::allocate(p).is_err());
}

#[test]
fn wow64_startup_failed_thread_creation_releases_the_complete_companion_extent() {
    let mut process = process();
    let p = process.state_mut();
    initialize_profile(p, profile(false)).unwrap();
    let before = inventory(p);
    let committed = p.vm.committed_bytes();
    let objects = p.objects.iter_mut().count();
    assert_eq!(
        thread::create(p, p.modules.exe().entry, 0, u64::MAX, false),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(p.vm.committed_bytes(), committed);
    assert_eq!(inventory(p), before);
    assert_eq!(p.objects.iter_mut().count(), objects);
    let id = child(p);
    assert_eq!(
        p.space.u32(p.threads[&id].teb + 0xfdc).unwrap() as i32,
        -8192
    );
}

#[test]
fn wow64_startup_failed_information_publication_rolls_back_section_and_memory() {
    let mut process = process();
    let p = process.state_mut();
    p.vm.protect(p.peb, 4096, prot::READONLY).unwrap();
    let before = inventory(p);
    let objects = p.objects.iter_mut().count();
    let committed = p.vm.committed_bytes();
    assert_eq!(initialize_profile(p, profile(true)), Err(STATUS_NO_MEMORY));
    assert!(p.wow64.is_none());
    assert_eq!(inventory(p), before);
    assert_eq!(p.vm.committed_bytes(), committed);
    assert_eq!(p.objects.iter_mut().count(), objects);
}
