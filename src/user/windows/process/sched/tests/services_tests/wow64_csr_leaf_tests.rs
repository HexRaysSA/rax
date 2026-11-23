//! Execute the installed pure x86 NTDLL leaf and its own RET20 cleanup.
use super::*;
use crate::user::windows::process::WindowsConfig;

#[test]
fn wow64_csr_installed_x86_leaf_publishes_owned_connection_and_returns_with_ret20() {
    let image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe");
    let mut config =
        WindowsConfig::embedded("C:\\native-wow64-csr.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let state = p.wow64.as_ref().unwrap();
    let native_kernel = state.kernel;
    let machine = state.machine;
    let session = state.session;
    let directory = if session == 0 {
        "\\Windows".to_owned()
    } else {
        format!("\\Sessions\\{session}\\Windows")
    };
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let b =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space
        .put_wstr(b, &directory.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    p.space.wr(b + 4096, &[0xa5; 80]).unwrap();
    p.space.w8(b + 8192, 0xa5).unwrap();
    let before = p.objects.handle_count();
    let result =
        super::super::secure_connect_tests::installed::try_leaf(p, &mut thread, NAME, &args(b));
    let measured = matches!(
        (machine, native_kernel, session),
        (0xaa64, (10, 0, 29695 | 29698 | 29704), _)
            | (0xaa64, (10, 0, 29708), 1)
            | (0xaa64, (10, 0, 26200), 2)
            | (0x8664, (10, 0, 20348 | 26100), _)
    );
    if !measured {
        assert!(matches!(result, Err(reason) if reason.contains("WoW64 CSR")));
        assert_eq!(p.objects.handle_count(), before);
        assert!(p.wow64.as_ref().unwrap().csr.is_none());
        return;
    }
    assert_eq!(result.unwrap(), STATUS_SUCCESS);
    assert_eq!(p.objects.handle_count(), before + 1);
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0);
    assert_eq!(p.space.bytes(b + 4096, 80).unwrap(), [0xa5; 80]);
    publication(p, true);
    p.vm.protect(b + 4096, 4096, prot::READONLY).unwrap();
    p.space.w8(b + 8192, 0xa5).unwrap();
    let retry =
        super::super::secure_connect_tests::installed::try_leaf(p, &mut thread, NAME, &args(b));
    if (machine, native_kernel) == (0xaa64, (10, 0, 26200)) {
        assert!(matches!(retry, Err(reason) if reason.contains("measured first BASE call")));
        assert_eq!(p.objects.handle_count(), before + 1);
    } else {
        assert_eq!(retry.unwrap(), STATUS_ACCESS_VIOLATION);
    }
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0xa5);
}

#[test]
#[ignore = "requires the released Windows images and current-session BASE capture"]
fn wow64_base_nls_installed_kernelbase_leaf_copies_the_selected_snapshot() {
    use crate::user::windows::fs::{FileIdentity, FileLifetime};
    use crate::user::windows::object_namespace::{
        ImageSection,
        csr::{BASE_NLS_BYTES, BaseNlsReply},
        file_image,
    };

    let image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe");
    let mut config =
        WindowsConfig::embedded("C:\\native-wow64-base-nls.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let state = p.wow64.as_ref().unwrap();
    let (leaf, parent, output) = match (state.machine, state.kernel) {
        (0x8664, (10, 0, 20348)) => (0x15_5090, 0x12_bde7, 0x21_1f2c),
        (0x8664, (10, 0, 26100)) => (0x16_b660, 0x13_2c91, 0x27_210c),
        (0xaa64, (10, 0, 26200)) => (0x17_6450, 0x16_e1ed, 0x28_914c),
        identity => panic!("expected released x86 process profile, received {identity:?}"),
    };
    let server = p.object_namespace.selected_csr_server().unwrap();
    let directory = server.metadata.directory_path();
    let Some(BaseNlsReply::Information(snapshot)) = &server.base_nls else {
        panic!("the current-session BASE NLS capture is missing");
    };

    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let scratch =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space.put_wstr(scratch, &directory).unwrap();
    let status = super::super::secure_connect_tests::installed::try_leaf(
        p,
        &mut thread,
        NAME,
        &args(scratch),
    );
    assert_eq!(status.unwrap(), STATUS_SUCCESS);

    // The ordinary module loader can map pure x86 DLL bytes without a section
    // view. Private services are admitted only from the selected file identity
    // retained by a native image section, as when installed NTDLL maps it.
    let runtime = p.native.as_ref().unwrap();
    let path = runtime.dll("kernelbase.dll").unwrap().unwrap();
    let file = std::fs::File::open(path).unwrap();
    let identity = FileIdentity::retained(&file).unwrap();
    let backing = file_image::acquire(&file, 0, prot::READONLY, 0x0100_0000, true).unwrap();
    let section = ImageSection::created(backing, Arc::new(FileLifetime::new(identity)), None);
    let image = section.image_for(WinArch::X86).unwrap();
    let size = image.allocation_size();
    let base = if p.vm.is_free(image.preferred, size) {
        image.preferred
    } else {
        0x5300_0000
    };
    p.vm.map_section_image(
        section,
        &image,
        base,
        base,
        size,
        0,
        image.bytes.len() as u64,
        false,
        true,
    )
    .unwrap();
    assert!(p.vm.section_view(base + leaf + 12).is_some());
    let destination = base + output;
    let copy = [0x5a; BASE_NLS_BYTES];
    assert_ne!(copy.as_slice(), snapshot.as_slice());
    p.space.wr(destination, &copy).unwrap();
    // Place the guest at the transition to observe the service and the
    // installed leaf's RET separately from KernelBase process initialization.
    let sp = thread.cpu.sp() - 128;
    let transition = p.traps.wow64_transition();
    let resume = base + leaf + 12;
    p.space.w32(sp - 4, resume as u32).unwrap();
    p.space.w32(sp, (base + parent) as u32).unwrap();
    p.space.w32(sp + 4, destination as u32).unwrap();
    p.space.w32(sp + 8, BASE_NLS_BYTES as u32).unwrap();
    thread.cpu.set_gpr(0, 0x300b);
    thread.cpu.set_sp(sp - 4);
    thread.cpu.set_pc(transition);
    let stop = run_cpu(p, &mut thread.cpu, 1);
    assert!(matches!(stop, CpuStop::Fault(_)));
    let outcome = handle_stop(p, &mut thread, stop);
    assert_eq!(outcome, Outcome::Continue, "installed KernelBase BASE NLS");
    assert_eq!(thread.cpu.pc(), resume);
    assert_eq!(thread.cpu.sp(), sp);
    assert_eq!(thread.cpu.gpr(0) as u32, STATUS_SUCCESS);
    run_cpu(p, &mut thread.cpu, 1);
    assert_eq!(thread.cpu.pc(), base + parent);
    assert_eq!(thread.cpu.sp(), sp + 12, "KernelBase owns its RET8");
    assert_eq!(thread.cpu.gpr(0) as u32, STATUS_SUCCESS);
    assert!(thread.frames.is_empty());
    assert_eq!(
        p.space.bytes(destination, BASE_NLS_BYTES).unwrap(),
        snapshot.as_slice()
    );
    eprintln!("Validated installed KernelBase WoW64 BASE NLS leaf, owned snapshot and RET8");
}
