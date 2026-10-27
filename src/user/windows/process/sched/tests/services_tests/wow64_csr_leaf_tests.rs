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
    let native_kernel = p.wow64.as_ref().unwrap().kernel;
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let b =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space
        .put_wstr(b, &"\\Windows".encode_utf16().collect::<Vec<_>>())
        .unwrap();
    p.space.wr(b + 4096, &[0xa5; 80]).unwrap();
    p.space.w8(b + 8192, 0xa5).unwrap();
    let before = p.objects.handle_count();
    let result =
        super::super::secure_connect_tests::installed::try_leaf(p, &mut thread, NAME, &args(b));
    if native_kernel != (10, 0, 29695) {
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
    assert_eq!(
        super::super::secure_connect_tests::installed::leaf(p, &mut thread, NAME, &args(b)),
        STATUS_ACCESS_VIOLATION
    );
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0xa5);
}
