//! Installed ten-slot NTDLL entry and actual x86 RET40 cleanup.
use super::*;
use crate::user::windows::loader;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};
use crate::user::windows::registry::MACHINE_HIVE_KEY;

#[test]
fn installed_notify_key_leaf_consumes_ten_slots_and_completes_pending_lifetimes() {
    let native_arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else {
        WinArch::X64
    };
    for arch in [native_arch, WinArch::X86] {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-notify-key.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let base =
            p.vm.allocate(
                None,
                PAGE_SIZE * 2,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let attrs = base + 128;
        unicode(p, attrs + 64, base + 256, MACHINE_HIVE_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x40);
        for filter in [1, 0x10000001] {
            assert_eq!(
                super::super::installed::invoke(
                    p,
                    &mut t,
                    module,
                    "NtOpenKeyEx",
                    &[base, 0x20019, attrs, 0]
                ),
                STATUS_SUCCESS
            );
            let key = p.space.ptr(base, arch.ptr_size()).unwrap();
            let duplicate = u64::from(p.objects.duplicate(key, false).unwrap());
            let event = p.objects.insert(Object::Event {
                manual: true,
                signaled: 1,
            }) as u64;
            let io = base + PAGE_SIZE;
            p.space
                .wr(io, &vec![0xcc; arch.ptr_size() as usize * 2])
                .unwrap();
            assert_eq!(
                super::super::installed::invoke(
                    p,
                    &mut t,
                    module,
                    "NtNotifyChangeKey",
                    &[
                        key | 3,
                        event | 1,
                        0,
                        0,
                        if filter == 1 { io } else { 0 },
                        filter,
                        0,
                        0,
                        0,
                        1
                    ]
                ),
                STATUS_PENDING
            );
            assert!(matches!(
                p.objects.get(event),
                Some(Object::Event { signaled: 0, .. })
            ));
            assert_eq!(
                super::super::installed::invoke(p, &mut t, module, "NtClose", &[key]),
                0
            );
            assert!(matches!(
                p.objects.get(event),
                Some(Object::Event { signaled: 0, .. })
            ));
            assert_eq!(
                super::super::installed::invoke(p, &mut t, module, "NtClose", &[duplicate]),
                0
            );
            assert!(matches!(
                p.objects.get(event),
                Some(Object::Event { signaled: 1, .. })
            ));
            if filter == 1 {
                assert_eq!(p.space.u32(io).unwrap(), 0x10b);
                assert_eq!(
                    p.space.ptr(io + arch.ptr_size(), arch.ptr_size()).unwrap(),
                    0
                );
            } else {
                assert_eq!(
                    p.space.bytes(io, arch.ptr_size() as usize * 2).unwrap(),
                    vec![0xcc; arch.ptr_size() as usize * 2]
                );
            }
            assert_eq!(
                super::super::installed::invoke(p, &mut t, module, "NtClose", &[event]),
                0
            );
            assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
        }
    }
}
