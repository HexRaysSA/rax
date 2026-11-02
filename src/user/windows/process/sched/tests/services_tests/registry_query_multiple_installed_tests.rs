//! Real NTDLL leaves and x86 RET24, separate from whole-process startup.
use super::*;
use crate::user::windows::loader;
use crate::user::windows::memory::Mem;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn initialize(p: &mut Proc, base: u64, capacity: u32) {
    p.vm.protect(base, 65536, prot::READWRITE).unwrap();
    p.space.wr(base, &vec![0xA5; 65536]).unwrap();
    let stride = if p.arch.is64() { 24 } else { 16 };
    let name_stride = if p.arch.is64() { 16 } else { 8 };
    for (index, name) in ["One", "Three", "Five"].into_iter().enumerate() {
        let descriptor = base + 8192 + index as u64 * name_stride;
        unicode(p, descriptor, base + 12288 + index as u64 * 64, name);
        p.space
            .wptr(base + index as u64 * stride, p.arch.ptr_size(), descriptor)
            .unwrap();
    }
    p.space.w32(base + 49152, capacity).unwrap();
}

#[test]
fn native_query_multiple_value_key_installed_leaf_packing_faults_and_ret24() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else {
        WinArch::X64
    };
    for arch in [host, WinArch::X86] {
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
            WindowsConfig::embedded("C:\\native-query-multiple-values.exe", vec![], vec![], 4096)
                .unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let base =
            p.vm.allocate(None, 65536, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let before = (p.objects.handle_count(), p.objects.iter().count());
        let handles = input::handles(p);
        p.registry = Registry::default();
        let invoke = super::super::installed::invoke;
        let payload = [
            0x11, 0, 0, 0, 0x21, 0x22, 0x23, 0, 0x31, 0x32, 0x33, 0x34, 0x35,
        ];
        for (capacity, copied) in [(0, 0), (1, 4), (7, 8), (13, 13), (64, 13)] {
            initialize(p, base, capacity);
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    module,
                    "NtQueryMultipleValueKey",
                    &[
                        handles[0],
                        base,
                        3,
                        base + 32768,
                        base + 49152,
                        base + 53248,
                    ]
                ),
                if capacity < 13 {
                    STATUS_BUFFER_OVERFLOW
                } else {
                    STATUS_SUCCESS
                }
            );
            assert_eq!(p.space.u32(base + 49152).unwrap(), copied);
            assert_eq!(p.space.u32(base + 53248).unwrap(), 13);
            let mut expected = vec![0xA5; 128];
            expected[..copied as usize].copy_from_slice(&payload[..copied as usize]);
            assert_eq!(p.space.bytes(base + 32768, 128).unwrap(), expected);
            let stride = if arch.is64() { 24 } else { 16 };
            for (index, fields) in [[1, 0, 3], [3, 4, 3], [5, 8, 3]].into_iter().enumerate() {
                let expected = if fields[0] + fields[1] <= capacity {
                    fields
                } else {
                    [0; 3]
                };
                for (word, value) in expected.into_iter().enumerate() {
                    assert_eq!(
                        p.space
                            .u32(base + index as u64 * stride + arch.ptr_size() + word as u64 * 4)
                            .unwrap(),
                        value
                    );
                }
            }
        }
        initialize(p, base, 13);
        p.vm.protect(base + 49152, PAGE_SIZE, prot::READONLY)
            .unwrap();
        assert_eq!(
            invoke(
                p,
                &mut t,
                module,
                "NtQueryMultipleValueKey",
                &[
                    handles[0],
                    base,
                    3,
                    base + 32768,
                    base + 49152,
                    base + 53248,
                ]
            ),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(p.space.bytes(base + 32768, 13).unwrap(), payload);
        assert_eq!(p.space.u32(base + 53248).unwrap(), 13);
        assert_eq!(p.space.u32(base + arch.ptr_size()).unwrap(), 0xA5A5_A5A5);
        p.vm.protect(base + 49152, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        for index in [0, 3, 5, 6, 7] {
            assert_eq!(
                invoke(p, &mut t, module, "NtClose", &[handles[index]]),
                STATUS_SUCCESS
            );
        }
        assert_eq!((p.objects.handle_count(), p.objects.iter().count()), before);
    }
}
