//! Modern process-parameter fields must never alias the following heap strings.
//! Sizes/tail offsets come from the independently compiled PHNT layout and the
//! suspended-child observations in specifications/windows/native-process-parameters.

use super::*;
use crate::user::windows::process::WindowsProcess;

#[test]
fn modern_parameter_tail_is_zero_and_disjoint_from_strings_all_abis() {
    for arch in WinArch::ALL {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        for image_path in ["C:\\app\\probe.exe", "C:\\long directory\\program name.exe"] {
            let mut config =
                WindowsConfig::embedded(image_path, vec!["a b".into(), "tail\\".into()], vec![], 0)
                    .unwrap();
            config.seed = Some(1);
            config.env = Some(vec![("TEST".into(), "value".into())]);
            config.arena_bytes = 64 << 20;
            config.cwd = Some("C:\\working directory\\".into());
            let process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
            let p = process.state();
            let o = offsets(arch);
            let (tail, extent, partition) = if arch.is64() {
                (0x410, 0x448, 0x420)
            } else {
                (0x2A4, 0x2C4, 0x2AC)
            };
            assert_eq!(p.space.u32(p.params + o.pp_length).unwrap(), extent);
            assert_eq!(p.space.u32(p.params + o.pp_maximum_length).unwrap(), extent);
            assert_eq!(
                p.space
                    .bytes(p.params + tail, (extent as u64 - tail) as usize)
                    .unwrap(),
                vec![0; (extent as u64 - tail) as usize]
            );
            assert_eq!(p.space.u16(p.params + partition).unwrap(), 0);
            assert_eq!(p.space.ptr(p.params + partition + o.ptr, o.ptr).unwrap(), 0);
            for field in [
                o.pp_current_directory,
                o.pp_image_path_name,
                o.pp_command_line,
                o.pp_dll_path,
            ] {
                let length = u64::from(p.space.u16(p.params + field).unwrap()) + 2;
                let buffer = p.space.ptr(p.params + field + o.ptr, o.ptr).unwrap();
                assert!(
                    buffer + length <= p.params || buffer >= p.params + u64::from(extent),
                    "{arch}: string {field:#x} aliases process-parameter tail"
                );
            }
            let image_buffer = p
                .space
                .ptr(p.params + o.pp_image_path_name + o.ptr, o.ptr)
                .unwrap();
            assert_eq!(
                p.space.wstr(image_buffer, 256).unwrap(),
                image_path.encode_utf16().collect::<Vec<_>>()
            );
        }
    }
}
