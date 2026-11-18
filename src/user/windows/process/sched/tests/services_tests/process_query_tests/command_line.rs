use super::super::registry_tests::call;
use super::{WinArch, setup};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

#[test]
fn native_process_command_line_uses_caller_width_and_preserves_unwritten_bytes() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, scratch) = setup(arch);
        let p = process.state_mut();
        let layout = offsets(arch);
        let width = layout.ptr;
        let header = 2 * width;
        let text: Vec<_> = r#""guest.exe" "space and λ🚀""#.encode_utf16().collect();
        let bytes = (text.len() * 2) as u16;
        let required = header + u64::from(bytes) + 2;
        let params = scratch + 0x200;
        let string = scratch + 0x800;
        p.params = params;
        if p.peb != 0 {
            p.space
                .wptr(p.peb + layout.peb_process_parameters, width, params)
                .unwrap();
        }
        p.space.put_wstr(string, &text).unwrap();
        let descriptor = params + layout.pp_command_line;
        p.space.w16(descriptor, bytes).unwrap();
        p.space.w16(descriptor + 2, bytes + 2).unwrap();
        p.space.wptr(descriptor + width, width, string).unwrap();
        let self_object = p.objects.create(Object::Process {
            pid: p.pid,
            exit_code: None,
        });
        let read = u64::from(p.objects.open_access(self_object, false, 0x1000).unwrap());
        let denied = u64::from(p.objects.open_access(self_object, false, 0x10).unwrap());
        let returned = scratch + 0x100;
        let current = arch.ptr(CURRENT_PROCESS);
        for length in [0, header - 1, required - 1] {
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    "NtQueryInformationProcess",
                    &[current, 60, scratch, length, returned],
                ),
                STATUS_INFO_LENGTH_MISMATCH
            );
        }
        assert_eq!(p.space.u32(returned).unwrap(), required as u32);
        assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xa5; 128]);

        for (handle, status) in [
            (denied, STATUS_ACCESS_DENIED),
            (0, STATUS_INVALID_HANDLE),
            (arch.ptr(CURRENT_THREAD), STATUS_OBJECT_TYPE_MISMATCH),
        ] {
            p.space.w32(returned, 4).unwrap();
            let status_observed = call(
                p,
                &mut thread,
                "NtQueryInformationProcess",
                &[handle, 60, scratch, required, returned],
            );
            assert_eq!(status_observed, status);
            assert_eq!(
                p.space.u32(returned).unwrap(),
                if width == 4 { 4u32.wrapping_sub(8) } else { 4 }
            );
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xa5; 128]);
        }
        for offset in 0..=4 {
            let status = if width == 8 && offset % 4 != 0 {
                STATUS_DATATYPE_MISALIGNMENT
            } else {
                STATUS_SUCCESS
            };
            p.space.wr(scratch, &[0xa5; 128]).unwrap();
            p.space.w32(returned, 0x1122_3344).unwrap();
            let out = scratch + offset;
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    "NtQueryInformationProcess",
                    &[read, 60, out, required + 16, returned],
                ),
                status
            );
            if status != STATUS_SUCCESS {
                assert_eq!(p.space.u32(returned).unwrap(), 0x1122_3344);
                assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xa5; 128]);
                continue;
            }
            assert_eq!(p.space.u32(returned).unwrap(), required as u32);
            assert_eq!(p.space.u16(out).unwrap(), bytes);
            assert_eq!(p.space.u16(out + 2).unwrap(), bytes + 2);
            if width == 8 {
                assert_eq!(p.space.u32(out + 4).unwrap(), 0xa5a5_a5a5);
            }
            assert_eq!(p.space.ptr(out + width, width).unwrap(), out + header);
            assert_eq!(p.space.wunits(out + header, text.len()).unwrap(), text);
            assert_eq!(p.space.u16(out + required - 2).unwrap(), 0);
            assert_eq!(p.space.u16(out + required).unwrap(), 0xa5a5);
        }
    }
}
