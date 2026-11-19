use super::*;
use crate::user::windows::objects::WindowStation;

fn service<const N: usize>(
    p: &mut Proc,
    t: &mut Thread,
    pc: u64,
    name: &str,
    values: [u64; N],
) -> u64 {
    let dispatch = super::super::super::super::super::services::dispatch;
    let index = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.win32u_services = Some((index, named_table(p.arch, name, 0x1001)));
    let sp = t.cpu.sp();
    t.cpu.set_pc(pc);
    match p.arch {
        WinArch::Arm64 => {
            for (index, value) in values.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
        WinArch::X64 => {
            for (index, value) in values.into_iter().enumerate() {
                if let Some(register) = [10, 2, 8, 9].get(index) {
                    t.cpu.set_gpr(*register, value);
                } else {
                    p.space
                        .w64(sp + 0x28 + 8 * (index - 4) as u64, value)
                        .unwrap();
                }
            }
        }
        WinArch::X86 => unreachable!(),
    }
    assert_eq!(dispatch(p, t, 0x1001, pc - 4), Some(Outcome::Continue));
    assert_eq!(t.cpu.sp(), sp);
    assert_eq!(t.cpu.pc(), pc);
    t.cpu.gpr(0)
}

#[test]
fn process_window_station_preserves_attachment_and_object_information_boundaries() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let (mut process, mut thread, entry) = setup(arch);
        let p = process.state_mut();
        let station = WindowStation::selected(
            "TestStation".encode_utf16().collect(),
            0x000f_037f,
            0,
            1,
            vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        )
        .unwrap();
        let expected = u64::from(p.objects.assign_window_station(station.clone()).unwrap());
        let Availability::Available(inputs) = &mut p.native.as_mut().unwrap().gui else {
            unreachable!();
        };
        std::sync::Arc::get_mut(inputs).unwrap().window_station = Ok(station.clone());
        let dispatch = super::super::super::super::super::services::dispatch;
        let resume = entry + 0x4000;
        let original_sp = thread.cpu.sp();
        thread.cpu.set_pc(resume);
        assert_eq!(
            dispatch(p, &mut thread, 0x12fd, resume - 4),
            Some(Outcome::Continue)
        );
        assert_eq!(thread.cpu.pc(), entry);
        arguments(p, &mut thread, [0, 0, 0]);
        assert_eq!(
            dispatch(p, &mut thread, 5, entry + 0x100),
            Some(Outcome::Continue)
        );
        assert_eq!(thread.cpu.sp(), original_sp);
        assert_eq!(thread.cpu.pc(), resume);

        let last_error = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        let status = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_status;
        let out = entry + 0x5000;
        let needed = out + 0x100;
        let text: Vec<_> = station
            .name
            .iter()
            .copied()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let bytes = text.len() as u64;
        let before = p.objects.handle_count();
        for _ in 0..2 {
            assert_eq!(
                service(p, &mut thread, resume, "NtUserGetProcessWindowStation", []),
                expected
            );
        }
        p.space.w32(last_error, 0x5aa5).unwrap();
        p.space.w32(status, 0xc000_0034).unwrap();
        p.space.wr(out, &[0xa5; 64]).unwrap();
        p.space.w64(needed, u64::MAX).unwrap();
        let object = "NtUserGetObjectInformation";
        assert_eq!(
            service(p, &mut thread, resume, object, [expected, 2, 0, 0, needed]),
            0
        );
        assert_eq!(p.space.u32(needed).unwrap(), bytes as u32);
        assert_eq!(p.space.u32(last_error).unwrap(), 122);
        assert_eq!(p.space.u32(status).unwrap(), 0xc000_0034);

        assert_eq!(
            service(
                p,
                &mut thread,
                resume,
                object,
                [expected | 1, 2, out, bytes, needed + 1]
            ),
            1
        );
        assert_eq!(p.space.bytes(out, bytes as usize).unwrap(), text);
        assert_eq!(p.space.u8(out + bytes).unwrap(), 0xa5);
        assert_eq!(p.space.u32(needed + 1).unwrap(), bytes as u32);
        assert_eq!(p.space.u32(last_error).unwrap(), 122);

        assert_eq!(
            service(
                p,
                &mut thread,
                resume,
                object,
                [expected, 1, out + 2, 11, needed]
            ),
            0
        );
        assert_eq!(p.space.u32(last_error).unwrap(), 998);
        assert_eq!(p.space.u32(status).unwrap(), 0x8000_0002);
        assert_eq!(
            service(p, &mut thread, resume, object, [expected, 2, 0, 1, needed]),
            0
        );
        assert_eq!(p.space.u32(status).unwrap(), 0xc000_0005);

        let close = "NtUserCloseWindowStation";
        assert_eq!(service(p, &mut thread, resume, close, [expected | 3]), 0);
        assert_eq!(p.space.u32(last_error).unwrap(), 170);
        assert_eq!(p.space.u32(status).unwrap(), 0x8000_0011);
        assert_eq!(p.objects.handle_count(), before);
        assert!(p.objects.close(expected).is_err());
        let duplicate = u64::from(p.objects.duplicate(expected, false).unwrap());
        assert_eq!(service(p, &mut thread, resume, close, [duplicate]), 1);
        assert_eq!(p.objects.handle_count(), before);
        assert_eq!(service(p, &mut thread, resume, close, [duplicate]), 0);
        assert_eq!(p.space.u32(status).unwrap(), 0xc000_0008);
    }
}
