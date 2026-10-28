//! Replay real thread-opening grants through their existing Win32 consumers.
use super::*;
use serde_json::Value;

fn replay(text: &str, arch_count: usize) {
    let receipt: Value = serde_json::from_str(text).unwrap();
    assert_eq!(receipt["state"], "finished");
    let rows = receipt["cases"].as_array().unwrap();
    assert_eq!(rows.len(), arch_count);
    let mut compared = 0;
    for row in rows {
        assert_eq!(row["exit_code"], 0);
        let arch = match row["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown architecture {other}"),
        };
        let observations = row["observations"].as_array().unwrap();
        assert_eq!(observations.len(), 6);
        for observed in observations {
            let value = |name: &str| observed[name].as_u64().unwrap();
            with_context(arch, |c, data| {
                let original = integer(c, "CreateThread", &[0, 0, 0x1000, 0, 4, data + 32]);
                assert_ne!(original, 0);
                let tid = c.mem().u32(data + 32).unwrap();
                let width = arch.ptr_size();
                let oa = data + 128;
                let cid = data + 256;
                let size = if width == 4 { 24 } else { 48 };
                c.mem().wr(oa, &vec![0; size]).unwrap();
                c.mem().w32(oa, size as u32).unwrap();
                c.mem().wptr(cid, width, c.p.pid.into()).unwrap();
                c.mem().wptr(cid + width, width, tid.into()).unwrap();
                assert_eq!(
                    integer(c, "NtOpenThread", &[data, value("access"), oa, cid]),
                    0
                );
                let opened = c.mem().ptr(data, width).unwrap();
                assert_eq!(c.p.objects.id(opened), c.p.objects.id(original));
                assert_eq!(c.p.objects.access(opened), Some(value("grant") as u32));
                c.set_last_error(0x1234_5678).unwrap();
                assert_eq!(integer(c, "SuspendThread", &[opened]), value("suspended"));
                assert_eq!(u64::from(c.last_error().unwrap()), value("suspend_error"));
                c.set_last_error(0x1234_5678).unwrap();
                assert_eq!(integer(c, "ResumeThread", &[opened]), value("resumed"));
                assert_eq!(u64::from(c.last_error().unwrap()), value("resume_error"));
                let count = c.p.threads[&tid].suspend;
                assert_eq!(
                    count,
                    u32::from(value("suspended") != u64::from(u32::MAX))
                        + u32::from(value("resumed") == u64::from(u32::MAX))
                );
                for previous in (1..=count).rev() {
                    assert_eq!(integer(c, "ResumeThread", &[original]), u64::from(previous));
                }
                assert_eq!(c.p.threads[&tid].suspend, 0);
                c.p.objects.close(opened).unwrap();
                c.p.objects.close(original).unwrap();
            });
            compared += 1;
        }
    }
    assert_eq!(compared, 6 * arch_count);
}

#[test]
fn native_thread_open_resume_only_and_generic_execute_match_native_consumers() {
    replay(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-open-thread/resume-observations-arm64-29695-v1.json"
        )),
        3,
    );
    if let Some(path) = std::env::var_os("RAX_NATIVE_THREAD_RESUME_OBSERVATIONS") {
        replay(&std::fs::read_to_string(path).unwrap(), 2);
    }
}
