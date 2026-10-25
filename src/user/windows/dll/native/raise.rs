//! `NtRaiseException`: dispatch the caller-supplied record and context.

use crate::user::windows::context::{ExceptionRecord, RegContext};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};

pub(super) fn raise(c: &mut Ctx) -> ApiResult {
    let (record, context) = (c.ptr(0)?, c.ptr(1)?);
    let record = ExceptionRecord::read(&c.p.space, c.p.arch, record)?;
    // Capture both inputs before deciding delivery. Native second-chance
    // raises still reject unreadable records and contexts.
    let context = RegContext::read(&c.p.space, c.p.arch, context)?;
    // FirstChance is BOOLEAN, not the four-byte Win32 BOOL. A second-chance
    // raise has already exhausted user handlers; redispatching it can repeat
    // a failed unwind indefinitely.
    if c.arg(2)? as u8 == 0 {
        return Ok(Flow::TerminateProcess(record.code));
    }
    // The supplied context can describe an earlier fault rather than this
    // export's caller frontier.
    Ok(Flow::RaiseIn {
        record,
        context: Box::new(context),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::hle::ApiErr;
    use crate::user::windows::memory::{Mem, mem, prot};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    const CODE: u32 = 0xe042_5345;

    fn with_call(arch: WinArch, test: impl FnOnce(&mut Ctx, u64, u64, &RegContext)) {
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
        let mut config = WindowsConfig::new("raise-test.exe", Vec::new());
        config.arena_bytes = 64 << 20;
        config.seed = Some(1);
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let scratch =
            p.vm.allocate(None, 0x2000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let record = scratch + 0x100;
        let context = scratch + 0x200;
        ExceptionRecord::new(CODE, 0x1234, vec![0xa5])
            .write(&p.space, arch, record)
            .unwrap();
        let mut saved = RegContext::capture(&thread.cpu);
        saved.set_pc(0x1234);
        saved.write(&p.space, context).unwrap();
        let sp = thread.cpu.sp();
        let api = crate::user::windows::dll::nt_service("NtRaiseException", arch).unwrap();
        let mut call = Ctx {
            p,
            t: &mut thread,
            api,
            entry_pc: 0x5678,
            entry_sp: sp,
            ret_addr: 0x9abc,
            cursor: sp,
        };
        test(&mut call, record, context, &saved);
    }

    fn arguments(c: &mut Ctx, record: u64, context: u64, first: u64) {
        for (index, value) in [record, context, first].into_iter().enumerate() {
            match c.p.arch {
                WinArch::X86 => {
                    c.p.space
                        .w32(c.entry_sp + 4 + index as u64 * 4, value as u32)
                        .unwrap()
                }
                WinArch::X64 => c.t.cpu.set_gpr([1, 2, 8][index], value),
                WinArch::Arm64 => c.t.cpu.set_gpr(index, value),
            }
        }
    }

    #[test]
    fn second_chance_uses_boolean_low_byte_and_preserves_execution_state() {
        for arch in WinArch::ALL {
            with_call(arch, |c, record, context, _| {
                for first in [0, 0x100, 0xffff_ff00] {
                    arguments(c, record, context, first);
                    let before = RegContext::capture(&c.t.cpu);
                    assert!(
                        matches!(raise(c).unwrap(), Flow::TerminateProcess(CODE)),
                        "{arch}/{first:#x}"
                    );
                    assert_eq!(RegContext::capture(&c.t.cpu), before);
                    assert!(c.t.frames.is_empty());
                }
            });
        }
    }

    #[test]
    fn first_chance_preserves_the_supplied_record_and_context() {
        for arch in WinArch::ALL {
            with_call(arch, |c, record, context, saved| {
                for first in [1, 0x80, 0xffff_ff01] {
                    arguments(c, record, context, first);
                    let Flow::RaiseIn { record, context } = raise(c).unwrap() else {
                        panic!("{arch}/{first:#x}: missing first-chance dispatch")
                    };
                    assert_eq!(record.code, CODE);
                    assert_eq!(record.address, 0x1234);
                    assert_eq!(record.params, [0xa5]);
                    assert_eq!(*context, *saved);
                }
            });
        }
    }

    #[test]
    fn second_chance_validates_both_input_buffers_before_termination() {
        for arch in WinArch::ALL {
            with_call(arch, |c, record, context, saved| {
                for (record, context) in [(0, context), (record, 0)] {
                    arguments(c, record, context, 0);
                    assert!(matches!(raise(c), Err(ApiErr::Fault(_))), "{arch}");
                }
                let page = record & !0xfff;
                let split = page + 0x1000 - RegContext::size(arch) as u64 + 1;
                saved.write(&c.p.space, split).unwrap();
                c.p.vm
                    .protect(page + 0x1000, 0x1000, prot::NOACCESS)
                    .unwrap();
                arguments(c, record, split, 0);
                assert!(
                    matches!(raise(c), Err(ApiErr::Fault(_))),
                    "{arch}: trailing context byte"
                );
            });
        }
    }
}
