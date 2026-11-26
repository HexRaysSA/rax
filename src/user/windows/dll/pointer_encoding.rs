//! Process-cookie pointer encoding shared by NTDLL and the public Win32 aliases.

use super::super::hle::{ApiResult, Arg::Ptr, Conv::Stdcall, Ctx, Export, Flow};

pub(super) static NTDLL_EXPORTS: &[Export] = &[
    Export::func("RtlEncodePointer", Stdcall, &[Ptr], encode),
    Export::func("RtlDecodePointer", Stdcall, &[Ptr], decode),
];

pub(super) static KERNEL_FORWARDS: &[Export] = &[
    Export::forward("EncodePointer", "NTDLL.RtlEncodePointer"),
    Export::forward("DecodePointer", "NTDLL.RtlDecodePointer"),
];

fn encode(c: &mut Ctx) -> ApiResult {
    Flow::ret(encode_value(c, c.ptr(0)?))
}

pub(super) fn encode_value(c: &Ctx, value: u64) -> u64 {
    let cookie = c.p.process_cookie;
    if c.arch().is64() {
        (value ^ u64::from(cookie)).rotate_right(cookie)
    } else {
        u64::from((value as u32 ^ cookie).rotate_right(cookie))
    }
}

fn decode(c: &mut Ctx) -> ApiResult {
    Flow::ret(decode_value(c, c.ptr(0)?))
}

pub(super) fn decode_value(c: &Ctx, value: u64) -> u64 {
    let cookie = c.p.process_cookie;
    if c.arch().is64() {
        value.rotate_left(cookie) ^ u64::from(cookie)
    } else {
        u64::from((value as u32).rotate_left(cookie) ^ cookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::hle::Value;
    use crate::user::windows::loader::{self, SymRef};
    use crate::user::windows::memory::Mem;
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    use crate::user::windows::traps::Trap;

    #[test]
    fn kernelbase_pointer_exports_use_the_guest_cookie_and_width() {
        let images: &[&[u8]] = &[
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
            include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"),
        ];
        for image in images {
            let mut config = WindowsConfig::new("pointer-encoding.exe", vec![]);
            config.arena_bytes = 64 << 20;
            config.seed = Some(1);
            let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
            let p = process.state_mut();
            let module = loader::load_dll(p, "kernelbase.dll").unwrap();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let sp = t.cpu.sp() - 64;
            let raw = p.arch.ptr(0x0123_4567_89ab_cdef);
            let encoded = if p.arch.is64() {
                0x81d2_f680_2468_ace5
            } else {
                0x81d2_f685
            };
            for (name, input, expected) in [
                ("EncodePointer", raw, encoded),
                ("DecodePointer", encoded, raw),
            ] {
                let pc = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                    .unwrap()
                    .unwrap();
                let Some(Trap::Entry(api)) = p.traps.lookup(pc) else {
                    panic!("{name} must resolve to a callable export");
                };
                match p.arch {
                    WinArch::X86 => p.space.w32(sp + 4, input as u32).unwrap(),
                    WinArch::X64 => t.cpu.set_gpr(1, input),
                    WinArch::Arm64 => t.cpu.set_gpr(0, input),
                }
                let result = (api.imp)(&mut Ctx {
                    p,
                    t: &mut t,
                    api,
                    entry_pc: pc,
                    entry_sp: sp,
                    ret_addr: 0,
                    cursor: sp,
                })
                .unwrap();
                assert!(matches!(result, Flow::Ret(Value::Int(value)) if value == expected));
            }
        }
    }
}
