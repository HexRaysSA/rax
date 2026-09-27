use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{Api, Item, Value};
use crate::user::windows::memory::{Mem, prot};
use crate::user::windows::process::{Thread, WindowsConfig, WindowsProcess};

fn fixture(arch: WinArch) -> (WindowsProcess, Thread) {
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
    let mut config = WindowsConfig::new("fls-test.exe", vec![]);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let t = p.threads.remove(&tid).unwrap();
    (process, t)
}

fn api(name: &str) -> &'static Api {
    EXPORTS
        .iter()
        .find_map(|e| match &e.item {
            Item::Func(a) if a.name == name => Some(a),
            _ => None,
        })
        .unwrap()
}

fn args(c: &mut Ctx, values: &[u64]) {
    for (i, &value) in values.iter().enumerate() {
        match c.arch() {
            WinArch::X86 => {
                c.p.space
                    .w32(c.entry_sp + 4 + 4 * i as u64, value as u32)
                    .unwrap()
            }
            WinArch::X64 => c.t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::Arm64 => c.t.cpu.set_gpr(i, value),
        }
    }
}

fn invoke(c: &mut Ctx, name: &str, values: &[u64]) -> ApiResult {
    c.api = api(name);
    args(c, values);
    (c.api.imp)(c)
}

fn int(result: ApiResult) -> u64 {
    match result.unwrap() {
        Flow::Ret(Value::Int(v)) => v,
        _ => panic!("expected integer result"),
    }
}

#[test]
fn slots_are_pointer_width_correct_and_errors_do_not_fabricate_values_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        let mut c = Ctx {
            p,
            t: &mut t,
            api: api("FlsAlloc"),
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        c.set_last_error(0x1234).unwrap();
        let index = int(invoke(&mut c, "FlsAlloc", &[0]));
        assert_eq!(index, 1);
        assert_eq!(c.last_error().unwrap(), 0x1234);
        assert_eq!(int(invoke(&mut c, "FlsGetValue", &[index])), 0);
        assert_eq!(c.last_error().unwrap(), 0);
        let value = if arch.is64() {
            0x1234_5678_9ABC_DEF0
        } else {
            0x9ABC_DEF0
        };
        assert_eq!(int(invoke(&mut c, "FlsSetValue", &[index, value])), 1);
        assert_eq!(int(invoke(&mut c, "FlsGetValue", &[index])), value);
        for bad in [0, u64::from(u32::MAX)] {
            for name in ["FlsGetValue", "FlsSetValue", "FlsFree"] {
                assert_eq!(int(invoke(&mut c, name, &[bad, value])), 0);
                assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
            }
        }
        assert_eq!(int(invoke(&mut c, "FlsFree", &[index])), 1);
        assert_eq!(int(invoke(&mut c, "FlsAlloc", &[0])), index);
        assert_eq!(int(invoke(&mut c, "FlsGetValue", &[index])), 0);
    }
}

#[test]
fn free_calls_all_nonnull_contexts_and_closing_index_cannot_be_reallocated_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        let mut c = Ctx {
            p,
            t: &mut t,
            api: api("FlsAlloc"),
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        let slot = int(invoke(&mut c, "FlsAlloc", &[0x1234_0000])) as u32;
        assert_eq!(
            int(invoke(&mut c, "FlsSetValue", &[u64::from(slot), 11])),
            1
        );
        c.p.tls.fls_set(FlsKey::Fiber(0x20000), slot, 22).unwrap();
        c.p.tls.fls_set(FlsKey::Thread(88), slot, 0).unwrap();
        let Flow::Call {
            target,
            args: values,
            then,
        } = invoke(&mut c, "FlsFree", &[u64::from(slot)]).unwrap()
        else {
            panic!("expected first callback");
        };
        assert_eq!((target, values), (0x1234_0000, vec![11]));
        assert_eq!(int(invoke(&mut c, "FlsGetValue", &[u64::from(slot)])), 0);
        assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
        let other = int(invoke(&mut c, "FlsAlloc", &[0]));
        assert_ne!(other, u64::from(slot));
        let Flow::Call {
            target,
            args: values,
            then,
        } = then(&mut c, 0xDEAD).unwrap()
        else {
            panic!("expected second callback");
        };
        assert_eq!((target, values), (0x1234_0000, vec![22]));
        assert_eq!(int(then(&mut c, 0xBEEF)), 1); // Callback is VOID.
        assert_eq!(int(invoke(&mut c, "FlsAlloc", &[0])), u64::from(slot));
        assert_eq!(int(invoke(&mut c, "FlsGetValue", &[u64::from(slot)])), 0);
        assert!(c.p.tls.fls_take_abandoned().is_empty());
    }
}

#[test]
fn context_cleanup_handles_callback_rearming_and_preserves_current_identity_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        let mut c = Ctx {
            p,
            t: &mut t,
            api: api("FlsAlloc"),
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        let slot = c.p.tls.fls_alloc(0x1234_0000).unwrap();
        let target = FlsKey::Fiber(0x20000);
        let caller = c.t.fls_key();
        c.p.tls.fls_set(target, slot, 11).unwrap();
        c.p.tls.fls_set(caller, slot, 22).unwrap();
        let Flow::Call {
            args: values, then, ..
        } = cleanup(&mut c, target, Box::new(|_, _| Flow::ret(77))).unwrap()
        else {
            panic!("expected target cleanup callback");
        };
        assert_eq!(values, [11]);
        assert_eq!(c.t.fls_key(), caller);
        assert_eq!(c.p.tls.fls_get(caller, slot), Ok(22));
        c.p.tls.fls_set(target, slot, 33).unwrap();
        let Flow::Call {
            args: values, then, ..
        } = then(&mut c, 0).unwrap()
        else {
            panic!("rearmed callback missing");
        };
        assert_eq!(values, [33]);
        assert_eq!(int(then(&mut c, 0)), 77);
        assert_eq!(c.p.tls.fls_get(target, slot), Ok(0));
        assert_eq!(c.p.tls.fls_get(caller, slot), Ok(22));
    }
}

#[test]
fn abandoned_callback_and_guest_teb_faults_are_explicit_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        let mut c = Ctx {
            p,
            t: &mut t,
            api: api("FlsAlloc"),
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        let slot = c.p.tls.fls_alloc(0xDEAD_0000).unwrap();
        c.p.tls.fls_set(c.t.fls_key(), slot, 11).unwrap();
        let Flow::Call { then, .. } = invoke(&mut c, "FlsFree", &[u64::from(slot)]).unwrap() else {
            panic!("callback missing");
        };
        drop(then);
        let receipts = c.p.tls.fls_take_abandoned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].tid, c.t.tid);
        assert_eq!(receipts[0].kind, "FlsFree");
        assert_eq!(c.p.tls.fls_alloc(0), Ok(slot));
        c.p.vm.protect(c.t.teb, 0x1000, prot::NOACCESS).unwrap();
        assert!(matches!(
            invoke(&mut c, "FlsGetValue", &[u64::from(slot)]),
            Err(ApiErr::Fault(_))
        ));
        assert!(matches!(
            invoke(&mut c, "FlsSetValue", &[0, 1]),
            Err(ApiErr::Fault(_))
        ));
    }
}
