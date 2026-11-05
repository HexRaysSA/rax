//! Actual selected EC compiler thunk, shared by private generated leaf functions.
use super::*;
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{AddressRequirements, PrivateAttributes};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn installed_ec_thunk_returns_from_private_code_on_both_sides_of_its_module() {
    let image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe");
    let mut config =
        WindowsConfig::embedded("C:\\private-ec-call.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let module = loader::load_dll(p, "ntdll.dll").unwrap();
    let attributes = PrivateAttributes {
        node: None,
        ec_code: true,
    };
    if !p.vm.has_code_bitmap() {
        assert_ne!(
            p.native.as_ref().unwrap().object_namespace.native_machine,
            Some(0xaa64)
        );
        assert_eq!(
            p.vm.allocate_extended_attributes(
                None,
                4096,
                mem::RESERVE | mem::COMMIT,
                prot::EXECUTE_READWRITE,
                AddressRequirements::default(),
                attributes
            ),
            Err(crate::user::windows::memory::VmError::InvalidParameter)
        );
        println!(
            "EC capability unavailable: selected kernel is not ARM64; rejection branch validated"
        );
        return;
    }
    let export = loader::lookup(
        p,
        module,
        &SymRef::Name(b"RtlRunOnceExecuteOnce".to_vec(), None),
    )
    .unwrap()
    .unwrap();
    let stub = p.space.bytes(export, 14).unwrap();
    let original = if stub[..10] == [0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9] {
        export
            .checked_add_signed(
                i64::from(i32::from_le_bytes(stub[10..14].try_into().unwrap())) + 14,
            )
            .unwrap()
    } else {
        export
    };
    let prefix = p.space.u32(original - 4).unwrap();
    let thunk = original
        .checked_add_signed(i64::from((prefix & !3) as i32))
        .unwrap();
    let unchanged = p.space.bytes(thunk, 64).unwrap();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let call_sp = thread.cpu.sp();
    for above in [false, true] {
        let lowest = if above {
            (thunk + 65536) & !65535
        } else {
            (thunk - (1 << 29)) & !65535
        };
        let highest = if above {
            ((thunk + (1 << 29)) & !65535) - 1
        } else {
            (thunk & !65535) - 1
        };
        let owner =
            p.vm.allocate_extended_attributes(
                None,
                65536,
                mem::RESERVE | mem::COMMIT,
                prot::EXECUTE_READWRITE,
                AddressRequirements {
                    lowest,
                    highest,
                    alignment: 65536,
                },
                attributes,
            )
            .unwrap()
            .0;
        let target = owner + 0x200;
        let delta = i32::try_from(thunk as i64 - target as i64).unwrap();
        let expected = if above { 0x1234u32 } else { 0x4321u32 };
        p.space
            .w32(target - 4, delta as u32 | (prefix & 3))
            .unwrap();
        p.space.w32(target, 0xd2800000 | expected << 5).unwrap();
        p.space.w32(target + 4, 0xd65f03c0).unwrap();
        let resume = p.traps.callback_return();
        thread.cpu.set_sp(call_sp - 8);
        p.space.w64(call_sp - 8, resume).unwrap();
        thread.cpu.set_pc(target);
        let mut returned = false;
        for _ in 0..64 {
            let boundary = thread.cpu.run_routed(64, |pc, active, context| {
                p.modules
                    .instruction_route(&p.space, &p.vm, pc, active, context)
            });
            if thread.cpu.pc() == resume {
                returned = true;
                break;
            }
            assert_eq!(handle_stop(p, &mut thread, boundary), Outcome::Continue);
        }
        assert!(
            returned,
            "private EC function did not return through the installed entry thunk"
        );
        assert_eq!(thread.cpu.gpr(0), u64::from(expected));
        assert_eq!(thread.cpu.sp(), call_sp);
        assert_eq!(p.space.bytes(thunk, 64).unwrap(), unchanged);
        p.vm.release(owner).unwrap();
    }
    println!("EC_PRIVATE_INSTALLED_THUNK_CALLS_PASSED=2");
}
