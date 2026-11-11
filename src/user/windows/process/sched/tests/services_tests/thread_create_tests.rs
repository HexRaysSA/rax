//! Raw-service thread creation, independent of the built-in CreateThread shim.
use super::{Outcome, Proc, Thread, WinArch, fixture, handle_stop, stop};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::objects::Object;

const SERVICE: u32 = 0x1e1;

fn enter(process: &mut Proc, caller: &mut Thread, arguments: [u64; 11]) -> Outcome {
    let previous_sp = caller.cpu.sp();
    let sp = previous_sp - 256;
    caller.cpu.set_sp(sp);
    caller.cpu.set_pc(0x1234_0004);
    match process.arch {
        WinArch::Arm64 => {
            for (index, value) in arguments.into_iter().enumerate() {
                if index < 8 {
                    caller.cpu.set_gpr(index, value);
                } else {
                    process
                        .space
                        .w64(sp + (index as u64 - 8) * 8, value)
                        .unwrap();
                }
            }
        }
        WinArch::X64 => {
            caller.cpu.set_gpr(0, SERVICE.into());
            caller.cpu.set_gpr(1, 0x1234_0004);
            for (index, value) in arguments.into_iter().enumerate() {
                if index < 4 {
                    caller.cpu.set_gpr([10, 2, 8, 9][index], value);
                } else {
                    process
                        .space
                        .w64(sp + 40 + (index as u64 - 4) * 8, value)
                        .unwrap();
                }
            }
        }
        WinArch::X86 => {
            process.space.w32(sp, 0x1234_0004).unwrap();
            process.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (index, value) in arguments.into_iter().enumerate() {
                process
                    .space
                    .w32(sp + 8 + index as u64 * 4, value as u32)
                    .unwrap();
            }
            caller.cpu.set_gpr(0, SERVICE.into());
        }
    }
    let outcome = if process.arch == WinArch::X86 {
        super::super::super::super::services::wow64(process, caller, 0x1234_0000)
    } else {
        handle_stop(process, caller, stop(process.arch, SERVICE))
    };
    if outcome == Outcome::Continue {
        assert_eq!(caller.cpu.pc(), 0x1234_0004);
        assert_eq!(
            caller.cpu.sp(),
            sp + if process.arch == WinArch::X86 { 4 } else { 0 }
        );
        assert!(caller.frames.is_empty());
    }
    caller.cpu.set_sp(previous_sp);
    outcome
}

#[test]
fn native_thread_create_owns_exact_stack_teb_and_suspend_state_all_abis() {
    for arch in WinArch::ALL {
        for suspended in [0, 1] {
            let (mut process, mut caller) = fixture(arch, "NtCreateThreadEx", SERVICE);
            let state = process.state_mut();
            let output = state
                .vm
                .allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
            let before = state.threads.len();
            let args = [
                output,
                0x1fffff,
                0,
                arch.ptr(u64::MAX),
                0x1234_5000,
                0x5678,
                suspended,
                0,
                0x1000,
                0x1_0000,
                0,
            ];
            assert_eq!(enter(state, &mut caller, args), Outcome::Continue, "{arch}");
            assert_eq!(caller.cpu.gpr(0), 0, "{arch}");
            assert_eq!(state.threads.len(), before + 1);
            let handle = state.space.ptr(output, arch.ptr_size()).unwrap();
            assert_eq!(state.objects.access(handle), Some(0x1fffff));
            let Some(Object::Thread {
                tid,
                exit_code: None,
            }) = state.objects.get(handle)
            else {
                panic!("new guest thread object");
            };
            let created = &state.threads[tid];
            assert_eq!(created.start, 0x1234_5000);
            assert_eq!(created.param, 0x5678);
            assert_eq!(created.suspend, suspended as u32);
            assert_eq!(created.runnable(), suspended == 0);
            assert_eq!(created.stack_base - created.stack_alloc, 0x1_0000);
            assert_eq!(created.stack_base - created.stack_limit, 0x1000);
            let layout = offsets(arch);
            assert_eq!(
                state
                    .space
                    .ptr(created.teb + layout.teb_stack_limit, layout.ptr)
                    .unwrap(),
                created.stack_limit
            );
            assert_eq!(
                state
                    .space
                    .ptr(created.teb + layout.teb_deallocation_stack, layout.ptr)
                    .unwrap(),
                created.stack_alloc
            );
            assert_eq!(
                state
                    .space
                    .ptr(created.teb + layout.teb_client_id, layout.ptr)
                    .unwrap(),
                u64::from(state.pid)
            );
            assert_eq!(
                state
                    .space
                    .ptr(created.teb + layout.teb_client_id + layout.ptr, layout.ptr)
                    .unwrap(),
                u64::from(*tid)
            );
        }
    }
}

#[path = "thread_create_tests/replay.rs"]
mod replay;

#[path = "thread_create_tests/object_attributes.rs"]
mod object_attributes;
