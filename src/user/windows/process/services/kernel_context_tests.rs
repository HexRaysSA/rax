use super::*;
use crate::user::windows::context::{ExceptionRecord, RegContext};
use crate::user::windows::hle::{Ctx, Flow, Value};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::STATUS_INVALID_PARAMETER;
use crate::user::windows::process::{Thread, WindowsProcess, native_start};

fn fixture() -> (WindowsProcess, Thread, u64) {
    let (mut process, mut thread) = native_start::tests::fixture(WinArch::X64);
    let p = process.state_mut();
    let mut native = native_start::tests::runtime(None);
    native.object_namespace.native_machine = Some(0xaa64);
    p.native = Some(native);
    let context = thread.cpu.arm64_kernel_context().unwrap();
    thread.cpu.apply_kernel_context(&context).unwrap();
    let scratch = (thread.cpu.sp() - 0x1000) & !15;
    (process, thread, scratch)
}

fn invoke(
    process: &mut WindowsProcess,
    thread: &mut Thread,
    name: &str,
    kernel: bool,
) -> ApiResult {
    let api = dll::nt_service(name, WinArch::X64).unwrap();
    let sp = thread.cpu.sp();
    let mut context = Ctx {
        p: process.state_mut(),
        t: thread,
        api,
        entry_pc: 0x10000,
        entry_sp: sp,
        ret_addr: 0x10004,
        cursor: sp,
    };
    if kernel {
        call("NTDLL", &mut context)
    } else {
        (api.imp)(&mut context)
    }
}

#[test]
fn native_continue_reads_arm64_frame_and_boolean_without_mutating_the_live_thread() {
    for alert in [0, 1, 0x100, 0x101] {
        let (mut process, mut thread, address) = fixture();
        let mut saved = thread.cpu.arm64_kernel_context().unwrap();
        saved.set_pc(0x123400);
        saved.set_sp(thread.cpu.sp() - 0x80);
        saved.write(&process.state().space, address).unwrap();
        thread.cpu.set_call_gpr(0, address);
        thread.cpu.set_call_gpr(1, alert);
        let before = RegContext::capture(&thread.cpu);
        let flow = invoke(&mut process, &mut thread, "NtContinue", true).unwrap();
        let received = match flow {
            Flow::Resume(context) if alert as u8 == 0 => context,
            Flow::ResumeAlertable(context) if alert as u8 != 0 => context,
            _ => panic!("Unexpected native continuation for {alert:#x}"),
        };
        assert_eq!(*received, saved);
        assert_eq!(received.arch(), WinArch::Arm64);
        assert_eq!(RegContext::capture(&thread.cpu), before);
        thread.cpu.apply_kernel_context(&received).unwrap();
        assert_eq!(thread.cpu.pc(), 0x123400);
        assert_eq!(thread.cpu.sp(), saved.sp());
    }
}

#[test]
fn malformed_native_flags_cannot_be_accepted_as_coincidental_amd64_flags() {
    let (mut process, mut thread, address) = fixture();
    let mut saved = thread.cpu.arm64_kernel_context().unwrap();
    saved.set_flags(0);
    saved.set_gpr(5, 0x0010000f); // Native X5 occupies AMD64 ContextFlags's offset.
    saved.set_sp(0);
    saved.write(&process.state().space, address).unwrap();
    thread.cpu.set_call_gpr(0, address);
    thread.cpu.set_call_gpr(1, 0);
    let before = RegContext::capture(&thread.cpu);
    assert!(
        matches!(invoke(&mut process, &mut thread, "NtContinue", true).unwrap(),
        Flow::Ret(Value::Int(status)) if status == u64::from(STATUS_INVALID_PARAMETER))
    );
    assert_eq!(RegContext::capture(&thread.cpu), before);
    assert_eq!(
        process.state().space.bytes(address, 912).unwrap(),
        saved.bytes()
    );
}

#[test]
fn logical_continue_api_keeps_amd64_layout_even_during_ec_execution() {
    let (mut process, mut thread, address) = fixture();
    let mut saved = RegContext::capture(&thread.cpu);
    saved.set_pc(0x123400);
    saved.write(&process.state().space, address).unwrap();
    thread.cpu.set_call_gpr(0, address);
    thread.cpu.set_call_gpr(1, 0);
    match invoke(&mut process, &mut thread, "NtContinue", false).unwrap() {
        Flow::Resume(context) => assert_eq!(*context, saved),
        _ => panic!("Unexpected logical continuation"),
    }
}

#[test]
fn native_raise_projects_first_chance_and_keeps_second_chance_capture_order() {
    for first in [false, true] {
        let (mut process, mut thread, address) = fixture();
        let mut saved = thread.cpu.arm64_kernel_context().unwrap();
        saved.set_pc(0x123400);
        saved.set_sp(thread.cpu.sp() - 0x80);
        if !first {
            saved.set_flags(0);
        }
        saved.write(&process.state().space, address).unwrap();
        let record = address + 0x600;
        ExceptionRecord::new(0xe1234567, 0x123400, vec![0x42])
            .write(&process.state().space, WinArch::X64, record)
            .unwrap();
        thread.cpu.set_call_gpr(0, record);
        thread.cpu.set_call_gpr(1, address);
        thread.cpu.set_call_gpr(2, u64::from(first));
        let before = RegContext::capture(&thread.cpu);
        match invoke(&mut process, &mut thread, "NtRaiseException", true).unwrap() {
            Flow::RaiseIn { context, record } if first => {
                assert_eq!(context.arch(), WinArch::X64);
                assert_eq!(context.pc(), saved.pc());
                assert_eq!(context.sp(), saved.sp());
                assert_eq!(record.code, 0xe1234567);
            }
            Flow::TerminateProcess(0xe1234567) if !first => {}
            _ => panic!("Unexpected native raise"),
        }
        assert_eq!(RegContext::capture(&thread.cpu), before);
    }
}

#[test]
fn native_get_thread_context_uses_instruction_selected_arm64_layout_without_cpu_mutation() {
    let (mut process, mut thread, address) = fixture();
    process.state().space.wr(address, &vec![0; 1232]).unwrap();
    process
        .state()
        .space
        .w32(address + 48, 0x0010_000f)
        .unwrap();
    thread.cpu.set_call_gpr(0, u64::MAX - 1);
    thread.cpu.set_call_gpr(1, address);
    let before = RegContext::capture(&thread.cpu);
    assert!(matches!(
        invoke(&mut process, &mut thread, "NtGetContextThread", true).unwrap(),
        Flow::Ret(Value::Int(0))
    ));
    assert_eq!(process.state().space.u32(address).unwrap(), 0x0040_0000);
    assert_eq!(
        process.state().space.u32(address + 48).unwrap(),
        0x0010_000f
    );
    assert_eq!(RegContext::capture(&thread.cpu), before);
}

#[test]
fn logical_get_thread_context_keeps_amd64_layout_during_native_arm64_execution() {
    let (mut process, mut thread, address) = fixture();
    process.state().space.wr(address, &vec![0; 1232]).unwrap();
    process
        .state()
        .space
        .w32(address + 48, 0x0010_000f)
        .unwrap();
    thread.cpu.set_call_gpr(0, u64::MAX - 1);
    thread.cpu.set_call_gpr(1, address);
    let before = RegContext::capture(&thread.cpu);
    assert!(matches!(
        invoke(&mut process, &mut thread, "NtGetContextThread", false).unwrap(),
        Flow::Ret(Value::Int(0))
    ));
    assert_eq!(process.state().space.u32(address).unwrap(), 0);
    assert_eq!(
        process.state().space.u32(address + 48).unwrap(),
        0x0010_000f
    );
    assert_eq!(RegContext::capture(&thread.cpu), before);
}
