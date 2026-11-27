//! Empty, dormant GameOS notifications in the offline launch profile.

use crate::user::windows::{
    hle::{ApiResult, Archs, Arg::*, Conv::Stdcall, Ctx, Export, Flow},
    memory::Mem,
    nt::status::{STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER},
    objects::Object,
};

const RUNTIME_SUBSCRIPTION: &str = "GameOS runtime WNF subscription";
const GLOBAL_CONNECTIVITY_STATE: u64 = 0x418b_0223_a3bc_2075;

pub(in crate::user::windows::dll) fn runtime_state(name: u64) -> Option<&'static [u8]> {
    match name {
        0x41c6_0d2a_a3bc_3875 | 0x41c6_0d2a_a3bc_4075 | 0x41c6_0d2a_a3bc_5075 => Some(&[]),
        // IPHLPAPI consumes an eight-byte global connectivity state.
        GLOBAL_CONNECTIVITY_STATE => Some(&[0; 8]),
        _ => None,
    }
}

pub(in crate::user::windows::dll) static EXPORTS: &[Export] = &[
    Export::func(
        "RtlSubscribeWnfStateChangeNotification",
        Stdcall,
        &[Ptr, I64, I32, Ptr, Ptr, Ptr, I32, I32],
        subscribe,
    )
    .only(Archs::X64),
    Export::func(
        "RtlUnsubscribeWnfStateChangeNotification",
        Stdcall,
        &[Ptr],
        unsubscribe,
    )
    .only(Archs::X64),
    Export::func(
        "RtlUnsubscribeWnfNotificationWaitForCompletion",
        Stdcall,
        &[Ptr],
        unsubscribe,
    )
    .only(Archs::X64),
];

fn subscribe(c: &mut Ctx) -> ApiResult {
    let name = c.arg(1)?;
    if !c.p.cfg.gameos_analysis || runtime_state(name).is_none() {
        return Err(c.unsupported(format!("RtlSubscribeWnfStateChangeNotification {name:#x}")));
    }
    let output = c.ptr(0)?;
    if output == 0 || c.ptr(3)? == 0 || c.ptr(5)? != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let Some(id) = c.p.objects.try_create(Object::Opaque(RUNTIME_SUBSCRIPTION)) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(id, false, 0) else {
        c.p.objects.release(id);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(output, handle.into()) {
        let _ = c.p.objects.close(handle.into());
        return Err(fault.into());
    }
    Flow::ret(0)
}

fn unsubscribe(c: &mut Ctx) -> ApiResult {
    if !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("RtlUnsubscribeWnfStateChangeNotification"));
    }
    let handle = c.ptr(0)?;
    if !matches!(
        c.p.objects.get(handle),
        Some(Object::Opaque(RUNTIME_SUBSCRIPTION))
    ) || c.p.objects.close(handle).is_err()
    {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    Flow::ret(0)
}
