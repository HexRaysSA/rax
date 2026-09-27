//! Address-keyed Win32 synchronization exports. Guest storage is opaque;
//! undefined ownership/initialization misuse is rejected explicitly.

mod condition;
mod critical;
mod srw;
#[cfg(test)]
mod tests;

use crate::user::windows::hle::{Arg::*, Conv::Stdcall, Export};

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "InitializeCriticalSection",
        Stdcall,
        &[Ptr],
        critical::initialize,
    ),
    Export::func(
        "InitializeCriticalSectionAndSpinCount",
        Stdcall,
        &[Ptr, I32],
        critical::initialize_spin,
    ),
    Export::func(
        "InitializeCriticalSectionEx",
        Stdcall,
        &[Ptr, I32, I32],
        critical::initialize_ex,
    ),
    Export::func("DeleteCriticalSection", Stdcall, &[Ptr], critical::delete),
    Export::func("EnterCriticalSection", Stdcall, &[Ptr], critical::enter),
    Export::func(
        "TryEnterCriticalSection",
        Stdcall,
        &[Ptr],
        critical::try_enter,
    ),
    Export::func("LeaveCriticalSection", Stdcall, &[Ptr], critical::leave),
    Export::func(
        "SetCriticalSectionSpinCount",
        Stdcall,
        &[Ptr, I32],
        critical::spin,
    ),
    Export::func("InitializeSRWLock", Stdcall, &[Ptr], srw::initialize),
    Export::func(
        "AcquireSRWLockExclusive",
        Stdcall,
        &[Ptr],
        srw::acquire_exclusive,
    ),
    Export::func("AcquireSRWLockShared", Stdcall, &[Ptr], srw::acquire_shared),
    Export::func(
        "TryAcquireSRWLockExclusive",
        Stdcall,
        &[Ptr],
        srw::try_exclusive,
    ),
    Export::func("TryAcquireSRWLockShared", Stdcall, &[Ptr], srw::try_shared),
    Export::func(
        "ReleaseSRWLockExclusive",
        Stdcall,
        &[Ptr],
        srw::release_exclusive,
    ),
    Export::func("ReleaseSRWLockShared", Stdcall, &[Ptr], srw::release_shared),
    Export::func(
        "InitializeConditionVariable",
        Stdcall,
        &[Ptr],
        condition::initialize,
    ),
    Export::func(
        "WakeConditionVariable",
        Stdcall,
        &[Ptr],
        condition::wake_one,
    ),
    Export::func(
        "WakeAllConditionVariable",
        Stdcall,
        &[Ptr],
        condition::wake_all,
    ),
    Export::func(
        "SleepConditionVariableCS",
        Stdcall,
        &[Ptr, Ptr, I32],
        condition::sleep_cs,
    ),
    Export::func(
        "SleepConditionVariableSRW",
        Stdcall,
        &[Ptr, Ptr, I32, I32],
        condition::sleep_srw,
    ),
    Export::func(
        "WaitOnAddress",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32],
        condition::wait_address,
    ),
    Export::func(
        "WakeByAddressSingle",
        Stdcall,
        &[Ptr],
        condition::wake_address_one,
    ),
    Export::func(
        "WakeByAddressAll",
        Stdcall,
        &[Ptr],
        condition::wake_address_all,
    ),
];
