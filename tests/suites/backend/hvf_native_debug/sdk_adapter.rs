//! Execute the actual SDK bridge with only FFI calls substituted.
use super::native_step;
#[path = "../../../../src/backend/hvf/native_step_host.rs"]
mod bridge;
use std::cell::RefCell;

#[derive(Default)]
struct Sdk {
    misc: u64,
    control: u64,
    guest_flags: u64,
    fail_capability: bool,
    fail_read: bool,
    fail_write: bool,
    trace: Vec<(u32, u64)>,
}

thread_local! {
    static SDK: RefCell<Sdk> = RefCell::new(Sdk::default());
}

#[allow(non_camel_case_types)]
mod bindings {
    use super::SDK;
    pub type hv_vcpuid_t = u32;
    pub type hv_vmx_capability_t = u32;
    pub const HV_VMX_CAP_PROCBASED: u32 = 1;
    pub const HV_VMX_CAP_MISC: u32 = 10;
    pub const HV_SUCCESS: i32 = 0;
    #[derive(Clone, Copy)]
    #[repr(u32)]
    pub enum hv_vmx_vmcs_field_t {
        VMCS_CTRL_CPU_BASED = 0x4002,
    }
    pub fn hv_error_string(_: i32) -> &'static str {
        "injected SDK failure"
    }
    pub unsafe fn hv_vmx_read_capability(field: u32, value: *mut u64) -> i32 {
        SDK.with_borrow_mut(|sdk| {
            sdk.trace.push((field, 0));
            if sdk.fail_capability {
                return -1;
            }
            let result = match field {
                HV_VMX_CAP_PROCBASED => u64::from(u32::MAX) << 32,
                HV_VMX_CAP_MISC => sdk.misc,
                _ => panic!("unexpected capability field {field}"),
            };
            // SAFETY: the actual bridge passed an exclusive initialized u64
            // output pointer. This synchronous substitute retains no pointer.
            unsafe { value.write(result) };
            0
        })
    }
}

mod convert {
    use super::{SDK, bindings::hv_vmx_vmcs_field_t};
    pub fn vmcs_read(id: u32, field: hv_vmx_vmcs_field_t) -> Result<u64, &'static str> {
        assert_eq!(id, 7);
        assert_eq!(field as u32, 0x4002);
        SDK.with_borrow_mut(|sdk| {
            sdk.trace.push((field as u32, sdk.control));
            if sdk.fail_read {
                Err("SDK read failed")
            } else {
                Ok(sdk.control)
            }
        })
    }
    pub fn vmcs_write(id: u32, field: hv_vmx_vmcs_field_t, value: u64) -> Result<(), &'static str> {
        assert_eq!(id, 7);
        assert_eq!(field as u32, 0x4002);
        SDK.with_borrow_mut(|sdk| {
            sdk.trace.push((field as u32, value));
            if sdk.fail_write {
                Err("SDK write failed")
            } else {
                sdk.control = value;
                Ok(())
            }
        })
    }
}

#[test]
fn sdk_bridge_toggles_only_monitor_trap_and_never_accesses_guest_flags() {
    for flags in [2, 0x102, 0x1_0202, 0x1_0302] {
        SDK.with_borrow_mut(|sdk| {
            *sdk = Sdk {
                guest_flags: flags,
                control: 0x8100_0080,
                ..Sdk::default()
            }
        });
        let state = native_step::State::default();
        let mut host = bridge::Host(7);
        for enabled in [false, true, false, true, true, false] {
            state.configure(&mut host, enabled).unwrap();
            SDK.with_borrow(|sdk| {
                assert_eq!(sdk.guest_flags, flags);
                assert_eq!(sdk.control, 0x8100_0080 | if enabled { 1 << 27 } else { 0 });
                assert!(
                    sdk.trace
                        .iter()
                        .all(|(field, _)| matches!(field, 1 | 0x4002))
                );
            });
        }
    }
}

#[test]
fn hlt_activity_admission_uses_the_sdk_misc_capability_and_required_bit() {
    for bit in 0..64 {
        for supported in [false, true] {
            let misc = (1u64 << bit) | if supported { 1 << 6 } else { 0 };
            SDK.with_borrow_mut(|sdk| {
                *sdk = Sdk {
                    misc,
                    ..Sdk::default()
                }
            });
            assert_eq!(
                bridge::validate_halt_activity().is_ok(),
                supported || bit == 6
            );
            SDK.with_borrow(|sdk| assert_eq!(sdk.trace, [(10, 0)]));
        }
    }
    SDK.with_borrow_mut(|sdk| {
        *sdk = Sdk {
            misc: 1 << 6,
            fail_capability: true,
            ..Sdk::default()
        }
    });
    assert!(bridge::validate_halt_activity().is_err());
}

#[test]
fn sdk_errors_remain_visible_and_fence_later_host_access() {
    for failed in 0..3 {
        SDK.with_borrow_mut(|sdk| {
            *sdk = Sdk {
                fail_capability: failed == 0,
                fail_read: failed == 1,
                fail_write: failed == 2,
                ..Sdk::default()
            }
        });
        let state = native_step::State::default();
        let mut host = bridge::Host(7);
        assert!(state.configure(&mut host, true).is_err());
        assert!(state.ready().is_err());
        let calls = SDK.with_borrow(|sdk| sdk.trace.len());
        assert!(state.configure(&mut host, false).is_err());
        SDK.with_borrow(|sdk| assert_eq!(sdk.trace.len(), calls));
    }
}
