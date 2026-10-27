//! Host-independent execution of the actual Intel capability/initialization path.
#[allow(unused_imports)]
#[path = "../../../src/backend/hvf/bindings.rs"]
mod bindings;
#[path = "../../../src/backend/hvf/controls.rs"]
mod controls;
#[allow(dead_code)]
#[path = "../../../src/backend/hvf/run_loop.rs"]
mod run_loop;
use bindings::*;
use controls::{ControlAccess, ControlError, REQUESTS, initialize, value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Read(u32),
    Write(hv_vmx_vmcs_field_t, u64),
}
struct Host {
    caps: [u64; 4],
    trace: Vec<Call>,
    committed: Vec<(hv_vmx_vmcs_field_t, u64)>,
    fail_at: Option<usize>,
}
impl Host {
    fn new() -> Self {
        Self {
            caps: [u64::from(u32::MAX) << 32; 4],
            trace: vec![],
            committed: vec![],
            fail_at: None,
        }
    }
    fn call(&mut self, call: Call) -> Result<(), usize> {
        let at = self.trace.len();
        self.trace.push(call);
        if self.fail_at == Some(at) {
            Err(at)
        } else {
            Ok(())
        }
    }
}
impl ControlAccess for Host {
    type Error = usize;
    fn capability(&mut self, field: hv_vmx_capability_t) -> Result<u64, usize> {
        self.call(Call::Read(field))?;
        let index = REQUESTS
            .iter()
            .position(|x| x.0 == field)
            .expect("unneeded capability query");
        Ok(self.caps[index])
    }
    fn write(&mut self, field: hv_vmx_vmcs_field_t, data: u64) -> Result<(), usize> {
        self.call(Call::Write(field, data))?;
        self.committed.push((field, data));
        Ok(())
    }
}
#[test]
fn every_individual_capability_bit_obeys_required_and_allowed_masks() {
    for bit in 0..32 {
        let mask = 1u32 << bit;
        for required in [false, true] {
            for allowed in [false, true] {
                for requested in [false, true] {
                    let cap = (u64::from(u32::MAX & if allowed { u32::MAX } else { !mask }) << 32)
                        | if required { u64::from(mask) } else { 0 };
                    let got = value::<usize>(19, cap, if requested { u64::from(mask) } else { 0 });
                    let expected = if required && !allowed {
                        Err(ControlError::Inconsistent {
                            capability: 19,
                            bits: u64::from(mask),
                        })
                    } else if requested && !allowed {
                        Err(ControlError::Unsupported {
                            capability: 19,
                            bits: u64::from(mask),
                        })
                    } else {
                        Ok(if required || requested {
                            u64::from(mask)
                        } else {
                            0
                        })
                    };
                    assert_eq!(
                        got, expected,
                        "bit{bit} required{required} allowed{allowed} requested{requested}"
                    );
                }
            }
        }
    }
    assert_eq!(
        value::<usize>(3, u64::MAX, 1 << 40),
        Err(ControlError::Unsupported {
            capability: 3,
            bits: 1 << 40
        })
    );
}
#[test]
fn seeded_full_width_masks_preserve_all_mandatory_and_forbidden_bits() {
    let mut seed = 0xe427_b65d_u32;
    for _ in 0..65536 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let allowed = seed;
        let required = seed.rotate_left(7) & allowed;
        let requested = seed.rotate_right(11) & allowed;
        let got = value::<usize>(
            7,
            (u64::from(allowed) << 32) | u64::from(required),
            u64::from(requested),
        )
        .unwrap();
        for bit in 0..32 {
            let set = got & (1 << bit) != 0;
            assert_eq!(set, (required | requested) & (1 << bit) != 0);
            if set {
                assert_ne!(allowed & (1 << bit), 0);
            }
        }
        assert_eq!(got >> 32, 0);
    }
}
#[test]
fn complete_initialization_reads_four_banks_before_ten_exact_writes() {
    let mut h = Host::new();
    h.caps[0] |= 1 << 1;
    initialize(&mut h).unwrap();
    assert_eq!(
        &h.trace[..4],
        &[Call::Read(0), Call::Read(1), Call::Read(2), Call::Read(3)]
    );
    use hv_vmx_vmcs_field_t::*;
    assert_eq!(
        h.committed,
        vec![
            (VMCS_CTRL_PIN_BASED, (1 << 0) | (1 << 1) | (1 << 3)),
            (
                VMCS_CTRL_CPU_BASED,
                (1 << 7) | (1 << 19) | (1 << 20) | (1 << 24) | (1 << 31)
            ),
            (VMCS_CTRL_CPU_BASED2, (1 << 1) | (1 << 3) | (1 << 7)),
            (VMCS_CTRL_VMENTRY_CONTROLS, (1 << 9) | (1 << 15)),
            (VMCS_CTRL_EXC_BITMAP, 0),
            (VMCS_CTRL_CR0_MASK, 1 << 5),
            (VMCS_CTRL_CR0_SHADOW, 1 << 5),
            (VMCS_CTRL_CR4_MASK, 0),
            (VMCS_CTRL_CR4_SHADOW, 0),
            (VMCS_GUEST_LINK_POINTER, u64::MAX),
        ]
    );
    assert_eq!(h.trace.len(), 14);
}
#[test]
fn every_capability_api_error_stops_before_any_vmcs_mutation() {
    for fail in 0..4 {
        let mut h = Host::new();
        h.fail_at = Some(fail);
        assert_eq!(initialize(&mut h), Err(ControlError::Host(fail)));
        assert_eq!(h.trace.len(), fail + 1);
        assert!(h.committed.is_empty());
    }
}
#[test]
fn every_missing_requested_control_is_reported_before_any_write() {
    for (bank, (field, _, requested)) in REQUESTS.into_iter().enumerate() {
        for bit in 0..32 {
            let mask = 1u64 << bit;
            if requested & mask == 0 {
                continue;
            }
            let mut h = Host::new();
            h.caps[bank] &= !(mask << 32);
            assert_eq!(
                initialize(&mut h),
                Err(ControlError::Unsupported {
                    capability: field,
                    bits: mask
                })
            );
            assert_eq!(h.trace.len(), 4);
            assert!(h.committed.is_empty());
        }
    }
}
#[test]
fn contradictory_masks_fail_for_every_bank_and_bit_before_writes() {
    for (bank, (field, _, _)) in REQUESTS.into_iter().enumerate() {
        for bit in 0..32 {
            let mask = 1u64 << bit;
            let mut h = Host::new();
            h.caps[bank] = (h.caps[bank] & !(mask << 32)) | mask;
            assert_eq!(
                initialize(&mut h),
                Err(ControlError::Inconsistent {
                    capability: field,
                    bits: mask
                })
            );
            assert_eq!(h.trace.len(), 4);
            assert!(h.committed.is_empty());
        }
    }
}
#[test]
fn every_write_failure_preserves_prior_commits_and_stops_the_sequence() {
    let mut baseline = Host::new();
    initialize(&mut baseline).unwrap();
    for fail in 4..14 {
        let mut h = Host::new();
        h.fail_at = Some(fail);
        assert_eq!(initialize(&mut h), Err(ControlError::Host(fail)));
        assert_eq!(h.trace, baseline.trace[..=fail]);
        assert_eq!(h.committed, baseline.committed[..fail - 4]);
    }
}
