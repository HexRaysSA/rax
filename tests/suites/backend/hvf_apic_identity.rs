//! Production identity projection and APIC_BASE publication with SDK substitution.
#[path = "../../../src/isa/x86_64/identity.rs"]
mod apic_profile;
#[path = "../../../src/backend/hvf/apic_identity.rs"]
mod policy;
#[path = "../../../src/backend/hvf/priority.rs"]
mod priority;
use std::sync::atomic::{AtomicU32, Ordering};

struct Register(AtomicU32);
impl priority::Register for Register {
    fn load(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
    fn store(&self, value: u32) {
        self.0.store(value, Ordering::SeqCst);
    }
}
struct Sdk {
    base: u64,
    gpr: [u64; 16],
    rip: u64,
    gp: bool,
    calls: Vec<(&'static str, u64)>,
    fail: Option<usize>,
    state: priority::State<Register>,
}
impl Sdk {
    fn new(id: u32) -> Self {
        Self {
            base: apic_profile::initial_apic_base(id),
            gpr: [u64::MAX; 16],
            rip: 0x1000,
            gp: false,
            calls: vec![],
            fail: None,
            state: priority::State::new(Register(AtomicU32::new(0))),
        }
    }
    fn call(&mut self, name: &'static str, value: u64) -> Result<(), String> {
        self.calls.push((name, value));
        if self.fail == Some(self.calls.len()) {
            Err("SDK may have partially changed".into())
        } else {
            Ok(())
        }
    }
}
impl policy::Access for Sdk {
    type Error = String;
    fn ready(&self) -> Result<(), String> {
        self.state.ready()
    }
    fn base(&self) -> u64 {
        self.base
    }
    fn publish(&mut self, value: u64) {
        self.base = value;
    }
    fn write_gpr(&mut self, index: u8, value: u64) -> Result<(), String> {
        self.gpr[usize::from(index)] = value;
        self.call(if index == 0 { "rax" } else { "rdx" }, value)
    }
    fn advance(&mut self) -> Result<(), String> {
        self.rip += 2;
        self.call("advance_before_model_publish", self.base)
    }
    fn inject_gp(&mut self) -> Result<(), String> {
        self.gp = true;
        self.call("gp", self.base)
    }
    fn fence(&self, error: String) -> String {
        self.state.poison(error)
    }
}

#[test]
fn configured_ids_replace_only_the_architectural_identity_fields() {
    let value = (0x1234_5678, 0x89ab_cdef, 0x7654_3210, 0x8765_4321);
    for id in (0..=255).chain([0x1234_5678, u32::MAX]) {
        let leaf1 = apic_profile::project_cpuid(1, value, id);
        assert_eq!(
            leaf1,
            (
                value.0,
                (value.1 & 0x00ff_ffff) | ((id & 255) << 24),
                value.2,
                value.3
            )
        );
        for leaf in [0xb, 0x1f] {
            assert_eq!(
                apic_profile::project_cpuid(leaf, value, id),
                (value.0, value.1, value.2, id)
            );
        }
        for leaf in [0, 7, 0xd, 0x8000_0000] {
            assert_eq!(apic_profile::project_cpuid(leaf, value, id), value);
        }
    }
}

#[test]
fn reset_identity_is_per_cpu_and_reads_zero_extend_before_exact_completion() {
    for id in 0..255 {
        let mut sdk = Sdk::new(id);
        let expected = 0xfee0_0800 | if id == 0 { 256 } else { 0 };
        policy::read(&mut sdk).unwrap();
        assert_eq!(sdk.base, expected);
        assert_eq!(sdk.gpr[0], expected);
        assert_eq!(sdk.gpr[2], 0);
        assert_eq!(sdk.gpr[1], u64::MAX);
        assert_eq!(sdk.rip, 0x1002);
        assert_eq!(
            sdk.calls,
            [
                ("rax", expected),
                ("rdx", 0),
                ("advance_before_model_publish", expected)
            ]
        );
    }
}

#[test]
fn writable_bsp_flag_is_published_only_after_sdk_completion() {
    for id in 0..255 {
        let mut sdk = Sdk::new(id);
        let old = sdk.base;
        policy::write(&mut sdk, old ^ 256).unwrap();
        assert_eq!(sdk.calls, [("advance_before_model_publish", old)]);
        assert_eq!(sdk.base, old ^ 256);
        assert_eq!(sdk.rip, 0x1002);
        assert!(!sdk.gp);
    }
}

#[test]
fn unrepresented_base_mode_enable_and_reserved_bits_fault_without_retirement() {
    for bit in (0..64).filter(|bit| *bit != 8) {
        let mut sdk = Sdk::new(1);
        let old = sdk.base;
        policy::write(&mut sdk, old ^ (1u64 << bit)).unwrap();
        assert!(sdk.gp);
        assert_eq!(sdk.rip, 0x1000);
        assert_eq!(sdk.base, old);
        assert_eq!(sdk.gpr, [u64::MAX; 16]);
        assert_eq!(sdk.calls, [("gp", old)]);
        assert!(sdk.state.ready().is_ok());
    }
}

#[test]
fn partial_sdk_read_completion_failures_fence_every_retry() {
    for failure in 1..=3 {
        let mut sdk = Sdk::new(1);
        sdk.fail = Some(failure);
        assert!(policy::read(&mut sdk).is_err());
        assert_eq!(sdk.base, 0xfee0_0800);
        assert!(sdk.state.ready().is_err());
        let calls = sdk.calls.len();
        assert!(policy::read(&mut sdk).is_err());
        assert!(policy::write(&mut sdk, 0xfee0_0900).is_err());
        assert_eq!(sdk.calls.len(), calls);
    }
}

#[test]
fn partial_sdk_write_or_fault_injection_never_publishes_model_and_fences_entry() {
    for value in [0xfee0_0900, 0] {
        let mut sdk = Sdk::new(1);
        sdk.fail = Some(1);
        assert!(policy::write(&mut sdk, value).is_err());
        assert_eq!(sdk.base, 0xfee0_0800);
        assert!(sdk.state.ready().is_err());
        let calls = sdk.calls.len();
        assert!(policy::write(&mut sdk, 0xfee0_0900).is_err());
        assert_eq!(sdk.calls.len(), calls);
    }
}

#[cfg(all(feature = "hvf", target_os = "macos"))]
#[test]
fn actual_configured_hvf_cpuid_profile_uses_guest_identity_on_each_subleaf() {
    let config = rax::backend::hvf::rosetta::CpuidConfig::default();
    for id in 0..255 {
        let base = config.cpuid(1, 0);
        let actual = config.cpuid_for_cpu(1, 0, id);
        assert_eq!(actual.1 >> 24, id);
        assert_eq!(
            (actual.0, actual.1 & 0x00ff_ffff, actual.2, actual.3),
            (base.0, base.1 & 0x00ff_ffff, base.2, base.3)
        );
        for subleaf in [0, 1, 2, u32::MAX] {
            let base = config.cpuid(0xb, subleaf);
            assert_eq!(
                config.cpuid_for_cpu(0xb, subleaf, id),
                (base.0, base.1, base.2, id)
            );
        }
    }
}
