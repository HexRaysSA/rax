//! Bind captured host identity independently of the emulated caller's version.
use super::*;

#[derive(serde::Deserialize)]
pub(super) struct Acquisition {
    native_kernel: String,
    native_machine: Option<String>,
}

impl Acquisition {
    pub(super) fn apply(&self, p: &mut Proc) {
        let Some(machine) = &self.native_machine else {
            // The immutable historical corpus predates native_machine metadata.
            // Keep its portable reference personality rather than invent identity.
            assert_eq!(self.native_kernel, "10.0.29698.0");
            return;
        };
        let machine = match machine.to_ascii_lowercase().as_str() {
            "amd64" | "x86_64" => 0x8664,
            "arm64" | "aarch64" => 0xaa64,
            other => panic!("uncaptured native machine {other}"),
        };
        let version: Vec<u32> = self
            .native_kernel
            .split('.')
            .map(|part| part.parse().unwrap())
            .collect();
        assert!((3..=4).contains(&version.len()));
        kernel(p, version[0], version[1], version[2], Some(machine));
    }
}

pub(super) fn kernel(p: &mut Proc, major: u32, minor: u32, build: u32, machine: Option<u16>) {
    super::super::system_processor_tests::kernel_profile(p, machine.unwrap_or(0));
    let native = p.native.as_mut().unwrap();
    native.version.major = major;
    native.version.minor = minor;
    native.version.build = build;
    native.object_namespace.native_machine = machine;
    std::sync::Arc::make_mut(&mut p.cfg).version.build = if build == 20348 { 29698 } else { 20348 };
}

#[test]
fn native_instruction_cache_amd64_profile_uses_native_identity_and_preserves_reference_order() {
    for (major, minor, build, machine, admitted) in [
        (10, 0, 20348, Some(0x8664), true),
        (10, 0, 20347, Some(0x8664), false),
        (10, 0, 20349, Some(0x8664), false),
        (10, 0, 26100, Some(0x8664), false),
        (11, 0, 20348, Some(0x8664), false),
        (10, 1, 20348, Some(0x8664), false),
        (10, 0, 20348, Some(0xaa64), false),
        (10, 0, 20348, Some(0x14c), false),
        (10, 0, 20348, None, false),
        (10, 0, 29698, Some(0xaa64), false),
        (10, 0, 29704, Some(0xaa64), false),
    ] {
        let (mut process, mut thread) = fixture(WinArch::X64, "NtFlushInstructionCache", SERVICE);
        let p = process.state_mut();
        kernel(p, major, minor, build, machine);
        let epoch = p.space.code_epoch();
        let resources = (p.objects.handle_count(), p.vm.committed_bytes());
        assert_eq!(
            native_call(p, &mut thread, [0, 1, u64::MAX]),
            Outcome::Continue
        );
        assert_eq!(
            thread.cpu.gpr(0) as u32,
            if admitted {
                nt::status::STATUS_SUCCESS
            } else {
                nt::status::STATUS_ACCESS_VIOLATION
            },
            "{major}/{minor}/{build}/{machine:?}"
        );
        assert_eq!(p.space.code_epoch() > epoch, admitted);
        assert_eq!(
            (p.objects.handle_count(), p.vm.committed_bytes()),
            resources
        );
    }
}
