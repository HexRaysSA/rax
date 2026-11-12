use super::*;
use crate::user::windows::object_namespace::CodeBitmapPlan;
use crate::user::windows::process::thread::chpe::ContextOwner;

#[test]
fn thread_context_owner_uses_native_identity_for_main_child_and_cloned_carrier() {
    for main in [false, true] {
        for machine in [None, Some(0x8664), Some(0xaa64)] {
            let mut process = fixture(WinArch::X64);
            let p = process.state_mut();
            p.vm.publish_ec_image(
                &CodeBitmapPlan {
                    base: Some(0x1000_0000_0000),
                    ranges: vec![],
                },
                0,
                0,
            )
            .unwrap();
            if let Some(machine) = machine {
                let mut native = runtime(Some(machine), (10, 0, 29704));
                native.startup = Some(EntryPoints {
                    loader: 0x50000,
                    thread: 0x51000,
                    module: 0x40000,
                    callback: None,
                });
                p.native = Some(native);
            }
            std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
            let tid =
                super::super::super::super::thread::create(p, 0x52000, 0x1234, 0, main).unwrap();
            let cpu = &p.threads[&tid].cpu;
            let expected = if machine == Some(0xaa64) {
                ContextOwner::NativeRtl
            } else {
                ContextOwner::Interpreter
            };
            let WinCpu::Arm64Ec(ec) = cpu else {
                panic!("missing EC binding")
            };
            assert_eq!(
                ec.area.as_ref().unwrap().owner,
                expected,
                "main={main} machine={machine:?}"
            );
            let cloned = cpu.new_thread();
            let WinCpu::Arm64Ec(ec) = &cloned else {
                panic!("missing cloned EC binding")
            };
            assert_eq!(ec.area.as_ref().unwrap().owner, expected);
        }
    }
}
