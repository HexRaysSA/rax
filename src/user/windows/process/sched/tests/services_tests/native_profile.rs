//! Captured kernel identity for portable native-behavior replay.
use super::Proc;

pub(super) fn kernel_profile(p: &mut Proc, build: u32, machine: u16) {
    use crate::user::windows::{loader::apiset_schema::ApiSetSchema, native::NativeRuntime};
    let schema: Vec<u8> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let mut native = NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: Default::default(),
        apisets: ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        gui: Default::default(),
        code_integrity: Err("controlled filename query profile".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
    };
    native.version.build = build;
    native.object_namespace.native_machine = Some(machine);
    p.native = Some(native);
    std::sync::Arc::make_mut(&mut p.cfg).version.build = 12345;
}
