//! Literal native pagefile-view observations and guest ownership boundaries.
use super::*;
use crate::user::mm::SharedObject;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};
use std::sync::{Arc, Weak};

#[path = "section_map_pagefile_tests/ownership.rs"]
mod ownership;
#[path = "section_map_pagefile_tests/replay.rs"]
mod replay;

pub(super) fn backed_section(p: &mut Proc) -> (u64, Weak<SharedObject>) {
    let backing = Arc::new(SharedObject::anonymous(65536).unwrap());
    let weak = Arc::downgrade(&backing);
    let id = p.objects.create(Object::Mapping {
        file: None,
        size: 65536,
        protect: prot::READWRITE,
        attributes: 0x0800_0000,
        shared: Some(backing),
    });
    (p.objects.open_access(id, false, 6).unwrap().into(), weak)
}

fn process(arch: WinArch, laa: bool) -> (WindowsProcess, Thread) {
    if !laa {
        return fixture(arch, "NtMapViewOfSection", SERVICE);
    }
    assert_eq!(arch, WinArch::X86);
    let mut bytes =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            .to_vec();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let flags = u16::from_le_bytes(bytes[pe + 22..pe + 24].try_into().unwrap()) | 0x20;
    bytes[pe + 22..pe + 24].copy_from_slice(&flags.to_le_bytes());
    let mut config = WindowsConfig::embedded("C:\\pagefile-laa.exe", vec![], vec![], 1).unwrap();
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, bytes).unwrap();
    let p = process.state_mut();
    let module = p.modules.by_name("ntdll.dll").unwrap();
    p.modules.nt_services = Some((module, table(arch, "NtMapViewOfSection", SERVICE)));
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    thread.attached = true;
    thread.main = false;
    (process, thread)
}
