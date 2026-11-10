use super::*;
use crate::isa::x86_64::{X86UserSegment, gdt_entry};
use crate::user::windows::arch::{WOW64_FS_GDT_INDEX, WinCpu};
use crate::user::windows::context::{RegContext, x64};
use crate::user::windows::process::native_start::EntryPoints;

fn native_thread(main: bool) -> (WindowsProcess, u32) {
    let mut process = fixture(WinArch::X64);
    let p = process.state_mut();
    let mut native = runtime(Some(0xaa64), (10, 0, 29704));
    native.startup = Some(EntryPoints {
        loader: 0x50000,
        thread: 0x51000,
        module: 0x40000,
        callback: None,
    });
    p.native = Some(native);
    // The actual native identity selects the profile, independently of copy.
    std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
    let tid = super::super::super::thread::create(p, 0x52000, 0x1234, 0, main).unwrap();
    (process, tid)
}

fn selectors(cpu: &WinCpu) -> [u16; 6] {
    let v = cpu.x86().unwrap().vcpu();
    [
        X86UserSegment::Cs,
        X86UserSegment::Ss,
        X86UserSegment::Ds,
        X86UserSegment::Es,
        X86UserSegment::Fs,
        X86UserSegment::Gs,
    ]
    .map(|segment| v.user_selector(segment))
}

#[test]
fn chpe_thread_creation_replays_native_selectors_before_saving_loader_context() {
    let profile: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/specifications/windows/native-chpe-segments/profile-29704-v1.json"
    ))
    .unwrap();
    assert_eq!(profile["kernel"], serde_json::json!([10, 0, 29704]));
    assert_eq!(profile["controller_exit"], 0);
    assert_eq!(profile["child_exit"], 0);
    assert_eq!(profile["child_resume_previous"], 1);
    let expected = ["cs", "ss", "ds", "es", "fs", "gs"]
        .map(|name| profile["initial_selectors"][name].as_u64().unwrap() as u16);
    assert_eq!(expected, [0x33, 0x2b, 0x2b, 0x2b, 0x53, 0x2b]);
    assert_eq!(profile["fs_base"], 0);
    assert_eq!(profile["descriptor_observations"][2]["access"], 0x40f300);
    assert_eq!(profile["descriptor_observations"][2]["limit"], 4095);
    for main in [false, true] {
        let (process, tid) = native_thread(main);
        let p = process.state();
        let thread = &p.threads[&tid];
        assert_eq!(selectors(&thread.cpu), expected, "main={main}");
        let v = thread.cpu.x86().unwrap().vcpu();
        assert_eq!(v.fs_base(), 0);
        assert_eq!(v.gs_base(), thread.teb);
        assert_eq!(
            v.user_gdt_entry(WOW64_FS_GDT_INDEX),
            Some(gdt_entry(0x40f3, 0, 0xfff))
        );
        let saved = RegContext::read(&p.space, WinArch::X64, thread.cpu.gpr(1)).unwrap();
        let offsets = [
            x64::SEG_CS,
            x64::SEG_SS,
            x64::SEG_DS,
            x64::SEG_ES,
            x64::SEG_FS,
            x64::SEG_GS,
        ];
        for (offset, selector) in offsets.into_iter().zip(expected) {
            assert_eq!(
                u16::from_le_bytes(saved.bytes()[offset..offset + 2].try_into().unwrap()),
                selector,
                "main={main} offset={offset:#x}"
            );
        }
        assert_eq!(saved.validate(&thread.cpu), Ok(()));
        assert_eq!(thread.cpu.pc(), 0x50000);
    }
}

#[test]
fn chpe_thread_segments_survive_reload_clone_and_reject_unowned_context_changes() {
    let (mut process, tid) = native_thread(false);
    let p = process.state_mut();
    let original = &p.threads[&tid];
    let teb = original.teb;
    let mut cpu = original.cpu.new_thread();
    let descriptor = cpu.x86().unwrap().vcpu().user_gdt_entry(WOW64_FS_GDT_INDEX);
    assert_eq!(descriptor, Some(gdt_entry(0x40f3, 0, 0xfff)));
    cpu.x86_mut()
        .unwrap()
        .vcpu_mut()
        .load_user_segment(X86UserSegment::Fs, 0x53)
        .unwrap();
    assert_eq!(cpu.teb(), teb);
    let area = super::super::super::thread::chpe::Area::allocate(&mut p.vm).unwrap();
    cpu.bind_chpe_area(area.clone()).unwrap();
    let mut cloned = cpu.new_thread();
    assert_eq!(selectors(&cloned), selectors(&cpu));
    assert_eq!(
        cloned
            .x86()
            .unwrap()
            .vcpu()
            .user_gdt_entry(WOW64_FS_GDT_INDEX),
        descriptor
    );
    assert_eq!(cloned.teb(), teb);
    cloned
        .x86_mut()
        .unwrap()
        .vcpu_mut()
        .load_user_segment(X86UserSegment::Fs, 0x53)
        .unwrap();
    assert_eq!(cloned.x86().unwrap().vcpu().fs_base(), 0);
    let before = RegContext::capture(&cpu);
    for (offset, selector) in [(x64::SEG_FS, 0u16), (x64::SEG_GS, 0), (x64::SEG_FS, 0x7b)] {
        let mut bytes = before.bytes().to_vec();
        bytes[offset..offset + 2].copy_from_slice(&selector.to_le_bytes());
        let changed = RegContext::from_bytes(WinArch::X64, bytes);
        assert_eq!(changed.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(RegContext::capture(&cpu), before);
    }
    p.space.w16(area.context + x64::SEG_FS as u64, 0).unwrap();
    assert!(cpu.sync_chpe_area(false).is_err());
    assert_eq!(RegContext::capture(&cpu), before);
}

#[test]
fn chpe_thread_fs_descriptor_executes_the_native_lar_lsl_observations() {
    use crate::user::windows::arch::CpuStop;
    use crate::user::windows::memory::mem;

    let (mut process, tid) = native_thread(false);
    let p = process.state_mut();
    let mut cpu = p.threads[&tid].cpu.new_thread();
    let teb = cpu.teb();
    let code = 0x5000_0000;
    p.vm.allocate(
        Some(code),
        2 * PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap();
    // The native producer's XOR/LAR/SETZ/MOV; XOR/LSL/SETZ/MOV sequence.
    p.space
        .wr(
            code,
            &[
                0x31, 0xc0, 0x0f, 0x02, 0xc1, 0x0f, 0x94, 0x42, 0x08, 0x89, 0x02, 0x31, 0xc0, 0x0f,
                0x03, 0xc1, 0x0f, 0x94, 0x42, 0x09, 0x89, 0x42, 0x04,
            ],
        )
        .unwrap();
    p.vm.protect(code, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    let output = code + PAGE_SIZE;
    cpu.set_pc(code);
    cpu.set_gpr(1, 0x53);
    cpu.set_gpr(2, output);
    let result = cpu.run(8);
    assert!(matches!(result, CpuStop::Yield), "{result:?}");
    assert_eq!(p.space.u32(output).unwrap(), 0x0040_f300);
    assert_eq!(p.space.u32(output + 4).unwrap(), 0xfff);
    assert_eq!(p.space.bytes(output + 8, 2).unwrap(), [1, 1]);
    assert_eq!(cpu.x86().unwrap().vcpu().fs_base(), 0);
    assert_eq!(cpu.teb(), teb);
}

#[test]
fn chpe_thread_initialization_leaves_other_constructed_profiles_unchanged() {
    for arch in WinArch::ALL {
        for identity in [
            None,
            Some((Some(0x8664), (10, 0, 29704))),
            Some((Some(0xaa64), (10, 0, 29703))),
            Some((Some(0xaa64), (10, 0, 29705))),
            Some((None, (10, 0, 29704))),
        ] {
            let mut process = fixture(arch);
            let p = process.state_mut();
            p.native = identity.map(|(machine, kernel)| runtime(machine, kernel));
            let mut cpu = p.threads.values().next().unwrap().cpu.new_thread();
            let before = RegContext::capture(&cpu);
            let teb = cpu.teb();
            initialize_thread(p, &mut cpu).unwrap();
            assert_eq!(RegContext::capture(&cpu), before, "{arch}/{identity:?}");
            assert_eq!(cpu.teb(), teb);
        }
    }
}
