use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess, thread};

fn process(arch: WinArch) -> WindowsProcess {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::embedded("C:\\teb-extent.exe", vec![], vec![], 4096).unwrap();
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(config, image.to_vec()).unwrap()
}

#[test]
fn teb_second_page_writes_preserve_peb_and_other_threads_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        for _ in 0..2 {
            thread::create(p, p.modules.exe().entry, 0, 0x10000, false).unwrap();
        }
        let tebs: Vec<_> = p.threads.values().map(|thread| thread.teb).collect();
        let peb = p.space.bytes(p.peb, 4096).unwrap();
        for (index, &teb) in tebs.iter().enumerate() {
            assert!(
                teb + 8192 <= p.peb,
                "{arch}: second TEB page must precede PEB"
            );
            let neighbors: Vec<_> = tebs
                .iter()
                .filter(|&&other| other != teb)
                .map(|&other| (other, p.space.bytes(other, 8192).unwrap()))
                .collect();
            // Includes the installed x86 scheduler data slot at TEB+0x1018
            // and the last byte of the second page, rather than one field only.
            p.space
                .wr(teb + 4096, &vec![0xa0 + index as u8; 4096])
                .unwrap();
            assert_eq!(p.space.bytes(p.peb, 4096).unwrap(), peb, "{arch}");
            for (other, bytes) in neighbors {
                assert_eq!(p.space.bytes(other, 8192).unwrap(), bytes, "{arch}");
            }
        }
        let id = *p.threads.keys().next().unwrap();
        let dead = p.threads.remove(&id).unwrap();
        let teb = dead.teb;
        thread::destroy(p, dead, 0);
        for address in [teb, teb + 4096] {
            assert_eq!(p.vm.query(address).unwrap().state, mem::RESERVE, "{arch}");
        }
        // Inspect the reclaimed allocation before thread initialization writes
        // native64 TLS fields in its second page.
        let replacement = Allocation::allocate(p).unwrap();
        assert_eq!(replacement.teb, teb, "{arch}: released extent is reusable");
        assert!(
            p.space
                .bytes(teb, 8192)
                .unwrap()
                .iter()
                .all(|&byte| byte == 0),
            "{arch}: recommitted TEB extent must be zero before initialization"
        );
        assert_eq!(p.space.bytes(p.peb, 4096).unwrap(), peb, "{arch}");
        replacement.release(p);
    }
}

#[test]
fn creation_flags_preserve_unrelated_bits_in_both_wow64_teb_views() {
    let mut process = process(WinArch::X86);
    let p = process.state_mut();
    let base =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let allocation = Allocation {
        base,
        bytes: 16384,
        teb: base + 8192,
        companion: Some(base),
        claim: None,
        owner: None,
        chpe: None,
    };
    for flags in [0, 2, 4, 0x20, 0x27] {
        p.space.w16(base + 0x17ee, 0x1201).unwrap();
        p.space.w16(base + 8192 + 0xfca, 0x0202).unwrap();
        allocation.initialize_creation_flags(p, flags).unwrap();
        let bits = if flags & 2 != 0 { 8 } else { 0 } | if flags & 0x20 != 0 { 0x4000 } else { 0 };
        assert_eq!(p.space.u16(base + 0x17ee).unwrap(), 0x1201 | bits);
        assert_eq!(p.space.u16(base + 8192 + 0xfca).unwrap(), 0x0202 | bits);
    }
}
