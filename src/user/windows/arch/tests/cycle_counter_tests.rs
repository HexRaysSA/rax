//! Windows ARM64's user-readable processor cycle counter.
use super::*;

const MRS_PMCCNTR: u32 = 0xD53B_9D00;

fn words(words: &[u32]) -> AddressSpace {
    space(
        &words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn windows_pmccntr_retires_all_destinations_without_losing_context() {
    for rt in 0..32 {
        let space = words(&[MRS_PMCCNTR | rt]);
        let mut cpu = WinCpu::new(WinArch::Arm64, &space);
        cpu.set_pc(CODE);
        cpu.set_sp(TEB + PAGE_SIZE);
        for n in 0..31 {
            cpu.set_gpr(n, 0x8BAD_F00D_0000_0000 + n as u64);
        }
        cpu.set_teb(TEB);
        cpu.a64_mut().unwrap().core_mut().set_nzcv_bits(0b1011);
        let before = (0..31).map(|n| cpu.gpr(n)).collect::<Vec<_>>();
        assert!(matches!(cpu.run(0), CpuStop::Yield));
        assert_eq!(cpu.pc(), CODE);
        assert!(matches!(cpu.run(1), CpuStop::Yield), "rt={rt}");
        assert_eq!(cpu.pc(), CODE + 4, "rt={rt}");
        assert_eq!(cpu.sp(), TEB + PAGE_SIZE, "rt={rt}");
        assert_eq!(cpu.a64().unwrap().core().nzcv_bits(), 0b1011, "rt={rt}");
        assert_eq!(cpu.a64().unwrap().core().instruction_count(), 1);
        assert_eq!(cpu.a64().unwrap().core().cycle_count(), Some(1));
        for (n, expected) in before.into_iter().enumerate() {
            if n != rt as usize {
                assert_eq!(cpu.gpr(n), expected, "rt={rt} x{n}");
            }
        }
        #[cfg(not(all(windows, target_arch = "aarch64")))]
        if rt < 31 {
            assert_eq!(cpu.gpr(rt as usize), 0, "rt={rt}");
        }
        assert_eq!(space.u32(CODE).unwrap(), MRS_PMCCNTR | rt);
    }
}

#[test]
fn windows_pmccntr_inherits_the_profile_in_new_threads() {
    let space = words(&[MRS_PMCCNTR | 8]);
    let mut original = WinCpu::new(WinArch::Arm64, &space);
    original.set_pc(CODE);
    let mut child = original.new_thread();
    assert!(matches!(child.run(1), CpuStop::Yield));
    assert_eq!(child.pc(), CODE + 4);
    assert_eq!(original.pc(), CODE);
    assert_eq!(original.a64().unwrap().core().instruction_count(), 0);
}

#[test]
fn windows_pmccntr_read_preserves_an_exclusive_reservation_across_slices() {
    // LLVM MC: LDAXR X0,[X3]; MRS X8,PMCCNTR_EL0; STLXR W1,X2,[X3].
    let space = words(&[0xC85F_FC60, MRS_PMCCNTR | 8, 0xC801_FC62]);
    space.w64(TEB, 0x1122_3344_5566_7788).unwrap();
    let mut cpu = WinCpu::new(WinArch::Arm64, &space);
    cpu.set_pc(CODE);
    cpu.set_gpr(3, TEB);
    cpu.set_gpr(2, 0x8877_6655_4433_2211);
    for step in 0..3 {
        assert!(matches!(cpu.run(1), CpuStop::Yield), "step={step}");
    }
    assert_eq!(cpu.gpr(0), 0x1122_3344_5566_7788);
    assert_eq!(cpu.gpr(1), 0);
    assert_eq!(space.u64(TEB).unwrap(), 0x8877_6655_4433_2211);
}

#[test]
fn windows_pmccntr_does_not_grant_other_pmu_reads_or_writes() {
    for word in [
        0xD51B_9D00, // MSR PMCCNTR_EL0,X0.
        0xD53B_9C00, // MRS X0,PMCR_EL0.
        0xD53B_9E00, // MRS X0,PMUSERENR_EL0.
        0xD538_1000, // MRS X0,SCTLR_EL1.
    ] {
        let space = words(&[word]);
        let mut cpu = WinCpu::new(WinArch::Arm64, &space);
        cpu.set_pc(CODE);
        assert!(
            matches!(cpu.run(1), CpuStop::Undefined { pc: CODE, .. }),
            "{word:#010x}"
        );
        assert_eq!(cpu.pc(), CODE);
        assert_eq!(cpu.a64().unwrap().core().instruction_count(), 0);
    }
}

#[test]
fn pmccntr_remains_disabled_in_the_default_os_neutral_arm64_cpu() {
    let space = words(&[MRS_PMCCNTR]);
    let mut cpu = A64UserCpu::new(&space);
    cpu.core_mut().set_pc(CODE);
    assert!(matches!(cpu.run(1), A64Exit::Undefined { pc: CODE, .. }));
    assert_eq!(cpu.pc(), CODE);
    assert_eq!(cpu.core().instruction_count(), 0);
}

#[cfg(not(all(windows, target_arch = "aarch64")))]
#[test]
fn windows_pmccntr_virtual_cycles_include_the_reads_themselves() {
    let space = words(&[MRS_PMCCNTR, MRS_PMCCNTR | 1, 0xD503_201F, MRS_PMCCNTR | 2]);
    let mut cpu = WinCpu::new(WinArch::Arm64, &space);
    cpu.set_pc(CODE);
    assert!(matches!(cpu.run(4), CpuStop::Yield));
    assert_eq!((cpu.gpr(0), cpu.gpr(1), cpu.gpr(2)), (0, 1, 3));
    assert_eq!(cpu.a64().unwrap().core().cycle_count(), Some(4));
}

#[cfg(all(windows, target_arch = "aarch64"))]
#[test]
fn windows_pmccntr_matches_a_pinned_native_processor_counter() {
    use std::ffi::c_void;

    #[repr(C)]
    struct ProcessorNumber {
        group: u16,
        number: u8,
        reserved: u8,
    }

    #[repr(C)]
    struct GroupAffinity {
        mask: usize,
        group: u16,
        reserved: [u16; 3],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThread() -> *mut c_void;
        fn GetCurrentProcessorNumberEx(processor: *mut ProcessorNumber);
        fn SetThreadGroupAffinity(
            thread: *mut c_void,
            affinity: *const GroupAffinity,
            previous: *mut GroupAffinity,
        ) -> i32;
    }

    fn reference() -> u64 {
        let value: u64;
        // SAFETY: the Windows ARM64 ABI grants EL0 reads. ISB brackets this
        // independent reference sample; no guest address or state is used.
        unsafe {
            std::arch::asm!(
                "isb",
                "mrs {value}, pmccntr_el0",
                "isb",
                value = out(reg) value,
                options(nostack, preserves_flags),
            );
        }
        value
    }

    // A dedicated thread owns the temporary affinity through its exit. This
    // leaves the test runner's affinity intact, including Windows 11's
    // unrestricted multi-group default; a saved one-group mask cannot encode
    // that default. Select the processor actually running this helper so its
    // group and processor are available under the process's existing policy.
    std::thread::spawn(|| {
        let space = words(&[MRS_PMCCNTR | 8]);
        let mut cpu = WinCpu::new(WinArch::Arm64, &space);
        cpu.set_pc(CODE);
        let mut processor = ProcessorNumber {
            group: 0,
            number: 0,
            reserved: 0
        };
        // SAFETY: initialized host-owned PROCESSOR_NUMBER storage.
        unsafe {
            GetCurrentProcessorNumberEx(&mut processor);
        }
        let mask = 1usize
            .checked_shl(u32::from(processor.number))
            .expect("processor index fits its native group mask");
        let affinity = GroupAffinity {
            mask,
            group: processor.group,
            reserved: [0; 3]
        };
        // SAFETY: only this temporary helper thread, with its actual processor
        // and zero reserved fields. PreviousGroupAffinity is optional. Thread
        // exit removes the setting on both success and panic.
        assert_ne!(
            unsafe {
                SetThreadGroupAffinity(GetCurrentThread(), &affinity, std::ptr::null_mut())
            }, 0);
        let before = reference();
        let stop = cpu.run(1);
        let after = reference();
        let actual = cpu.gpr(8);
        assert!(matches!(stop, CpuStop::Yield));
        let span = after.wrapping_sub(before);
        assert!(
            span < 1 << 63,
            "native counter jumped backwards: {before:#x} -> {after:#x}");
        assert!(
            actual.wrapping_sub(before) <= span,
            "before={before:#x} actual={actual:#x} after={after:#x}");
        println!(
            "native-pmccntr before={before:#x} actual={actual:#x} after={after:#x} group={} affinity={mask:#x}",
            processor.group);
    })
    .join()
    .expect("native counter calibration thread");
}
