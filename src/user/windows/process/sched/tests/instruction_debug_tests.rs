//! Native ARM64 comparator dispatch, using the actual context installation path.
use super::*;

#[test]
fn arm64_instruction_debug_context_produces_breakpoint_status_at_faulting_pc() {
    for enabled in [false, true] {
        let mut p = process(WinArch::Arm64);
        let (pc, _) =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap();
        p.space.w32(pc, 0x91000400).unwrap(); // ADD X0,X0,#1
        p.vm.protect(pc, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
        let mut thread = thread(&mut p, 8);
        thread.cpu.set_pc(pc);
        thread.cpu.set_gpr(0, 41);
        let mut bytes = vec![0; 120];
        bytes[..4].copy_from_slice(&(if enabled { 0x1e5u32 } else { 0x1e4 }).to_le_bytes());
        bytes[32..40].copy_from_slice(&pc.to_le_bytes());
        thread
            .cpu
            .apply_kernel_debug_context(WinArch::Arm64, &bytes, 1 << 32)
            .unwrap();
        let stop = thread.cpu.run(1);
        if enabled {
            assert!(
                matches!(stop, CpuStop::HardwareBreakpoint { pc: at } if at == pc),
                "{stop:?}"
            );
            assert_eq!((thread.cpu.pc(), thread.cpu.gpr(0)), (pc, 41));
            assert_eq!(
                handle_stop(&mut p, &mut thread, stop),
                Outcome::ProcessTerminate(STATUS_BREAKPOINT)
            );
        } else {
            assert!(matches!(stop, CpuStop::Yield));
            assert_eq!((thread.cpu.pc(), thread.cpu.gpr(0)), (pc + 4, 42));
        }
    }
}
