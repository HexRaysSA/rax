//! ARM64 local-exclusive-monitor lifetime at Windows scheduler boundaries.

use super::*;

// Encodings match the independently assembled CPU-adapter test corpus:
// LDXR X0,[X1]; ADD X0,X0,#1; STXR W2,X0,[X1]; NOP.
const LDXR_X0_X1: u32 = 0xC85F_7C20;
const ADD_X0_X0_1: u32 = 0x9100_0400;
const STXR_W2_X0_X1: u32 = 0xC802_7C20;
const NOP: u32 = 0xD503_201F;
const INITIAL: u64 = 0x35;

fn fixture(with_peer: bool) -> (Proc, u64, u64) {
    let mut p = process(WinArch::Arm64);
    let (code, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    for (i, instruction) in [LDXR_X0_X1, ADD_X0_X0_1, STXR_W2_X0_X1, NOP]
        .into_iter()
        .enumerate()
    {
        p.space.w32(code + 4 * i as u64, instruction).unwrap();
    }
    p.vm.protect(code, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    let (data, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    p.space.w64(data, INITIAL).unwrap();

    let mut owner = thread(&mut p, 8);
    owner.cpu.set_pc(code);
    owner.cpu.set_gpr(1, data);
    p.threads.insert(8, owner);
    if with_peer {
        let mut peer = thread(&mut p, 12);
        peer.cpu.set_pc(code + 12);
        p.threads.insert(12, peer);
    }
    (p, code, data)
}

fn step_selected(p: &mut Proc, previous: &mut u32) -> (u32, CpuStop) {
    let tid = select(p, *previous).expect("runnable test thread");
    clear_on_thread_switch(p, *previous, tid);
    *previous = tid;
    let stop = p.threads.get_mut(&tid).unwrap().cpu.run(1);
    (tid, stop)
}

#[test]
fn arm64_one_instruction_yields_preserve_same_thread_reservation() {
    let (mut p, code, data) = fixture(false);
    let mut previous = 0;
    for pc in [code + 4, code + 8, code + 12] {
        let (tid, stop) = step_selected(&mut p, &mut previous);
        assert_eq!(tid, 8);
        assert!(matches!(stop, CpuStop::Yield), "{stop:?}");
        assert_eq!(p.threads[&tid].cpu.pc(), pc);
    }
    assert_eq!(p.threads[&8].cpu.gpr(2), 0, "STXR must succeed");
    assert_eq!(p.space.ptr(data, 8).unwrap(), INITIAL + 1);
}

#[test]
fn arm64_selected_peer_invalidates_outgoing_reservation() {
    let (mut p, code, data) = fixture(true);
    let mut previous = 0;
    let (tid, stop) = step_selected(&mut p, &mut previous);
    assert_eq!(tid, 8);
    assert!(matches!(stop, CpuStop::Yield), "{stop:?}");
    assert_eq!(p.threads[&8].cpu.pc(), code + 4);

    let (tid, stop) = step_selected(&mut p, &mut previous);
    assert_eq!(tid, 12, "round-robin must select the peer");
    assert!(matches!(stop, CpuStop::Yield), "{stop:?}");
    p.threads.get_mut(&12).unwrap().suspend = 1;

    for pc in [code + 8, code + 12] {
        let (tid, stop) = step_selected(&mut p, &mut previous);
        assert_eq!(tid, 8);
        assert!(matches!(stop, CpuStop::Yield), "{stop:?}");
        assert_eq!(p.threads[&8].cpu.pc(), pc);
    }
    assert_eq!(p.threads[&8].cpu.gpr(2), 1, "STXR must fail");
    assert_eq!(p.space.ptr(data, 8).unwrap(), INITIAL);
}

#[test]
fn round_robin_selection_excludes_suspended_and_blocked_threads() {
    let mut p = process(WinArch::X64);
    let t1 = thread(&mut p, 8);
    let t2 = thread(&mut p, 12);
    p.threads.insert(8, t1);
    p.threads.insert(12, t2);
    assert_eq!(select(&p, 0), Some(8));
    assert_eq!(select(&p, 8), Some(12));
    assert_eq!(select(&p, 12), Some(8));
    p.threads.get_mut(&8).unwrap().suspend = 1;
    assert_eq!(select(&p, 12), Some(12));
    p.threads.get_mut(&12).unwrap().state = ThreadState::Waiting(sync::Wait::Sleep {
        deadline: None,
        alertable: false,
    });
    assert_eq!(select(&p, 12), None);
}

#[test]
fn bounded_process_calls_preserve_reservations_until_an_actual_thread_switch() {
    use std::sync::atomic::AtomicBool;
    for with_peer in [false, true] {
        let (mut p, _, data) = fixture(with_peer);
        Arc::make_mut(&mut p.cfg).slice_insns = 1;
        let mut scheduler = Scheduler::default();
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            scheduler.run_slice(&mut p, 1, &cancelled),
            RunStatus::BudgetExhausted
        );
        if with_peer {
            assert_eq!(
                scheduler.run_slice(&mut p, 1, &cancelled),
                RunStatus::BudgetExhausted
            );
            p.threads.get_mut(&12).unwrap().suspend = 1;
        }
        for _ in 0..2 {
            assert_eq!(
                scheduler.run_slice(&mut p, 1, &cancelled),
                RunStatus::BudgetExhausted
            );
        }
        assert_eq!(p.threads[&8].cpu.gpr(2), u64::from(with_peer));
        assert_eq!(
            p.space.ptr(data, 8).unwrap(),
            INITIAL + u64::from(!with_peer)
        );
    }
}
