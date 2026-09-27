use super::*;

const I: u32 = PTHRW_INC;

#[test]
fn sequence_comparisons_wrap() {
    assert!(is_seqlower(I, 2 * I));
    assert!(!is_seqlower(2 * I, I));
    assert!(is_seqhigher(2 * I, I));
    // Flag bits do not count.
    assert!(is_seqlower_eq(I | 0x7f, I));
    assert!(is_seqhigher_eq(I, I | 0x3));
    // Across the wrap, a small count is higher than a large one.
    let top = PTHRW_COUNT_MASK;
    assert!(is_seqhigher(0, top));
    assert!(is_seqlower(top, I));
    assert_eq!(diff_genseq(3 * I, I), 2 * I);
    assert_eq!(diff_genseq(0, top), I);
    assert_eq!(find_diff(5 * I, 2 * I), 3);
    assert_eq!(find_diff(2 * I, 5 * I), 3);
    assert_eq!(find_diff(I, I), 0);
}

fn waiter(seq: u32, tid: u64) -> Kwe {
    Kwe {
        state: KweState::InWait,
        lockseq: seq,
        count: 1,
        tid,
    }
}

fn never(_: u64) -> bool {
    false
}

#[test]
fn sequence_fit_insertion_orders_waiters() {
    let mut kwq = Kwq::default();
    for (seq, tid) in [(3 * I, 3), (I, 1), (5 * I, 5), (4 * I, 4)] {
        assert_eq!(
            kwq.insert(QUEUE_WRITE, waiter(seq, tid), seq, Fit::Seq, &mut never),
            0
        );
    }
    let order: Vec<u64> = kwq.queues[QUEUE_WRITE].list.iter().map(|k| k.tid).collect();
    assert_eq!(order, [1, 3, 4, 5]);
    assert_eq!(
        (
            kwq.queues[QUEUE_WRITE].firstnum,
            kwq.queues[QUEUE_WRITE].lastnum
        ),
        (I, 5 * I)
    );
    assert_eq!((kwq.lowseq, kwq.highseq, kwq.inqueue), (I, 5 * I, 4));
    // A second waiter at an end's sequence is refused.
    assert_eq!(
        kwq.insert(QUEUE_WRITE, waiter(I, 9), I, Fit::Seq, &mut never),
        Errno::EBUSY.0
    );
    // Removal keeps the bounds.
    let i = kwq.position_of(QUEUE_WRITE, 5).expect("queued");
    kwq.remove(QUEUE_WRITE, i);
    assert_eq!(
        (kwq.highseq, kwq.queues[QUEUE_WRITE].lastnum),
        (4 * I, 4 * I)
    );
    assert_eq!(kwq.count_tolowest(QUEUE_WRITE, 3 * I), 2);
    assert_eq!(kwq.find_seq_till(4 * I, 3), (true, 3));
    assert_eq!(kwq.find_seq_till(4 * I, 4), (false, 3));
}

#[test]
fn first_fit_insertion_keeps_arrival_order() {
    let mut kwq = Kwq::default();
    for (seq, tid) in [(3 * I, 3), (I, 1), (2 * I, 2)] {
        kwq.insert(QUEUE_WRITE, waiter(seq, tid), seq, Fit::First, &mut never);
    }
    let order: Vec<u64> = kwq.queues[QUEUE_WRITE].list.iter().map(|k| k.tid).collect();
    assert_eq!(order, [3, 1, 2]);
    assert_eq!(kwq.queues[QUEUE_WRITE].firstnum, I);
}

#[test]
fn a_prepost_beside_a_cancelled_waiter() {
    let mut kwq = Kwq::default();
    kwq.insert(QUEUE_WRITE, waiter(I, 7), I, Fit::Seq, &mut never);
    // A fake entry at a waiter's sequence counts even when refused ...
    kwq.prepost(KweState::Prepost, I, &mut never);
    assert_eq!((kwq.inqueue, kwq.fakecount), (1, 1));
    // ... and is queued beside a thread being cancelled.
    kwq.prepost(KweState::Prepost, I, &mut |t| t == 7);
    assert_eq!((kwq.inqueue, kwq.fakecount), (2, 2));
}

#[test]
fn wait_queues_are_freed_when_unused() {
    let mut t = Table::default();
    t.find(0x1000, I, 0, 0, wqtype::INWAIT | wqtype::MTX)
        .expect("found");
    assert_eq!(t.get_mut(0x1000).kind, wqtype::MTX);
    // Another kind of object at the address while in use: EINVAL.
    assert_eq!(t.find(0x1000, 0, 0, 0, wqtype::CVAR), Err(Errno::EINVAL));
    t.release(0x1000, true, wqtype::INWAIT | wqtype::MTX);
    assert!(!t.kwqs.contains_key(&0x1000));
    // A read-write lock's queue stays for the cleanup delay.
    t.find(0x2000, 0, 0, 0, wqtype::RWLOCK).expect("found");
    t.release(0x2000, false, wqtype::RWLOCK);
    assert!(t.kwqs.get(&0x2000).is_some_and(|k| k.freed_at.is_some()));
    // Reused as a condition variable once unused.
    t.find(0x2000, 0, 0, 0, wqtype::CVAR)
        .expect("reinitialized");
    assert_eq!(t.get_mut(0x2000).kind, wqtype::CVAR);
}

#[test]
fn condition_variable_update() {
    let mut kwq = Kwq {
        kind: wqtype::CVAR,
        ..Default::default()
    };
    kwq.clear_reinit_bits();
    kwq.update_cv(3 * I, I, I | sbit::CV_C);
    assert_eq!((kwq.lword, kwq.uword), (3 * I, I));
    assert_eq!(kwq.lastunlockseq, I);
    // Lower values do not move the words back.
    kwq.update_cv(2 * I, 0, 0);
    assert_eq!(kwq.lword, 3 * I);
}
