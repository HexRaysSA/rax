use super::*;
use crate::user::windows::memory::prot;

fn reserved() -> Query {
    // Native pure x86 Kernel32: logical F0000, last run E5000..F4000.
    Query {
        base: 0x7575_5000,
        allocation: 0x7567_0000,
        size: 0xf000,
        state: mem::RESERVE,
        protection: 0,
        kind: mem::IMAGE,
    }
}

#[test]
fn native_image_region_retains_reserved_owner_tail_without_expanding_copied_bytes() {
    let selected = reserved().select(0x7567_0000, 0xf0000, 0xe5000).unwrap();
    assert_eq!(
        selected.region,
        ImageRegion {
            offset: 0xe5000,
            size: 0xb000,
            state: mem::RESERVE,
            protection: 0
        }
    );
    assert_eq!(selected.reserved_tail, 0x4000);
    let mut ordinary = reserved();
    ordinary.size = 0xb000;
    ordinary.state = mem::COMMIT;
    ordinary.protection = prot::READONLY;
    let selected = ordinary.select(0x7567_0000, 0xf0000, 0xe5000).unwrap();
    assert_eq!(selected.region.size, 0xb000);
    assert_eq!(selected.reserved_tail, 0);
}

#[test]
fn native_image_region_rejects_foreign_inconsistent_or_unbounded_query_spans() {
    for mutate in [
        |q: &mut Query| q.allocation += 4096,
        |q: &mut Query| q.base -= 4096,
        |q: &mut Query| q.base += 4096,
        |q: &mut Query| q.kind = mem::PRIVATE,
        |q: &mut Query| q.size = 0,
        |q: &mut Query| q.size += 1,
        |q: &mut Query| q.size = u64::MAX,
        |q: &mut Query| q.size = 0xb000 + MAX_IMAGE_TAIL_BYTES + 4096,
        |q: &mut Query| q.state = mem::FREE,
        |q: &mut Query| q.protection = prot::READONLY,
    ] {
        let mut q = reserved();
        mutate(&mut q);
        assert!(q.select(0x7567_0000, 0xf0000, 0xe5000).is_err());
    }
    let mut committed = reserved();
    committed.state = mem::COMMIT;
    committed.protection = prot::READONLY;
    assert!(committed.select(0x7567_0000, 0xf0000, 0xe5000).is_err());
    for (base, size, offset) in [
        (0, 0xf0000, 0xe5000),
        (0x7567_0001, 0xf0000, 0xe5000),
        (0x7567_0000, 0xf0001, 0xe5000),
        (0x7567_0000, 0xf0000, 0xf0000),
        (0x7567_0000, MAX_IMAGE_BYTES + 4096, 0),
        (u64::MAX - 4095, 8192, 0),
    ] {
        assert!(reserved().select(base, size, offset).is_err());
    }
}

#[test]
fn native_image_region_page_and_tail_limits_preserve_progress_and_exact_end() {
    for (base, bytes) in [(65536, 4096), (0x1_0000_0000, MAX_IMAGE_BYTES)] {
        let q = Query {
            base,
            allocation: base,
            size: bytes + MAX_IMAGE_TAIL_BYTES,
            state: mem::RESERVE,
            protection: 0,
            kind: mem::IMAGE,
        };
        let selected = q.select(base, bytes, 0).unwrap();
        assert_eq!(selected.region.size, bytes);
        assert_eq!(selected.reserved_tail, MAX_IMAGE_TAIL_BYTES);
    }
}

#[test]
fn native_image_tail_query_keeps_reserved_ownership_and_rejects_untyped_payload() {
    let base = 0x7000_0000;
    let payload = 0x474000;
    let tail = || Query {
        base: base + payload,
        allocation: base,
        size: 0x3000,
        state: mem::RESERVE,
        protection: 0,
        kind: mem::IMAGE,
    };
    assert_eq!(tail().reserved_after(base, payload).unwrap(), 0x3000);
    let mut adjacent = tail();
    adjacent.allocation += payload;
    assert_eq!(adjacent.reserved_after(base, payload).unwrap(), 0);
    for mutate in [
        |q: &mut Query| q.base -= 4096,
        |q: &mut Query| q.size = 0,
        |q: &mut Query| q.size = MAX_IMAGE_TAIL_BYTES + 4096,
        |q: &mut Query| q.kind = mem::PRIVATE,
        |q: &mut Query| q.protection = prot::READONLY,
        |q: &mut Query| q.state = mem::COMMIT,
    ] {
        let mut query = tail();
        mutate(&mut query);
        assert!(query.reserved_after(base, payload).is_err());
    }
    assert!(tail().reserved_after(u64::MAX - 4095, 8192).is_err());
}
