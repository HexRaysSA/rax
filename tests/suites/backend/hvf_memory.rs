//! Actual native mapping policy with deterministic SDK failures.
#[path = "../../../src/backend/hvf/memory_layout.rs"]
mod memory_layout;
use memory_layout::{Layout, MapAccess, Mapping, Span};
use std::collections::BTreeSet;

// Re-export the real product types while replacing only the SDK in the adapter
// tests. These tests do not execute Hypervisor.framework or guest instructions.
mod error {
    pub use rax::error::{Error, Result};
}
mod devices {
    pub use rax::devices::{bus, pci};
}
mod vm {
    pub use rax::vm::memory;
}
#[path = "../../../src/machine/pc/ram.rs"]
pub(crate) mod pc_ram;
mod machine {
    pub(crate) mod pc {
        pub(crate) use crate::pc_ram as ram;
    }
}
#[path = "hvf_memory/native_adapter.rs"]
mod native_adapter;

fn span(start: u64, size: u64) -> Span {
    Span::new(start, size).unwrap()
}

#[test]
fn reported_ram_excludes_padding_and_fixed_device_pages_even_above_four_gib() {
    for size in [0, 4096, 128 << 20, 4 << 30, 8 << 30, 64 << 30] {
        let layout =
            Layout::new(size, &[span(0xfec0_0000, 0x20), span(0xfee0_0000, 0x1000)]).unwrap();
        let end = if size > 3 << 30 {
            size + (1 << 30)
        } else {
            size
        };
        assert!(!layout.contains_mapped(end, 1));
        assert_eq!(
            layout.mapped.iter().map(|span| span.len()).sum::<u64>(),
            size
        );
        assert!(!layout.contains_logical(size + (4 << 30) - 1, 1));
        assert!(!layout.contains_mapped(0xfec0_0000, 4));
        assert!(!layout.contains_logical(0xfee0_0000, 4));
        if size > 3 << 30 {
            assert!(layout.contains_mapped(4 << 30, 4096));
        }
    }
}

#[test]
fn subpage_holes_keep_adjacent_ram_logical_but_not_natively_mapped() {
    let layout = Layout::new(0x5000, &[span(0x2010, 0x20)]).unwrap();
    assert_eq!(layout.mapped, [span(0, 0x2000), span(0x3000, 0x2000)]);
    assert!(layout.contains_logical(0x2000, 0x10));
    assert!(!layout.contains_logical(0x2010, 1));
    assert!(layout.contains_logical(0x2030, 0xfd0));
    assert!(!layout.contains_mapped(0x2000, 1));
    assert!(!layout.contains_logical(0x2000, 0x31));
}

#[test]
fn unsorted_overlapping_holes_merge_without_duplicate_or_empty_maps() {
    let layout = Layout::new(
        0x10000,
        &[
            span(0x4004, 3),
            span(0x2000, 0x3000),
            span(0x5000, 0x1000),
            span(0xf800, 0x2000),
        ],
    )
    .unwrap();
    assert_eq!(layout.mapped, [span(0, 0x2000), span(0x6000, 0x9000)]);
    for address in 0..0x10000 {
        let expected = !(0x2000..0x6000).contains(&address) && address < 0xf000;
        assert_eq!(layout.contains_mapped(address, 1), expected, "{address:#x}");
    }
}

#[test]
fn wrapping_empty_and_unaligned_descriptors_reject_before_native_calls() {
    assert!(Span::new(u64::MAX, 2).is_err());
    assert!(Span::new(0, 0).is_err());
    assert!(Layout::new(4097, &[]).is_err());
    assert!(Layout::new(4096, &[Span { start: 4, end: 3 }]).is_err());
    let layout = Layout::new(4096, &[]).unwrap();
    assert!(!layout.contains_logical(u64::MAX, 2));
    assert!(!layout.contains_mapped(0, 0));
}

#[derive(Default)]
struct Host {
    pages: BTreeSet<u64>,
    calls: usize,
    failures: BTreeSet<usize>,
    uncertain_failure: bool,
}
impl Host {
    fn change(&mut self, span: Span, map: bool) -> Result<(), String> {
        assert_eq!(span.start & 4095, 0);
        assert_eq!(span.len() & 4095, 0);
        self.calls += 1;
        if self.failures.contains(&self.calls) {
            return Err(format!("SDK fault {}", self.calls));
        }
        for p in (span.start..span.end).step_by(4096) {
            if map {
                assert!(self.pages.insert(p), "duplicate map");
            } else {
                assert!(self.pages.remove(&p), "unmap missing page");
            }
        }
        Ok(())
    }
}
impl MapAccess for Host {
    fn map(&mut self, span: Span) -> Result<(), String> {
        self.change(span, true)
    }
    fn unmap(&mut self, span: Span) -> Result<(), String> {
        self.change(span, false)
    }
    fn failed_operation_is_atomic(&self) -> bool {
        !self.uncertain_failure
    }
}

#[test]
fn bar_relocation_decode_disable_and_restore_publish_the_exact_native_pages() {
    let mut mapping = Mapping::default();
    let mut host = Host::default();
    for holes in [
        vec![span(0x2100, 0x20)],
        vec![span(0x7100, 0x20)],
        vec![],
        vec![span(0x2100, 0x20)],
    ] {
        let target = Layout::new(0x10000, &holes).unwrap();
        mapping.publish(target.clone(), &mut host).unwrap();
        let expected: BTreeSet<u64> = (0..0x10000)
            .step_by(4096)
            .filter(|p| target.contains_mapped(*p, 4096))
            .collect();
        assert_eq!(host.pages, expected);
        assert_eq!(mapping.layout, target);
        let calls = host.calls;
        mapping.publish(target, &mut host).unwrap();
        assert_eq!(host.calls, calls);
    }
}

#[test]
fn every_initial_map_and_relocation_failure_rolls_back_without_publishing() {
    let first = Layout::new(0x10000, &[span(0x2000, 0x1000), span(0x6000, 0x1000)]).unwrap();
    for fail in 1..=3 {
        let mut mapping = Mapping::default();
        let mut host = Host {
            failures: [fail].into(),
            ..Default::default()
        };
        assert!(mapping.publish(first.clone(), &mut host).is_err());
        assert!(host.pages.is_empty());
        assert_eq!(mapping.layout, Layout::default());
        assert!(mapping.ready().is_ok());
    }
    let next = Layout::new(0x10000, &[span(0x1000, 0x1000), span(0x8000, 0x1000)]).unwrap();
    for fail in 1..=4 {
        let mut mapping = Mapping::default();
        let mut host = Host::default();
        mapping.publish(first.clone(), &mut host).unwrap();
        let old = host.pages.clone();
        host.failures.insert(host.calls + fail);
        assert!(mapping.publish(next.clone(), &mut host).is_err());
        assert_eq!(host.pages, old);
        assert_eq!(mapping.layout, first);
        assert!(mapping.ready().is_ok());
    }
}

#[test]
fn uncertain_sdk_errors_and_failed_rollback_permanently_prohibit_entry() {
    let first = Layout::new(0x10000, &[span(0x2000, 0x1000)]).unwrap();
    for (failures, uncertain) in [([2, 3].into(), false), ([1].into(), true)] {
        let mut mapping = Mapping::default();
        let mut host = Host {
            failures,
            uncertain_failure: uncertain,
            ..Default::default()
        };
        assert!(mapping.publish(first.clone(), &mut host).is_err());
        assert!(mapping.ready().is_err());
        let calls = host.calls;
        assert!(mapping.publish(first.clone(), &mut host).is_err());
        assert_eq!(calls, host.calls);
    }
}

#[test]
fn every_small_layout_transition_matches_independent_page_and_byte_membership() {
    for initial in 0u32..16 {
        let holes = |mask: u32| {
            (0..4)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| span(i * 4096 + 16, 32))
                .collect::<Vec<_>>()
        };
        let mut mapping = Mapping::default();
        let mut host = Host::default();
        mapping
            .publish(Layout::new(4 * 4096, &holes(initial)).unwrap(), &mut host)
            .unwrap();
        for target in 0u32..16 {
            mapping
                .publish(Layout::new(4 * 4096, &holes(target)).unwrap(), &mut host)
                .unwrap();
            for page in 0..4 {
                let present = target & (1 << page) == 0;
                assert_eq!(host.pages.contains(&(page * 4096)), present);
                for offset in [0, 15, 16, 47, 48, 4095] {
                    let address = page * 4096 + offset;
                    assert_eq!(
                        mapping.layout.contains_logical(address, 1),
                        present || !(16..48).contains(&offset)
                    );
                }
            }
        }
    }
}

#[test]
fn high_ram_keeps_subpage_device_exclusions_and_holes_outside_ram_do_not_remove_backing() {
    let layout = Layout::new(
        (3 << 30) + 0x5000,
        &[span((4 << 30) + 0x2010, 0x20), span(0xc100_0000, 0x1000)],
    )
    .unwrap();
    assert!(layout.contains_logical(4 << 30, 0x2000));
    assert!(layout.contains_logical((4 << 30) + 0x2000, 0x10));
    assert!(!layout.contains_logical((4 << 30) + 0x2010, 1));
    assert!(layout.contains_logical((4 << 30) + 0x2030, 0xfd0));
    assert!(!layout.contains_mapped((4 << 30) + 0x2000, 1));
    assert!(layout.contains_mapped((4 << 30) + 0x3000, 0x2000));
    assert!(!layout.contains_logical(3 << 30, 1));
    assert!(!layout.contains_logical((4 << 30) + 0x5000, 1));
}
