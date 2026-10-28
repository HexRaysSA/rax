use super::*;
use crate::user::mm::{AddressSpace, SpaceConfig};
use crate::user::windows::memory::Mem;
use crate::user::windows::object_namespace::data::DataRegion;

const LOGS: [&str; 4] = [
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-alpc-csr/native/native-csr-client-connect-v6-four-views-arm64.log"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-alpc-csr/native/native-csr-client-connect-v6-four-views-x64.log"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-alpc-csr/native/native-csr-client-connect-v6-four-views-x86.log"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-alpc-csr/native/native-csr-client-connect-v6-four-views-x86-laa.log"
    )),
];

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(name))
        .unwrap()
}
fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn capture(log: &str) -> ([u8; INFORMATION_BYTES], [ClientView; 2]) {
    let query = log
        .lines()
        .find(|line| line.starts_with("CONNECT sample=0 "))
        .unwrap();
    assert_eq!(field(query, "status="), "00000000");
    assert_eq!(field(query, "exception="), "00000000");
    let bytes = hex(field(query, "data="));
    assert_eq!(bytes.len(), 1024);
    assert!(bytes[INFORMATION_BYTES..].iter().all(|&byte| byte == 0xA5));
    let views = [16, 40].map(|slot| {
        let prefix = format!("MAP slot={slot} ");
        let lines: Vec<_> = log
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();
        let base = u64::from_str_radix(field(lines[0], "base="), 16).unwrap();
        let mut size = 0;
        let regions = lines
            .iter()
            .map(|line| {
                let offset: u64 = field(line, "offset=").parse().unwrap();
                let span: u64 = field(line, "bytes=").parse().unwrap();
                assert_eq!(offset, size);
                size += span;
                let committed = field(line, "state=") == "00001000";
                assert_eq!(field(line, "type="), "00040000");
                let bytes = if committed {
                    assert_eq!(field(line, "protect="), "00000002");
                    assert_eq!(field(line, "stable="), "1");
                    Some(hex(field(line, "hex=")).into())
                } else {
                    assert_eq!(field(line, "state="), "00002000");
                    assert_eq!(field(line, "protect="), "00000000");
                    None
                };
                DataRegion {
                    offset,
                    size: span,
                    bytes,
                }
            })
            .collect();
        ClientView {
            base,
            section: DataSection::private_readonly(size, regions).unwrap(),
        }
    });
    (bytes[..INFORMATION_BYTES].try_into().unwrap(), views)
}
fn vm() -> VirtualMemory {
    VirtualMemory::new(
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 4 << 20,
            reserved_phys: Vec::new(),
        })
        .unwrap(),
        65536,
        1 << 47,
    )
}

pub(super) fn fixture(index: usize) -> Arc<CsrClientData> {
    let (information, views) = capture(LOGS[index]);
    CsrClientData::selected(information, views).unwrap()
}

fn committed_prefix(bytes: u64) -> ([u8; INFORMATION_BYTES], [ClientView; 2]) {
    let (mut information, mut views) = capture(LOGS[0]);
    let original = views[0].section.regions[0].bytes.as_ref().unwrap();
    let mut payload = vec![0x5a; bytes as usize];
    let copied = payload.len().min(original.len());
    payload[..copied].copy_from_slice(&original[..copied]);
    let mut regions = vec![DataRegion {
        offset: 0,
        size: bytes,
        bytes: Some(payload.into()),
    }];
    if bytes < 1 << 21 {
        regions.push(DataRegion {
            offset: bytes,
            size: (1 << 21) - bytes,
            bytes: None,
        });
    }
    views[0].section = DataSection::private_readonly(1 << 21, regions).unwrap();
    // Optional typed pointers outside a smaller prefix must be absent.
    // Required SHAREDINFO identities continue to describe these same views.
    for offset in POINTER_SLOTS {
        let address = word(&information, offset);
        if address >= views[0].base + bytes && address < views[0].base + (1 << 21) {
            information[offset..offset + 8].fill(0);
        }
    }
    (information, views)
}

#[test]
fn native_csr_client_data_accepts_growing_prefix_and_fully_committed_bounded_table() {
    for committed in [4096, 8192, 12288, 16384, (1 << 21) - 4096, 1 << 21] {
        let (information, views) = committed_prefix(committed);
        let data = CsrClientData::selected(information, views).unwrap();
        let mut vm = vm();
        assert_eq!(data.map(&mut vm).unwrap().len(), 2);
        assert!(data.map(&mut vm).unwrap().is_empty());
        assert_eq!(vm.committed_bytes(), committed + 32768);
        let base = data.views[0].base;
        assert_eq!(
            vm.space().bytes(base, committed as usize).unwrap(),
            data.views[0].section.regions[0]
                .bytes
                .as_ref()
                .unwrap()
                .as_ref()
        );
        assert!(vm.space().w8(base + committed - 1, 0).is_err());
        if committed < 1 << 21 {
            assert!(vm.space().u8(base + committed).is_err());
        }
        for view in &data.views {
            vm.release(view.base).unwrap();
        }
        assert_eq!(vm.committed_bytes(), 0);
    }
}

#[test]
fn native_csr_client_data_replays_three_native_grown_geometries_without_relocating_views() {
    let geometry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-csr-client-data-geometry/geometry-29683-v1.json"
    )))
    .unwrap();
    let mut count = 0;
    for sample in geometry["samples"].as_array().unwrap() {
        assert_eq!(sample["inputs_unchanged"], true);
        assert_eq!(sample["sharedinfo_identities_match"], true);
        assert_eq!(sample["trailing_canary_preserved"], true);
        let native = &sample["views"][0];
        assert_eq!(native["size"].as_u64().unwrap(), 1 << 21);
        let committed = native["committed"].as_u64().unwrap();
        assert_eq!(committed, 12288);
        assert_eq!(native["regions"][0]["protection"].as_u64().unwrap(), 2);
        let (information, views) = committed_prefix(committed);
        let bases = views.each_ref().map(|view| view.base);
        let data = CsrClientData::selected(information, views).unwrap();
        let mut vm = vm();
        data.map(&mut vm).unwrap();
        assert_eq!(vm.committed_bytes(), 45056);
        assert_eq!(data.views.each_ref().map(|view| view.base), bases);
        assert_eq!(vm.space().u8(bases[0] + 8192).unwrap(), 0x5a);
        assert!(vm.space().u8(bases[0] + 12288).is_err());
        assert!(vm.space().w8(bases[0] + 8192, 0).is_err());
        assert_eq!(data.information, information);
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn native_csr_client_data_rejects_sparse_prefix_wrong_extent_and_foreign_grown_pointer() {
    let (mut information, mut views) = committed_prefix(12288);
    for offset in POINTER_SLOTS {
        if !matches!(offset, 8 | 16 | 40) {
            information[offset..offset + 8].fill(0);
        }
    }
    information[32..40].copy_from_slice(&(views[0].base + 8192).to_le_bytes());
    views[0].section = DataSection::private_readonly(
        1 << 21,
        vec![
            DataRegion {
                offset: 0,
                size: 4096,
                bytes: Some(vec![0; 4096].into()),
            },
            DataRegion {
                offset: 4096,
                size: 4096,
                bytes: None,
            },
            DataRegion {
                offset: 8192,
                size: 4096,
                bytes: Some(vec![0; 4096].into()),
            },
            DataRegion {
                offset: 12288,
                size: (1 << 21) - 12288,
                bytes: None,
            },
        ],
    )
    .unwrap();
    assert!(CsrClientData::selected(information, views).is_err());
    let (information, mut views) = committed_prefix(12288);
    views[0].section = DataSection::private_readonly(
        1 << 22,
        vec![
            DataRegion {
                offset: 0,
                size: 12288,
                bytes: Some(vec![0; 12288].into()),
            },
            DataRegion {
                offset: 12288,
                size: (1 << 22) - 12288,
                bytes: None,
            },
        ],
    )
    .unwrap();
    assert!(CsrClientData::selected(information, views).is_err());
    for address_offset in [12288, (1 << 21) - 1] {
        let (mut information, views) = committed_prefix(12288);
        information[32..40].copy_from_slice(&(views[0].base + address_offset).to_le_bytes());
        assert!(CsrClientData::selected(information, views).is_err());
    }
    let (mut information, views) = committed_prefix(12288);
    let second = views[1].base;
    assert_eq!(views[0].base + (1 << 21), second);
    information[32..40].copy_from_slice(&second.to_le_bytes());
    assert!(CsrClientData::selected(information, views).is_ok());
    let (mut information, views) = committed_prefix(12288);
    let outside_both = views[1].base + views[1].section.size;
    information[32..40].copy_from_slice(&outside_both.to_le_bytes());
    assert!(CsrClientData::selected(information, views).is_err());
}

#[test]
fn native_csr_client_data_replays_all_four_selected_snapshots() {
    for log in LOGS {
        let (information, views) = capture(log);
        let data = CsrClientData::selected(information, views).unwrap();
        let mut vm = vm();
        data.map(&mut vm).unwrap();
        assert_eq!(vm.committed_bytes(), 40960);
        assert_eq!(data.information, information);
        for view in &data.views {
            assert!(view.section.path.is_empty());
            for region in &view.section.regions {
                let address = view.base + region.offset;
                if let Some(bytes) = &region.bytes {
                    assert_eq!(
                        vm.space().bytes(address, bytes.len()).unwrap(),
                        bytes.as_ref()
                    );
                    assert!(vm.space().w8(address, 1).is_err());
                    assert_eq!(vm.query(address).unwrap().protect, prot::READONLY);
                } else {
                    assert!(vm.space().u8(address).is_err());
                }
            }
        }
        let bases = data.views.each_ref().map(|view| view.base);
        drop(data);
        assert!(vm.space().u8(bases[0]).is_ok());
        for base in bases {
            vm.release(base).unwrap();
        }
        assert_eq!(vm.committed_bytes(), 0);
    }
}

#[test]
fn native_csr_client_data_mapping_collision_rolls_back_only_new_views() {
    for index in 0..2 {
        let (information, views) = capture(LOGS[0]);
        let data = CsrClientData::selected(information, views).unwrap();
        let mut vm = vm();
        let occupied = data.views[index].base;
        vm.map_data_section(
            data.views[index].section.clone(),
            occupied,
            0,
            data.views[index].section.size,
            prot::WRITECOPY,
        )
        .unwrap();
        vm.space().w32(occupied, 0x9669).unwrap();
        let committed = vm.committed_bytes();
        assert!(data.map(&mut vm).is_err());
        assert_eq!(vm.committed_bytes(), committed);
        assert_eq!(vm.space().u32(occupied).unwrap(), 0x9669);
        assert!(vm.allocation(data.views[1 - index].base).is_none());
    }
}

#[test]
fn native_csr_client_data_rejects_foreign_and_reserved_pointer_fields() {
    for offset in POINTER_SLOTS {
        for reserved in [false, true] {
            let (mut information, views) = capture(LOGS[0]);
            let address = if reserved {
                views[0].base + 8192
            } else {
                0x1234_0000
            };
            information[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
            assert!(
                CsrClientData::selected(information, views).is_err(),
                "slot {offset} reserved {reserved}"
            );
        }
    }
}

#[test]
fn native_csr_client_data_does_not_rewrite_untyped_address_sized_values() {
    let (mut information, views) = capture(LOGS[0]);
    information[576..584].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    let data = CsrClientData::selected(information, views).unwrap();
    assert_eq!(data.information, information);
}

#[test]
fn native_csr_client_data_reuse_checks_current_pages_and_snapshot_identity() {
    for protection in [
        prot::NOACCESS,
        prot::WRITECOPY,
        prot::READONLY | prot::GUARD,
    ] {
        let data = fixture(0);
        let mut vm = vm();
        assert_eq!(data.map(&mut vm).unwrap().len(), 2);
        assert!(data.map(&mut vm).unwrap().is_empty());
        let base = data.views[0].base;
        vm.protect(base + 4096, 4096, protection).unwrap();
        assert_eq!(vm.allocation(base).unwrap().protect, prot::READONLY);
        assert!(!vm.owns_readonly_data_view(base, &data.views[0].section));
        let committed = vm.committed_bytes();
        assert!(data.map(&mut vm).is_err());
        assert_eq!(vm.committed_bytes(), committed);
        assert_eq!(vm.query(base + 4096).unwrap().protect, protection);
        let other = fixture(0);
        assert!(!vm.owns_readonly_data_view(data.views[1].base, &other.views[1].section));
    }
}
