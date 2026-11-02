//! Exact initialization prescribed by the independent native producer.
use super::{Case, NLS_KEY, Object, Proc, Registry, Value, WinArch};
use crate::user::windows::memory::Mem;
use crate::user::windows::registry::SelectedKey;

const NAMES: [&str; 9] = [
    "", "One", "Three", "Five", "Dword", "Text", "Qword", "Multi", "Absent",
];
const IDS: [[usize; 3]; 15] = [
    [0, 0, 0],
    [1, 0, 0],
    [2, 0, 0],
    [3, 0, 0],
    [1, 2, 0],
    [2, 1, 0],
    [1, 2, 3],
    [3, 1, 2],
    [1, 1, 1],
    [1, 8, 3],
    [8, 1, 2],
    [1, 2, 8],
    [0, 1, 0],
    [4, 5, 6],
    [7, 3, 1],
];

pub(super) fn handles(p: &mut Proc) -> [u64; 8] {
    let upcase = (0..=u16::MAX)
        .map(|u| {
            if (97..=122).contains(&u) || u == 0xE4 {
                u - 32
            } else {
                u
            }
        })
        .collect();
    let data: &[&[u8]] = &[
        &[],
        &[0x11],
        &[0x21, 0x22, 0x23],
        &[0x31, 0x32, 0x33, 0x34, 0x35],
        &[0x41, 0x42, 0x43, 0x44],
        &[0x41, 0, 0, 0],
        &[1, 2, 3, 4, 5, 6, 7, 8],
        &[0x41, 0, 0, 0, 0, 0],
    ];
    p.registry = Registry::selected(
        upcase,
        vec![SelectedKey {
            path: NLS_KEY,
            children: 0,
            values: data
                .iter()
                .enumerate()
                .map(|(i, data)| Value {
                    name: NAMES[i].encode_utf16().collect(),
                    kind: [0, 3, 3, 3, 4, 1, 11, 7][i],
                    data: data.to_vec(),
                })
                .chain([Value {
                    name: "Äbc".encode_utf16().collect(),
                    kind: 3,
                    data: data[3].to_vec(),
                }])
                .collect(),
        }],
    )
    .unwrap();
    let key = p
        .registry
        .key(&NLS_KEY.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    let mut handles = [0, 0, 0xDEAD_BEEF, 0, p.arch.ptr(u64::MAX), 0, 0, 0];
    for (index, access) in [(0, 0xF003F), (5, 0), (6, 1), (7, 2)] {
        let id = p.objects.create_registry_key(key.clone(), 0).unwrap();
        handles[index] = p.objects.open_access(id, false, access).unwrap().into();
    }
    let event = p.objects.create(Object::Event {
        manual: false,
        signaled: 0,
    });
    handles[3] = p
        .objects
        .open_access(event, false, 0x1F0003)
        .unwrap()
        .into();
    handles
}

fn put(bytes: &mut [u8], at: usize, value: u64, size: usize) {
    bytes[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
}

pub(super) fn arena(case: &Case, arch: WinArch, base: u64) -> (Vec<u8>, [u32; 17]) {
    let mut bytes = vec![case.number("poison") as u8; 65536];
    let ew = case.get("watch_offsets")[0].as_u64().unwrap() as usize;
    let lw = case.get("watch_offsets")[2].as_u64().unwrap() as usize;
    let width = arch.ptr_size() as usize;
    let stride = if width == 8 { 24 } else { 16 };
    let string_stride = if width == 8 { 16 } else { 8 };
    let separate_names = case.optional_number("input_layout", 0) == 5;
    for i in 0..case.optional_number("initialized_entries", 3) as usize {
        let id = if i < 3 {
            IDS[case.number("plan") as usize][i]
        } else {
            1
        };
        let units: Vec<u16> = NAMES[id].encode_utf16().chain([0]).collect();
        let text_at = if separate_names {
            20480 + i * 4096
        } else {
            12288 + i * 64
        };
        for (j, unit) in units.iter().enumerate() {
            put(&mut bytes, text_at + j * 2, u64::from(*unit), 2);
        }
        let descriptor = 8192 + i * if separate_names { 4096 } else { string_stride };
        put(&mut bytes, descriptor, (units.len() as u64 - 1) * 2, 2);
        put(&mut bytes, descriptor + 2, units.len() as u64 * 2, 2);
        put(
            &mut bytes,
            descriptor + if width == 8 { 8 } else { 4 },
            base + text_at as u64,
            width,
        );
        put(&mut bytes, ew + i * stride, base + descriptor as u64, width);
    }
    let mut protections = [4; 17];
    protections[16] = 1;
    let flags = |role| match role {
        6 => 2,
        7 => 0x104,
        8 => 1,
        12 => 0x102,
        _ => 0,
    };
    for (key, page) in [("entry_role", 0), ("data_role", 8)] {
        let role = case.number(key);
        if flags(role) != 0 {
            protections[page] = flags(role);
        }
        match role {
            9 | 14 => protections[page + 1] = 1,
            10 => protections[page + 1] = 0x104,
            11 => protections[page + 1] = 2,
            15 => protections[page + 1] = 0x102,
            _ => {}
        }
    }
    match case.number("length_role") {
        4 => protections[12] = 2,
        5 => protections[12] = 0x104,
        6 => protections[12] = 1,
        10 => protections[13] = 1,
        11 => protections[12] = 0x102,
        _ => {}
    }
    match case.number("required_role") {
        4 => protections[13] = 2,
        5 => protections[13] = 0x104,
        6 => protections[13] = 1,
        11 => protections[14] = 1,
        12 => protections[13] = 0x102,
        _ => {}
    }
    names(case, arch, base, ew, &mut bytes, &mut protections);
    put(&mut bytes, lw, case.number("capacity"), 4);
    (bytes, protections)
}

fn names(
    case: &Case,
    arch: WinArch,
    base: u64,
    ew: usize,
    bytes: &mut [u8],
    protections: &mut [u32; 17],
) {
    for (role, slot) in [
        (
            case.optional_number("name_role", 0),
            case.optional_number("name_slot", 0) as usize,
        ),
        (
            case.optional_number("second_name_role", 0),
            case.optional_number("second_name_slot", 0) as usize,
        ),
    ] {
        if role == 0 {
            continue;
        }
        let separate_names = case.optional_number("input_layout", 0) == 5;
        let width = arch.ptr_size() as usize;
        let string_stride = if width == 8 { 16 } else { 8 };
        let entry_stride = if width == 8 { 24 } else { 16 };
        let buffer_offset = if width == 8 { 8 } else { 4 };
        let original = 8192 + slot * if separate_names { 4096 } else { string_stride };
        let mut descriptor_at = original;
        let mut pointer = base + original as u64;
        let mut descriptor = bytes[original..original + string_stride].to_vec();
        let mut text_at = if separate_names {
            20480 + slot * 4096
        } else {
            16384
        };
        match role {
            1 => pointer = 0,
            2 => pointer = 1,
            3 => {
                descriptor_at = 8192 + if separate_names { slot * 4096 } else { 0 } + 1025;
                pointer = base + descriptor_at as u64;
            }
            4..=7 => {
                protections[if separate_names { 2 + slot } else { 2 }] = match role {
                    4 => 2,
                    5 => 0x104,
                    7 => 0x102,
                    _ => 1,
                }
            }
            8 | 9 => {
                descriptor_at = 45056 - 4;
                pointer = base + descriptor_at as u64;
                protections[11] = if role == 8 { 1 } else { 0x104 };
            }
            10 => put(&mut descriptor, 2, 0, 2),
            11 => {
                put(&mut descriptor, 0, 1, 2);
                put(&mut descriptor, buffer_offset, 0, width);
            }
            12 => put(&mut descriptor, 0, 3, 2),
            13 => {
                put(&mut descriptor, 0, 0, 2);
                put(&mut descriptor, buffer_offset, 1, width);
            }
            14 => {
                put(&mut descriptor, 0, 6, 2);
                put(&mut descriptor, buffer_offset, 0, width);
            }
            15..=24 | 26 => {
                match role {
                    15 => text_at += 1,
                    16..=19 => {
                        protections[if separate_names { 5 + slot } else { 4 }] = match role {
                            16 => 2,
                            17 => 0x104,
                            19 => 0x102,
                            _ => 1,
                        }
                    }
                    20..=22 => {
                        text_at = 20480 - 2;
                        protections[5] = match role {
                            20 => 1,
                            21 => 0x104,
                            _ => 2,
                        };
                    }
                    _ => {}
                }
                let text = match role {
                    23 => "oNe",
                    24 => "One\0tail",
                    26 => "äbc",
                    _ => "One",
                };
                let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
                for (i, unit) in units.iter().enumerate() {
                    put(bytes, text_at + 2 * i, u64::from(*unit), 2);
                }
                put(&mut descriptor, 0, (units.len() as u64 - 1) * 2, 2);
                put(&mut descriptor, buffer_offset, base + text_at as u64, width);
            }
            25 => put(&mut descriptor, 2, 1, 2),
            27 => put(&mut descriptor, 0, 0xFFFE, 2),
            28 => put(&mut descriptor, 0, 0xFFFF, 2),
            29 => {
                put(&mut descriptor, 0, 6, 2);
                put(
                    &mut descriptor,
                    buffer_offset,
                    arch.ptr(u64::MAX - 15),
                    width,
                );
            }
            30 => pointer = arch.ptr(u64::MAX - 15),
            _ => panic!("unknown native name role"),
        }
        bytes[descriptor_at..descriptor_at + string_stride].copy_from_slice(&descriptor);
        put(bytes, ew + slot * entry_stride, pointer, width);
    }
}

pub(super) fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}
