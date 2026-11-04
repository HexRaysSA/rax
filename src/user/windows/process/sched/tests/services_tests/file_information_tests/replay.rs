use super::*;
use serde_json::Value;

fn decoded(row: &Value, key: &str, bytes: usize) -> Vec<u8> {
    let mut result = vec![0xA5; bytes];
    for (offset, hex) in row[key].as_object().unwrap() {
        let offset = offset.parse::<usize>().unwrap();
        let hex = hex.as_str().unwrap();
        for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            result[offset + i] =
                u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
    }
    result
}

#[test]
fn file_information_replays_independent_native_stream_class_length_and_fault_controls() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-file-information/observations-v1.json"
    )))
    .unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 19776);
    for arch in WinArch::ALL {
        let label = match arch {
            WinArch::Arm64 => "arm64",
            WinArch::X64 => "x64",
            WinArch::X86 => "x86",
        };
        for role in ["console.in", "null", "event", "invalid"] {
            let (mut process, mut thread, base) = setup(arch);
            let p = process.state_mut();
            let handle = match role {
                "console.in" => u64::from(p.objects.insert(Object::Console(StdStream::In))),
                "null" => u64::from(p.objects.insert(Object::Null)),
                "event" => u64::from(p.objects.insert(Object::Event {
                    manual: true,
                    signaled: 0,
                })),
                _ => 0x1234,
            };
            for row in cases
                .iter()
                .filter(|r| r["arch"] == label && r["role"] == role)
            {
                p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
                p.space
                    .wr(base, &vec![0xA5; 6 * PAGE_SIZE as usize])
                    .unwrap();
                let data = base + 3 * PAGE_SIZE;
                for address in [base + PAGE_SIZE, data + PAGE_SIZE] {
                    p.vm.protect(address, PAGE_SIZE, prot::NOACCESS).unwrap();
                }
                let (mut io, mut output) = (base + 64, data + 64);
                match row["case"].as_u64().unwrap() {
                    0 => {}
                    1 => io = 0,
                    2 => output = 0,
                    3 => {
                        io = 0;
                        output = 0
                    }
                    4 => io = 1,
                    5 => output = 1,
                    6 => {
                        io = 1;
                        output = 1
                    }
                    7 => io += 1,
                    8 => output += 1,
                    9 => io = base + PAGE_SIZE - 4,
                    10 => io = base + PAGE_SIZE - arch.ptr_size(),
                    11 => output = data + PAGE_SIZE - 4,
                    12 => {
                        p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    13 => {
                        p.vm.protect(data, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    14 => {
                        for address in [base, data] {
                            p.vm.protect(address, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                                .unwrap();
                        }
                    }
                    15 => {
                        p.vm.protect(data, PAGE_SIZE, prot::READONLY).unwrap();
                    }
                    16 => {
                        p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
                    }
                    17 => output = io,
                    18 => output = io + arch.ptr_size(),
                    19 => output = arch.ptr(u64::MAX - 3),
                    20 => io = arch.ptr(u64::MAX - 3),
                    21 => io = data + 68,
                    other => panic!("unknown native case {other}"),
                }
                let status = invoke(
                    p,
                    &mut thread,
                    &[
                        handle,
                        io,
                        output,
                        row["length"].as_u64().unwrap(),
                        row["class"].as_u64().unwrap(),
                    ],
                );
                assert_eq!(
                    status,
                    u32::try_from(row["status"].as_u64().unwrap()).unwrap(),
                    "{label} {role} row={row}"
                );
                assert_eq!(
                    p.vm.query(base).unwrap().protect,
                    row["io_protect"].as_u64().unwrap() as u32,
                    "{row}"
                );
                assert_eq!(
                    p.vm.query(data).unwrap().protect,
                    row["data_protect"].as_u64().unwrap() as u32,
                    "{row}"
                );
                p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
                for (key, address, bytes) in [
                    ("io_base", base + 48, 64),
                    ("data_base", data + 48, 160),
                    ("io_tail", base + PAGE_SIZE - 24, 48),
                    ("data_tail", data + PAGE_SIZE - 24, 64),
                ] {
                    assert_eq!(
                        p.space.bytes(address, bytes).unwrap(),
                        decoded(row, key, bytes),
                        "{label} {role} {key} row={row}"
                    );
                }
            }
        }
    }
}
