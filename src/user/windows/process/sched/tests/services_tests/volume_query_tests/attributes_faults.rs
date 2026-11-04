//! Raw native fault/guard/alias rows are replayed without status normalization.
use super::attributes::{bind_payload, disk, hex};
use super::*;
use std::collections::BTreeMap;
use std::io::Seek;
fn value(raw: &str) -> u32 {
    u32::from_str_radix(raw, 16).unwrap()
}
#[test]
fn native_volume_attributes_replays_all_12584_pointer_guard_alias_and_kind_observations() {
    let controls: [(WinArch, &str); 4] = [
        (
            WinArch::Arm64,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-attributes/faults-arm64-29698-v1.log"
            ),
        ),
        (
            WinArch::X64,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-attributes/faults-x64-29698-v1.log"
            ),
        ),
        (
            WinArch::X86,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-attributes/faults-x86-29698-v1.log"
            ),
        ),
        (
            WinArch::X86,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-attributes/faults-x86-laa-29698-v1.log"
            ),
        ),
    ];
    let mut failures = Vec::new();
    let mut total = 0;
    for (profile_index, (arch, text)) in controls.into_iter().enumerate() {
        let mut count = 0;
        for line in text.lines().filter(|s| s.starts_with("role=")) {
            let fields: BTreeMap<_, _> = line
                .split_whitespace()
                .map(|s| s.split_once('=').unwrap())
                .collect();
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let ib = base;
            let ob = base + 3 * PAGE_SIZE;
            let mut path = None;
            let mut device = None;
            let synchronous = !fields["role"].ends_with("-async");
            let handle = if fields["role"] == "invalid" {
                0xDEAD
            } else if fields["role"] == "process" {
                arch.ptr(u64::MAX)
            } else {
                let object = match fields["role"] {
                    "conin" => Object::Console(StdStream::In),
                    "nul" => Object::Null,
                    "pipe-read" | "pipe-write" => Object::Pipe {
                        pipe: 1,
                        write: fields["role"] == "pipe-write",
                    },
                    "event" => Object::Event {
                        manual: false,
                        signaled: 0,
                    },
                    "disk" | "directory" | "disk-async" | "directory-async" => {
                        let (object, name, calibrated) =
                            disk(fields["role"].starts_with("directory"), !synchronous);
                        path = Some(name);
                        device = Some(calibrated);
                        object
                    }
                    role => panic!("unrecognized native role {role}"),
                };
                let id = p.objects.create(object);
                u64::from(p.objects.open_access(id, false, 0).unwrap())
            };
            let (mut io, mut out) = (ib + PAGE_SIZE + 256, ob + PAGE_SIZE + 256);
            let guarded = prot::READWRITE | prot::GUARD;
            match fields["case"] {
                "valid" => {}
                "io-null" => io = 0,
                "out-null" => out = 0,
                "both-null" => {
                    io = 0;
                    out = 0;
                }
                "io-bad" => io = 0xDEAD0000,
                "out-bad" => out = 0xDEAD0000,
                "io-readonly" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
                        .unwrap();
                }
                "out-readonly" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
                        .unwrap();
                }
                "io-guard" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                }
                "out-guard" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                }
                "io-noaccess" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "out-noaccess" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "io-unaligned" => io += 1,
                "out-unaligned" => out += 1,
                "same" => out = io,
                "out-io-plus4" => out = io + 4,
                "io-out-plus4" => io = out + 4,
                "io-cross-noaccess" => {
                    io = ib + 2 * PAGE_SIZE - 8;
                    p.vm.protect(ib + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "out-cross-noaccess" => {
                    out = ob + 2 * PAGE_SIZE - 4;
                    p.vm.protect(ob + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "both-guard" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                }
                "io-readonly-guard" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, prot::READONLY | prot::GUARD)
                        .unwrap();
                }
                "out-readonly-guard" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, prot::READONLY | prot::GUARD)
                        .unwrap();
                }
                case => panic!("unrecognized native case {case}"),
            }
            let before = p.objects.iter().map(|(id, _)| id).collect::<Vec<_>>();
            let status = invoke(
                p,
                &mut t,
                &[handle, io, out, fields["len"].parse().unwrap(), 5],
            );
            let protections = [
                ("io-protect", ib + PAGE_SIZE),
                ("out-protect", ob + PAGE_SIZE),
                ("io-tail", ib + 2 * PAGE_SIZE),
                ("out-tail", ob + 2 * PAGE_SIZE),
            ];
            let mut ok = status == value(fields["status"]) && fields["returned"] == "1";
            for (name, address) in protections {
                ok &= p.vm.query(address).unwrap().protect == value(fields[name]);
            }
            p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
            let locations = [
                ("io", ib + PAGE_SIZE + 240),
                ("out", ob + PAGE_SIZE + 240),
                ("io-edge", ib + 2 * PAGE_SIZE - 32),
                ("out-edge", ob + 2 * PAGE_SIZE - 32),
            ];
            let mut expected = locations.map(|(name, address)| (address, hex(fields[name])));
            if let Some(device) = device {
                bind_payload(
                    &mut expected,
                    out,
                    io,
                    arch,
                    synchronous,
                    value(fields["status"]),
                    device,
                );
            }
            for (address, expected) in expected {
                ok &= p.space.bytes(address, expected.len()).unwrap() == expected;
            }
            ok &= p.objects.iter().map(|(id, _)| id).collect::<Vec<_>>() == before;
            if let Some(Object::File(file)) = p.objects.get_mut(handle)
                && !file.directory
                && !file.overlapped
            {
                ok &= file.host.as_mut().unwrap().stream_position().unwrap() == 7;
            }
            if !ok {
                failures.push(format!(
                    "profile{profile_index}/{arch}/{}/len{} expected{} got{status:08X} role{}",
                    fields["case"], fields["len"], fields["status"], fields["role"]
                ));
            }
            if p.objects.get(handle).is_some() {
                drop(p.objects.close(handle).unwrap());
            }
            if let Some(path) = path {
                if path.is_dir() {
                    std::fs::remove_dir(path).unwrap();
                } else {
                    std::fs::remove_file(path).unwrap();
                }
            }
            count += 1;
            total += 1;
        }
        assert_eq!(count, 3146);
    }
    assert_eq!(total, 12584);
    assert!(
        failures.is_empty(),
        "{} mismatches: {:?}",
        failures.len(),
        &failures[..failures.len().min(12)]
    );
}
