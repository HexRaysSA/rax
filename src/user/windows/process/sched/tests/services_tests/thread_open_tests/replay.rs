//! Case inputs match the independently executed C probe, not the service code.
use super::*;
use serde_json::Value;

fn number(row: &Value, name: &str) -> u32 {
    row[name].as_u64().unwrap() as u32
}

fn corpus(text: &str, expected_archs: usize) {
    let data: Value = serde_json::from_str(text).unwrap();
    assert_eq!(data["state"], "finished");
    let rows = data["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 290 * expected_archs);
    let mut compared = 0;
    let mut asynchronous_release = 0;
    for row in rows {
        assert_eq!(row["exit_code"], 0);
        let arch = match row["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unrecognized ABI {other}"),
        };
        let which = row["case"].as_u64().unwrap() as u32;
        let observed = &row["observation"];
        assert_eq!(number(observed, "raised"), 0);
        assert_eq!(number(observed, "last_error"), LAST_ERROR);
        if which == 42 {
            // Closing the last user handle races native kernel teardown refs.
            // The C probe does not observe their release instant. Validate its
            // bounded result here; the deterministic lifetime test owns guest
            // retain/release transitions instead of guessing a native instant.
            assert!(matches!(
                number(observed, "status"),
                STATUS_SUCCESS | STATUS_INVALID_CID
            ));
            asynchronous_release += 1;
            continue;
        }
        let find = |case: u32| -> &Value {
            &rows
                .iter()
                .find(|r| r["arch"] == row["arch"] && r["case"] == case)
                .unwrap()["observation"]
        };
        let security_case = if (240..248).contains(&which) {
            240
        } else if which >= 282 {
            282
        } else if (148..154).contains(&which) {
            148
        } else {
            8
        };
        let security = number(find(security_case), "status");
        let bypass = if (240..248).contains(&which) || which >= 282 {
            false
        } else {
            number(find(10), "status") == 0
        };
        let maximum_security = (security == 0).then(|| {
            number(
                find(if security_case == 8 {
                    9
                } else {
                    security_case + 1
                }),
                "grant",
            )
        });
        let (mut process, mut t) = fixture(arch, "NtOpenThread", SERVICE);
        let p = process.state_mut();
        p.thread_access = Ok(Access::new(0x1fffff, security, bypass, maximum_security).unwrap());
        let base = scratch(p);
        p.space.wr(base, &vec![0xcc; 24576]).unwrap();
        let (mut oa, mut cid) = inputs(p, &t, base);
        let mut output = base + 128;
        let width = arch.ptr_size();
        let oa_size = if width == 4 { 24 } else { 48 };
        let original = p.space.bytes(oa, oa_size).unwrap();
        let identity = p.space.bytes(cid, 2 * width as usize).unwrap();
        let mut protect = Vec::new();
        if (40..42).contains(&which) {
            p.objects.create(Object::Thread {
                tid: 0x44,
                exit_code: (which == 41).then_some(37),
            });
            p.space.wptr(cid + width, width, 0x44).unwrap();
        }
        if (154..170).contains(&which) {
            oa = base + 16384 - u64::from((which - 154) * 4);
            p.space.wr(oa, &original).unwrap();
            protect.push((base + 16384, prot::NOACCESS));
        }
        if (170..186).contains(&which) {
            cid = base + 16384 - u64::from((which - 170) * 2);
            p.space.wr(cid, &identity).unwrap();
            protect.push((base + 16384, prot::NOACCESS));
        }
        if (186..202).contains(&which) {
            let sd = base + 16384 + 128;
            p.space.wr(sd, &[0; 64]).unwrap();
            p.space.wptr(oa + 4 * width, width, sd).unwrap();
            if which != 186 {
                p.space.w8(sd, 1).unwrap();
            }
            match which {
                188 => p.space.w8(sd + 2, 4).unwrap(),
                189 => p.space.w8(sd + 3, 0x80).unwrap(),
                190 => p.space.w16(sd + 2, 0x8004).unwrap(),
                191 => p.space.w16(sd + 2, 0xffff).unwrap(),
                192 => p.space.w8(sd + 1, 0xff).unwrap(),
                193 => p.space.wptr(oa + 4 * width, width, sd + 1).unwrap(),
                194 => protect.push((base + 16384, prot::NOACCESS)),
                195 => protect.push((base + 16384, prot::READWRITE | prot::GUARD)),
                196 | 197 => {
                    p.space.w8(sd + 3, 0x80).unwrap();
                    p.space
                        .w32(sd + if which == 196 { 4 } else { 8 }, 0xfffffff0)
                        .unwrap();
                }
                198 => {
                    p.space.w16(sd + 2, 0x8004).unwrap();
                    p.space.w32(sd + 16, 0xfffffff0).unwrap();
                }
                199 => p.space.w32(oa, 0).unwrap(),
                200 => cid = 0,
                201 => output = 0,
                _ => {}
            }
        }
        if (202..214).contains(&which) {
            let qos = base + 20480 + 128;
            p.space.wr(qos, &[0; 12]).unwrap();
            p.space.w32(qos, 12).unwrap();
            p.space.w32(qos + 4, 2).unwrap();
            p.space.wptr(oa + 5 * width, width, qos).unwrap();
            if which < 208 {
                p.space.w32(qos, (which - 202) * 4).unwrap();
            }
            match which {
                208 => p.space.w32(qos + 4, u32::MAX).unwrap(),
                209 => p.space.w8(qos + 8, 0xff).unwrap(),
                210 => p.space.w8(qos + 9, 0xff).unwrap(),
                211 => p.space.wptr(oa + 5 * width, width, base + 16384).unwrap(),
                212 | 213 => {
                    p.space
                        .wr(base + 16384, &p.space.bytes(qos, 12).unwrap())
                        .unwrap();
                    p.space.wptr(oa + 5 * width, width, base + 16384).unwrap();
                    protect.push((
                        base + 16384,
                        if which == 212 {
                            prot::NOACCESS
                        } else {
                            prot::READWRITE | prot::GUARD
                        },
                    ));
                }
                _ => {}
            }
        }
        if (248..264).contains(&which) {
            p.space
                .w32(oa + 3 * width, 1 << (which - 248 + 16))
                .unwrap();
        }
        if (264..270).contains(&which) {
            if which < 267 {
                p.space
                    .wptr(cid + width, width, u64::from(t.tid + which - 264 + 1))
                    .unwrap();
            } else {
                p.space
                    .wptr(cid, width, u64::from(p.pid + which - 267 + 1))
                    .unwrap();
            }
        }
        if (270..274).contains(&which) {
            let sd = base + 16384 + 128;
            p.space.wr(sd, &[0; 64]).unwrap();
            p.space.w8(sd, 1).unwrap();
            p.space.wptr(oa + 4 * width, width, sd).unwrap();
            p.space.w32(sd + 4 + u64::from(which - 270) * 4, 1).unwrap();
            if which >= 272 {
                p.space
                    .w8(sd + 2, if which == 272 { 0x10 } else { 4 })
                    .unwrap();
            }
        }
        if (274..282).contains(&which) {
            let name = base + 20480 + 128;
            let size = match which {
                274 => 1,
                275 | 280 | 281 => 2,
                276 => 3,
                277 => 65534,
                278 => 65535,
                _ => 0,
            };
            p.space.wr(name, &[0; 16]).unwrap();
            p.space.w16(name, size).unwrap();
            p.space
                .w16(name + 2, if which >= 279 { 0 } else { size })
                .unwrap();
            p.space
                .wptr(
                    name + width,
                    width,
                    if which == 279 || which == 280 {
                        1
                    } else {
                        base + 16384 + 128
                    },
                )
                .unwrap();
            p.space.wptr(oa + 2 * width, width, name).unwrap();
            if which == 281 {
                protect.push((base + 16384, prot::READWRITE | prot::GUARD));
            }
        }
        match which {
            21 => p.space.wptr(cid, width, 0).unwrap(),
            22 => p.space.wptr(cid, width, u64::from(p.pid + 1)).unwrap(),
            23 => p.space.wptr(cid, width, arch.ptr(u64::MAX)).unwrap(),
            24 => p.space.wptr(cid + width, width, 0).unwrap(),
            25 => p
                .space
                .wptr(cid + width, width, arch.ptr(u64::MAX - 1))
                .unwrap(),
            26 => p.space.wptr(cid + width, width, 0x7ffffffc).unwrap(),
            27 => cid = 0,
            28 => cid = 1,
            29 | 30 => {
                cid += if which == 29 { 1 } else { 4 };
                p.space.wr(cid, &identity).unwrap();
            }
            31 => p
                .space
                .wptr(cid, width, u64::from(p.pid) | (1 << 32))
                .unwrap(),
            32 => p
                .space
                .wptr(cid + width, width, u64::from(t.tid) | (1 << 32))
                .unwrap(),
            33 => oa = 0,
            34 => oa = 1,
            35 | 36 => {
                oa += if which == 35 { 1 } else { 4 };
                p.space.wr(oa, &original).unwrap();
            }
            37 => p.space.w32(oa, 0).unwrap(),
            38 => p.space.w32(oa, oa_size as u32 - 1).unwrap(),
            39 => p.space.w32(oa, oa_size as u32 + 1).unwrap(),
            43 | 48 | 224 | 226 => {
                let header = base + 20480 + 128;
                p.space.wr(header, &[0; 16]).unwrap();
                if which == 48 {
                    p.space.w32(header, 12).unwrap();
                    p.space.w32(header + 4, 2).unwrap();
                }
                p.space
                    .wptr(
                        oa + if which == 48 { 5 * width } else { 2 * width },
                        width,
                        header,
                    )
                    .unwrap();
                if which == 224 {
                    cid = 0;
                }
                if which == 226 {
                    p.space.w32(oa + 3 * width, u32::MAX).unwrap();
                }
            }
            44 | 82 | 90 | 220 | 225 | 229 => {
                p.space.wptr(oa + 2 * width, width, 1).unwrap();
                if which == 82 || which == 225 {
                    cid = 0;
                }
                if which == 90 {
                    p.space.wptr(cid + width, width, 0).unwrap();
                }
                if which == 220 {
                    protect.push((base + 8192, prot::READWRITE | prot::GUARD));
                }
                if which == 229 {
                    p.space.w32(oa + 3 * width, 0x10).unwrap();
                }
            }
            45 | 91 | 227 => {
                p.space.wptr(oa + width, width, 0x1234).unwrap();
                if which == 91 {
                    p.space.wptr(cid + width, width, 0).unwrap();
                }
                if which == 227 {
                    cid = 0;
                }
            }
            46 | 88 | 230 => {
                p.space.wptr(oa + 4 * width, width, 1).unwrap();
                if which == 88 {
                    p.space.wptr(cid + width, width, 0).unwrap();
                }
                if which == 230 {
                    protect.push((base + 8192, prot::READWRITE | prot::GUARD));
                }
            }
            47 | 89 | 93 | 231 => {
                p.space.wptr(oa + 5 * width, width, 1).unwrap();
                if which == 89 {
                    p.space.wptr(cid + width, width, 0).unwrap();
                }
                if which == 231 {
                    protect.push((base + 8192, prot::READWRITE | prot::GUARD));
                }
            }
            49..=56 => {
                p.space
                    .w32(
                        oa + 3 * width,
                        [2, 0x40, 0x200, 0x400, 0x2000, 0x80, 1, u32::MAX][(which - 49) as usize],
                    )
                    .unwrap();
            }
            57 => output = 0,
            58 => output = 1,
            59 => output += 1,
            60 => output += 4,
            61 => protect.push((base, prot::READONLY)),
            62 => protect.push((base, prot::NOACCESS)),
            63 => protect.push((base, prot::READWRITE | prot::GUARD)),
            64 => protect.push((base, prot::READONLY | prot::GUARD)),
            65 | 66 => {
                output = base + 4096 - width / 2;
                protect.push((
                    base + 4096,
                    if which == 65 {
                        prot::NOACCESS
                    } else {
                        prot::READWRITE | prot::GUARD
                    },
                ));
            }
            67 => output = oa,
            68 => output = cid,
            69 => output = cid + width,
            70 => output = oa + 3 * width,
            71 => protect.push((base + 4096, prot::NOACCESS)),
            72 | 219 => {
                protect.push((base + 4096, prot::READWRITE | prot::GUARD));
                if which == 219 {
                    cid = 0;
                }
            }
            73 => protect.push((base + 8192, prot::NOACCESS)),
            74 => protect.push((base + 8192, prot::READWRITE | prot::GUARD)),
            75 => {
                output = 0;
                cid = 0;
            }
            76 => {
                output = 0;
                oa = 0;
            }
            77 => {
                output = 1;
                cid = 0;
            }
            78 => {
                output = 1;
                oa = 1;
            }
            79 => {
                oa = 1;
                cid = 0;
            }
            80 => {
                oa = 0;
                cid = 1;
            }
            81 => {
                p.space.w32(oa, 0).unwrap();
                cid = 1;
            }
            83 => {
                p.space.wptr(cid + width, width, 0).unwrap();
                output = 0;
            }
            84 => {
                p.space.wptr(cid + width, width, 0).unwrap();
                protect.push((base, prot::READWRITE | prot::GUARD));
            }
            85 | 86 => p.space.wptr(cid + width, width, 0).unwrap(),
            87 => {
                p.space.wptr(cid + width, width, 0).unwrap();
                p.space.w32(oa + 3 * width, u32::MAX).unwrap();
            }
            92 => p.space.w32(oa, 0).unwrap(),
            94 => {
                p.space.w32(oa, 0).unwrap();
                p.space.w32(oa + 3 * width, u32::MAX).unwrap();
            }
            95 => {
                cid = 1;
                p.space.w32(oa + 3 * width, u32::MAX).unwrap();
            }
            96 => {
                cid = base + 12288 - width;
                p.space.wr(cid, &identity).unwrap();
                protect.push((base + 12288, prot::NOACCESS));
            }
            97 => {
                oa = base + 8192 - oa_size as u64 / 2;
                p.space.wr(oa, &original).unwrap();
                protect.push((base + 8192, prot::NOACCESS));
            }
            98 => {
                p.space.w32(oa, 0).unwrap();
                protect.push((base + 8192, prot::READWRITE | prot::GUARD));
            }
            99 => {
                output = 0;
                p.space.w32(oa, 0).unwrap();
            }
            132..=147 => p.space.w32(oa + 3 * width, 1 << (which - 132)).unwrap(),
            214 => {
                protect.push((base, prot::NOACCESS));
                protect.push((base + 4096, prot::READWRITE | prot::GUARD));
            }
            215 => {
                protect.push((base, prot::READONLY));
                protect.push((base + 8192, prot::READWRITE | prot::GUARD));
            }
            216 => {
                output = 0;
                protect.push((base + 4096, prot::READWRITE | prot::GUARD));
            }
            217 => {
                oa = 0;
                protect.push((base + 8192, prot::READWRITE | prot::GUARD));
            }
            218 => {
                p.space.w32(oa, 0).unwrap();
                protect.push((base, prot::READWRITE | prot::GUARD));
            }
            221 => cid = 0,
            222 => p.space.w32(oa + 3 * width, u32::MAX).unwrap(),
            223 => output = 0,
            228 => {
                p.space.w32(oa + 3 * width, 0x10).unwrap();
                cid = 0;
            }
            232..=235 => {
                output = base + 4096
                    - if which == 232 {
                        width
                    } else if which == 233 {
                        width - 1
                    } else {
                        1
                    };
                protect.push((
                    base + 4096,
                    if which <= 233 {
                        prot::NOACCESS
                    } else if which == 234 {
                        prot::READONLY | prot::GUARD
                    } else {
                        prot::READWRITE | prot::GUARD
                    },
                ));
                oa = base + 12288 + 128;
                p.space.wr(oa, &original).unwrap();
            }
            _ => {}
        }
        let before = p.space.bytes(base, 24576).unwrap();
        for &(address, flags) in &protect {
            p.vm.protect(address, 4096, flags).unwrap();
        }
        let count = p.objects.handle_count();
        let args = [output, u64::from(number(observed, "access")), oa, cid];
        let status = call(p, &mut t, args);
        assert_eq!(
            status,
            number(observed, "status"),
            "{} case {which}",
            row["arch"]
        );
        let protections: Vec<_> = (0..6)
            .map(|page| p.vm.query(base + page * 4096).unwrap().protect)
            .collect();
        assert_eq!(
            protections,
            observed["protections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u32)
                .collect::<Vec<_>>(),
            "{} case {which}",
            row["arch"]
        );
        assert_eq!(
            p.objects.handle_count() - count,
            observed["handle_delta"].as_u64().unwrap() as usize,
            "{} case {which}",
            row["arch"]
        );
        p.vm.protect(base, 24576, prot::READWRITE).unwrap();
        let mut expected = before;
        if status == 0 {
            let handle = p.space.ptr(output, width).unwrap();
            assert_eq!(
                p.objects.access(handle),
                Some(number(observed, "grant")),
                "{} case {which}",
                row["arch"]
            );
            assert_eq!(
                p.objects.flags(handle),
                Some(if number(observed, "handle_attributes") & 2 != 0 {
                    1
                } else {
                    0
                })
            );
            assert!(
                matches!(p.objects.get(handle),Some(Object::Thread{tid,..}) if *tid==if which==40||which==41 {0x44}else{t.tid})
            );
            let offset = (output - base) as usize;
            expected[offset..offset + width as usize]
                .copy_from_slice(&handle.to_le_bytes()[..width as usize]);
        }
        assert_eq!(
            p.space.bytes(base, 24576).unwrap(),
            expected,
            "caller bytes {} case {which}",
            row["arch"]
        );
        compared += 1;
    }
    assert_eq!(compared, 289 * expected_archs);
    assert_eq!(asynchronous_release, expected_archs);
}

#[test]
fn native_thread_open_replays_native_status_grants_guards_and_all_caller_bytes() {
    corpus(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-open-thread/observations-arm64-29695-v5.json"
        )),
        3,
    );
    if let Some(path) = std::env::var_os("RAX_NATIVE_OPEN_THREAD_OBSERVATIONS") {
        corpus(&std::fs::read_to_string(path).unwrap(), 2);
    }
}
