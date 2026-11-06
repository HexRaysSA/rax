//! Recreate the independent observer's inputs without sharing handler logic.
use super::*;

pub(super) struct Setup {
    pub args: [u64; 6],
    pub buffers: [(u64, u64); 4],
    pub target: u64,
    pub before: [Vec<u8>; 4],
}

pub(super) fn prepare(p: &mut Proc, case: &str) -> Setup {
    let protection = match case {
        "rw-target"
        | "noaccess-target"
        | "uncommitted-target"
        | "badrecord-nostorage"
        | "uncommitted-rw-nearby-exec"
        | "readonly-rw-nearby-exec"
        | "noaccess-rw-nearby-exec"
        | "partial-storage" => prot::READWRITE,
        "rx-target" => prot::EXECUTE_READ,
        _ => prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
    };
    let target =
        p.vm.allocate(Some(0x4000_0000), 0x80000, mem::RESERVE, protection)
            .unwrap()
            .0;
    if !matches!(case, "uncommitted-target" | "uncommitted-exec-target") {
        let (bytes, committed_protection) = if case == "partial-storage" {
            (PAGE_SIZE, prot::EXECUTE_READWRITE | prot::TARGETS_INVALID)
        } else {
            (0x4000, protection)
        };
        p.vm.commit(target, bytes, committed_protection).unwrap();
    }
    if case == "noaccess-target" {
        p.vm.protect(target, PAGE_SIZE, prot::NOACCESS).unwrap();
    }
    if case.ends_with("-rw-nearby-exec") {
        p.vm.protect(target + PAGE_SIZE, PAGE_SIZE, prot::EXECUTE_READWRITE)
            .unwrap();
        if case.starts_with("uncommitted") {
            p.vm.decommit(target, PAGE_SIZE).unwrap();
        } else {
            p.vm.protect(
                target,
                PAGE_SIZE,
                if case.starts_with("readonly") {
                    prot::READONLY
                } else {
                    prot::NOACCESS
                },
            )
            .unwrap();
        }
    }
    if case == "decommitted-exec-target" {
        p.vm.decommit(target, 0x4000).unwrap();
    }
    let width = p.arch.ptr_size();
    let mut buffers = [(0, 0); 4];
    for (index, (base, at)) in buffers.iter_mut().enumerate() {
        *base =
            p.vm.allocate(
                Some(0x5000_0000 + index as u64 * 0x10000),
                8192,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        p.space.wr(*base, &[0xa5; 8192]).unwrap();
        let label = ["range", "information", "targets", "processed"][index];
        let offset = if case == format!("{label}-misaligned") {
            129
        } else if case == format!("{label}-plus2") {
            130
        } else if case == format!("{label}-plus4") {
            132
        } else if case == format!("{label}-cross-page") {
            PAGE_SIZE
                - match label {
                    "information" => {
                        if width == 4 {
                            16
                        } else {
                            20
                        }
                    }
                    "processed" => 2,
                    _ => width,
                }
        } else {
            128
        };
        *at = *base + offset;
    }
    let [(_, ranges), (_, information), (_, targets), (_, processed)] = buffers;
    let mut range_base = target;
    let mut range_bytes = PAGE_SIZE;
    let mut entries = 1u32;
    let mut reserved = 0u32;
    let mut output = processed;
    let mut table = targets;
    let mut section = 0;
    let mut file_offset = 0;
    let mut descriptors = [(0u64, 1u64), (16, 1), (32, 1), (48, 1)];
    let mut args = [
        p.arch.ptr(u64::MAX),
        2,
        1,
        ranges,
        information,
        if width == 4 { 32 } else { 40 },
    ];
    match case {
        "invalidate" => descriptors[0].1 = 0,
        "length-0" | "no-registration" => args[5] = 0,
        "length-16" => args[5] = 16,
        "length-24" => args[5] = 24,
        "length-32" => args[5] = 32,
        "length-40" => args[5] = 40,
        "length-48" => args[5] = 48,
        "range-count-0" => args[2] = 0,
        "range-count-2" => args[2] = 2,
        "range-null" => args[3] = 0,
        "range-bad" => args[3] = 1,
        "range-size-0" => range_bytes = 0,
        "range-size-1" => range_bytes = 1,
        "range-base-unaligned" => range_base += 1,
        "range-spans-uncommitted" => range_bytes = 0x5000,
        "information-null" => args[4] = 0,
        "information-bad" => args[4] = 1,
        "reserved-1" => reserved = 1,
        "section-process" => section = p.arch.ptr(u64::MAX),
        "file-offset-1" => file_offset = 1,
        "handle-null" => args[0] = 0,
        "handle-bad" => args[0] = 0x1234,
        "handle-thread" => args[0] = p.arch.ptr(u64::MAX - 1),
        "handle-query-only" => {
            let object = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            args[0] = p.objects.open_access(object, false, 0x1000).unwrap().into();
        }
        "handle-vm-operation" | "handle-vm-write" | "handle-vm-both" => {
            let object = p.objects.create(Object::Process {
                pid: p.pid,
                exit_code: None,
            });
            let access = match case {
                "handle-vm-operation" => 8,
                "handle-vm-write" => 32,
                _ => 40,
            };
            args[0] = p.objects.open_access(object, false, access).unwrap().into();
        }
        "entries-0" => entries = 0,
        "entries-2" => entries = 2,
        "entries-3" => entries = 3,
        "targets-null" => table = 0,
        "targets-bad" => table = 1,
        "processed-null" => output = 0,
        "processed-bad" => output = 1,
        "offset-1" => descriptors[0].0 = 1,
        "offset-15" => descriptors[0].0 = 15,
        "offset-16" => descriptors[0].0 = 16,
        "offset-last-slot" => descriptors[0].0 = PAGE_SIZE - 16,
        "offset-end" => descriptors[0].0 = PAGE_SIZE,
        "offset-max" => descriptors[0].0 = p.arch.ptr(u64::MAX),
        "flags-2" => descriptors[0].1 = 2,
        "flags-3" => descriptors[0].1 = 3,
        "flags-4" => descriptors[0].1 = 4,
        "flags-5" => descriptors[0].1 = 5,
        "flags-8" => descriptors[0].1 = 8,
        "flags-16" => descriptors[0].1 = 16,
        "flags-high" => descriptors[0].1 = 0x8000_0000,
        "flags-max" => descriptors[0].1 = p.arch.ptr(u64::MAX),
        "duplicate" => {
            entries = 2;
            descriptors[1].0 = 0;
        }
        "descending" => {
            entries = 2;
            descriptors[0].0 = 16;
            descriptors[1].0 = 0;
        }
        "second-unaligned" => {
            entries = 2;
            descriptors[1].0 = 17;
        }
        "second-bad-flags" => {
            entries = 2;
            descriptors[1].1 = 0x8000_0000;
        }
        "second-export-flag" | "second-xfg-flag" => {
            entries = 2;
            descriptors[1].1 = if case == "second-export-flag" { 4 } else { 8 };
        }
        "partial-storage" => {
            range_bytes = 0x80000;
            entries = 2;
            descriptors[1].0 = 0x40000;
        }
        "duplicate-invalidate" => {
            entries = 2;
            descriptors[1] = (0, 0);
        }
        "duplicate-revalidate" => {
            entries = 2;
            descriptors[0].1 = 0;
            descriptors[1].0 = 0;
        }
        "first-unaligned" => {
            entries = 2;
            descriptors[0].0 = 1;
        }
        "alias-info-count" => output = information,
        "alias-info-reserved" => output = information + 4,
        "alias-target-offset" => output = targets,
        "alias-target-flags" => output = targets + width,
        "alias-second-offset" => {
            entries = 2;
            output = targets + 2 * width;
        }
        "alias-range-address" => output = ranges,
        _ => {}
    }
    match case {
        "badlength-badrange" => {
            args[5] = 0;
            args[3] = 1;
        }
        "badlength-badinfo" => {
            args[5] = 0;
            args[4] = 1;
        }
        "badlength-count0" => {
            args[5] = 0;
            args[2] = 0;
        }
        "count0-badinfo" => {
            args[2] = 0;
            args[4] = 1;
        }
        "count2-badinfo" => {
            args[2] = 2;
            args[4] = 1;
        }
        "badinfo-badrange" => {
            args[4] = 1;
            args[3] = 1;
        }
        "badhandle-badinfo" => {
            args[0] = 0;
            args[4] = 1;
        }
        "badhandle-badrange" => {
            args[0] = 0;
            args[3] = 1;
        }
        "reserved-badrange" => {
            reserved = 1;
            args[3] = 1;
        }
        "reserved-badtargets" => {
            reserved = 1;
            table = 1;
        }
        "badhandle-badtargets" => {
            args[0] = 0;
            table = 1;
        }
        "badprocessed-badtargets" => {
            output = 1;
            table = 1;
        }
        "badrecord-badprocessed" => {
            descriptors[0].0 = 1;
            output = 1;
        }
        "badrecord-nostorage" => descriptors[0].0 = 1,
        "badflags-badhandle" => {
            descriptors[0].1 = p.arch.ptr(u64::MAX);
            args[0] = 0;
        }
        "badflags-badprocessed" => {
            descriptors[0].1 = p.arch.ptr(u64::MAX);
            output = 1;
        }
        "entries0-badprocessed" => {
            entries = 0;
            output = 1;
        }
        "entries0-badtargets" => {
            entries = 0;
            table = 1;
        }
        "badhandle-badprocessed" => {
            args[0] = 0;
            output = 1;
        }
        "badlength-badhandle" => {
            args[5] = 0;
            args[0] = 0;
        }
        _ => {}
    }
    for index in 0..2 {
        p.space
            .wptr(ranges + index * 2 * width, width, range_base)
            .unwrap();
        p.space
            .wptr(ranges + index * 2 * width + width, width, range_bytes)
            .unwrap();
    }
    p.space.w32(information, entries).unwrap();
    p.space.w32(information + 4, reserved).unwrap();
    p.space.wptr(information + 8, width, output).unwrap();
    p.space.wptr(information + 8 + width, width, table).unwrap();
    p.space
        .wptr(information + 8 + 2 * width, width, section)
        .unwrap();
    p.space
        .w64(information + if width == 4 { 24 } else { 32 }, file_offset)
        .unwrap();
    for (index, (offset, flags)) in descriptors.into_iter().enumerate() {
        p.space
            .wptr(targets + index as u64 * 2 * width, width, offset)
            .unwrap();
        p.space
            .wptr(targets + index as u64 * 2 * width + width, width, flags)
            .unwrap();
    }
    p.space.w32(processed, 0xabab_abab).unwrap();
    let before = buffers.map(|(_, address)| p.space.bytes(address, 64).unwrap());
    for (label, index, protection, second) in [
        ("range-unreadable", 0, prot::NOACCESS, false),
        ("range-cross-page", 0, prot::NOACCESS, true),
        ("information-unreadable", 1, prot::NOACCESS, false),
        ("information-readonly", 1, prot::READONLY, false),
        ("information-cross-page", 1, prot::NOACCESS, true),
        ("targets-unreadable", 2, prot::NOACCESS, false),
        ("targets-readonly", 2, prot::READONLY, false),
        ("targets-cross-page", 2, prot::NOACCESS, true),
        ("processed-readonly", 3, prot::READONLY, false),
        ("processed-unwritable", 3, prot::NOACCESS, false),
        ("processed-cross-page", 3, prot::NOACCESS, true),
        (
            "processed-writable-guard",
            3,
            prot::READWRITE | prot::GUARD,
            false,
        ),
        (
            "processed-readonly-guard",
            3,
            prot::READONLY | prot::GUARD,
            false,
        ),
    ] {
        if case == label {
            p.vm.protect(
                buffers[index].0 + if second { PAGE_SIZE } else { 0 },
                if second { PAGE_SIZE } else { 8192 },
                protection,
            )
            .unwrap();
        }
    }
    if case == "released-exec-target" {
        p.vm.release(target).unwrap();
    }
    Setup {
        args,
        buffers,
        target,
        before,
    }
}
