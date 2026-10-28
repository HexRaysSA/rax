//! Inputs independently reproduce the versioned C producer's cases.
use super::*;

pub(super) struct Setup {
    pub args: [u64; 6],
    pub base: u64,
    pub target: u64,
}

fn write_ranges(p: &Proc, address: u64, pairs: [(u64, u64); 2]) {
    let width = p.arch.ptr_size();
    for (index, (base, size)) in pairs.into_iter().enumerate() {
        let at = address + index as u64 * width * 2;
        p.space.wptr(at, width, base).unwrap();
        p.space.wptr(at + width, width, size).unwrap();
    }
}

pub(super) fn prepare(p: &mut Proc, id: u32) -> Setup {
    let base =
        p.vm.allocate(None, 32768, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let target =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space.wr(base, &[0xcc; 32768]).unwrap();
    let mut ranges = base + 128;
    let mut information = base + 8192 + 128;
    let mut pairs = [(target, 4096), (target + 4096, 4096)];
    write_ranges(p, ranges, pairs);
    p.space.w32(information, 0).unwrap();
    let mut process = p.arch.ptr(u64::MAX);
    let (mut class, mut length, mut flags, mut count) = (0u64, 4u64, 0u32, 1u64);
    let width = p.arch.ptr_size();
    if id == 1 || id == 49 || id == 192 {
        flags = 1;
    }
    if (2..34).contains(&id) {
        flags = 1 << (id - 2);
    }
    if id == 34 {
        flags = u32::MAX;
    }
    if id == 35 {
        flags = 3;
    }
    if (36..42).contains(&id) {
        length = [0, 1, 3, 5, 8, u32::MAX as u64][(id - 36) as usize];
    }
    if matches!(id, 44 | 45) {
        information += u64::from(id - 43);
    }
    if matches!(id, 50 | 51) {
        information = base + 16384 - if id == 50 { 3 } else { 4 };
    }
    if matches!(id, 54 | 55) {
        ranges += if id == 54 { 1 } else { 4 };
    }
    if matches!(id, 60 | 61) {
        ranges = base + 4096 - (2 * width - u64::from(id == 60));
    }
    if id == 62 {
        count = 0;
    }
    if (63..66).contains(&id) {
        count = 2;
        if id == 64 {
            pairs[1].0 = 1;
        }
        if id == 65 {
            pairs[0].0 = 1;
        }
    }
    if (70..79).contains(&id) || (193..202).contains(&id) {
        let index = if id >= 193 {
            flags = 1;
            id - 193
        } else {
            id - 70
        };
        let rights = [0, 8, 16, 24, 0x400, 0x1000, 0x1400, 0x100000, 0x1fffff];
        let object = p.objects.create(Object::Process {
            pid: p.pid,
            exit_code: None,
        });
        process = p
            .objects
            .open_access(object, false, rights[index as usize])
            .unwrap()
            .into();
    }
    if (202..205).contains(&id) {
        count = 2;
        flags = 1;
        if id == 202 {
            pairs[1].0 = 1;
        }
        if id == 203 {
            pairs[0].0 = 1;
        }
    }
    if id == 205 {
        flags = 1;
        pairs[0].1 = 16384;
    }
    let target_case = if (100..120).contains(&id) {
        flags = 1;
        id - 21
    } else {
        id
    };
    match target_case {
        79 => pairs[0].0 = 0,
        80 => pairs[0].0 = 1,
        81 => pairs[0].0 = target + 1,
        82 => pairs[0].0 = target + 4095,
        83 => pairs[0].1 = 0,
        84 => pairs[0].1 = 1,
        85 => pairs[0].1 = 4095,
        86 => pairs[0].1 = 4097,
        87 => pairs[0].1 = p.arch.ptr(u64::MAX),
        88 => pairs[0].0 = p.arch.ptr(u64::MAX),
        89 => {
            pairs[0].0 = p.arch.ptr(u64::MAX) - 2047;
            pairs[0].1 = 8192;
        }
        90 => pairs[0].0 = 1 << (width * 8 - 1),
        91 => {
            p.vm.free(target, 16384, mem::DECOMMIT).unwrap();
        }
        92 => {
            p.vm.free(target, 4096, mem::DECOMMIT).unwrap();
        }
        93 => {
            p.vm.free(target, 0, mem::RELEASE).unwrap();
        }
        94 => {
            p.vm.protect(target, 4096, prot::NOACCESS).unwrap();
        }
        95 => {
            p.vm.protect(target, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        96 => {
            p.vm.protect(target, 4096, prot::READONLY).unwrap();
        }
        97 => {
            p.vm.protect(target, 4096, prot::EXECUTE).unwrap();
        }
        98 => {
            p.vm.protect(target, 4096, prot::EXECUTE_READ).unwrap();
        }
        99 | 192 => {
            p.vm.protect(target, 4096, prot::READONLY | prot::GUARD)
                .unwrap();
        }
        _ => {}
    }
    match id {
        120 => {
            count = 0;
            information = 0;
        }
        121 => {
            count = 0;
            ranges = 0;
        }
        122 => {
            count = 0;
            length = 0;
        }
        123 => {
            count = 0;
            process = 0;
        }
        124 => {
            process = 0;
            length = 0;
        }
        125 => {
            process = 0;
            information = 0;
        }
        126 => {
            process = 0;
            ranges = 0;
        }
        127 => {
            length = 0;
            information = 0;
        }
        128 => {
            length = 0;
            ranges = 0;
        }
        129 => {
            information = 0;
            ranges = 0;
        }
        130 => {
            flags = 2;
            ranges = 0;
        }
        131 => {
            flags = 2;
            process = 0;
        }
        _ => {}
    }
    if (132..140).contains(&id) {
        count =
            [0x7fffffff, 0x80000000, 0xffffffff, p.arch.ptr(u64::MAX)][((id - 132) % 4) as usize];
        ranges = 1;
        if id >= 136 {
            length = 0;
        }
    }
    if (140..148).contains(&id) {
        class = if id & 1 != 0 { u32::MAX as u64 } else { 8 };
        if matches!(id, 142 | 143) {
            length = 0;
        }
        if matches!(id, 144 | 145) {
            information = 0;
        }
        if matches!(id, 146 | 147) {
            ranges = 0;
        }
    }
    if (148..156).contains(&id) {
        information = base + 16384 - u64::from(id - 148);
    }
    if (156..180).contains(&id) {
        ranges = base + 4096 - u64::from(id - 156);
    }
    match id {
        180 | 186 => process = 0,
        181 | 187 => count = 0,
        182 | 188 => length = 0,
        183 | 189 => flags = 2,
        184 | 190 => information = 0,
        185 | 191 => ranges = 0,
        _ => {}
    }
    if (206..334).contains(&id) {
        class = u64::from((id - 206) / 8);
        match (id - 206) % 8 {
            0 => length = 0,
            1 => length = 4,
            2 => length = 8,
            3 => length = 16,
            4 => information = 0,
            5 => count = 0,
            6 => ranges = 0,
            7 => process = 0,
            _ => unreachable!(),
        }
    }
    if (334..342).contains(&id) {
        if width == 8 {
            pairs[0] = (
                0x7fff_fffe_ffff + u64::from((id - 334) / 2) - 1,
                if (id - 334) & 1 != 0 { 0 } else { 1 },
            );
        } else {
            pairs[0] = (
                0xffff_fffe + u64::from((id - 334) / 4),
                1 + u64::from((id - 334) % 4),
            );
        }
    }
    if (base..base + 32764).contains(&information) {
        p.space.w32(information, flags).unwrap();
    }
    if (base..base + 32768 - 4 * width).contains(&ranges) {
        write_ranges(p, ranges, pairs);
    }
    let mut protection = Vec::new();
    match id {
        42 => information = 0,
        43 => information = 1,
        46 => protection.push((base + 8192, prot::READONLY)),
        47 => protection.push((base + 8192, prot::NOACCESS)),
        48 => protection.push((base + 8192, prot::READWRITE | prot::GUARD)),
        49 => protection.push((base + 8192, prot::READONLY | prot::GUARD)),
        52 => ranges = 0,
        53 => ranges = 1,
        56 => protection.push((base, prot::READONLY)),
        57 => protection.push((base, prot::NOACCESS)),
        58 => protection.push((base, prot::READWRITE | prot::GUARD)),
        59 => protection.push((base, prot::READONLY | prot::GUARD)),
        66 => process = 0,
        67 => process = 0x1234,
        68 => process = p.arch.ptr(u64::MAX - 1),
        69 => {
            let object = p.objects.create(Object::Event {
                manual: false,
                signaled: 0,
            });
            process = p.objects.open(object, false).into();
        }
        _ => {}
    }
    if matches!(id, 50 | 51) || (148..156).contains(&id) {
        protection.push((base + 16384, prot::NOACCESS));
    }
    if matches!(id, 60 | 61) || (156..180).contains(&id) {
        protection.push((base + 4096, prot::NOACCESS));
    }
    if (180..186).contains(&id) {
        protection.push((base, prot::READWRITE | prot::GUARD));
    }
    if (186..192).contains(&id) {
        protection.push((base + 8192, prot::READWRITE | prot::GUARD));
    }
    for (address, protect) in protection {
        p.vm.protect(address, 4096, protect).unwrap();
    }
    Setup {
        args: [process, class, count, ranges, information, length],
        base,
        target,
    }
}
