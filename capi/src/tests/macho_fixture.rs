//! Static Mach-O images shared by process ABI and adapter regressions.
use rax_engine::user::image::macho::*;

const BASE: u64 = 0x1_0000_0000;
pub(crate) const ENTRY: u64 = BASE + 0x1000;
pub(crate) const DATA: u64 = BASE + 0x1200;
const PAGE: u64 = 0x4000;

fn command(kind: u32, body: &[u8]) -> Vec<u8> {
    [
        kind.to_le_bytes().to_vec(),
        ((8 + body.len()) as u32).to_le_bytes().to_vec(),
        body.to_vec(),
    ]
    .concat()
}
fn segment(name: &[u8], address: u64, size: u64, file_size: u64, protection: u32) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[..name.len()].copy_from_slice(name);
    for value in [address, size, 0, file_size] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [protection, protection, 0, 0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    command(LC_SEGMENT_64, &body)
}
pub(crate) fn image(arm: bool, code: &[u8], dyld: bool, file_type: u32) -> Vec<u8> {
    let (kind, subtype, flavor, words, pc_offset) = if arm {
        (
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            ARM_THREAD_STATE64,
            ARM_THREAD_STATE64_COUNT,
            256,
        )
    } else {
        (
            CPU_TYPE_X86_64,
            CPU_SUBTYPE_X86_64_ALL,
            X86_THREAD_STATE64,
            X86_THREAD_STATE64_COUNT,
            128,
        )
    };
    let mut state = vec![0; words as usize * 4];
    state[pc_offset..pc_offset + 8].copy_from_slice(&ENTRY.to_le_bytes());
    let state = [
        flavor.to_le_bytes().to_vec(),
        words.to_le_bytes().to_vec(),
        state,
    ]
    .concat();
    let mut commands = vec![
        segment(b"__PAGEZERO", 0, BASE, 0, 0),
        segment(b"__TEXT", BASE, PAGE, PAGE, VM_PROT_READ | VM_PROT_EXECUTE),
        command(LC_UNIXTHREAD, &state),
    ];
    if dyld {
        let mut body = 12u32.to_le_bytes().to_vec();
        body.extend_from_slice(b"/usr/lib/dyld\0");
        body.resize((body.len() + 7) & !7, 0);
        commands.push(command(LC_LOAD_DYLINKER, &body));
    }
    let mut bytes = Vec::new();
    for word in [
        MH_MAGIC_64,
        kind,
        subtype,
        file_type,
        commands.len() as u32,
        commands.iter().map(Vec::len).sum::<usize>() as u32,
        0,
        0,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for command in commands {
        bytes.extend(command);
    }
    bytes.resize(PAGE as usize, 0);
    bytes[0x1000..0x1000 + code.len()].copy_from_slice(code);
    bytes[0x1200..0x1204].copy_from_slice(b"rax\n");
    bytes
}
