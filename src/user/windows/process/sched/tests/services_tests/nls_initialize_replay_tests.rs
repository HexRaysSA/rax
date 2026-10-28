//! Every original native record, including mapping deltas and fault copybacks.
use super::*;
use std::collections::BTreeSet;

const CORPORA: [(WinArch, &str); 4] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-nls-initialize/native-nls-initialize-arm64.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-nls-initialize/native-nls-initialize-x64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-nls-initialize/native-nls-initialize-x86.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-nls-initialize/native-nls-initialize-x86-laa.log"
        ),
    ),
];

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(&format!("{name}=")))
        .unwrap()
}
fn integer(line: &str, name: &str) -> i64 {
    field(line, name).parse().unwrap()
}
fn hex(line: &str, name: &str) -> u64 {
    u64::from_str_radix(field(line, name), 16).unwrap()
}

fn arg(base: u64, index: usize, variant: i64, arch: WinArch) -> u64 {
    match variant {
        0 => base + 256 + index as u64 * 32,
        1 => 0,
        2 => 1,
        3 => base + 4096 + 256 + index as u64 * 32,
        4 => base + 8192 + 256 + index as u64 * 32,
        5 => base + 257 + index as u64 * 32,
        6 => base + 4095,
        7 => arch.ptr(u64::MAX),
        8 => base + 384,
        9 => base + 12288 + 256 + index as u64 * 32,
        _ => panic!("unrecognized original fixture variant"),
    }
}

#[test]
fn native_nls_initialize_replays_both_measured_builds_outputs_guards_and_retained_views() {
    let mut cases = 0;
    let mut late_retained = 0;
    for (arch, raw, build) in CORPORA
        .into_iter()
        .flat_map(|(arch, raw)| [29683, 29695].map(|build| (arch, raw, build)))
    {
        let lines: Vec<_> = raw.lines().collect();
        let mut profile_cases = 0;
        for (index, line) in lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with("case "))
        {
            let (mut process, mut thread, base) = setup(arch, build);
            let p = process.state_mut();
            let args: Vec<_> = (0..4)
                .map(|i| {
                    let variant = if i as i64 == integer(line, "argument") {
                        integer(line, "variant")
                    } else if i as i64 == integer(line, "other") {
                        integer(line, "other-variant")
                    } else {
                        0
                    };
                    arg(base, i, variant, arch)
                })
                .collect();
            let before: BTreeSet<_> = p.vm.allocations().map(|a| a.base).collect();
            let charge = p.vm.committed_bytes();
            assert_eq!(
                invoke(p, &mut thread, &args),
                Outcome::Continue,
                "{arch} build {build}: {line}"
            );
            assert_eq!(
                thread.cpu.gpr(0),
                hex(line, "status"),
                "{arch} build {build}: {line}"
            );
            assert_eq!(
                p.vm.query(base + 12288).unwrap().protect as u64,
                hex(lines[index + 1], "protect"),
                "{arch} build {build}: {line}"
            );
            let delta = integer(lines[index + 2], "after") - integer(lines[index + 2], "before");
            let new: Vec<_> =
                p.vm.allocations()
                    .filter(|a| !before.contains(&a.base))
                    .collect();
            assert_eq!(new.len() as i64, delta, "{arch} build {build}: {line}");
            assert_eq!(
                p.vm.committed_bytes(),
                charge + new.len() as u64 * 864256,
                "{arch} build {build}: {line}"
            );
            let encoded = field(lines[index + 3], "hex");
            let mut expected: Vec<_> = (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(expected.len(), 144);
            if let Some(view) = new.first() {
                assert_eq!(view.size, 864256);
                assert!(p.vm.is_nls_view(view.base));
                assert_eq!(p.vm.query(view.base).unwrap().protect, prot::READONLY);
                // Relocate only the original base-output byte span. Preserve
                // any native64 locale overwrite of aliased low pointer bytes.
                let bytes = view.base.to_le_bytes();
                if thread.cpu.gpr(0) == 0
                    && args[0] >= base + 256
                    && args[0] + arch.ptr_size() <= base + 400
                {
                    for byte in 0..arch.ptr_size() {
                        let address = args[0] + byte;
                        if arch != WinArch::X86 && address >= args[1] && address < args[1] + 4 {
                            continue;
                        }
                        expected[(address - base - 256) as usize] = bytes[byte as usize];
                    }
                }
                if thread.cpu.gpr(0) != 0 {
                    late_retained += 1;
                }
            }
            assert_eq!(
                p.space.bytes(base + 256, 144).unwrap(),
                expected,
                "{arch} build {build}: {line}"
            );
            assert!(thread.frames.is_empty());
            profile_cases += 1;
        }
        assert_eq!(profile_cases, 79);
        cases += profile_cases;
    }
    assert_eq!(cases, 632);
    assert_eq!(late_retained, 16);
}
