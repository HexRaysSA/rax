//! The generated Linux tables agree with the vendored UAPI headers.
//!
//! `src/user/linux/abi/{syscalls,errno_table}.rs` are produced by
//! `tools/linux/gen_syscalls.py`; this test re-derives both from
//! `docs/specifications/linux/uapi-6.19` independently, so a hand edit or a
//! stale regeneration fails here.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rax::user::linux::abi::LinuxAbi;
use rax::user::linux::abi::errno_table::{ERRNO_TABLE, errno_name};
use rax::user::linux::abi::syscalls::Sysno;

fn uapi() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/specifications/linux/uapi-6.19")
}

fn defines(path: &str, prefix: &str) -> BTreeMap<String, u64> {
    let text = std::fs::read_to_string(uapi().join(path)).expect("vendored UAPI header");
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() != Some("#define") {
            continue;
        }
        let (Some(name), Some(value)) = (it.next(), it.next()) else {
            continue;
        };
        if let (Some(n), Ok(v)) = (name.strip_prefix(prefix), value.parse::<u64>()) {
            out.insert(n.to_string(), v);
        }
    }
    out
}

fn check_table(abi: LinuxAbi, header: &str) {
    let expected = defines(header, "__NR_");
    assert!(
        expected.len() > 300,
        "{header}: parsed {} entries",
        expected.len()
    );
    for (name, nr) in &expected {
        let sysno = abi
            .sysno(*nr)
            .unwrap_or_else(|| panic!("{abi:?}: number {nr} ({name}) is unknown"));
        assert_eq!(sysno.name(), name, "{abi:?}: number {nr}");
        assert_eq!(abi.number(sysno), Some(*nr));
    }
    // No number outside the header resolves.
    for nr in 0..2048u64 {
        if let Some(s) = abi.sysno(nr) {
            assert_eq!(
                expected.get(s.name()),
                Some(&nr),
                "{abi:?}: extra number {nr}"
            );
        }
    }
}

#[test]
fn x86_64_syscall_numbers_match_unistd_64() {
    check_table(LinuxAbi::X86_64, "x86-linux-any/asm/unistd_64.h");
}

#[test]
fn aarch64_syscall_numbers_match_unistd_64() {
    check_table(LinuxAbi::Aarch64, "aarch64-linux-any/asm/unistd_64.h");
}

#[test]
fn riscv64_syscall_numbers_match_unistd_64() {
    check_table(LinuxAbi::Riscv64, "riscv-linux-any/asm/unistd_64.h");
}

#[test]
fn every_sysno_name_is_unique_and_sorted() {
    let names: Vec<&str> = Sysno::ALL.iter().map(|s| s.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(names, sorted);
}

#[test]
fn errno_values_match_asm_generic() {
    let mut expected = defines("any-linux-any/asm-generic/errno-base.h", "");
    expected.extend(defines("any-linux-any/asm-generic/errno.h", ""));
    expected.retain(|k, _| k.starts_with('E'));
    let table: BTreeMap<String, u64> = ERRNO_TABLE
        .iter()
        .map(|&(n, v)| (n.to_string(), v as u64))
        .collect();
    for (name, value) in &expected {
        assert_eq!(table.get(name), Some(value), "{name}");
    }
    // Aliases (EWOULDBLOCK, EDEADLOCK) are defined by name in the header.
    assert_eq!(table.get("EWOULDBLOCK"), table.get("EAGAIN"));
    assert_eq!(table.get("EDEADLOCK"), table.get("EDEADLK"));
    assert_eq!(table.len(), expected.len() + 2);
    assert_eq!(errno_name(11), Some("EAGAIN"));
    assert_eq!(errno_name(133), Some("EHWPOISON"));
}
