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
use rax::user::linux::abi::syscalls::{self, Sysno};

fn uapi() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/specifications/linux/uapi-6.19")
}

/// The `#define`s of `path` whose names start with `prefix` and whose
/// values are numbers, or ARM EABI's `(__NR_SYSCALL_BASE + n)` (a base of
/// 0 for EABI).
fn defines(path: &str, prefix: &str) -> BTreeMap<String, u64> {
    let text = std::fs::read_to_string(uapi().join(path)).expect("vendored UAPI header");
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() != Some("#define") {
            continue;
        }
        let (Some(name), Some(mut value)) = (it.next(), it.next()) else {
            continue;
        };
        if value == "(__NR_SYSCALL_BASE" {
            if it.next() != Some("+") {
                continue;
            }
            let Some(n) = it.next().and_then(|n| n.strip_suffix(')')) else {
                continue;
            };
            value = n;
        }
        if let (Some(n), Ok(v)) = (name.strip_prefix(prefix), value.parse::<u64>()) {
            out.insert(n.to_string(), v);
        }
    }
    out
}

/// The table `sysno`/`number` give agrees with `header` both ways.
fn check_numbers(
    what: &str,
    header: &str,
    sysno: impl Fn(u64) -> Option<Sysno>,
    number: impl Fn(Sysno) -> Option<u64>,
) {
    let expected = defines(header, "__NR_");
    assert!(
        expected.len() > 300,
        "{header}: parsed {} entries",
        expected.len()
    );
    for (name, nr) in &expected {
        let s = sysno(*nr).unwrap_or_else(|| panic!("{what}: number {nr} ({name}) is unknown"));
        assert_eq!(s.name(), name, "{what}: number {nr}");
        assert_eq!(number(s), Some(*nr));
    }
    // No number outside the header resolves.
    for nr in 0..2048u64 {
        if let Some(s) = sysno(nr) {
            assert_eq!(
                expected.get(s.name()),
                Some(&nr),
                "{what}: extra number {nr}"
            );
        }
    }
}

fn check_table(abi: LinuxAbi, header: &str) {
    check_numbers(
        &format!("{abi:?}"),
        header,
        |n| abi.sysno(n),
        |s| abi.number(s),
    );
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
fn i386_syscall_numbers_match_unistd_32() {
    check_table(LinuxAbi::I386, "x86-linux-any/asm/unistd_32.h");
}

/// ARM EABI: `unistd-eabi.h`, and arm64's `syscall_32.tbl` (the table of
/// a compatibility task, from which `unistd32.h` is generated) names the
/// same call at every number.
#[test]
fn arm_syscall_numbers_match_unistd_eabi_and_the_arm64_compat_table() {
    check_table(LinuxAbi::Arm, "arm-linux-any/asm/unistd-eabi.h");
    let tbl = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs/specifications/linux/kernel-6.19/arch/arm64/tools/syscall_32.tbl");
    let text = std::fs::read_to_string(tbl).expect("vendored syscall_32.tbl");
    let mut rows = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let nr: u64 = cols[0].parse().expect("a number");
        let s = LinuxAbi::Arm
            .sysno(nr)
            .unwrap_or_else(|| panic!("arm: {nr} is unknown"));
        assert_eq!(s.name(), cols[2], "arm: syscall_32.tbl number {nr}");
        rows += 1;
    }
    assert_eq!(rows, syscalls::ARM_TABLE.len());
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
