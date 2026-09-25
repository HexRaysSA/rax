//! The morok program corpus produces the output a real kernel produced.
//!
//! `tests/fixtures/user/linux/programs` (see its README) holds 97 C and C++
//! programs from the morok project, trimmed to run in milliseconds, built
//! for x86-64, AArch64, and RV64, with the stdout and exit status each one
//! produced on Linux. Every program runs under `rax-user` in every execution
//! mode and must match its recording after the `noise.txt` filters, except
//! for the divergences listed in `known-divergences.txt`, which must still
//! diverge: the list names rax's open defects exactly, so a fix or a new
//! failure both fail the test until the list is updated.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::sha256;
use super::support::{fixtures, run_in};

const ARCHES: [&str; 3] = ["x86_64", "aarch64", "riscv64"];

fn corpus() -> PathBuf {
    fixtures().join("programs")
}

/// Non-empty, non-comment lines of a corpus file, split on whitespace.
fn table(file: &str) -> Vec<Vec<String>> {
    std::fs::read_to_string(corpus().join(file))
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .collect()
}

struct Program {
    name: String,
    args: Vec<String>,
}

/// `cases.txt`: each program and its arguments.
fn programs() -> Vec<Program> {
    table("cases.txt")
        .into_iter()
        .map(|mut row| Program {
            name: row.remove(0),
            args: row,
        })
        .collect()
}

/// An execution mode: a guest architecture and how rax-user runs it.
struct Mode {
    label: &'static str,
    arch: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
}

const MODES: [Mode; 5] = [
    Mode {
        label: "x86_64",
        arch: "x86_64",
        args: &[],
        env: &[],
    },
    Mode {
        label: "x86_64-nojit",
        arch: "x86_64",
        args: &[],
        env: &[("RAX_NO_JIT", "1")],
    },
    Mode {
        label: "aarch64",
        arch: "aarch64",
        args: &[],
        env: &[],
    },
    Mode {
        label: "riscv64",
        arch: "riscv64",
        args: &[],
        env: &[],
    },
    Mode {
        label: "riscv64-jit",
        arch: "riscv64",
        args: &["--riscv-jit"],
        env: &[],
    },
];

/// A `noise.txt` filter, applied to both the recording and the run.
#[derive(Debug, PartialEq)]
enum Filter {
    /// Masks hexadecimal addresses (`0x` and six or more digits): heap
    /// addresses that address-space randomization changes on every run.
    Addresses,
    /// Masks the number just before `" WORD"`: a measured time or count.
    NumberBefore(String),
    /// Masks a whole line containing `WORD` (a measured ratio), keeping the
    /// line itself so that the output's shape is still compared.
    Line(String),
    /// Ignores standard output entirely (the exit status still counts).
    IgnoreStdout,
}

fn parse_filter(s: &str) -> Filter {
    match s.split_once(':') {
        None if s == "addresses" => Filter::Addresses,
        None if s == "ignore-stdout" => Filter::IgnoreStdout,
        Some(("number-before", w)) if !w.is_empty() => Filter::NumberBefore(w.to_string()),
        Some(("line", w)) if !w.is_empty() => Filter::Line(w.to_string()),
        _ => panic!("unknown noise filter {s}"),
    }
}

/// `noise.txt`: `(arch, program) -> filters`, where the arch column may be
/// `*` for every architecture.
fn noise() -> BTreeMap<(String, String), Vec<Filter>> {
    let mut out: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for row in table("noise.txt") {
        assert!(row.len() >= 4, "noise filter {row:?} needs a reason");
        let arches: Vec<&str> = if row[0] == "*" {
            ARCHES.to_vec()
        } else {
            assert!(ARCHES.contains(&row[0].as_str()), "unknown arch {}", row[0]);
            vec![row[0].as_str()]
        };
        for arch in arches {
            out.entry((arch.to_string(), row[1].clone()))
                .or_default()
                .push(parse_filter(&row[2]));
        }
    }
    out
}

/// Masks every run of `[0-9.]` that starts with a digit and ends just
/// before `" word"` (as `record-expected.sh` does with Perl).
fn mask_number_before(line: &str, word: &str) -> String {
    let needle = format!(" {word}");
    let b = line.as_bytes();
    let mut out = String::new();
    let mut done = 0;
    let mut at = 0;
    while let Some(i) = line[at..].find(&needle).map(|i| i + at) {
        let mut s = i;
        while s > done && (b[s - 1].is_ascii_digit() || b[s - 1] == b'.') {
            s -= 1;
        }
        while s < i && b[s] == b'.' {
            s += 1;
        }
        if s < i {
            out.push_str(&line[done..s]);
            out.push('?');
            done = i;
        }
        at = i + needle.len();
    }
    out.push_str(&line[done..]);
    out
}

fn mask_addresses(line: &str) -> String {
    let b = line.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"0x") {
            let n = b[i + 2..]
                .iter()
                .take_while(|c| c.is_ascii_hexdigit())
                .count();
            if n >= 6 {
                out.push_str("0x?");
                i += 2 + n;
                continue;
            }
        }
        let c = line[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// `stdout` with `filters` applied.
fn denoise(stdout: &[u8], filters: &[Filter]) -> String {
    if filters.contains(&Filter::IgnoreStdout) {
        return String::new();
    }
    let text = String::from_utf8_lossy(stdout);
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let mut l = line.to_string();
        for f in filters {
            l = match f {
                Filter::Addresses => mask_addresses(&l),
                Filter::NumberBefore(w) => mask_number_before(&l, w),
                Filter::Line(w) if l.contains(w.as_str()) => if l.ends_with('\n') {
                    "<masked>\n"
                } else {
                    "<masked>"
                }
                .to_string(),
                Filter::Line(_) => l,
                Filter::IgnoreStdout => unreachable!("handled above"),
            };
        }
        out.push_str(&l);
    }
    out
}

/// `known-divergences.txt`: `(mode, program) -> reason`.
fn known() -> BTreeMap<(String, String), String> {
    table("known-divergences.txt")
        .into_iter()
        .map(|row| {
            assert!(row.len() >= 3, "divergence {row:?} needs a reason");
            assert!(
                MODES.iter().any(|m| m.label == row[0]),
                "unknown mode {}",
                row[0]
            );
            ((row[0].clone(), row[1].clone()), row[2..].join(" "))
        })
        .collect()
}

fn expected(arch: &str, name: &str) -> (Vec<u8>, i32) {
    let dir = corpus().join("expected").join(arch);
    let stdout = std::fs::read(dir.join(format!("{name}.stdout"))).unwrap();
    let status = std::fs::read_to_string(dir.join(format!("{name}.status")))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (stdout, status)
}

/// The first line where `want` and `got` differ, for the failure report.
fn first_difference(want: &str, got: &str) -> String {
    let (w, g): (Vec<_>, Vec<_>) = (want.lines().collect(), got.lines().collect());
    for i in 0..w.len().max(g.len()) {
        if w.get(i) != g.get(i) {
            return format!(
                "line {}: expected {:?}, got {:?} ({} vs {} lines)",
                i + 1,
                w.get(i).unwrap_or(&"<end>"),
                g.get(i).unwrap_or(&"<end>"),
                w.len(),
                g.len()
            );
        }
    }
    "trailing newline".to_string()
}

/// Runs one program in `mode`; `None` if it matched its recording, else why
/// not.
fn check(mode: &Mode, p: &Program, filters: &[Filter]) -> Option<String> {
    let exe = corpus().join("bin").join(mode.arch).join(&p.name);
    let exe = exe.to_str().unwrap();
    let mut args: Vec<&str> = mode.args.to_vec();
    args.push(exe);
    args.extend(p.args.iter().map(String::as_str));
    // A fresh working directory per run: programs create files there.
    let cwd = std::env::temp_dir().join(format!(
        "rax-user-corpus-{}-{}-{}",
        std::process::id(),
        mode.label,
        p.name
    ));
    std::fs::create_dir_all(&cwd).unwrap();
    let r = run_in(Some(&cwd), &args, mode.env, None, Duration::from_secs(300));
    let _ = std::fs::remove_dir_all(&cwd);
    let (want_out, want_status) = expected(mode.arch, &p.name);
    let (want, got) = (denoise(&want_out, filters), denoise(&r.stdout, filters));
    let Some(status) = r.status else {
        return Some("timed out".to_string());
    };
    if status != want_status {
        return Some(format!(
            "exit status {status}, expected {want_status}; stderr: {}",
            r.stderr.lines().last().unwrap_or("")
        ));
    }
    (want != got).then(|| format!("stdout differs at {}", first_difference(&want, &got)))
}

/// Runs the whole corpus in `mode` in parallel and requires the divergences
/// to be exactly the known ones.
fn run_mode(label: &str) {
    let mode = MODES.iter().find(|m| m.label == label).unwrap();
    let programs = programs();
    let noise = noise();
    let known: BTreeSet<String> = known()
        .into_keys()
        .filter(|(m, _)| m == label)
        .map(|(_, p)| p)
        .collect();
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(BTreeMap::new());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(p) = programs.get(i) else { break };
                    let filters = noise
                        .get(&(mode.arch.to_string(), p.name.clone()))
                        .map_or(&[][..], Vec::as_slice);
                    if let Some(why) = check(mode, p, filters) {
                        failures.lock().unwrap().insert(p.name.clone(), why);
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    let mut report = Vec::new();
    for (name, why) in &failures {
        if !known.contains(name) {
            report.push(format!("  {label}/{name}: {why}"));
        }
    }
    for name in &known {
        if !failures.contains_key(name) {
            report.push(format!(
                "  {label}/{name}: now matches Linux; remove it from known-divergences.txt"
            ));
        }
    }
    eprintln!(
        "{label}: {} programs, {} match, {} known divergences",
        programs.len(),
        programs.len() - failures.len(),
        known.len()
    );
    assert!(
        report.is_empty(),
        "{label}: the corpus differs from its recording:\n{}",
        report.join("\n")
    );
}

#[test]
fn corpus_x86_64_matches_linux() {
    run_mode("x86_64");
}

#[test]
fn corpus_x86_64_matches_linux_without_jit() {
    run_mode("x86_64-nojit");
}

#[test]
fn corpus_aarch64_matches_linux() {
    run_mode("aarch64");
}

#[test]
fn corpus_riscv64_matches_linux() {
    run_mode("riscv64");
}

#[test]
fn corpus_riscv64_matches_linux_with_jit() {
    run_mode("riscv64-jit");
}

/// Parses `manifest.toml` into `path -> sha256`.
fn manifest() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(corpus().join("manifest.toml")).unwrap();
    let mut out = BTreeMap::new();
    let mut path = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(" = ") else {
            continue;
        };
        let v = v.trim_matches('"').to_string();
        match k {
            "path" => path = Some(v),
            "sha256" => {
                out.insert(path.take().expect("path before sha256"), v);
            }
            _ => {}
        }
    }
    out
}

#[test]
fn corpus_binaries_match_manifest() {
    let m = manifest();
    for (path, want) in &m {
        let bytes = std::fs::read(corpus().join(path)).unwrap();
        assert_eq!(
            &sha256::hex(&bytes),
            want,
            "{path} does not match manifest.toml"
        );
    }
    let programs = programs();
    for p in &programs {
        for arch in ARCHES {
            let path = format!("bin/{arch}/{}", p.name);
            assert!(m.contains_key(&path), "{path} is not in manifest.toml");
            let (_, status) = expected(arch, &p.name);
            assert!((0..=255).contains(&status), "{arch}/{} status", p.name);
        }
    }
    assert_eq!(m.len(), programs.len() * ARCHES.len());
}

#[test]
fn corpus_sources_are_upstream_or_annotated() {
    // upstream.sha256 lists every vendored source with its upstream hash; a
    // source that differs from upstream must say where (`rax:` comments).
    let upstream: BTreeMap<String, String> =
        std::fs::read_to_string(corpus().join("upstream.sha256"))
            .unwrap()
            .lines()
            .map(|l| {
                let (sum, file) = l.split_once("  ").expect("sha256sum format");
                (file.to_string(), sum.to_string())
            })
            .collect();
    let mut sources = BTreeSet::new();
    for entry in std::fs::read_dir(corpus().join("src")).unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_name().unwrap().to_str().unwrap().to_string();
        let bytes = std::fs::read(&path).unwrap();
        let want = upstream
            .get(&file)
            .unwrap_or_else(|| panic!("{file} is not in upstream.sha256"));
        if &sha256::hex(&bytes) != want {
            assert!(
                String::from_utf8_lossy(&bytes).contains("rax: "),
                "{file} differs from upstream without a `rax:` annotation"
            );
        }
        let stem = file.rsplit_once('.').unwrap().0.to_string();
        assert!(sources.insert(stem), "{file}: two sources for one program");
    }
    assert_eq!(
        sources.len(),
        upstream.len(),
        "upstream.sha256 names a missing source"
    );
    let listed: BTreeSet<String> = programs().into_iter().map(|p| p.name).collect();
    assert_eq!(
        sources, listed,
        "cases.txt must list every source exactly once"
    );
}

#[test]
fn corpus_tables_are_consistent() {
    let names: BTreeSet<String> = programs().into_iter().map(|p| p.name).collect();
    // Every filter names a program and changes its recording (a filter that
    // changes nothing is stale).
    for ((arch, name), filters) in noise() {
        assert!(names.contains(&name), "noise.txt: unknown program {name}");
        let (stdout, _) = expected(&arch, &name);
        for f in &filters {
            if *f != Filter::IgnoreStdout {
                assert_ne!(
                    denoise(&stdout, std::slice::from_ref(f)),
                    String::from_utf8_lossy(&stdout),
                    "noise.txt: {f:?} changes nothing in {arch}/{name}"
                );
            }
        }
    }
    for (_, name) in known().keys() {
        assert!(
            names.contains(name),
            "known-divergences.txt: unknown program {name}"
        );
    }
    // Overrides: another architecture's recording is copied verbatim; QEMU
    // runs and kernel-derived expectations are recorded in expected/ORACLE.
    let oracle = std::fs::read_to_string(corpus().join("expected/ORACLE")).unwrap();
    for row in table("oracle-overrides.txt") {
        assert!(row.len() >= 4, "override {row:?} needs a reason");
        let (arch, name, source) = (&row[0], &row[1], &row[2]);
        assert!(ARCHES.contains(&arch.as_str()), "unknown arch {arch}");
        assert!(
            names.contains(name),
            "oracle-overrides.txt: unknown program {name}"
        );
        if source == "kernel" {
            assert!(oracle.contains(&format!("override: {arch}/{name} from the kernel source")));
        } else if let Some(q) = source.strip_prefix("qemu-") {
            assert_eq!(q, arch, "{arch}/{name} must run under its own QEMU");
            assert!(oracle.contains(&format!("override: {arch}/{name} run under ")));
        } else {
            assert!(ARCHES.contains(&source.as_str()), "unknown source {source}");
            assert_eq!(
                expected(arch, name),
                expected(source, name),
                "{arch}/{name}"
            );
        }
    }
}

#[test]
fn noise_filters_mask_only_their_targets() {
    let f = |s: &str| parse_filter(s);
    let t = |text: &str, filters: &[Filter]| denoise(text.as_bytes(), filters);
    assert_eq!(
        t(
            "  Time: 0.000000208 seconds\nfib(20) = 6765\n",
            &[f("number-before:seconds")]
        ),
        "  Time: ? seconds\nfib(20) = 6765\n"
    );
    assert_eq!(
        t(
            "result: 1291890006563070912 (12 ms)\n",
            &[f("number-before:ms)")]
        ),
        "result: 1291890006563070912 (? ms)\n"
    );
    assert_eq!(
        t("0  0xffff9d3e00d0  5  0x10  0xabcdef\n", &[f("addresses")]),
        "0  0x?  5  0x10  0x?\n"
    );
    assert_eq!(t("anything\n", &[f("ignore-stdout")]), "");
    assert_eq!(
        t("a\n  is 90.6x faster\nb", &[f("line:faster")]),
        "a\n<masked>\nb"
    );
    assert_eq!(
        mask_number_before("x 1.5 ms and 2 ms", "ms"),
        "x ? ms and ? ms"
    );
    assert_eq!(mask_number_before(" ms", "ms"), " ms");
}
