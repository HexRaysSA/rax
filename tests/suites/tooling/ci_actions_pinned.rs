use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn external_github_actions_are_pinned_to_full_commit_shas() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    for dir in [".github/actions", ".github/workflows"] {
        collect_yaml_files(&root.join(dir), &mut files);
    }

    let mut violations = Vec::new();
    for file in files {
        let contents = fs::read_to_string(&file)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.display()));
        let rel = file.strip_prefix(&root).unwrap_or(&file);

        for (line_idx, line) in contents.lines().enumerate() {
            let Some(action_ref) = parse_uses_value(line) else {
                continue;
            };

            if is_local_action(action_ref) || action_ref.starts_with("docker://") {
                continue;
            }

            if !is_full_sha_ref(action_ref) {
                violations.push(format!(
                    "{}:{} uses {}",
                    rel.display(),
                    line_idx + 1,
                    action_ref
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "external GitHub Actions must be pinned to full commit SHAs:\n{}",
        violations.join("\n")
    );
}

#[test]
fn licensing_resolves_locked_dependencies_for_fresh_runners() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = fs::read_to_string(root.join(".github/workflows/licensing.yml"))
        .expect("failed to read licensing workflow");
    assert!(
        workflow.contains("run: python tools/licensing/check.py"),
        "licensing workflow must run its distribution check"
    );
    assert!(
        workflow.contains("run: python -m unittest discover -s tools/licensing"),
        "licensing workflow must run the checker's host-path regression tests"
    );

    let checker = fs::read_to_string(root.join("tools/licensing/check.py"))
        .expect("failed to read licensing checker");
    assert!(
        checker.contains("'--locked'"),
        "package check must preserve locked dependency resolution"
    );
    assert!(
        !checker.contains("'--offline'"),
        "fresh runners must be allowed to fetch locked git dependencies"
    );

    for workflow in ["ci.yml", "full-suite.yml"] {
        let contents = fs::read_to_string(root.join(".github/workflows").join(workflow))
            .unwrap_or_else(|err| panic!("failed to read {workflow}: {err}"));
        assert!(
            contents.contains("--test ci_actions_pinned"),
            "{workflow} must run workflow regression tests"
        );
    }
}

#[test]
fn scheduled_differential_separates_oracles_diagnostics_and_assembler_capabilities() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/differential.yml");
    let contents = fs::read_to_string(&workflow)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow.display()));
    let normalized = contents.split_whitespace().collect::<Vec<_>>().join(" ");

    for required in [
        "--include-ignored",
        "--skip report_evex_spec_forms_rejected_by_smir_lifter",
        "--skip qemu_evex_unimplemented_avx512_corpus_matches_rax_when_enabled",
        "evex_generated_corpus_covers_supported_selectors_and_forms \\ -- --exact --nocapture",
        "skips=--skip evex_generated_corpus_covers_supported_selectors_and_forms --skip qemu_evex_generated_corpus_matches_rax",
    ] {
        assert!(
            normalized.contains(required),
            "scheduled differential workflow is missing required policy fragment: {required}"
        );
    }
}

#[test]
fn scheduled_kvm_keeps_host_dependent_differentials_informational() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/kvm.yml");
    let contents = fs::read_to_string(&workflow)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow.display()));

    for job in ["kvm-differential", "kvm-avx512"] {
        let marker = format!("  {job}:\n");
        let start = contents
            .find(&marker)
            .unwrap_or_else(|| panic!("KVM workflow is missing {job}"));
        let section = contents[start + marker.len()..]
            .lines()
            .take_while(|line| line.trim().is_empty() || line.starts_with("    "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            section.contains("continue-on-error: true"),
            "host-dependent {job} must retain diagnostics without failing the workflow"
        );
    }
}

#[test]
fn experimental_cross_builds_report_failures_without_red_checks() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/cross.yml");
    let contents = fs::read_to_string(&workflow)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow.display()));

    let marker = "  cross-experimental:\n";
    let start = contents
        .find(marker)
        .expect("cross workflow is missing its experimental job");
    let section = contents[start + marker.len()..]
        .lines()
        .take_while(|line| line.trim().is_empty() || line.starts_with("    "))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        section.contains("continue-on-error: true"),
        "experimental targets must remain explicitly non-gating"
    );
    assert!(
        section.contains("if cross +nightly build")
            && section.contains("Experimental cross-build unavailable"),
        "experimental target failures must become visible warnings, not red checks"
    );
}

#[test]
fn push_ci_runs_host_specific_scalar_and_evex_jit_regressions() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/ci.yml");
    let contents = fs::read_to_string(&workflow)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow.display()));

    for target in [
        "--test smir_jit_vcpu",
        "--test smir_jit_aarch32_aarch64",
        "--test smir_jit_thumb_aarch64",
        "--test smir_jit_x86_aarch64",
        "--test smir_jit_evex_masking",
        "--test riscv_smir_x86_jit",
        "--test riscv_smir_aarch64_jit",
    ] {
        assert!(
            contents.contains(target),
            "push CI core slice must execute {target}"
        );
    }

    let core_step_start = contents
        .find("      - name: cargo test (core slice)\n")
        .expect("push CI is missing the core test step");
    let core_step_end = contents[core_step_start..]
        .find("      # The x86-64 JIT suite")
        .map(|offset| core_step_start + offset)
        .expect("push CI is missing the native x86-64 JIT step boundary");
    let core_step = &contents[core_step_start..core_step_end];
    assert!(
        core_step.contains("-- --include-ignored --test-threads=1 --nocapture"),
        "push CI must serialize raw native core tests and preserve failure output"
    );
}

#[test]
fn scheduled_full_suite_runs_every_host_specific_jit_regression_binary() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/full-suite.yml");
    let contents = fs::read_to_string(&workflow)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow.display()));

    for target in [
        "--test smir_jit_vcpu",
        "--test smir_jit_aarch32_aarch64",
        "--test smir_jit_thumb_aarch64",
        "--test smir_jit_x86_aarch64",
        "--test smir_jit_evex_masking",
        "--test riscv_smir_x86_jit",
        "--test riscv_smir_aarch64_jit",
        "--test aarch64_smir_native",
    ] {
        assert!(
            contents.contains(target),
            "scheduled full-suite SMIR-host shard must execute {target}"
        );
    }
}

#[test]
fn scheduled_full_suite_serializes_native_jit_shards_and_preserves_diagnostics() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/full-suite.yml");
    let contents = fs::read_to_string(&workflow)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow.display()));

    for shard in ["unit", "smir-host"] {
        let marker = format!("name: {shard},");
        let shard_line = contents
            .lines()
            .find(|line| line.contains(&marker))
            .unwrap_or_else(|| panic!("scheduled Full suite is missing the {shard} shard"));
        assert!(
            shard_line.contains("harness: \"--include-ignored --test-threads=1 --nocapture\""),
            "scheduled Full suite {shard} shard must serialize native tests and preserve output"
        );
    }

    for shard in ["x86_64", "arm"] {
        let marker = format!("name: {shard},");
        let shard_line = contents
            .lines()
            .find(|line| line.contains(&marker))
            .unwrap_or_else(|| panic!("scheduled Full suite is missing the {shard} shard"));
        assert!(
            shard_line.contains("harness: \"--include-ignored\""),
            "host-independent Full suite {shard} shard must retain its parallel harness"
        );
    }

    let cargo_step_start = contents
        .find("      - name: cargo test (${{ matrix.shard.name }})\n")
        .expect("scheduled Full suite is missing its cargo test step");
    let cargo_step_end = contents[cargo_step_start..]
        .find("\n  # Doctests")
        .map(|offset| cargo_step_start + offset)
        .expect("scheduled Full suite is missing the doctest step boundary");
    let cargo_step = &contents[cargo_step_start..cargo_step_end];
    assert!(
        cargo_step.contains(
            "if [ \"${{ matrix.shard.name }}\" = \"unit\" ] || [ \"${{ matrix.shard.name }}\" = \"smir-host\" ]; then"
        ) && cargo_step.contains("export RAX_JIT_TRACE=1"),
        "scheduled Full suite must arm native crash diagnostics only for native JIT shards"
    );
    assert!(
        cargo_step.contains("-- ${{ matrix.shard.harness }}"),
        "scheduled Full suite must apply each shard's explicit harness policy"
    );
}

fn collect_yaml_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()));

    for entry in entries {
        let path = entry
            .unwrap_or_else(|err| panic!("failed to read entry in {}: {err}", dir.display()))
            .path();
        if path.is_dir() {
            collect_yaml_files(&path, files);
        } else if is_yaml_file(&path) {
            files.push(path);
        }
    }
}

fn is_yaml_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("yml" | "yaml")
    )
}

fn parse_uses_value(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let value = trimmed
        .strip_prefix("- uses:")
        .or_else(|| trimmed.strip_prefix("uses:"))?
        .split('#')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(|ch| ch == '"' || ch == '\'');

    if value.is_empty() { None } else { Some(value) }
}

fn is_local_action(action_ref: &str) -> bool {
    action_ref.starts_with("./") || action_ref.starts_with("../")
}

fn is_full_sha_ref(action_ref: &str) -> bool {
    let Some((_, reference)) = action_ref.rsplit_once('@') else {
        return false;
    };

    reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
}
