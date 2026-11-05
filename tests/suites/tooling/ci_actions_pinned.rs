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
        let contents = read_workflow(&file)
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
    let workflow = read_workflow(root.join(".github/workflows/licensing.yml"))
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
        let contents = read_workflow(root.join(".github/workflows").join(workflow))
            .unwrap_or_else(|err| panic!("failed to read {workflow}: {err}"));
        assert!(
            contents.contains("--test ci_actions_pinned"),
            "{workflow} must run workflow regression tests"
        );
    }
}

#[test]
fn native_windows_corpus_capture_follows_rust_cache_restore() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = read_workflow(root.join(".github/workflows/windows-exception-profile.yml"))
        .expect("failed to read native Windows workflow");
    let job = workflow_block(&workflow, "  observe:");
    let prepare_marker = "      - name: Prepare contained native CSR build directories";
    let setup_marker = "      - uses: ./.github/actions/setup-rust";
    let capture_marker = "      - name: Observe native CFG private-code lifecycle";
    let prepare = job
        .find(prepare_marker)
        .expect("missing contained temporary directory setup");
    let setup = job.find(setup_marker).expect("missing Rust/cache setup");
    let capture = job
        .find(capture_marker)
        .expect("missing first native capture");
    assert!(
        prepare < setup && setup < capture,
        "initialize contained temporary directories and restore Rust caches before native capture; a partial cache restore removes custom target corpora"
    );
    assert_eq!(
        job.matches(setup_marker).count(),
        1,
        "a later Rust/cache setup can remove freshly captured corpora"
    );
    let prepare = workflow_block(&job, prepare_marker);
    for required in [
        "$csrTmp = Join-Path $env:GITHUB_WORKSPACE 'target/native-csr-build-tmp'",
        "\"TMPDIR=$csrTmp\" >> $env:GITHUB_ENV",
        "\"TMP=$csrTmp\" >> $env:GITHUB_ENV",
        "\"TEMP=$csrTmp\" >> $env:GITHUB_ENV",
    ] {
        assert!(
            prepare.contains(required),
            "missing contained build setting: {required}"
        );
    }
}

#[test]
fn native_cfg_collection_cannot_reuse_cached_or_unqualified_observations() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = read_workflow(root.join(".github/workflows/windows-exception-profile.yml"))
        .expect("failed to read native Windows workflow");
    for source in [
        "docs/specifications/windows/native-cfg-private-code/**",
        "tools/ci/windows_cfg_private_code.py",
        "tools/ci/test_windows_cfg_private_code.py",
        "tools/ci/windows_cfg_original_protection.py",
        "tools/ci/test_windows_cfg_original_protection.py",
    ] {
        assert_eq!(
            workflow.matches(&format!("      - {source}\n")).count(),
            2,
            "both push and PR filters must include {source}"
        );
    }
    let job = workflow_block(&workflow, "  observe:");
    let capture = workflow_block(
        &job,
        "      - name: Observe native CFG private-code lifecycle",
    );
    assert!(
        capture.contains(
            "python -B -m unittest discover -s tools/ci -p test_windows_cfg_private_code.py"
        ) && capture.contains("python -B tools/ci/windows_cfg_private_code.py")
            && capture.contains(
                "python -B -m unittest discover -s tools/ci -p test_windows_cfg_original_protection.py"
            )
            && capture.contains("python -B tools/ci/windows_cfg_original_protection.py")
    );
    assert_eq!(
        capture
            .matches("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
            .count(),
        4,
        "a passing collector must not hide a failed provenance test"
    );
    let artifact = workflow_block(
        &job,
        "      - name: Preserve native CFG private-code observations",
    );
    assert!(
        artifact.contains("if: always()")
            && artifact.contains("path: |")
            && artifact.contains("target/native-cfg-private-code-v1")
            && artifact.contains("target/native-cfg-original-protection-v1")
            && artifact.contains("if-no-files-found: error")
    );
    let setup = workflow_block(&job, "      - uses: ./.github/actions/setup-rust");
    assert!(
        setup.contains("workspaces: . -> target/native-csr-cargo")
            && !setup.contains("target/native-cfg-private-code-v1")
            && !setup.contains("target/native-cfg-original-protection-v1")
    );
}

#[test]
fn native_windows_corpus_paths_are_outside_the_rust_cache_workspace() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = read_workflow(root.join(".github/workflows/windows-exception-profile.yml"))
        .expect("failed to read native Windows workflow");
    let job = workflow_block(&workflow, "  observe:");
    let prepare = workflow_block(
        &job,
        "      - name: Prepare contained native CSR build directories",
    );
    for required in [
        "$csrTarget = Join-Path $env:GITHUB_WORKSPACE 'target/native-csr-cargo'",
        "\"CARGO_TARGET_DIR=$csrTarget\" >> $env:GITHUB_ENV",
    ] {
        assert!(
            prepare.contains(required),
            "missing Cargo-only output setting: {required}"
        );
    }
    let setup = workflow_block(&job, "      - uses: ./.github/actions/setup-rust");
    assert!(
        setup.contains("workspaces: . -> target/native-csr-cargo"),
        "cache restore/save must exclude native corpus directories"
    );
    assert_eq!(
        workflow
            .matches("      - .github/actions/setup-rust/**")
            .count(),
        2,
        "push and pull-request filters must cover the shared cache action"
    );
    let action = read_workflow(root.join(".github/actions/setup-rust/action.yml"))
        .expect("failed to read shared Rust action");
    let input = workflow_block(&action, "  workspaces:");
    assert!(
        input.contains("default: \".\""),
        "other callers retain their default workspace"
    );
    let cache = workflow_block(&action, "    - name: Restore cargo + target cache");
    assert!(
        cache.contains("workspaces: ${{ inputs.workspaces }}"),
        "forward the caller's cache workspace mapping"
    );
}

#[test]
fn windows_process_suite_is_registered_and_reachable_in_ci_commands() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        fs::read_to_string(root.join("Cargo.toml")).expect("failed to read Cargo manifest");
    let manifest: toml::Value = toml::from_str(&manifest).expect("invalid Cargo manifest");
    let runner = "tests/suites/user/windows/main.rs";
    assert!(
        manifest["test"]
            .as_array()
            .expect("missing Cargo test registry")
            .iter()
            .any(|entry| {
                entry["name"].as_str() == Some("user_windows")
                    && entry["path"].as_str() == Some(runner)
            })
            && root.join(runner).is_file(),
        "Windows process runner must be an explicitly registered Cargo test target"
    );

    let mut missing = Vec::new();
    let ci = read_workflow(root.join(".github/workflows/ci.yml"))
        .expect("failed to read push CI workflow");
    let job = workflow_block(&ci, "  test-core:");
    let core = workflow_block(&job, "      - name: cargo test (core slice)");
    let run = workflow_block(&core, "        run: |");
    let mut lines = run.lines();
    let mut line = lines
        .find(|line| line.trim_start().starts_with("cargo test "))
        .expect("push CI core slice must execute cargo test")
        .split('#')
        .next()
        .unwrap();
    let mut command = line.to_owned();
    while line.trim_end().ends_with('\\') {
        line = lines
            .next()
            .expect("unterminated core cargo command")
            .split('#')
            .next()
            .unwrap();
        command.push('\n');
        command.push_str(line);
    }
    for target in ["user_linux", "user_windows"] {
        if !selects_test_target(&command, target) {
            missing.push(format!("ci.yml core command must select --test {target}"));
        }
    }

    let full = read_workflow(root.join(".github/workflows/full-suite.yml"))
        .expect("failed to read full-suite workflow");
    let job = workflow_block(&full, "  full:");
    let matrix = workflow_block(&job, "      matrix:");
    let shards = workflow_block(&matrix, "        shard:");
    let unit = shards
        .lines()
        .find(|line| line.trim_start().starts_with("- { name: unit,"))
        .expect("full-suite workflow is missing its unit shard");
    let tests = unit
        .split_once("tests: \"")
        .and_then(|(_, value)| value.split_once('"'))
        .expect("unit shard must declare its test selection")
        .0;
    for target in ["user_linux", "user_windows"] {
        if !selects_test_target(tests, target) {
            missing.push(format!(
                "full-suite.yml unit shard must select --test {target}"
            ));
        }
    }
    let step = workflow_block(&job, "      - name: cargo test (${{ matrix.shard.name }})");
    let run = workflow_block(&step, "        run: |");
    assert!(
        run.lines().any(|line| {
            line.trim() == "cargo test $profile_flag ${{ matrix.platform.features }} ${{ matrix.shard.tests }} -- ${{ matrix.shard.harness }}"
        }),
        "full-suite cargo command must consume the unit shard's test selection"
    );
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[test]
fn workflow_test_selection_excludes_comments_harness_arguments_and_name_prefixes() {
    assert!(selects_test_target(
        "cargo test --test user_windows -- --nocapture",
        "user_windows"
    ));
    for command in [
        "cargo test --test user_linux # --test user_windows",
        "cargo test --test user_linux -- --test user_windows",
        "cargo test --test user_windows_extra",
        "cargo test --no-run --test user_windows",
    ] {
        assert!(
            !selects_test_target(command, "user_windows"),
            "false reachability: {command}"
        );
    }
    let contents = "  selected:\n    run: |\n      cargo test --test user_linux\n  unrelated:\n    run: |\n      cargo test --test user_windows\n";
    let selected = workflow_block(contents, "  selected:");
    assert!(!selects_test_target(&selected, "user_windows"));
}

#[test]
fn scheduled_differential_separates_oracles_diagnostics_and_assembler_capabilities() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/differential.yml");
    let contents = read_workflow(&workflow)
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
    let contents = read_workflow(&workflow)
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
    let contents = read_workflow(&workflow)
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
    let contents = read_workflow(&workflow)
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
fn push_ci_runs_darwin_fixtures_against_a_required_native_oracle() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ci = read_workflow(root.join(".github/workflows/ci.yml"))
        .expect("failed to read push CI workflow");
    let job = workflow_block(&ci, "  test-user-darwin:");
    // The suite's native runs are an oracle only on the macOS release the
    // personality reproduces (tests/suites/user/darwin/support.rs).
    assert!(
        job.lines().any(|line| line.trim() == "runs-on: xcode-27"),
        "user_darwin must run on the macOS 27 image"
    );
    let step = workflow_block(
        &job,
        "      - name: cargo test (user_darwin, native oracle required)",
    );
    assert!(
        step.lines()
            .any(|line| line.trim() == "RAX_USER_DARWIN_REQUIRE_ORACLE: \"1\""),
        "a skipped Darwin comparison must fail the lane"
    );
    let run = workflow_block(&step, "        run: |");
    assert!(
        selects_test_target(&run, "user_darwin"),
        "the Darwin lane must select --test user_darwin"
    );
    let gate = workflow_block(&ci, "  ci-success:");
    let needs = gate
        .lines()
        .find_map(|line| line.trim().strip_prefix("needs: ["))
        .and_then(|line| line.strip_suffix(']'))
        .expect("the aggregate gate must list its needs");
    assert!(
        needs.split(',').any(|job| job.trim() == "test-user-darwin"),
        "the aggregate gate must require the Darwin lane"
    );
}

#[test]
fn scheduled_full_suite_runs_every_host_specific_jit_regression_binary() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/full-suite.yml");
    let contents = read_workflow(&workflow)
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
    let contents = read_workflow(&workflow)
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

#[test]
fn ebpf_validation_runs_every_oracle_and_partitions_the_formal_tier() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workflow = root.join(".github/workflows/ebpf-validation.yml");
    let contents = read_workflow(&workflow)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow.display()));

    for command in [
        "python3 tools/ebpf-conformance/run.py conformance",
        "python3 tools/ebpf-reference/run.py",
        "python3 tools/ebpf-conformance/run.py kernel-le",
        "python3 tools/ebpf-conformance/run.py kernel-be",
        "python3 tools/ebpf-conformance/run.py admission-be",
        "python3 tools/ebpf-formal/run.py --jobs ${{ matrix.shard.jobs }} ${{ matrix.shard.harnesses }}",
    ] {
        assert!(
            contents.contains(command),
            "eBPF validation workflow must run `{command}`"
        );
    }

    // Every harness of run.py's default families must belong to exactly one
    // formal shard, and no shard may select a harness outside them.
    let formal = root.join("tools/ebpf-formal");
    let families = default_kani_families(&formal.join("run.py"));
    let mut harnesses = Vec::new();
    collect_kani_harnesses(&formal.join("src"), &formal.join("src"), &mut harnesses);
    let shards = formal_shard_filters(&workflow_block(&contents, "  formal:"));
    assert!(
        !families.is_empty() && !harnesses.is_empty() && !shards.is_empty(),
        "eBPF validation contract found no Kani families, harnesses, or shards"
    );

    let mut violations = Vec::new();
    for (shard, filters) in &shards {
        for filter in filters {
            // The filter selects the same harnesses whether Kani matches it as
            // a prefix or as a substring of the qualified name.
            let by_prefix = harnesses
                .iter()
                .filter(|harness| harness.starts_with(filter.as_str()))
                .count();
            let by_substring = harnesses
                .iter()
                .filter(|harness| harness.contains(filter.as_str()))
                .count();
            if by_prefix == 0 || by_prefix != by_substring {
                violations.push(format!(
                    "shard {shard}: --harness {filter} selects {by_prefix} harnesses by prefix and {by_substring} by substring"
                ));
            }
        }
    }

    let mut selected = 0;
    for harness in &harnesses {
        let in_default_family = families
            .iter()
            .any(|family| harness.starts_with(family.as_str()));
        let owners = shards
            .iter()
            .filter(|(_, filters)| {
                filters
                    .iter()
                    .any(|filter| harness.starts_with(filter.as_str()))
            })
            .count();
        match (in_default_family, owners) {
            (true, 1) => selected += 1,
            (false, 0) => {}
            _ => violations.push(format!(
                "{harness}: default family {in_default_family}, selected by {owners} shards"
            )),
        }
    }

    assert!(
        violations.is_empty(),
        "eBPF validation formal shards must partition the default Kani families:\n{}",
        violations.join("\n")
    );
    assert!(
        selected > 0,
        "eBPF validation formal shards select no harness"
    );
}

/// The quoted entries of `DEFAULT_FAMILIES = [...]` in `tools/ebpf-formal/run.py`.
fn default_kani_families(run_py: &Path) -> Vec<String> {
    let contents = fs::read_to_string(run_py)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", run_py.display()));
    contents
        .lines()
        .skip_while(|line| *line != "DEFAULT_FAMILIES = [")
        .skip(1)
        .take_while(|line| line.trim() != "]")
        .map(|line| {
            line.trim()
                .trim_end_matches(',')
                .trim_matches('"')
                .to_string()
        })
        .collect()
}

/// Every `#[kani::proof]` harness under `dir`, named by its crate-relative
/// path as Kani's `--harness` filter matches it.
fn collect_kani_harnesses(src: &Path, dir: &Path, harnesses: &mut Vec<String>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()));

    for entry in entries {
        let path = entry
            .unwrap_or_else(|err| panic!("failed to read entry in {}: {err}", dir.display()))
            .path();
        if path.is_dir() {
            collect_kani_harnesses(src, &path, harnesses);
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }

        let relative = path.strip_prefix(src).unwrap_or(&path).with_extension("");
        let mut module = relative
            .iter()
            .map(|component| component.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        if matches!(module.last().map(String::as_str), Some("mod" | "lib")) {
            module.pop();
        }

        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let mut in_proof = false;
        for line in contents.lines().map(str::trim) {
            if line == "#[kani::proof]" {
                in_proof = true;
            } else if in_proof {
                if let Some(signature) = line.strip_prefix("fn ") {
                    let name = signature.split('(').next().unwrap_or(signature);
                    let mut qualified = module.clone();
                    qualified.push(name.to_string());
                    harnesses.push(qualified.join("::"));
                    in_proof = false;
                }
            }
        }
    }
}

/// Each `formal` matrix shard's name and `--harness` filters.
fn formal_shard_filters(block: &str) -> Vec<(String, Vec<String>)> {
    block
        .lines()
        .filter(|line| line.contains("harnesses:"))
        .map(|line| {
            let name = line
                .split("name:")
                .nth(1)
                .and_then(|rest| rest.split(',').next())
                .unwrap_or("")
                .trim()
                .to_string();
            let tokens = line
                .split_whitespace()
                .map(|token| token.trim_matches(|ch| ch == '"' || ch == '}' || ch == ','))
                .collect::<Vec<_>>();
            let filters = tokens
                .windows(2)
                .filter(|pair| pair[0] == "--harness")
                .map(|pair| pair[1].to_string())
                .collect();
            (name, filters)
        })
        .collect()
}

// This contract accepts the workflows' current indentation and simple shell
// continuations; unfamiliar layouts fail closed instead of matching other jobs.
fn workflow_block(contents: &str, marker: &str) -> String {
    let indent = marker.len() - marker.trim_start().len();
    let prefix = " ".repeat(indent + 1);
    let mut lines = contents.lines();
    lines
        .find(|line| *line == marker)
        .unwrap_or_else(|| panic!("missing workflow block: {marker}"));
    lines
        .take_while(|line| line.trim().is_empty() || line.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("\n")
}

fn selects_test_target(command: &str, target: &str) -> bool {
    let args = command
        .lines()
        .flat_map(|line| line.split('#').next().unwrap().split_whitespace())
        .take_while(|arg| *arg != "--")
        .collect::<Vec<_>>();
    !args.contains(&"--no-run") && args.windows(2).any(|args| args == ["--test", target])
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

// Workflows are text inputs on native Windows checkouts as well as Unix hosts.
fn read_workflow(path: impl AsRef<Path>) -> std::io::Result<String> {
    fs::read_to_string(path).map(|source| normalize_workflow_text(&source))
}

fn normalize_workflow_text(source: &str) -> String {
    source.replace("\r\n", "\n")
}

#[test]
fn workflow_policy_markers_and_test_selection_accept_crlf() {
    let source = "  selected:\r\n    run: |\r\n      cargo test --test user_linux -- --nocapture\r\n  unrelated:\r\n    run: |\r\n      cargo test --test user_windows\r\n";
    let workflow = normalize_workflow_text(source);
    assert!(
        workflow.contains("  selected:\n"),
        "line-bound policy markers must accept a native Windows checkout"
    );
    let selected = workflow_block(&workflow, "  selected:");
    assert!(selects_test_target(&selected, "user_linux"));
    assert!(!selects_test_target(&selected, "user_windows"));
}
