# Retained native Intel build and execution evidence

The [manual Intel workflow](../../../.github/workflows/native-intel-hvf-mmio.yml)
builds and signs the real consumer in one job, uploads that result, and executes
the retained binary in a second Intel job. A guest failure cannot erase the
already uploaded build report. Both jobs use `macos-15-intel`.

```text
exact source -> prepare -> signed binary + build report -> artifact
exact source -> execute <- verified artifact -> guest observations
```

The preceding [run 41968179867](https://github.com/HexRaysSA/rax/actions/runs/41968179867)
was cancelled with the annotation "The job has exceeded the maximum execution
time of 45m0s". No artifacts or usable logs were retrievable. Whether that run
entered a guest is unknown; the timeout does not identify a compiler, backend,
or platform failure. This change preserves that unresolved result.

The new build uses the same `x86_64-suite,smir-jit,hvf,debug` feature set with
debug assertions and overflow checks enabled. CI explicitly selects optimization
level 0; the legacy command's default remains level 1. Compilation has a 1800 s
deadline. Native execution has a separate 600 s deadline. Each command writes
its phase, arguments, exit status and raw output incrementally; stderr also
streams to the workflow log. Timeouts terminate the invocation's own process
group, including compiler descendants. Pipe drainage shares that deadline.

The second job downloads the artifact produced by its prerequisite job in the
same workflow run. Before guest entry, admission requires exact engine input,
consumer, driver, support-module and executable SHA-256 values, a completed
successful compilation report, strict code-signature verification, and an
untranslated Intel host with usable Hypervisor.framework. The engine input map
covers `src/**/*.rs`, Rust/TOML files under `vendor/vm-memory`, `Cargo.toml`,
`Cargo.lock`, and `.cargo/config.toml`. The expected observation count must be
positive and exact, with ordered integer case identifiers and Boolean passes.
An empty, partial or reordered report cannot qualify execution.

The artifact is trusted as output from the same workflow run. Its checksums
establish consistency; they do not authenticate an arbitrary externally supplied
binary and manifest. Artifact download does not preserve executable permission,
so the driver restores the owner execute bit before signature verification.

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/hvf -p test_intel_mmio_prepared.py -v
python3 tools/hvf/intel_mmio_native_probe.py \
  --compile-only --export-guest --opt-level 0 --output /tmp/rax-intel-build-report
python3 tools/hvf/intel_mmio_native_probe.py \
  --execute-prepared /tmp/rax-intel-build-report --output /tmp/rax-intel-run-report
```

Use new report directories. `--export-guest` requires `--compile-only`.
`--execute-prepared` and `--compile-only` are mutually exclusive. The existing
single-command build-and-run interface remains supported. The driver removes
its temporary build directory; an explicitly exported signed executable remains
in the requested report directory for inspection and transport.

[Qualification](qualification.json) records 14 complete Python tests, all 15
tests in the declared `ci_actions_pinned` Cargo target, workflow validation, an
actual signed Intel cross-build/export, and rejection on Apple Silicon before
guest entry. These checks do not establish native Intel guest correctness. The
cross-build used the combined pending 130-case consumer; production source has
114 cases until the separately pinned audit candidate is applied.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | Prepared input comes from this workflow's prerequisite job | Binary/source attribution | Job output selects the same-run artifact; altered source, tooling, binary or unsuccessful report must reject | Retained trust boundary; admission partitions tested |
| A2 | A signed cross-build can be transported before native execution | Split-job execution | Export the real signed executable, admit it, and verify its signature after copying | Confirmed locally; hosted transport remains unverified |
| A3 | A supported Intel host is required before guest entry | Native execution claim | Attempt execution on Apple Silicon; require availability failure and no guest command | Confirmed negative control |

High-impact unresolved scope: the previous timeout's internal cause and native
guest outcomes remain unknown. Neither the workflow restructuring nor local
model tests close the broader HVF, checkpoint, SMP or A32-FP audit findings.
Admission work is linear in the inspected source and executable bytes; retained
input-map space is proportional to the number of scoped source files.
