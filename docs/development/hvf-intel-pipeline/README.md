# Retained native Intel build and execution evidence

The [manual Intel workflow](../../../.github/workflows/native-intel-hvf-mmio.yml)
builds and signs the real consumer, uploads that result, and then verifies and
executes the retained binary on the same `macos-15-intel` runner. A guest failure
cannot erase the already uploaded build report. This retains separate build and
execution phases without allocating a second runner.

```text
exact source -> prepare -> signed binary + build report -> uploaded artifact
                             |
                    source/signature admission
                             |
                  guest -> execution observations
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

The execution phase consumes the same prepared directory already uploaded by
the build phase. Before guest entry, admission requires exact scoped engine input,
consumer, driver, support-module and executable SHA-256 values, a completed
successful compilation report, strict code-signature verification, and an
untranslated Intel host with usable Hypervisor.framework. The engine input map
covers `src/**/*.rs`, Rust/TOML files under `vendor/vm-memory`, `Cargo.toml`,
`Cargo.lock`, and `.cargo/config.toml`. The expected observation count must be
positive and exact, with ordered integer case identifiers and Boolean passes.
An empty, partial or reordered report cannot qualify execution.

The artifact is trusted as output from the same workflow job. Its checksums
establish consistency; they do not authenticate an arbitrary externally supplied
binary and manifest. The driver also retains support for downloaded artifacts,
restoring the owner execute bit before signature verification when necessary.

The earlier two-job run 41992554080 successfully retained its build and then
spent over 20 minutes awaiting its second runner. It passed 118 native guest
cases before rejecting the first private PAT checkpoint because the SDK changed
control-register masks after the producer policy had been captured. The
[frontier evidence](../hvf-intel-frontier/README.md) distinguishes this partial
native result from a completed 130-case run. Reusing the allocated runner avoids
that second queue while preserving pre-execution artifact retention and all
admission checks. A build or upload failure prevents guest entry; execution
observations upload only when the guest phase was attempted.

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
| A1 | Prepared input comes from the earlier build phase in this job | Binary/source attribution | Upload precedes guest entry; altered source, tooling, binary or unsuccessful report must reject | Retained trust boundary; admission partitions tested |
| A2 | A signed build can be retained before native execution | Build preservation | Export the real signed executable, upload it, admit it and verify its signature | Confirmed in historical two-job runs, including 41992554080; updated one-job workflow execution pending |
| A3 | A supported Intel host is required before guest entry | Native execution claim | Attempt execution on Apple Silicon; require availability failure and no guest command | Confirmed negative control |

High-impact unresolved scope: the original timeout's internal cause remains
unknown; the latest native run passes 118 cases and then fails private capture.
Neither the workflow restructuring nor local
model tests close the broader HVF, checkpoint, SMP or A32-FP audit findings.
Admission work is linear in the inspected source and executable bytes; retained
input-map space is proportional to the number of scoped source files.
