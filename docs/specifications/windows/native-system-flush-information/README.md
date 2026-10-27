# Native system-flush information

`NtQuerySystemInformation` class 192 (`SystemFlushInformation`) is a startup
dependency of the selected native AMD64 build-20348 NTDLL. The unchanged
hardware-fault fixture stops at this unimplemented query before exception
delivery in CI run 40457693076. Its original source, binaries, assertions and
execution budgets remain unchanged.

The primary PHNT `ntexapi.h` declaration describes a pointer-free record:

| Offset (bytes) | Field | Width (bytes) |
| ---: | --- | ---: |
| 0 | `SupportedFlushMethods` | 4 |
| 4 | `ProcessorCacheFlushSize` | 4 |
| 8 | `SystemFlushCapabilities` | 8 |
| 16 | `Reserved[2]` | 16 |

The total is 4 + 4 + 8 + 16 = 32 bytes. The native control independently
checks the compiler's record size. It queries metadata; it does not issue a
cache, volume or persistent-memory flush. The selected source declaration is
[PHNT ntexapi.h at 53fbbdc5](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntexapi.h),
whose Git blob identity is recorded in `references.json`.

`run-v2.py` builds and executes native and compatibility controls on the
current Windows kernel. Its matrix covers short, exact, larger and maximum
lengths, output and ReturnLength faults, guards, mixed failures and four alias
positions. A second output poison distinguishes defined output from untouched
bytes. The optional WoW64 native-information export is observed separately.
Raw stdout, compiler/executable/source identities and selected NTDLL file
identities are retained. Source and executable bytes are checked after execution.
The driver records the actual compiler-input hash and its LF-normalized hash
separately; it preserves raw stdout bytes before parsing rows.

Build intermediates and temporary directories stay below the current repository's
`target` directory and are removed after their producer exits. The retained JSON
is a diagnostic artifact, not proof that a guest implementation exists.

Run on Windows from the repository root:

```text
python docs/specifications/windows/native-system-flush-information/run-v2.py
```

`--environment` accepts the existing private compiler-environment snapshot;
its contents are not printed. `--output` must name a new file below `target`.
`verify.py` checks each capture's raw stdout, projected rows, original executable
bytes, PE machine and compiler-input newline identity independently of the query
implementation.
Portable projection checks use `python -m unittest discover -s
docs/specifications/windows/native-system-flush-information`.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SF1 | The selected query has a 32-byte pointer-free record. | PHNT declaration and 2640 native calls on ARM64 build 29695 and AMD64 builds 20348/26100, including compatibility views. | Fixed-width observer window and snapshot design. | AMD64 and WoW64 calls; short, large, aliased and guarded buffers. | Replay the full matrices and reject a different successful extent. | Confirmed for all three measured kernels. |

The local 29695 control passes 264 ARM64, 264 x64-compatibility and 528 x86
queries. Ordinary queries return the same 32-byte record in all three views:
methods 0, cache-flush size 64 bytes, capabilities 0 and zero reserved words.
The separate WoW64 native-information API rejects class 192 without visiting
the destinations. These are observations of one ARM64 kernel; they do not
qualify the corresponding behavior on a native AMD64 kernel.

High impact: the guest query and AMD64 full-fixture qualification remain
unfinished. Persistent-memory flush semantics are a separate behavior from this
metadata query. This observation group changes no public C API, ABI version,
permission grant, dependency pin or package layout.

## Process-owned query implementation under validation

Native acquisition now captures class 192 into a process-owned 32-byte value.
It uses only a fixed native buffer and fixed class/length arguments. Two
differently poisoned captures must agree; three attempts bound acquisition.
Admission binds the immutable selected kernel version and native machine:
AMD64 builds 20348/26100 and ARM64 build 29695. Guest version fields cannot
select a different snapshot. Unavailable or unmeasured metadata is explicit.

Native64 keeps the common full-span output and ReturnLength probes before
minimum-size validation. WoW64 uses its observed private-result/copy path:
short lengths do not visit a nonnull output; destinations need no ULONG
alignment; the record is copied before ReturnLength; readonly guards are not
consumed by a rejected user-mode write. A null output with nonzero length
reports access violation and copies a zero length. The private workspace is
bounded by the configured emulation budget and x86 virtual-address ceiling;
oversized requests return no-memory without a host allocation proportional to
guest input. This is a guest resource bound, not reproduction of arbitrary
host memory-pressure conditions.

`replay.json` retains all 2640 scalar rows from the three kernel controls,
including full output windows and both guard transitions. No output value is
rebased. `project.py` regenerates it from the verified raw artifacts. The raw
captures retain the executed PE images; their artifact digests are separate
from the replay's capture identities. Both AMD64 observation jobs in run
40461812735 passed, including projection and raw-artifact verification.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SF2 | The selected native record is stable and fully defined during acquisition. | Three kernel captures and differently poisoned output buffers. | Fixed process-owned snapshot. | Missing, changed or partially written capture; guest version spoofing. | Differently poisoned host captures must agree in all 32 bytes; replay and installed-leaf checks. | Confirmed for the captured profiles and installed ARM64/WoW64 leaves. |

Final selected model gates pass three tests on macOS and Linux and four on
Windows ARM64, including exact replay of all 2640 queries. All 191 C API tests
pass on each host. The Windows gate executes the installed native ARM64 and
WoW64 query leaves and actual return sequences. The original hardware-fault
fixture separately passes on ARM64/WoW64 with unchanged source, binaries, Rust
test file, assertions and budgets. The portable gates precede a correction to
only the Windows-specific test-helper qualification path; shared model code
is identical. Linux uses the existing x86-64 container on the ARM64 host.

The original AMD64 fault-fixture implementation gate remains pending. Passing
the independent native AMD64 query controls does not establish completion of
installed-library process startup, linked Assist packages or the full
Linux/macOS/Windows process-userland objective.

The executed v1 driver is retained unchanged. V2 allows an aliased ReturnLength
word to contain copied record data, rather than treating that final word as an
independent report of record extent. It preserves the producer, all input cases
and the raw bytes. Portable verification accepts either recorded driver version.
