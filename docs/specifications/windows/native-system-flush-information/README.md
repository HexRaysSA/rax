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
| SF1 | The selected query has a 32-byte pointer-free record. | PHNT declaration and 1056 native build-29695 calls across ARM64, x64 compatibility and WoW64. | Fixed-width observer window and eventual snapshot design. | AMD64 and WoW64 calls; short, large, aliased and guarded buffers. | Capture the full native matrix on builds 20348 and 26100 and reject a different successful extent. | Confirmed for measured 29695 views; retained for AMD64 kernels. |

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

The executed v1 driver is retained unchanged. V2 allows an aliased ReturnLength
word to contain copied record data, rather than treating that final word as an
independent report of record extent. It preserves the producer, all input cases
and the raw bytes. Portable verification accepts either recorded driver version.
