# Independent AMD64 NLS initialization observations

The unchanged AMD64 hardware-fault startup fixture now reaches
`NtInitializeNlsFiles` and stops at its unmeasured native build profile. The
terminal evidence is CI run40563270795 on native Windows10.0.20348. Its original
source, PE binaries, Rust test, assertions and execution budgets remain fixed.

This observation step reuses the frozen three-argument x86/four-argument
native64 initialization and protection producers from the29695 qualification.
It runs79 initialization cases and12 protection/free cases for each of native
x64, x86 and x86-LAA on independent AMD64 kernels20348 and26100. Those are
process views of two kernels, rather than six independent kernels. The complete
raw stdout is retained without status or address substitution. Source, compiler,
executed PE, Python, installed NTDLL and locale.nls identities must remain stable.
The original x86 caller declaration consumes three arguments and preserves the
strict callee stack contract. No existing producer or test is changed.

`run-v1.py` runs only in the existing Windows observation matrix. Every build
and temporary output remains under this worktree's target directory and is
removed after the producer terminates. The versioned JSON report remains as
the artifact. macOS/Linux cannot provide this native observation and return an
explicit unsupported-host error; no shipping runtime behavior changes here.
Work is O(C + V) for C fixed cases and V enumerated virtual-memory regions;
the frozen producer bounds each enumeration to65536 regions and256 locale
views. Retained raw observations use O(O) space for O output bytes.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NA1 | Native AMD64 initialization may retain the measured output/probe/copy rules. | The original fixture reaches this service; other kernels are not evidence for its semantics. | Any future initialization profile extension. | Null, bad, unaligned, readonly, guarded and aliased outputs; retained views; protect/free. | Compare every native status, guard transition, output byte, view delta and lifetime against the existing model. | Retained pending native results; no runtime admission yet. |
| NA2 | Initialization and MUI require independent admission. | The current startup-profile predicate controls both services. | Scope of a future runtime fix. | Initialization agrees while MUI differs. | Trace every predicate consumer and keep unmeasured MUI unavailable. | Confirmed by current source consumers. |

High impact: full original startup still stops at unmeasured NLS initialization.
The observations alone do not qualify runtime behavior or MUI. Public/private
ABIs, package layout, dependencies and feature defaults are unaffected. No new
CI job is added. Retained failed compiler/native reports remain evidence;
corrective producers receive a new version.
