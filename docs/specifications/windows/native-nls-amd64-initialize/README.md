# Independent AMD64 NLS initialization observations

Before qualification, the unchanged AMD64 hardware-fault startup fixture reached
`NtInitializeNlsFiles` and stopped at its unmeasured native build profile in
CI run 40563270795 on native Windows 10.0.20348. Original source, PE binaries,
Rust test, assertions and execution budgets remain fixed. The resulting finite
runtime admission and qualification are recorded in [model.md](model.md).

The observation reuses the frozen three-argument x86 and four-argument native
64-bit initialization and protection producers from the 29695 qualification.
It runs 79 initialization cases and 12 protection/free cases for each native
x64, x86 and x86-LAA view on independent AMD64 kernels 20348 and 26100. These
are process views of two kernels. Complete raw stdout is retained without
status or address substitution. Source, compiler, executed PE, Python,
installed NTDLL and locale.nls identities must remain stable. The original
x86 caller declaration consumes three arguments and preserves the strict
callee stack contract. No existing producer or original test is changed.

`run-v1.py` runs in the existing Windows observation matrix. Every build and
temporary output remains under this worktree's target directory and is removed
after producer termination. The versioned JSON report remains as the artifact.
macOS and Linux return an explicit unsupported-host error for this native
observation; shared runtime behavior is separately qualified in model.md.
Work is O(C + V) for C fixed cases and V enumerated virtual-memory regions;
the frozen producer bounds each enumeration to 65536 regions and 256 locale
views. Retained raw observations use O(N) space for N output bytes.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NA1 | Native AMD64 initialization retains the measured output, probe and copy rules. | Complete independent native records and replay. | Finite initialization admission. | Null, invalid, unaligned, readonly, guarded and aliased outputs; retained views; protect/free. | Compare every native status, guard transition, output byte, view delta and lifetime with the model. | Confirmed; model.md records runtime qualification. |
| NA2 | Initialization and MUI require independent admission. | Predicate consumer audit and unavailable-MUI regression tests. | Preserved MUI availability. | Initialization agrees while MUI remains unmeasured. | Separate all predicate consumers and keep unmeasured MUI unavailable. | Confirmed by implementation and runtime tests. |

High impact: the complete original AMD64 startup test now stops in x86 WoW64
CSR startup. NLS observations do not establish MUI or complete process runtime
support. Public and private ABIs, package layout, dependencies and feature
defaults remain unchanged. No new CI job is added. Failed compiler and native
reports remain evidence; corrective producers receive a new version.
