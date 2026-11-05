# Preserve native ARM64 decoding across CHPE ABI tags

The initial ARM64X loader change enabled a metadata guard for every guest
architecture. Actual installed ARM64 `cmd.exe /d /c type NUL` exposed a
regression: native execution exited 0, while the emulator stopped after at most
512 guest instructions at NTDLL RVA 0x1BD6E0. The code map tags that range
ARM64EC, but its instructions are ARM64 instructions. An ABI tag does not
instruct native ARM64 hardware to switch its decoder.

The correction limits the metadata transition check to AMD64 compatibility
execution. Native ARM64 keeps ordinary instruction decoding and memory/page
permission checks. AMD64 execution still stops before decoding an ARM64 or
ARM64EC range until the separate mixed-ISA bridge is implemented. Other image,
namespace, export, calling-convention, permission and API contracts are unchanged.

`baseline-v1.json` binds the failing real-program observation to the published
b5c8a6ee source, exact native process identity, observer image and installed DLL
hash. `native-cmd-observer-v1.rs` is the unchanged observer source. Compile it
with the owning RAX library and define `RAX_PROBE_LIBRARY_SHA256` to that
library's SHA-256; its first output line records the binding. It first runs the
actual native command, then emulates the same installed executable and records
stdout, stderr, terminal state and an explicit instruction bound. Wrapper exit
0 means collection completed; it does not mean guest execution succeeded.

The scheduler regression places `MOVZ X0,#0xABCD` in an ARM64EC-tagged range of
an ARM64 process. One scheduling turn must execute that ARM64 instruction and
advance PC by 4 bytes. The published guard was observed to fail this test before
instruction decoding with the same false transition diagnostic. The corrected
predicate preserves native execution while retaining negative AMD64 cases.

The unchanged observer now records native exit 0 and guest
`Complete(Exited(0))`, with empty stdout/stderr and no observed active exception.
The guest instruction upper bound is 14,688,896 instructions. The count is a
slice-based upper bound, not a retired-instruction measurement. The selected
library SHA-256 is
`adcdfa435ca50310bf71b29b9fc1664a1d5caeca6acbb4a39483174caf1affe4`.
Both observations use the same installed NTDLL SHA-256 recorded in the baseline.

The retained observer can be compiled on Windows with the same Rust toolchain
and dependency directory as the owning RAX library:

```powershell
$env:RAX_PROBE_LIBRARY_SHA256 = (Get-FileHash $raxLibrary -Algorithm SHA256).Hash.ToLowerInvariant()
rustc +1.95.0 --edition=2024 .\docs\specifications\windows\native-arm64-hybrid-guard\native-cmd-observer-v1.rs --extern "rax=$raxLibrary" "-Ldependency=$dependencyDirectory" -C opt-level=2 -C debuginfo=0 -o .\target\native-cmd-observer.exe
.\target\native-cmd-observer.exe C:\Windows\System32\cmd.exe 1073741824 7 /d /c type NUL
```

`$raxLibrary` is the compiled `.rlib` and `$dependencyDirectory` is its matching
Cargo dependency directory; set both to paths inside this worktree. The
observer's final `TERMINAL` line must contain `Complete(Exited(0))`, and all
four native/guest stream fields must be empty. Its wrapper exit code alone is
insufficient.

Qualification covers complete affected module selections on macOS, Linux,
native Windows ARM64 and translated Windows x64, plus this actual installed CMD
comparison. Source and image hashes and final results are retained in
`qualification-v1.json`. The Assist pin must use the corrected source and its
actual archive consumers.

```text
Owning runtime                 Passed   Initial failures   Ignored
macOS ARM64                      160                  0         0
Linux amd64 translation          160                  0         0
Windows ARM64                    165                  0         0
Windows x64 translation          164                  1         0
Exact failed x64 case retry        1                  0         0
```

All 650 distinct selected cases have a passing result. The original x64 full
run remains recorded as 164 passes and one failure: live registry capture
rejected a changed shared physical `Local Settings` key before constructing the
guest. The exact failed case then passed with the identical executable, source
and installed DLL hashes. The writer is unknown. No capture-consistency guard
or test assertion was changed. This is a recorded transient capture failure,
not a claim that the original x64 full run passed without failures. All four
normal Clippy configurations pass with zero diagnostics in the changed files;
Windows retains the existing vendored `vm-memory` calling-convention warning.

Assumption A1 is that an ARM64EC ABI tag does not change ARM64 instruction
decoding in a native ARM64 process. The scheduler and real-program failures
under the original predicate, followed by successful execution under the
correction, confirm this for the tested instructions and installed build.
The falsification probe is the complete loader module selection, retaining
negative AMD64/ARM64EC, AMD64/ARM64 and unclassified-gap cases, followed by the
source-bound installed CMD comparison. The metadata check is O(M + log C) for
AMD64 execution with M modules and C code ranges, and O(1) for other
architectures; it allocates no successful-path state.

The full same-host Linux/macOS/Windows process objective remains incomplete.
ARM64EC context/register transitions, helper bindings, mixed-ISA execution and
unwinding, image extensions and non-KnownDLL projections remain required.
