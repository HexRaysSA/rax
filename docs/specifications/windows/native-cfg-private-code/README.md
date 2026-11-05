# Native private-code CFG lifecycle controls

This directory retains independent Windows API and private-call observations
needed to implement guest CFG state. The observers do not link RAX. Every
allocation and call target belongs to the observer process. They do not modify
other processes, installed DLLs or host mitigation settings.

`controls-arm64-29698-v1.json` binds exact observer source, executable, DLL and
stdout hashes to Windows ARM64 kernel `10.0.29698`. Its x64 process view uses
Windows translation; it is not a physical AMD64 result.

| Native process view | API observations | Private-call controls |
| --- | ---: | ---: |
| Translated x64 | 196 | 21 |
| ARM64 | 196 | 21 |

The API set contains 88 allocation, 66 protection, 24 Win32 target-update and
18 NT target-update observations. API results and private-call results are
different evidence: a successful update does not alone prove target admission.
Each call control runs in a fresh child. Successful children return `0x1234`
and release their reservation. Denied children reach the `CALL` marker before
their recorded `0xC0000409` exit; the operating system reclaims the process's
private allocations. Parent exit zero alone does not qualify any child.

Both recorded process views agree on all 21 call outcomes. Default private
executable allocation admits the leaf, including instruction-aligned targets
within a 16-byte slot. Explicit registration admits the aligned target without
admitting other offsets in the slot. Invalid targets remain invalid across the
recorded protection, recommit and decommit operations. Release followed by
fresh allocation restores default admission. In this kernel profile, an
ordinary change back to executable protection does not restore an invalid
target. This differs from the general documented default; other kernels must
be measured before generalizing it.

The NT target-update controls require a 40-byte information record for these
64-bit process views, publish a separate processed count, and leave the target
record's input flags unchanged. The Win32 wrapper publishes the processed bit
in each target record. The measured kernel accepts target updates on writable,
non-executable private memory; target validity and execute permission remain
separate state.

The call observer uses the documented WindowsApp import library for
`SetProcessValidCallTargets`. An earlier ARM64 observer called that API through
a dynamically resolved pointer and some children terminated before their
private `CALL` marker. Those exits are excluded. The cause of those earlier
terminations is unknown; they do not establish private target admission.
Compiler CFG instrumentation remains enabled at the private call site.

## Reproduction and capture

From the repository root, on Windows, macOS or Linux:

```text
python -B tools/ci/windows_cfg_private_code.py --verify-retained
python -B -m unittest discover -s tools/ci -p test_windows_cfg_private_code.py -v
```

Expected retained dimensions are four reports, 392 API observations and
42 private-call controls. The tests reject source drift, disabled CFG,
duplicate or missing observations, early child exits, wrong leaf returns,
unrelated exception statuses and missing release/completion markers.

To capture on native Windows AMD64 or ARM64 with Rust 1.95.0 and the matching
MSVC/Windows SDK linker libraries installed:

```text
python -B tools/ci/windows_cfg_private_code.py --output target/native-cfg-private-code-v1
```

The output directory must not exist and must resolve inside this checkout.
The collector compiles both observers with `-C control-flow-guard=yes` and
`/guard:cf`, verifies PE CFG metadata and native machine, and requires the
runtime CFG policy bit in every qualified call. Source and system-DLL hashes
are checked before and after execution. Process records preserve each original
PID and terminal result; there are no timeout restarts. Build and compiler
temporary directories remain inside the output directory and are removed
after successful capture. Raw stdout, stderr, compiler logs, process records
and `observations.json` remain as evidence.

The existing Windows 2022/2025 workflow captures independent AMD64 profiles and
uploads the observations even when a step fails. Its Cargo cache excludes the
corpus directory. Adding this wiring does not establish a successful CI result;
the resulting native artifacts must be inspected separately.

## Primary contracts and scope

- [Microsoft memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
  distinguish allocation-time `PAGE_TARGETS_INVALID` and protection-time
  `PAGE_TARGETS_NO_UPDATE`, both `0x40000000`.
- [Microsoft SetProcessValidCallTargets](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessvalidcalltargets)
  defines the public target-update API, offset alignment and import library.
- [Microsoft PE CFG metadata](https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata)
  defines image target tables and the check/dispatch pointer contracts.

| ID | Assumption / dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| CFG1 | The retained outcomes describe kernel 29698 and the recorded DLL/source identities. | Run the same immutable observers on independent AMD64 and other ARM64 kernels; disagreement prevents reuse of this profile. | Confirmed only for the retained process views. |
| CFG2 | Only children reaching their private-call marker can qualify admission. | Remove that marker, alter CFG policy or substitute another terminal status; validation must fail. | Confirmed by rejection tests. |
| CFG3 | Canonical producer identity normalizes LF/CRLF checkout conversion; exact raw compiler inputs are recorded separately. | Validate CRLF source with the same canonical hash, while preserving raw capture hashes; any non-newline change must fail. | Confirmed by the source-drift test. |

| Impact | Remaining requirement | Blocks this collection? |
| --- | --- | --- |
| High | Guest CFG target-state, image metadata, dynamic registration and call enforcement still require implementation. | No; this group records their native contract and does not accept previously rejected guest flags. |
| High | Other kernels, WoW64 CFG, mixed unwind/asynchronous dispatch and the pending general-registry permission/API choice remain open. | No; full process emulation remains incomplete. |
| Medium | The native collectors intentionally terminate denied-call children and run only on Windows. | No; macOS/Linux share the provenance validator and its tests, without a native-success stub. |
