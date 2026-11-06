# NT CFG target-record capture

`NtSetInformationVirtualMemory` class2 is the kernel boundary used by installed
Windows libraries to register call targets. This directory captures its caller
record layout, validation results, and buffer publication independently of RAX.
It supplies evidence for the general guest syscall handler; it does not provide
that handler or establish full Windows process support.

The observer uses only its current process, task-owned child processes and
task-owned virtual allocations. Each of 102 cases runs in a separate child.
The parent retains the child's NT result, four 64-byte before/after buffer
snapshots, terminal exit code, and allocation-release marker. An exception in a
conversion thunk is distinguished from an NT return. No guest pointer is passed
to a host kernel by RAX as part of this capture.

## Layout and observed scope

The NT list layout follows the primary [phnt memory-manager declarations](https://github.com/winsiderss/phnt/blob/master/ntmmapi.h).
The public API's target offsets and flags are documented by Microsoft in
[SetProcessValidCallTargets](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessvalidcalltargets).
Those declarations identify structures and interfaces; the retained execution
records establish the observed validation and publication behavior.

| Process view | Pointer bytes | List bytes | Cases | Kernel |
|---|---:|---:|---:|---|
| Native ARM64 | 8 | 40 | 102 | Windows 10.0.29698, ARM64 |
| Translated x64 | 8 | 40 | 102 | Same ARM64 kernel |
| x86 through WoW64 | 4 | 32 | 102 | Same ARM64 kernel |
| Native AMD64 | 8 | 40 | 102 | Windows 10.0.20348, AMD64 |
| x86 through WoW64 | 4 | 32 | 102 | Same 20348 AMD64 kernel |
| Native AMD64 | 8 | 40 | 102 | Windows 10.0.26100, AMD64 |
| x86 through WoW64 | 4 | 32 | 102 | Same 26100 AMD64 kernel |

The six list fields occupy 40 bytes on the 64-bit ABI: two 4-byte integers,
three 8-byte pointers, and one 8-byte file offset. On x86 the pointers occupy
4 bytes each; the 8-byte-aligned file offset introduces 4 padding bytes, giving
32 bytes in total. The observer writes fields separately into initialized
backing storage, including padding, and records `size_of` for each executable.

The retained corpus binds normalized and raw source hashes, executable hash,
PE machine/CFG metadata, selected DLL hashes, process identity and raw stdout.
The source was an uncommitted overlay on the recorded base commit during this
local capture. Its exact source hash identifies the compiled observer;
`source_commit: null` deliberately makes no claim that the observer existed in
the base commit. The collector records a real `GITHUB_SHA` for future CI runs.

Kernel identity is bound to the independent ARM64 private-code corpus through
the unchanged native DLL identities. The x86 report records the SysWOW64 DLL
view separately. The translated x64 report is explicitly identified and is not
native AMD64 evidence.

## Results that affect implementation

The ARM64 and translated x64 NT statuses agree across the retained cases.
Their 64-bit list-length and alignment rules do not describe WoW64 capture.
For example, the WoW64 thunk accepts the initialized unaligned range and list
records in this corpus and does not fault on several processed-output pointers
that the native 64-bit entry rejects. The compound cases distinguish conversion
before kernel entry from the kernel's own validation order.

The reserved-executable and decommitted-executable target controls return
success in all seven views. The released-reservation control returns
`0xC00000A0` with a zero processed count. Target registration depends on an
active private reservation and resident CFG bitmap storage, independently of
the target page's commitment or fetch permission. The guest VM primitive
preserves those distinctions; registration does not commit pages or grant
execute permission. The NT adapter also owns ABI-specific capture, process
handle access checks, policy validation and processed-count publication.

The 102-case corpus proves status and caller-buffer effects for these inputs.
A zero processed count does not, by itself, prove atomic bitmap mutation.
Successful registration does not prove subsequent indirect-call admission.
The separate mutation controls below establish admission only for their
specified private-code inputs. Image GFIDS registration, section-backed
requests, other export/XFG policy configurations and general guest indirect
dispatch still require their own execution evidence.
The six lifetime and twenty compound-fault cases extend the initial 76-case
development capture; the retained corpus uses the final identical 102-case
source for every process view.

## Focused capture and publication controls

`native-capture-shapes-v1.rs` and `capture-shapes-arm64-29698-v1.json` retain
13 further cases in each of the ARM64 kernel's three process views. They
distinguish two-byte from four-byte record alignment, `PROCESS_VM_OPERATION`
(`0x0008`) from `PROCESS_VM_WRITE` (`0x0020`), and guard visitation during
processed-output publication. The native 64-bit entry requires four-byte
alignment for the captured records. WoW64 converts the initialized unaligned
records in these controls. A native processed-output guard produces
`0x80000001` and consumes the guard. WoW64 retains its successful NT result;
the failed copyback consumes a writable guard but preserves a read-only guard.

`native-target-mutation-v1.rs` and `target-mutation-arm64-29698-v1.json` retain
ten fresh-child controls per process view. Each child reserves its own private
memory, commits one executable page with initially invalid CFG targets, and
calls only its constant-return leaf through an instrumented indirect call.
The valid control returns `0x1234`; the unregistered control terminates with
`0xC0000409`. This positive/negative pair establishes that the call site
actually enforces CFG in the captured process.

The mutation controls distinguish these publication boundaries:

| Input | NT result | Processed entries | First target admitted |
|---|---|---:|---|
| Second offset unaligned | `0xC000000D` | 0 | No |
| Second flags outside the accepted mask | `0xC000000D` | 0 | No |
| Second record requests export policy | `0xC0000022` | 0 | No |
| Second record requests XFG policy | `0xC00000BB` | 0 | No |
| Second target lacks resident bitmap storage | `0xC0000005` | 1 | Yes |
| Duplicate target, valid then invalid | `0x00000000` | 2 | No |
| Duplicate target, invalid then valid | `0x00000000` | 2 | Yes |

Thus structural and unsupported policy rejection precede target publication;
a later storage fault preserves an earlier target update. Duplicate records
apply in order. The storage control isolates two complete 256 KiB coverage
units inside one private reservation. It grants no access to the uncommitted
second target page.

These focused corpora bind their frozen source, build arguments, CFG-enabled
PE metadata, executable hash, native DLL identities, process creation identity
and complete stdout. They identify uncommitted observer overlays explicitly;
the recorded base commit is not claimed to contain those observers. The
focused mutation captures cover one ARM64 kernel, including translated x64;
they are not additional physical AMD64 kernel observations. The retained
datasets contain `7 * 102 + 3 * 13 + 3 * 10 = 783` observed NT calls.

## Reproduce and verify

From the repository root, verify the retained evidence on any host:

```text
python -B -m unittest discover -s tools/ci -p test_windows_cfg_target_records.py
python -B tools/ci/windows_cfg_target_records.py --verify docs/specifications/windows/native-cfg-target-records/controls-arm64-29698-v1.json
python -B tools/ci/windows_cfg_target_records.py --verify docs/specifications/windows/native-cfg-target-records/controls-amd64-20348-v1.json
python -B tools/ci/windows_cfg_target_records.py --verify docs/specifications/windows/native-cfg-target-records/controls-amd64-26100-v1.json
```

The guest service replay tests consume all three 102-case corpora and the two
focused corpora. They compare ABI return state, processed stores and private
target metadata; the capture-shape replay also compares guard protections.
Run the complete owning library test binary before claiming behavioral
validation:

```text
cargo test --locked --no-default-features --features x86_64-suite --lib
```

On native Windows AMD64 or ARM64, provide Rust 1.95.0 with its native target and
`i686-pc-windows-msvc`, the matching MSVC/SDK libraries, and Python. Then run:

```text
python -B tools/ci/windows_cfg_target_records.py
python -B tools/ci/windows_cfg_target_records.py --verify target/native-cfg-target-records-v1/observations.json
```

The collector requires a fresh output directory, compiles its native and x86
observers with CFG enabled, validates their PE metadata, checks source and DLL
identities before/after execution, and preserves complete stdout and process
receipts. It waits for the original child without timeout restarts. Terminal
build outputs are removed after qualification. Its private compiler inputs are
build dependencies; the observer does not supply an emulated runtime sysroot.

The Windows exception-profile workflow captures fresh AMD64 and WoW64 results
on Windows Server 2022 and 2025. Both trigger filters include the observer,
collector and parser tests; the output is kept outside the Rust-cache workspace
and uploaded even after a failed capture. The retained AMD64 corpora were
qualified from the successful capture/upload stages of
[workflow run 42132348483](https://github.com/HexRaysSA/rax/actions/runs/42132348483)
at `ef4ca203172f4df69aaa161cf8ea3e36356e514c`. Their four views add 408 NT
observations to the ARM64 corpus's 306. Capture success is distinct from the
workflow jobs' later Rust validation stages.

The parser's 19 rejection tests include LF and CRLF source fixtures plus explicit
rejection of doubled carriage returns. The first AMD64 CI attempt exposed a test
fixture that added CRLF to an already-CRLF checkout; that failed run is retained.
The fixture now constructs both newline forms from normalized LF bytes without
weakening the production source-identity check.

The subsequent native AMD64 run passed all 102 native-x64 cases per kernel but
stopped before running x86: MSVC's PE32 data-directory length is 64 bytes while
its load-configuration structure declares 192 bytes. Microsoft documents the
[64-byte x86 compatibility directory](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#load-configuration-directory).
The metadata reader now validates the extended structure's own declared size,
the complete file-backed section bounds and the required CFG flags. Regression
tests retain rejection of truncated, undersized and inconsistent structures.
Both failed CI stages remain separate from the retained ARM64 observations.
