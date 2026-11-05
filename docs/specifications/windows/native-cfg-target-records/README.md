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
success in all three views. The released-reservation control
returns `0xC00000A0` with a zero processed count. This contradicts directly using
RAX's current committed-private-page precondition as the NT handler's complete
validation rule. The runtime handler must account for reservation lifetime and
ABI-specific capture rather than forwarding every record to that primitive.

The corpus proves status and caller-buffer effects for these inputs. A zero
processed count does not, by itself, prove atomic bitmap mutation. Successful
registration does not prove subsequent indirect-call admission. Actual target
bit mutation, image GFIDS registration, section-backed requests, export/XFG
policy variants and indirect dispatch need their own execution evidence.
The six lifetime and twenty compound-fault cases extend the initial 76-case
development capture; the retained corpus uses the final identical 102-case
source for every process view.

## Reproduce and verify

From the repository root, verify the retained evidence on any host:

```text
python -B -m unittest discover -s tools/ci -p test_windows_cfg_target_records.py
python -B tools/ci/windows_cfg_target_records.py --verify docs/specifications/windows/native-cfg-target-records/controls-arm64-29698-v1.json
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
and uploaded even after a failed capture. Fresh CI results are separate from
the retained ARM64 corpus and are not claimed here before inspection.

The parser's 16 rejection tests include LF and CRLF source fixtures plus explicit
rejection of doubled carriage returns. The first AMD64 CI attempt exposed a test
fixture that added CRLF to an already-CRLF checkout; that failed run is retained.
The fixture now constructs both newline forms from normalized LF bytes without
weakening the production source-identity check.
