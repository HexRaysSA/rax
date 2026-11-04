# Fixed open-file state setters

`NtSetInformationFile` implements position (14), mode (16), completion flags
(41), and I/O priority (43). Other setters remain explicit unsupported services.
The five-argument export is appended after existing NTDLL families, preserving
their synthetic ordinals. Native and installed-library dispatch share it.

Position changes reach the retained file description. Duplicated handles share
state while independent opens remain separate. Attribute-only duplicates may
change position and priority even when a priority query through that reduced
handle is denied. Console, null, pipe, directory, and legacy metadata-only
positions belong to the guest object; no host standard handle is modified.
The portable mapped Windows disk uses 512-byte logical sectors for no-buffering
position validation, independently of the file-alignment mask. Windows delegates
that validation to the actual owned file's kernel/device contract.

Mode changes retain the synchronous/asynchronous category and the existing
no-buffering bit. Write-through and sequential flags can change; write-through
is suppressed by no-buffering in the captured profile. Delete-on-close remains
a separate lifetime property and is absent from queried mode in these controls.
The portable write consumers commit write-through data through the retained
file. Native Windows applies modes with a bounded private input record.
Sequential-scan and priority are advisory per-open state in the modeled portable
disk. Notification bits accumulate and cannot be cleared. Their acceptance
does not add asynchronous I/O or completion-port delivery: those unimplemented
operations retain explicit capability failures.

Microsoft documents the [five-argument service](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile),
[mode fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_mode_information),
and [sticky completion modes](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes).
The archived primary pages retain their issuing organization, URLs, retrieval
date, and hashes in `primary-sources-v1.json`. Native observations define the
additional rejection, ordering, padding, and aliasing behavior tested here.

## Independent controls and evidence bounds

Standalone C controls ran on one Windows ARM64 kernel, build 29698, using
ARM64, x64, and x86 process views. This is not a physical x86-64 kernel claim.
There were 28,620 scalar calls and 9,555 fault calls, with no pending result or
caller exception. Warmed process handle counts remained unchanged in every run.
Source bundles bind each captured binary to its exact source and toolchain;
receipts bind stdout and the installed DLL identities. The public corpus keeps
12,720 scalar calls and all 9,555 fault calls, about 10 MB of bounded evidence.
Scalar selection retains lengths 0, 4, and 8 plus every state-transition call.

Native IOSB probing precedes input alignment and object lookup. Input page
access and object rejection have distinct ordering. WoW64 additionally validates
nonnull input spans and captures position input before object lookup. A late
WoW64 IOSB fault preserves a completed state change and already-written bytes.
Native position publication differs for synchronous and asynchronous opens.
The replay checks complete sparse-byte windows, guards, statuses, before/after
state, duplicate parents, independent opens, and preserved LastError.

## Reproduce

Build and run each ABI in a fresh owned directory with an MSVC-compatible
compiler environment. Each control creates and removes only `state-v1.bin`
and `state-dir-v1`. Never reuse an occupied control directory.

```text
cmake -S docs/specifications/windows/native-file-state-set -B target/native-file-state-set -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build target/native-file-state-set --target file_state_scalars file_state_faults
target\native-file-state-set\file_state_scalars.exe
target\native-file-state-set\file_state_faults.exe
python docs/specifications/windows/native-file-state-set/verify.py
cargo +1.95.0 test --locked --no-default-features -p rax --lib --features x86_64-suite file_state_set_ -- --test-threads=1
```

Keep compiler temporary paths and build outputs inside the checkout. The Rust
controls execute the real service router for every guest ABI, real retained-file
I/O, and installed native/WoW64 leaves where Windows is available. They establish
these fixed setters, not complete Windows process execution.
