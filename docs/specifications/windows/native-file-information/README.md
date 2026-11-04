# Retained-file information queries

`NtQueryInformationFile` is a five-argument service. The implemented fixed-size
classes are 4, 5, 6, 7, 8, 14, 16, 17, 34, 35, 41, 43, 51, and 59. They expose
basic/standard/internal/EA/access information, current position, mode, alignment,
network-open attributes, attribute/reparse tags, completion-notification flags,
I/O priority, remote-device state, and file identity. Variable-size names, full
pipe-resource accounting, and other information classes remain separate work.
Their absence is explicit; this changeset does not establish complete Windows
process execution.

The Windows adapter queries an already owned file with private aligned buffers
and a fixed whitelist containing no guest addresses, handles, names, or process
identifiers. Pending requests retain the handle and buffers through observed
completion. POSIX adapters use retained file metadata and the existing virtual
mounted-disk profile. Duplicate handles share one cursor and mode; independent
opens keep separate cursors. Per-handle grants remain distinct from the shared
file object. A renamed pathname cannot replace a retained file.

Console, null, and modeled pipe handles use the shared guest resource contract.
These queries never operate on the host's unrelated standard handles. Completion
flags initially equal zero and the modeled I/O priority initially equals Normal;
the [fixed file-state setters](../native-file-state-set/README.md) retain changes
to these defaults. General guest file access and
read-only installed-library authority retain their existing policy.

Microsoft documents the [query prototype and class contracts](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile),
the [information-class enumeration](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class),
and the [mode mask](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_mode_information).
Native observations govern details which those pages do not specify. In
particular, the captured kernel accepts position queries for attribute-only
duplicates and asynchronously opened files. The implementation preserves that
observed behavior rather than enforcing the documentation's stronger position
preconditions.

## Independent observations

The controls ran on one Windows ARM64 kernel, build 29698, in ARM64, x64, and x86
process views. This is compatibility-process evidence, not evidence from a
physical x86-64 kernel. `faults-v1.c` issued 14,420 calls per view. Its immutable
source/image/DLL bindings are retained in `observations-v1.json`. The published
replay subset contains 19,776 calls: sixteen classes, four object roles, and 103
length/fault cases per role/class/view. All calls completed without a pending
operation or caller exception. The native leaf bytes confirm x86 `RET 20`.

The query loops left their process handle counts unchanged. Each control also
closed seven explicitly owned handles. Initial/final counts include a persistent
one-handle setup/teardown delta; those counts alone do not prove a handle leak
inside the query implementation.

Before each call the control fills its two 8192-byte regions with `0xA5`, protects
their second 4096-byte pages, and configures one caller fault or overlap. Sparse
byte runs encode only bytes changed from `0xA5`, relative to the named 64-, 160-,
48-, and 64-byte observation windows. Tests reconstruct every untouched byte and
compare status, page protection, output, IOSB, and boundary writes exactly.

The controls distinguish class/length rejection, output alignment, native IOSB
probing, WoW64 copyback, and late IOSB faults. A native synchronous query can
return success after a late IOSB write faults; the same asynchronous-file path
can return the fault. Unused upper IOSB status bytes are preserved or zeroed
according to the captured query path. Both output/IOSB overlaps are retained.
These are bounded observations for the recorded kernel and cases, not a proof
for every possible alias or future kernel.

`profile-v1.c` is the broader exploratory control for real files, reduced grants,
independent/duplicate opens, directories, consoles, null, pipes, and non-file
objects. Its exploratory classes are not all implemented by this changeset.

## Reproduce

Use an MSVC-compatible native Windows compiler for each desired process ABI:

```text
cmake -S docs/specifications/windows/native-file-information -B target/native-file-information -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build target/native-file-information --target file_information_faults
target\native-file-information\file_information_faults.exe
```

Run the executable in a fresh task-owned working directory: it creates and
removes `faults-v1.bin`. Select ARM64, x64, or x86 in the compiler environment;
do not run a second process in an already occupied control directory. The
standalone program uses the installed NTDLL and never links RAX.

Verify the frozen evidence and shared dispatcher tests:

```text
python docs/specifications/windows/native-file-information/verify.py
cargo +1.95.0 test --locked --no-default-features -p rax --lib --features x86_64-suite file_information_ -- --test-threads=1
```

Build directories and compiler temporary paths must remain inside the current
checkout. The tests supplement replay with real owned-file cursor, grant, mode,
identity, rename, and replacement controls. A native Windows test additionally
executes the installed service leaf and checks its return-stack cleanup.
