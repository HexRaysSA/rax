# Native registry key-body tag setter controls

`probe-v1.c` calls native `NtSetInformationKey` class 5
(`KeySetHandleTagsInformation`) or invalid classes 7 and `0xffffffff`. It opens
the fixed `\Registry\Machine` subject, queries grants and tag state, duplicates
and closes its own handles, and measures input-page protection before restoring
the probe's allocations. It does not change registry values, keys, write times,
virtualization, or layer state. CMake builds the same producer for each process
ABI with MSVC, C11, `/W4 /WX`, and the static CRT.

The retained controls were captured on Windows kernel 10.0.29695, native ARM64,
using ARM64, x64, and x86 processes. Each ABI records 5,372 input cases and 28
lifetime observations, with equal before/after process handle counts. The input
matrix covers exact lengths, every byte alignment, null/unreadable/read-only/
guarded input, page crossings, key grants including a zero-access duplicate,
invalid and wrong-type handles, invalid classes, all 32 single-bit and inverse-bit
vectors, and mixed high/low words. The lifecycle records cover aliases,
independent opens, low handle bits, last close, and native initial view tags.

`post-v1.c` adds 11,648 relative-open cases per ABI (34,944 retained cases).
It replaces parent tags before opening MACHINE, the redirected Command Processor
leaf, shared OLE, NLS, and the selected AppModel subject. Cases include empty-name
reopens and MACHINE-relative descendants, both parent views, four requested views,
single-bit/inverse-bit vectors, all 16 combinations of bits `0x100`–`0x800`, and
combined low/high payload bits. It records canonical names, grants, parent and
child tags before/after a child write, close behavior, and native root absence.
Another 36 controls distinguish initial hive tags by spelling: the SYSTEM SID
alias `S-1-5-18` resets native inheritance, whereas its physical `.Default` name
retains the ordinary WoW64 tags. Controlled creator-hive fixtures use this
measured canonical alias.

The native result order is invalid class, exact four-byte length, input capture,
then key-object validation. Unaligned input is admitted. Successful writes
replace the low 16 bits; they do not OR with existing tags. Setting through a
zero-grant duplicate succeeds, while querying tags through it is denied.
Duplicates share state and independent opens do not. The guest tests project
key bodies into controlled snapshot keys because this operation consumes key
identity and metadata rather than a registry path. A Windows-only test separately
enters the installed NTDLL exports using a real captured MACHINE handle, including
the x86 four-argument return convention.

Tag replacement affects subsequent opens. Native relative opens inherit arbitrary
parent tags, except when traversing the CurrentControlSet alias. WoW64 uses the
effective view bits (`requested != 0 ? requested : parent & 0x300`), rejects
`0x300`, and honors `0x400` redirection suppression. View conversion and physical
path handling can replace inherited metadata. The implementation expresses these
bit rules directly; retained native rows supply expectations only in tests.
Independent empty reopens retain separate state even when they name the same key.

`controls-v1.json` stores one deduplicated matrix and three ABI reports. Expand
each dense row using `row_fields`, then merge its `outputs[output]` record; the
projection was checked against every original native matrix row. The corpus
retains producer hashes, image/report hashes, native grants, input monitor bytes,
status, guard consumption, and raw lifetime query observations. Failed WoW64
`NtQueryKey` scratch-copy bytes are undefined: tests compare their statuses and
the key state through a readable duplicate, and do not assert those scratch bytes.
`post-controls-v1.json` losslessly deduplicates the relative-open rows and interns
complete native name records. Every compact row was expanded and compared with
the original producer output. Tests compare actual selected key identities,
grants, routing, statuses, tag updates and handle counts through the guest NT
dispatcher. `NtQueryKey` class 3 remains unsupported. The controlled NLS fixture
projects the native physical ControlSet alias into its fixed logical selection;
this test does not establish native NLS canonical-name capture.

The official enum declaration is retained under `references/`, with URL, retrieval
time and SHA-256. Microsoft identifies class 5 but reserves its behavior for
system use. The independent native observations supply the measured contract;
the declaration alone does not prove validation order or lifetime semantics.

Verify the retained producers on any host:

```text
python tools/ci/windows_key_set_information.py --verify-corpus
```

Expected output reports three producer inputs, three retained process ABIs, 16,116
matrix cases, 84 lifetime observations, 34,944 relative-open cases and 36 hive
spelling cases.
On native Windows with Visual Studio's C
tools, CMake, Python and Cargo available, capture fresh controls and replay them:

```text
python tools/ci/windows_key_set_information.py
```

The output directory is `target/native-key-set-information-v1`. An existing
directory is rejected to preserve evidence. It contains native JSON, build logs,
hash-bound `observations.json`, and `guest-replay.log`. The replay must execute
seven tests on Windows. ARM64 hosts capture three ABIs; AMD64 hosts capture x64
and x86. The existing CI Windows C API lane runs this gate and retains the output.

Native AMD64-kernel qualification and full installed CMD success are separate
gates; the retained ARM64-host corpus does not prove either. Other valid set
classes remain unsupported, and no new host registry mutation authority is added.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| K1 | The measured tag conversion rules apply beyond the retained bit combinations. | Three native process ABIs, single/inverse bits, mixed words and combined view/redirection flags. | General relative-open policy. | Arbitrary 16-bit payloads, explicit and inherited views, alias traversal and child writes. | Run both native producers and replay their complete rows on another Windows kernel. | Retained; finite native evidence. |
| K2 | The ARM64-host controls also describe native AMD64 kernels. | Not established by the retained corpus. | Native AMD64 qualification. | x64 and x86 on AMD64 Windows. | Existing Windows C API CI lane captures fresh producers and replays them. | Retained until that gate passes. |

The existing NLS canonical-name capture gap and unsupported `NtQueryKey` class 3
are medium-impact evidence boundaries, independent of this setter. The installed
CMD continuation reaches unsupported `NtNotifyChangeKey`, a high-impact remaining
process-emulation boundary. Neither is reported as implemented by this change.
