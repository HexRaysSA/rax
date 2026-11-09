# Retained-file cached signing level

`NtGetCachedSigningLevel` reads the Windows signing cache through the admitted
file object's retained host handle. It never reopens a pathname, forwards guest
handles or pointers to Windows, changes signing metadata, or derives a signing
level from an image name. The guest's `FILE_READ_DATA` or `GENERIC_READ` grant is
checked independently of the retained host descriptor's rights.

The Win32 declaration is documented by
[Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getcachedsigninglevel).
The native declaration is retained in
[PHNT](https://raw.githubusercontent.com/winsiderss/phnt/master/ntseapi.h).
The NT signing-level output is one byte; the Win32 output is a `ULONG`.
The captured sentinel buffers independently verify that distinction.

## Native evidence

`observations-v1.json` binds six read-only C campaigns to their source SHA-256,
native receipt SHA-256, executable identity, stdout identity, process view, and
kernel version. All eighteen executions completed with exit code zero on kernel
`10.0.29698.0`; the installed images were unchanged after each campaign.

| Campaign | Records | Coverage |
| --- | ---: | --- |
| V1 | 5088 | ARM64/x64/x86; signed and unsigned files, restricted grants, NUL, directories, invalid and wrong-type handles; 32 null-pointer shapes, capacities 0/20/64, unaligned flags, independent Win32 controls |
| V2 | 1035 | Ordered output faults, page boundaries, overlapping fields, five handle roles |
| V3 | 4497 | Optional null pointers, read-only guards, mandatory null pointers |
| V4 | 480 | Actual hash length versus caller capacity at a page boundary, capacities 0/20/32/64 |
| V5 | 4497 | Signed `cmd.exe` optional outputs, aliases, protected pages, and null handles |
| V6 | 780 | All 65 starting offsets from 0 through 64 bytes before a protected page, four protections, partial hash-copy effects |

The shared regression replays all **16278 NT records**, including complete
192-byte arenas, 96-byte boundary windows, status codes, and remaining page
protections. The other 99 records are file-open/profile metadata or independent
Win32 controls. Replay uses the real descriptor-driven guest argument reader and
guest virtual memory; the injected metadata comes from captured native records.
That replay does not itself execute the Windows host adapter.

## Publication contract

Mandatory null outputs and a null handle fail before output access. Invalid
handles, wrong object types, insufficient file rights, and missing cached
metadata also precede output access. On successful metadata capture:

1. Store four flag bytes, then one signing-level byte.
2. If the length pointer is present, require four-byte alignment, probe it for
   writing, and read its value **after** those earlier stores.
3. If both hash and length pointers are present and capacity is sufficient,
   copy the actual hash length. The measured 32-byte copy retains completed
   eight-byte stores after a later fault. Insufficient capacity leaves hash
   bytes intact and does not probe the hash destination.
4. Store the required length, then the optional algorithm when hash and length
   pointers are both present. Insufficient capacity still publishes those fields.

The length probe consumes a reached read-only guard. The hash-copy model reads
the initial three destination bytes before its eight-byte stores; this
operational representation reproduces the measured guard threshold and partial
copies without claiming the kernel uses those exact instructions. Subsequent
hash stores and direct flags/level/algorithm stores reject write protection
without consuming a read-only guard. Earlier writes survive later failures.

Absent-hash behavior comes from the live host query. The captured DLLs return
flags `0x100`, length zero, and no algorithm publication. Captured `cmd.exe`
instead returns `STATUS_BUFFER_TOO_SMALL`, flags `0x42`, length 64, and algorithm
zero when a length pointer is present. An absent length suppresses both hash and
algorithm access. No image-name rule selects either behavior in production.

Host capture starts with 64 private hash bytes and grows fallibly only for a
measured required length. Three query attempts bound concurrent cache changes;
an inconsistent response fails explicitly. Capture and publication use `O(h)`
storage and time for a hash of `h` bytes, with a constant number of host queries.
The guest length never controls host allocation.

## Assumption register and scope

| ID | Assumption | Basis and dependency | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| A1 | The native level occupies one byte. | All three captured caller views; guest output width. | Boundary and overlapping destinations must preserve adjacent sentinel bytes. | Confirmed for the captured kernel. |
| A2 | The retained file is the host query capability. | Existing file admission and borrowed `std::fs::File`; host identity. | A pathname reopen, forwarded guest pointer, or query after last close falsifies this. | Enforced by the adapter signature and ownership. |
| A3 | Publication follows the captured order. | V2-V4 complete buffers and guard state; shared publication. | Every recorded alias, short buffer, protected page, and null shape must match exactly. | Native scope is kernel 10.0.29698.0; replay qualification is reported separately. |
| A4 | Three initial read bytes and eight-byte stores represent the measured hash-copy effects. | V6 covers every starting offset 0..64 before the page in all three ABIs. | A different status, remaining guard, or completed-copy prefix falsifies the representation. | Native captures complete; replay qualification is reported separately. |

**Medium, non-blocking scope limit:** caller-buffer behavior on other Windows
kernel versions or other hash lengths is not established by this corpus. Host metadata is queried
live rather than inferred from a stored build profile. Windows guest signing
metadata on non-Windows hosts is explicitly unavailable; no trust level or
`STATUS_NOT_FOUND` is fabricated there. Linux/Linux and macOS/macOS emulation
do not consume this Windows-only metadata adapter.

The service is appended to both NT export representations, preserving all
existing synthetic ordinals and trap addresses. It changes no public RAX C ABI.
