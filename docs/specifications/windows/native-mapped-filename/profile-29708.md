# Windows 10.0.29708 ARM64 mapped-filename profile

This profile covers `NtQueryVirtualMemory` information class 2 on native
kernel 10.0.29708, machine ARM64 (0xAA64). The native capture used revision
1003. ARM64 and x64 callers exposed byte-counted short MUP names. Local NTFS
names truncated to complete UTF-16 code units. The x86 WoW64 controls cover
the separate 32-bit header, name-conversion and return-slot paths. Branch
selection uses the native kernel identity that the attached library catalog
reports. The registry WoW64 copy paths retain their independently qualified
build set.

## Native capture and replay

Identical image bytes from the 29704 acquisition were rerun on 29708. The 24
images comprise eight probe versions for each of the three caller ABIs. The
native capture recorded 1,701 distinct process identities, with exit zero and
empty stderr for each. The replay projection contains 1,359 class-2 queries,
24 name controls, 402 paired-volume queries and 12 paired-volume name
controls. The capture shares 96 executions between the complete and paired
series or between a series and its baseline, yielding
1,359 + 24 + 402 + 12 - 96 = 1,701 distinct executions.

The complete series covers mapped images and data, file movement and
deletion, handle validation, writable-prefix granularity, guard/read-only
boundaries and optional return slots. The paired series runs the same short
buffer probes against local NTFS (`\\Device\\HarddiskVolume3`) and the VM's
UNC share (`\\Device\\Mup`). Complete UTF-16LE names come from separate
successful controls or the corresponding successful case in the frozen
corpus. The runtime assertions use those names, the measured status, output
bytes, return length and page protections. ASLR-dependent pointers are
validated by their relation to the output buffer or to retired conversion
storage.

The ARM64 and x64 callers each exposed 22 odd byte lengths in the 67 paired
MUP query rows per ABI. The paired NTFS rows for these callers exposed zero.
The x64 and x86 probes execute through compatibility on the same ARM64
kernel.

## Provenance

- `profile-29708-v1.json` stores native process identities, observations,
  image and source hashes, physical provider hashes and the NTFS volume
  serial (unsigned 32-bit `0x2853EDE7`).
- `project-29708.py` verifies the fresh raw archive, selected probes, caller
  architectures and cases, volumes, providers, exit status and exact stdout
  bytes. Run it with `frozen-inputs-v1.json mapped708-native-results-v1.zip`
  and compare its stdout to the checked-in projection.
- The native evidence ZIP has SHA-256
  `853f715d33881779c3f4771b199fec9adeaeaf019805b416ecc15f06a3280b6f`.
  The frozen image manifest has SHA-256
  `7bcddae2be2ffaf33e3c1134bbf85de856df9551a2d5e47581a5bf4844666513`.
