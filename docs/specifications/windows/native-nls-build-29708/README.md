# NLS initialization and query-only MUI on Windows 29708

The runtime admits Windows 10.0.29708 when the independently captured native
machine is ARM64 (`0xAA64`). The controls ran on update revision 1003 in
native ARM64, AMD64 compatibility, x86 compatibility and x86-LAA processes.
Before this admission, `rax-user --windows-libraries native` ran the installed
`cmd.exe /d /c exit 0` through CSR and stopped at the unmeasured
`NtInitializeNlsFiles` profile. The independent native command exited 0.

| Observation | Native ARM64 kernel results |
| --- | --- |
| NLS initialization | 316 calls, four profiles of 79. Status, guard, view and output rows match the retained controls. |
| NLS protection and free | 48 calls, four profiles of 12. Protection, type, ownership and status rows match the retained controls. |
| Query-only MUI | 6,720 rows, four profiles of 1,680. Pointer, length, alias, partial-write and last-error rows match the retained controls. |
| Installed exports | Three per caller profile. The x86 initialization leaf returns with `RET 12`. |
| MUI bytes and generation | Four equal 1,232-byte payloads. Three captures with distinct live buffers agree with shared generation 1. |
| Physical providers | Stable before and after each session. ARM64 and AMD64 compatibility map `System32/ntdll.dll`. Both x86 processes map `SyChpe32/ntdll.dll`. |

The installed `locale.nls` has 862,808 bytes. Its rounded mapping size is
`ceil(862808 / 4096) * 4096 = 864256` bytes, including 1,448 padding bytes.
Its SHA-256 matches the preceding profile. This host's MUI payload has SHA-256
`1ff64f1d44c4f0d7eb67d5e575e26a983aea701279425c21471d216ac9da3ce1`.
MUI content varies by host. Runtime acquisition uses two distinct live
buffers, compares their bytes, and retains the bounded immutable snapshot.

[The typed profile](profile-29708-v1.json) records the fresh behavior hashes,
installed leaf bytes, physical provider identities, payload hashes, generation,
and producer source identities. The 12 canonical matrices are equal to the
corresponding matrices in the [29704 controls](../native-nls-build-29704/README.md).
The native evidence archive `native-nls-29708-controls-and-provenance-v1.zip`
has 1,309,477 bytes and SHA-256
`58cf60964490355b181ab4c3ee971eba2aace159f5b78dbef31d0b308bf1a766`.
It contains the 21 compiled probes, 25 native receipts and output streams,
exact source inputs, payloads, compiler commands, and a content manifest.

The emulator replay adds this build to the existing initialization, protection
and MUI fixtures. The resulting initialization matrix exercises 1,580 calls
and 40 late retained views. The query matrix exercises 25,200 rows. Adjacent
builds, foreign native machines, and missing installed data remain explicit
failure cases. NLS mapping still costs O(N) time and O(N) guest view storage for
a snapshot of N bytes. MUI uses the bounded immutable snapshot and one page of
guest copy scratch.

| ID | Assumption and basis | Dependent result | Falsification probe | Status |
| --- | --- | --- | --- | --- |
| N708-1 | All 7,084 canonical rows match the retained ARM64-kernel controls. | Exact Windows 10.0.29708 ARM64 admission. | A different status, guard, mapping, alias, protection or query row. | Confirmed for the retained observations. |
| N708-2 | The fresh payload and language generation are stable across the selected caller profiles. | Existing query-only snapshot acquisition and generation publication. | Different bytes in distinct live buffers, a changed generation, or a changed physical provider. | Confirmed for the retained observations. |

The scope covers NLS initialization and query-only MUI on the selected ARM64
kernel. Independent AMD64 and i386 kernels, MUI cache mutation, other native
service profiles, and whole-process completion require their own evidence.
