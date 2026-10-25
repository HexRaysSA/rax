# Readable NtRaiseException arguments

`native-second-chance-v4.cpp` and `run-second-chance-v5.py` extend the
unreadable-pointer observations with readable misaligned inputs and contexts
whose final bytes lie on a no-access page. Every call uses
`FirstChance=FALSE`. A fresh owned child makes each call so successful
second-chance termination cannot truncate the remaining matrix.

Each executable view runs 3 original cases + 32 record offsets + 32 context
offsets + 2 page-boundary cases = 69 cases. The local ARM64 kernel supplies
three executable views, for 207 children. The source/executable/compiler hashes,
actual kernel machine, build, executable view, status, termination code and
handler-cleanup fields are retained in `local-readable-alignment-v3.json`.
No register context, stack bytes or Microsoft instruction bytes are emitted.

| Input on build 29683 ARM64 kernel | ARM64 view | x64 view | WoW64 x86 view |
|---|---|---|---|
| Invalid record or invalid context address 1 | Access violation | Access violation | Access violation |
| Readable record offsets 1 through 32 | Terminates with supplied code | Terminates with supplied code | Terminates with supplied code |
| Readable context offsets divisible by 16 | Terminates with supplied code | Terminates with supplied code | Terminates with supplied code |
| Other readable context offsets 1 through 32 | Datatype misalignment | Terminates with supplied code | Terminates with supplied code |
| Misaligned context with final byte on no-access page | Datatype misalignment | Terminates with supplied code | Terminates with supplied code |
| Aligned context with final 16 bytes on no-access page | Terminates with supplied code | Terminates with supplied code | Terminates with supplied code |

The supplied termination code is `0xE0425345`. Returned failures are
`STATUS_ACCESS_VIOLATION` (`0xC0000005`) and
`STATUS_DATATYPE_MISALIGNMENT` (`0x80000002`). No user handler runs in these
observations. A returning child removes its handler and releases owned scratch;
Windows reclaims the terminating child's address space. Compiler and child
deadlines are 60 s and 15 s respectively. All intermediates remain under the
owning worktree and are removed after each compiler view.

The observer checks input identity, bounded integer status, process termination
or returned error, and handler cleanup. It retains the observed status rather
than assuming one kernel profile. Four projection tests pass on macOS, Linux
and Windows, including all 207 retained cases. Independent x64-kernel captures
run in the existing Windows 2022/2025 jobs. The earlier strict second-chance
control remains enabled and retains its known build-26100 WoW64 failure.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| RC1 | Second-chance input validation requires the complete context extent. | Previous model reads a complete legacy context before termination. | Existing capture behavior. | Make only the final context bytes unreadable. | Falsified by all three local views |
| RC2 | Readable and unreadable misaligned pointers have the same failure priority. | Previous low-address-only matrix. | A uniform alignment-before-copy rule. | Compare address 1 with readable offsets and a split extent. | Falsified for local ARM64 |
| RC3 | The same observed rules apply to independent x64 kernels. | No independent readable-buffer observations yet. | Future model profile. | Repeat the complete matrix on Windows 2022/2025. | Unconfirmed |

High impact, blocking exact native argument parity: the current model reads
more context bytes than these second-chance controls require. The minimum
required record/context prefix and the first-chance readable-buffer behavior
remain unknown. These observations do not implement a model correction or
qualify complete exception dispatch. Observation cost is O(C) child calls and
O(C) bounded scalar receipts for C = 69 cases per executable view.
