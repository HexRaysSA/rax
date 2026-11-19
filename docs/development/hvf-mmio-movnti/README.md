# Intel HVF MOVNTI device writes

An Intel guest can use `MOVNTI` to store a general-purpose register to
memory. At `9e38e04cbfe49f4da2f8a1c20905849236d1110d`, the HVF MMIO
planner rejected the instruction because the shared metadata decoder
did not represent it. The unchanged regression reproduces this rejection.

The decoder describes a write-only memory operand and a read-only register.
The default width is 32 bits, including in a 16-bit code segment. REX.W
selects 64 bits. The planner uses the captured low 4 or 8 source bytes in
little-endian order after checking that the EPT record identifies a translated
write to the decoded address. The existing output transaction retains the
address, bytes and instruction length while the device dispatch is pending.
Acknowledgment retires the instruction. The decoder follows the documented
NP prefix rules and rejects LOCK and register-only destinations.
[Intel SDM Vol. 2B, MOVNTI](https://cdrdv2-public.intel.com/858447/253667-088-sdm-vol-2b.pdf)
[Intel SDM Vol. 2, opcode notation](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)

The transfer takes constant time and storage within the 15-byte instruction
bound and 8-byte data bound. General cross-page and code coherence, and
write-combining behavior for WC device windows, remain open.

## Validation

The complete portable MMIO and guest-translation targets passed 103 and 8
tests, respectively. The complete C API Rust target passed 245 tests. The
local Intel consumer cross-built and passed strict code-signature verification.

| Assumption | Falsification probe | Status |
| --- | --- | --- |
| The encoded register and width determine the payload. | Compare exact bytes for both widths, extended registers, displacements and address-size override. Reject wrong EPT directions. | Portable tests passed. |
| Only documented register-to-memory encodings are admitted. | Decode each supported code width and reject unsupported prefixes, register destinations and truncation. | Portable tests passed. |
| The existing output lifecycle can retain an EPT write across vCPU restoration. | Reobserve the address and bytes before acknowledgment. Require a single RIP advance, unchanged source registers and status flags, and an executed post-transaction marker. | Hosted Intel cases passed. |

## Hosted Intel execution

All eight guest cases passed at signed commit
`20ec0c458b51fcd1d4916da7a4b01c103f136c08`. The Intel Core i7-8700B
runner used macOS 15.7.9 and SDK 15.5 inside a hypervisor. The consumer ran
as an Intel process without translation. The verifier matched both archive
digests, the signed executable and 4,850 engine source files at that commit.
It also checked the named MOVNTI profile in both version-2 run reports.

| Store | Address | Direct | Fresh vCPU after capture |
| --- | ---: | ---: | ---: |
| 32-bit EAX | `0x40000080` | 1 | 1 |
| 64-bit RAX | `0x40000080` | 1 | 1 |
| 32-bit R8D, address-size override | `0x40000084` | 1 | 1 |
| Unaligned 64-bit R8 | `0x40000087` | 1 | 1 |

The restored cases use an in-memory checkpoint record and stopped guest
RAM. Native bare-metal Intel execution and full VM file restoration remain
unverified for this profile.
[Hosted job](https://github.com/HexRaysSA/rax/actions/runs/44580363347/job/135759052369)
[Verified artifacts](native-movnti-verified.json)
[Guest observations](native-movnti-observations.jsonl)
