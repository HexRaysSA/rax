# Paired compare-exchange on Intel HVF MMIO

## CMPXCHG8B

The pre-fix emulator metadata rejected `0F C7 /1`. The decoder now supplies
one 8-byte read-write memory operand for the plain and LOCK forms, independent
of the operand-size override. The planner uses the existing compare-exchange
device request and requires an EPT record with write access. The decoder
rejects a register destination.

Let `low32(x)` be the unsigned low 32 bits. The comparison value is
`(low32(RDX) << 32) | low32(RAX)`, and the replacement is
`(low32(RCX) << 32) | low32(RBX)`. For example, input halves `0xabcd1234`
and `0x12345678` compare against the 8-byte little-endian value
`0xabcd123412345678`. On a match the device receives the replacement and
completion sets ZF. On a mismatch the transaction writes back the old value,
completion clears ZF, and EAX and EDX each receive a zero-extended 32-bit
half of that value. The other flags and the source registers retain their
values. The pending record appends an encoding for this completion behavior
and retains the existing compare-exchange operation and operand width.
Planning and completion use O(1) time and space for the bounded instruction
and 8-byte operand.
[Intel SDM 086, Vol. 2A, pp. 3-215 to 3-216](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| ID | Assumption and dependent result | Falsification probe | Result |
|---|---|---|---|
| P1 | The operand is a qword in each supported mode. | Decode 16-, 32- and 64-bit forms with LOCK, an operand-size override, and each truncated prefix. Try register-only and read-only EPT requests. | The qword controls pass and the rejected requests produce no plan. |
| P2 | The reply carries the original device bytes and can finish after decoding saved input. | Resume an encoded request and exercise equal and unequal device results with nonzero upper GPR halves and both initial ZF values. Compare six exact-byte x86-64 observations through Rosetta. | Register, flag and memory results agree with all six independent cases. |
| P3 | Completion fences on a rejected SDK write. | Accept the EAX write, reject the EDX write, and attempt completion again. | The completion error survives. No flags write, retirement or second callback occurs. The first register write has already happened. |

The corrected baseline reproducer fails three cases at metadata or planning,
and passes the rejection control. The first baseline attempt failed to compile
the test's length conversion and provides no runtime evidence.
[Qualification receipt](qualification.json)

### Native guest profile

The `cmpxchg8b` workflow profile selects twelve cases. It tests a match and a
mismatch for each of the plain, LOCK, and operand-size-prefixed instructions.
Each combination runs both directly and after restoring the pending private
record into a fresh native vCPU. The probe checks the original compare and
replacement values, returned device bytes, RAX, RDX, unchanged source registers,
all RFLAGS, and the post-instruction RIP and guest marker. Each case constructs
one VM and restores into at most one additional VM. Time and space scale with
the native VM setup and the fixed 2 MiB test RAM per VM.

| ID | Assumption and dependent result | Falsification probe | Status |
|---|---|---|---|
| P4 | Workflow and binary admission agree on the exact profile and case count. | Compare all workflow choices against the CLI, attest the new source, and test prepared observation admission. | Matching profile and count. All 53 Python and 16 workflow policy tests pass. |
| P5 | The target backend can surface and finish the new transaction on native Intel. | Execute all twelve guests and independently check the signed binary, source revision, and observation rows. | All twelve native Intel guest cases pass. |

Run `44362393833` completed six direct and six restored cases at
`806111a6a8b853c1f70a0f653d6a8cc680a2bc3b`. The signed x86-64 consumer ran
under Hypervisor.framework on a virtualized Intel Core i7-8700B with macOS
15.7.9 and SDK 15.5. Artifact verification matched both archives, all 4,767
engine inputs, the signed executable, and every register, device, flags,
and RIP observation in the twelve rows.
[Native job](https://github.com/HexRaysSA/rax/actions/runs/44362393833/job/135007014949)

The restore cases qualify the private CPU context on a fresh native vCPU.
Full checkpoint files, multi-CPU restoration and bare-metal Intel execution
remain open for this profile.
[Native profile admission receipt](native-profile-qualification.json)
[Verified native receipt](native-cmpxchg8b-verified.json)
[Native guest observations](native-cmpxchg8b-observations.jsonl)

In the software interpreter, a 32-bit segmented `CMPXCHG8B` operand can cross
from linear `0xfffffffc` into page zero while its offset remains within the
segment limit. The write preflight uses the same page advance as the actual
transfer. The RAX regression checks both physical destination halves. A
separate QEMU 11.1.2 protected-mode guest checks match and mismatch across
the wrap using distinct pages.
[Intel SDM 086, Vol. 1, section 3.1.1](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

## CMPXCHG16B

The REX.W form uses a 16-byte-aligned operand. RDX:RAX supplies the expected
value and RCX:RBX supplies the replacement, with each register contributing
64 bits. The device owner performs a single 16-byte read followed by a single
16-byte write under the same lock. The reply carries all 16 original bytes.
A mismatch clears ZF and writes both halves to RAX and RDX. The software
x86 interpreter also checks alignment and write permission before comparing
and issues writeback on either comparison result.
[Intel SDM 086, Vol. 2A, pp. 3-215 to 3-217](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The `cmpxchg16b` workflow tested plain and LOCK encodings, match and mismatch
for each, and both direct completion and private-context restoration into a
fresh vCPU. All eight passed on a virtualized Intel host with macOS 15.7.9
and SDK 15.5 at commit `89085226695e30d0f6e63887d25075be59d9555a`. Artifact
verification matched the executable hash and 4,821 engine input hashes, then
compared every register, flag, device value, and callback count. The mismatch
controls vary the low and high comparison halves independently.
[Native workflow](https://github.com/HexRaysSA/rax/actions/runs/44519217118)

The private vCPU record retains the suspended transfer. Complete VM files,
interrupt coherence across CPUs, and execution on bare-metal Intel macOS
require separate coverage.
