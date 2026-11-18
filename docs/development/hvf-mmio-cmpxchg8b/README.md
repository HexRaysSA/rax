# CMPXCHG8B on Intel HVF MMIO

The pre-fix emulator metadata rejected `0F C7 /1`. The decoder now supplies
one 8-byte read-write memory operand for the plain and LOCK forms, independent
of the operand-size override. The planner uses the existing compare-exchange
device request and requires an EPT record with write access. The decoder
rejects a register destination. The 16-byte REX.W form remains outside the
scalar MMIO contract.

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
| P1 | The operand is a qword in each supported mode. | Decode 16-, 32- and 64-bit forms with LOCK, an operand-size override, and each truncated prefix. Try register-only, read-only EPT and REX.W requests. | The qword controls pass and the rejected requests produce no plan. |
| P2 | The reply carries the original device bytes and can finish after decoding saved input. | Resume an encoded request and exercise equal and unequal device results with nonzero upper GPR halves and both initial ZF values. Compare six exact-byte x86-64 observations through Rosetta. | Register, flag and memory results agree with all six independent cases. |
| P3 | Completion fences on a rejected SDK write. | Accept the EAX write, reject the EDX write, and attempt completion again. | The completion error survives. No flags write, retirement or second callback occurs. The first register write has already happened. |

The corrected baseline reproducer fails three cases at metadata or planning,
and passes the rejection control. The first baseline attempt failed to compile
the test's length conversion and provides no runtime evidence.
[Qualification receipt](qualification.json)

High-impact limits are native Intel execution of these exact forms and the
remaining multi-vCPU MMIO and interrupt-coherence cases. The Rosetta comparison
runs ordinary instructions in a process. EPT exits, the native SDK completion
sequence, and a full VM checkpoint restore need separate execution evidence.
