# Legacy MOVBE on Intel HVF MMIO

The baseline planner rejected all six legacy MOVBE memory forms at metadata
decode. The shared decoder now describes the `0F 38 F0` load and `0F 38 F1`
store, including operand widths and access direction. The MMIO planner
byte-swaps 2-, 4-, and 8-byte transfers. Loads preserve the upper register bits
at 16 bits and clear them at 32 bits. Stores emit only the low operand-width
bytes, in reversed order. Existing I/O completion owns instruction retirement.

The pending input record retains byte-swap semantics with a new encoding
appended after the three existing completion variants. The input codec
round-trip verifies the result and confirms that device completion makes no
flag writes. The decoder rejects register-only encodings and LOCK and keeps
the F2 CRC32 encoding outside the MOVBE path. The planner reuses its existing
address and access checks and requires a matching EPT direction.

The planner is bounded by a 15-byte x86 instruction and an 8-byte operand.
Byte reversal uses O(n) time and O(1) temporary space for n transfer bytes.
For input bytes `aa bb cc dd`, the 32-bit result is `0xaabbccdd`.
For store source `0x1122334455667788`, the 4-byte transfer is `55 66 77 88`.
[Intel SDM 086, Vol. 2B, pp. 4-52 and 4-53](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| ID | Assumption and dependent result | Falsification probe | Status |
|---|---|---|---|
| M1 | Decode distinguishes all legacy MOVBE forms from invalid operands and CRC32. | Exercise 16-, 32-, and 64-bit defaults, operand overrides, truncation, register-only ModR/M, and F2 and LOCK prefixes. | Confirmed by portable metadata and MMIO tests. |
| M2 | Existing scalar completion preserves byte width, the architectural register merge, and flags. | Complete new and serialized inputs for all three sizes. Compare with the six exact-byte x86-64 Rosetta observations. | Confirmed for the portable planner and completion. |
| M3 | A real Intel HVF vCPU emits the required translated EPT records and can resume the decoded transaction after restoring private state. | Run MOVBE load and store guests across actual MMIO exits with and without a pending-I/O restore. | Confirmed for the 12 recorded transactions. |

The pre-fix standalone planner used the production decoder and failed all six
forms. The full portable MMIO and ISA oracle suites passed. The selected Intel
context module exercised legacy and new producer/consumer validation. Intel
macOS cross-compilation checked the hardware integration's type wiring.
[Qualification receipt](qualification.json)

The signed consumer built at `ba1806f0685b350f92ea837d7fb13ce8851057f1`
passed all 12 guest cases on the GitHub Intel runner with macOS 15.7.9
and SDK 15.5. The availability probe reported a native Intel process,
an Intel Core i7-8700B, and a virtualized host with Hypervisor.framework VM
creation available. The guest observations include six direct transactions
and six restored in a fresh native vCPU. Each guest completed its original
device request once and reached the post-MMIO marker with the expected register
value. The native test also checked the store bytes before acknowledging each
request. The artifact verification matched both archive digests, all 4,764
engine inputs against the published Git revision, and the executed consumer
against the signed build.
[Native run](https://github.com/HexRaysSA/rax/actions/runs/44346514351/job/134950259130)
[Verified receipts](native-movbe-verified.json)
[Guest observations](native-movbe-observations.jsonl)

The native result covers the legacy 16-, 32-, and 64-bit MOVBE forms on this
runner. Bare-metal execution, broader MMIO profiles and interrupt coherence
remain outside this qualification.
