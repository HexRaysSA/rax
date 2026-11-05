# Scalar MMIO shifts and rotations

[Scalar guest TF completion](../hvf-mmio-guest-debug/README.md) supersedes the historical TF-rejection controls and limitation below.

The Intel HVF scalar MMIO planner now admits `SHL`/`SAL`, `SHR`, `SAR`,
`ROL`, `ROR`, `RCL` and `RCR` with 8-, 16-, 32- and 64-bit memory operands.
It captures the immediate or CL count, incoming flags and carry before device
service. One existing device RMW transaction returns the old operand; completion
publishes flags and retires the instruction once. No GPR receives a writeback.

The implementation masks counts to five bits, or six for a 64-bit operand.
Carry rotations additionally reduce 8- and 16-bit counts modulo 9 and 17.
A 65-bit intermediate preserves carry during a 64-bit rotation. Every transform
uses O(1) time and space, with at most eight device operand bytes.

| Case | Required flag behavior |
|---|---|
| Masked count zero | Preserve all flags |
| RCL/RCR effective count zero | Preserve all flags |
| ROL/ROR masked count nonzero, full operand rotation | Update CF from the unchanged result |
| Any masked count one | Compute the instruction's specified OF |
| Larger nonzero counts | Do not compare undefined OF against the native oracle |
| Nonzero SHL/SHR count at least the operand width | Do not compare undefined CF |
| Nonzero shifts | Set SF/ZF/PF from the result; AF is undefined |
| Any rotation | Preserve SF/ZF/AF/PF |

The pinned source is Intel SDM revision 086, Vol.2B, **RCL/RCR/ROL/ROR**, pages
4-531 through 4-535, and **SAL/SAR/SHL/SHR**, pages 4-600 through 4-604, in the
[retained combined manual](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf).
The reference corpus also retains opcode group2 `/6`, observed as a SHL alias
on the measured Intel host; this observation is separate from the manual's
listed `/4` encoding.

The [reference manifest](../../../tests/fixtures/hvf/mmio-shifts-v1/manifest.json)
identifies physical Intel Haswell execution through Linux KVM. The independently
executing guest records all 16 GPRs, 24 operand/neighbor bytes and before/after
flags. RAX is not linked into the reference runner. The 12,672 cases cover eight
opcode groups, four widths, implicit-one/imm8/CL forms, sixteen count boundaries,
six operand patterns and two initial flag states. The existing planner rejected
the first native case in each group. The new production modules match all cases
under both allowed RMW EPT qualification forms: 25,344 comparisons.

The two retained binary fixtures total 4,308,500 bytes. They permit deterministic
replay without KVM, retain memory neighbors and unaffected registers, and avoid
embedding an emulator as its own oracle. The additional exhaustive count run matches all 196,992 cases against the
production modules, with zero mismatches in 393,984 EPT-form comparisons. It
covers every imm8/CL count and is retained outside the repository. Each independent guest uses 67,108,864 bytes
of RAM; output batches stay below the runner's 1,048,576-byte bound. Temporary
objects, guest ELFs and executables are removed by the collector.

A separate [native access probe](../../../tools/hvf/mmio_shift_access.c) verifies
64 masked-zero cases against a read-only page. An ordinary load succeeds; every
shift/rotate faults at the operand with a write-permission error. This verifies
permission admission. It does not observe external device cycles or HVF EPT
qualification fields.

The integration regressions also cover source-free JSON/bincode pending-state
continuation, full-turn versus zero-count carry rules, compatibility/address
widths, invalid LOCK/TF/EPT/truncated admission, malformed carry records, and
sticky completion failures after serialization. Existing scalar load, ALU and
RMW tests remain enabled.

The complete 47-test **module harness** passed with zero failures, ignores or
filters. It compiles current production MMIO and bus-transform code and the
original integration test bodies, using the previously qualified engine for
metadata, flags and codecs. Its dependency adapter omits the bus library's
separate unit-test block, as an ordinary integration dependency does; the test
bodies and assertions are unchanged. The first harness build omitted the
existing ALU comparison source and failed before running tests. That failure is
retained separately from the corrected input closure.

Later qualification ran the actual complete `hvf_mmio` Cargo binary: all
55 tests passed, with zero failures, ignored or filtered cases. Both frozen
full roots and their workspace checks completed; their current source coverage
is recorded in the [SDK qualification](../hvf-intel-sdk/sdk-model-qualification.json).
The module-harness record above remains separate historical evidence. To
reproduce the owning gates on a new source candidate, use its declared target directory:

```sh
cargo +stable test --locked --no-default-features \
  --features x86_64-suite,smir-jit,kvm,debug,hvf --test hvf_mmio
cargo +stable test --locked --no-default-features \
  --features x86_64-suite,smir-jit,kvm,debug,hvf --lib
```

Generate a fresh independent architectural reference on Linux x86-64 with KVM:

```sh
python3 tools/hvf/mmio_shift_oracle.py \
  --out /tmp/rax-shift-reference --llvm-bin /path/to/llvm/bin
# Optional: every imm8/CL count; keep this larger output outside the repository.
python3 tools/hvf/mmio_shift_oracle.py \
  --out /tmp/rax-shift-exhaustive --llvm-bin /path/to/llvm/bin --exhaustive-counts
```

The [qualification record](qualification.json) distinguishes these gates.

High impact: physical Intel macOS HVF SDK/EPT/device execution remains
unverified. Native Linux RAM execution and the portable planner do not establish
that platform result. Double shifts, wide atomic operations, strings, vectors,
and TF/debug completion remain separate C-HVF requirements. This component does
not close C-HVF or the four-finding goal.

The first complete Cargo check failed because the software CPU deferred-exit
codec also enumerates every bus operation. Its new shift records now use tags
12 through18, preserving tags0 through11 and the existing record fields.
Twelve records captured from the previous codec retain exact JSON and binary
compatibility. New tests cover every shift count/width, both debug build modes,
reserved fields, count overflow and invalid carry. The later complete Cargo
and frozen-root qualifications above include this integration correction.
