# MOVSXD metadata and Intel MMIO admission

Opcode `63 /r` in 64-bit code has three forms: 16-bit and 32-bit copies, and a
REX.W 32-to-64-bit signed extension. The source width is at most 32 bits. The
metadata decoder previously marked every form incomplete and gave the REX.W
destination a 32-bit width. Intel HVF MMIO therefore rejected these loads.

The correction supplies complete read/write metadata and uses the existing
plain/signed scalar input completion. It introduces no checkpoint field or
public ABI layout. Legacy 16/32-bit opcode 63 remains ARPL; LOCK remains invalid.

The native reference contains 768 executions: three operand sizes, 16 destination
registers, eight sign/boundary values and two flag states. Neighboring memory
contains nonzero bytes. A separate Linux KVM runner executes the generated
reference guest without linking RAX and captures all 16 GPRs, eight memory bytes
and flags before/after. Two native runs reproduced identical case/record bytes.
This verifies architectural RAM execution, not macOS HVF EPT or device ordering.

The owning MMIO binary compares these records with the actual product planner,
and retains the original 1,204-case corpus. Additional cases check register
forms, exact short replies, and serialized pending-read continuation.

The original three regressions were run against the predecessor: two failed
(incomplete metadata and unsupported MMIO), while the legacy/invalid control
passed. A first Cargo attempt reused a foreign cached binary and ran zero
selected tests; the harness rejected that result. Combined qualification uses a
source-digest cfg tag and a retained executable instead.

Primary instruction provenance: the archived Intel SDM 086, Volume 2B,
MOVSX/MOVSXD opcode and operand tables, pages 4-128/4-129:
[combined SDM](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf).
The [native fixture manifest](../../tests/fixtures/hvf/mmio-movsxd-v1/manifest.json)
records exact source/input/output hashes, tools, kernel and commands.

| ID | Assumption and dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| MX1 | SDM width/write semantics describe all three forms | Compare all registers, neighboring bytes and flags with the 768 native executions | Confirmed by 768 product/native record comparisons |
| MX2 | Existing plain/signed input descriptors retain these reads | Serialize each pending read before completion; reject every short reply | Confirmed by the complete 41-test MMIO target |
| MX3 | The compiled product corresponds to the declared source set | Distinct source-batch cfg, fresh compilation evidence, source hashes, stable executable and nonzero exact test counts | Fresh source-bound compilation and complete frozen library gate confirmed |

High impact: physical Intel macOS HVF execution remains unrun. TF, vector/string
MMIO and the full native checkpoint/timer transaction remain separate open
requirements. This change does not close the four audit findings.

Replay on Linux x86-64 with usable `/dev/kvm`, GCC and LLVM:

```sh
python3 tools/hvf/mmio_movsxd_oracle.py --out /tmp/rax-movsxd-replay --llvm-bin /path/to/llvm/bin
cargo test --locked --features x86_64-suite,hvf --test hvf_mmio -- --test-threads=1
```

The reference tool uses an exclusive output directory and automatically removes
its object, ELF and executable. Time/storage scale linearly with the case count;
the native guest has 67,108,864 bytes of RAM and a 10 s process alarm.

The [qualification record](hvf-mmio-movsxd-qualification.json) retains the source
identity, exact commands, actual counts and scope limits. The frozen library
gate passed 13259 tests with 61 ignored; no tests were filtered.
The later native checkpoint-writer correction has separate qualification.
