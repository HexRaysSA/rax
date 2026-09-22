# Native x86 replay with unmasked MXCSR

## Contract

The x86-64 JIT admits a region with any of MXCSR exception-mask bits 7 through
12 clear only when every executed native vector operation is covered by an
exact validated replay span whose instruction cannot raise a SIMD
floating-point exception for any operand bits. Missing instruction provenance,
memory operands, unsupported vector forms, and replay families that can raise
such exceptions retain the interpreter frontier. The existing host-feature,
control-state, and state-marshalling gates still apply.

The positive replay classifier covers integer, bitwise, transfer, shuffle,
cryptographic, and selected nonexceptional numeric register forms. A positive
classification means *exception-mask independence*, not MXCSR independence:
FP32/FP64 `VFPCLASS` still reads MXCSR.DAZ. `ADDPS` and other arithmetic,
conversion, and comparison families without a separate proof remain excluded.
The classifier tests require a live encoding fixture for each positive family,
an explicit conservative fixture for each remaining aggregate family, and
memory/truncation/reserved-encoding rejection.

The source authority is the checked-in [Intel SDM 086](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
Vol. 1 sections 11.5 and C.3 through C.7, together with the relevant Vol. 2
instruction exception tables. Its [provenance record](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md)
states the archive's known and unknown source fields. The allow-list source
identifies the specific nonexceptional numeric instruction tables.

## Host boundary

On physical x86-64, the existing entry trampoline loads the guest MXCSR before
native vector execution and saves it on exit. The JIT cache key includes the
all-exceptions-masked state, so a region compiled under one mask state cannot
be reused under the other. Interpreter callouts that change MXCSR to an
unmasked value still deopt at the completed call frontier; this conservative
path is independent of the entry policy.

The local x86-64 execution environment is Rosetta. A native `PTEST` region
entered with MXCSR `0x0041` returned `0x1FC1`, changing all six exception-mask
bits. This observed host behavior invalidates MXCSR round-trip parity for that
environment. The runtime therefore retains the unmasked-vector fallback under
Rosetta. The local test proves the fallback; it does not claim physical-x86
execution of the newly admitted branch.

The region scan takes O(N + P) expected time and O(N + P) auxiliary space for
N semantic operations and P source instructions. The byte-level classifier
has a fixed family count and inspects at most 15 instruction bytes per span.

## Verification

```sh
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib mxcsr_replay_policy -- --test-threads=1
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --target x86_64-apple-darwin --lib jit_unmasked_mxcsr_executes_exception_free_replay_and_rejects_fp_arithmetic -- --test-threads=1
```

The first command runs portable encoding and admission tests at O0/O1/O2.
The second command checks fallback under Rosetta or native execution on a
physical x86-64 macOS host. Physical x86-64 Linux execution remains an
unrun host-specific validation lane in this local worktree.

## Assumption register and bounded scope

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- | --- |
| A1 | The instruction exception tables cover every classified encoding. Each positive family uses an exact source-byte classifier. | Entry admission with unmasked MXCSR. | Complete fixture inventory and negative opcode/operand mutations; a positive encoding with a listed SIMD floating-point exception falsifies the entry policy. | Retained. |
| A2 | Physical x86-64 saves and reloads MXCSR exception-mask bits through `STMXCSR`/`LDMXCSR` as specified by the Intel SDM. | Native MXCSR round-trip parity. | Run the native differential test on physical x86-64 with `0x0041`, `0x0000`, and `0x1F00`; a changed mask bit falsifies this assumption. | Retained; local Rosetta observation does not test physical x86-64. |

- High: a new native vector instruction family needs explicit classification;
  the default result is fallback, so it does not block correctness.
- Medium: callout continuation remains conservative after a callee unmasks
  MXCSR, including regions whose later replay spans are exception free.
- Low: the classifier tests couple to the aggregate replay source inventory;
  a source organization change requires updating the inventory parser.
