# A32 register-form SIMD admission

VMVN register forms reject nonzero `size`. VUZP and VZIP reject 32-bit elements
in doubleword forms. They do not become VTRN aliases. The separately allocated
VTRN doubleword form continues to support 32-bit elements.

These decode constraints precede FP access controls and register effects in
both A32 and T32. A failed Thumb IT predicate still suppresses execution. No
instruction identifier, arithmetic helper, checkpoint layout or C ABI changes.

| Instruction | Valid element sizes | Quadword registers |
|---|---|---|
| VMVN register | `size=0`; bitwise operation | Even first register |
| VTRN | 8, 16 or 32 bits | Even first register |
| VUZP, VZIP doubleword | 8 or 16 bits | Not applicable |
| VUZP, VZIP quadword | 8, 16 or 32 bits | Even first register |

The checks use O(1) time and auxiliary storage. The canonical decode regression
matrix contains 16,384 combinations per family, or 65,536 total: both execution
states, every `size` value, D/M bank bits, source/destination register fields and
Q value. The pre-fix production decoder disagreed with the primary constraints
in 7,680 VMVN, 2,048 VUZP and 2,048 VZIP combinations. VTRN had no mismatch.
Five representative reserved words also executed and changed vector registers
when access was enabled. New cases cover decode priority under denied access,
register/status/RAM preservation, failed IT predicates and mixed-width faults
without retirement. Canonical-field coverage does not cover unrelated encodings,
all feature/security profiles or physical AArch32 execution.

Run the complete owning targets from the repository root:

```sh
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --test a32_fp_controls
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --test arm_vfp_a32
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --test arm
```

The independent primary reference is Arm DDI0597 ID032025, retained at
[`aarch32-isa-2025-03.pdf`](../../specifications/arm/aarch32-isa-2025-03.pdf).
VMVN register decode is on PDF page 1152, VUZP on 1461-1462 and VZIP on
1465-1466, using one-based PDF page numbers. The retained ASL agrees with these
constraints. [Provenance](provenance.json) records exact inputs and retrieval
metadata. The earlier hand-written positive tests used reserved words; their
positive data checks now use legal VMVN and VTRN encodings. This component does
not close the broader A32-FP finding.

[Qualification results](qualification.json) record the complete owning-target,
library and workspace gates, their source identities, and excluded test counts.
