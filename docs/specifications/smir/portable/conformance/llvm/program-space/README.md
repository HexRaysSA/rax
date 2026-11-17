# Allocated program-space library witnesses

These hand-authored LLVM modules use the exact portable compiler DataLayout with
`-pe1:64:64:64:64-P1`. They are not SMIR compiler output. The standalone C++ reader
links the supplied pinned LLVM24 IRReader/Verifier libraries and never constructs
an x86/AArch64 TargetMachine. The `smir64` triple is an IR string; accepting it here
does not register a backend or frontend.

AS1 program pointers have 64-bit representation/index and ABI/preferred alignment
64 bits = 8 B, stable representation, external state and zero null bits. The reader
queries every field, including `getNullPtrValue(1)`, and checks B/S are unsized.
The three initial positives cover source-effects SSA shapes, the exact two-B
aggregate group and null/declaration/load/store/phi/select/equality with AS0 storage.
Five malformed modules test cross-AS operands and unsized memory/vector rejection.

The two freeze modules **succeed in generic LLVM**. Their listed portable policy
requires rejection of B/S freeze; this witness does not implement that compiler
validator. Likewise BlockAddress parses in AS1 while its existing portable compiler
classification remains `E-CONSTANT-BLOCK-ADDRESS`. Address space alone cannot
select CodeAddress, a label, typed code or native domain. No origin, source plan,
receiver, permit, private Scope or call permission is issued by these observations.
Existing one-byte RAX descriptor globals remain deliberately invalid source proof.

Build and run from the RAX source root, using the supplied reference checkout:

```sh
python3 -B tools/smir-llvm-contract/build_program_space_reader.py \
  --llvm /Users/int/dev/llvm-project \
  --output /tmp/rax-portable-smir-01/LLVM/program-space-native
SMIR_PROGRAM_SPACE_ORACLE=/tmp/rax-portable-smir-01/LLVM/program-space-native/program-space-oracle \
SMIR_PROGRAM_SPACE_BUILD_RECEIPT=/tmp/rax-portable-smir-01/LLVM/program-space-native/build-receipt.json \
  python3 -B -m unittest discover -s tools/smir-llvm-contract -p test_program_space.py -v
```

Choose a fresh output directory. Missing native tools/receipts fail; tests never
skip or fall back to an old binary. The build records exact compiler, static LLVM
libraries, headers, configuration and selected non-system runtime hashes; before/
after guards remain active under `python -O`. The supplied library/source build
relationship is an explicit assumption, not an independently rebuilt LLVM/OS
attestation. The actual compiler artifact hash is the selected local reference
baseline, not a claim that arbitrary six-host builds have identical bytes.

`test_program_space.Pure` runs without native tools and checks cross-contract
consistency, adversarial request space IDs, the unchanged label diagnostic and
output-root guards. The Native class additionally tests expected layout mismatch
and missing-file failures. It retains actual commands, stdout/stderr, hashes and
false authority/admission flags under an external artifact directory. LLVM parsing
and generic verification are not source/Fn/ABI/descriptor checking, native guest
execution, JIT, emitter implementation or compiler freeze.

The reader's added constant observation walks unique LLVM Constant nodes/edges
and sorts B observed BlockAddress spaces: expected O(V+E+B log B) work and O(V+B)
storage for that walk using pointer-identity DenseSet, separately from LLVM's
parser/verifier costs. This is not a CPU/RSS or adversarial resource certificate.
No SourceQueryBudget/runtime authority is inferred from a tool timeout.

Assumptions: allocation is exact Root accepted revision; falsify mismatched
target/request/frontend layout or noninteger/duplicate/reversed spaces. Supplied
libraries match the recorded reference build; falsify compiler/version/source/
library/header drift. Structural validity is weaker than portable semantics;
falsify AS1-to-callability inference with the actual label case and generic freeze
acceptance. High-impact boundary: native structural success must not admit code.
Medium: all generators/schema/gate/fixture copies must migrate together. Low:
these observations say nothing about runtime performance or host qualification.
