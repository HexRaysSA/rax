# ASL expression binding repair

The expression parser reversed arithmetic and Boolean binding. At parent
`b2bd92170fed6b25dd6a1c57f720b624d7c4e7f2`, `1 + 2 * 3` produced a
multiply node over `1 + 2`. The primary allocation predicate
`size == '10' && (L == '1' || Q == '0')` also changed meaning: a reserved
size could satisfy the incorrectly grouped expression.

`BinOp::precedence` now follows Arm 111069 A.a section 4.4.5, retained in
`primary/` with its retrieval metadata and checksum. The supported legacy
spellings EOR, QUOT, REM, ++ and : remain available in their corresponding
classes. This is an expression-binding repair, not a claim of complete ASL1
language conformance. Existing permissive same-class associativity is retained.

Less-than comparisons previously entered the bit-slice parser and consumed
operands outside the Pratt precedence policy. Angle-slice parsing now restores
all lexer state when speculation fails, allowing ordinary comparison parsing.
Failed positions are remembered across rollback: without this, nested function
arguments containing comparisons repeatedly reparsed the same input. Dynamic
slice bounds now use the same arithmetic precedence as ordinary expressions.

## Validation

The actual parent failed all four initial regression tests. Its CLI parsed all
three complete primary files successfully; the failure was incorrect expression
structure rather than inability to read the files. The final parser retains
those exact counts: 1,604 instructions, 960 definitions and 926 register
specifications. The selected 562 FP/SIMD decode blocks also parse and retain
all source encoding names in order. Parsing success does not establish correct
architectural instruction execution.

Seven new tests cover all 438 cross-class operator pairs, 1,152 explicitly
parenthesized pairs, unary operands, arithmetic, all 16 field combinations of
the allocation predicate, concatenation and dynamic slices, 121 arithmetic
operator pairs inside slices, restored indentation and following definitions,
incomplete input, and 32 nested comparisons. The initial rollback-only change
hit a 2 s observation limit at nesting depth 20; the final remembered-failure
implementation parsed depths 4 through 32 successfully. These single process
samples are regression evidence, not throughput measurements.

The entire standalone package passed with default features and again with
`serde`: 69 passed, 0 failed and 1 ignored documentation example per selection.
The binary unit-test target has no tests; it is not counted as semantic coverage.
All-target Clippy with `serde`, formatting of the five owned Rust files, and
Git whitespace checks passed. Existing package warnings remain.

Commands ran with `--locked --offline`, the fixed Rust 1.99.1 toolchain, one
explicit task target directory, one build job and incremental compilation off.
Exact commands, environment, parent failures, source freeze, CLI output and
process exit receipts are retained under
`/Users/int/dev/rax-audit-work/four-findings-aarch64-private-state/asl-precedence-repair/`.
`source-freeze-v1.json` and `primary-final-v1.json` bind validation to the
qualified source and executable. The shared task cache is removed after commit.

## Assumption register and scope

| ID | Assumption and dependent result | Basis and falsification probe | Status |
|---|---|---|---|
| AP1 | Supported legacy spellings use Arm precedence classes; expression binding and later decode derivation depend on this. | Primary section 4.4.5 plus complete operator-pair AST checks, field truth tables and unchanged primary parse counts. A disagreeing AST or lost primary construct falsifies the result. | Confirmed within the tested classes and stated legacy compatibility. |

Pratt parsing of an unambiguous expression visits its N tokens linearly. A
lexer checkpoint copies indentation and pending-token state, not source bytes.
There are at most N distinct remembered failed angle positions, using O(N)
entries; each failed position is attempted once. This removes repeated failed
speculation at the same position. No general throughput bound is claimed for
the whole language parser; other grammar paths and allocation costs remain.

**High impact:** prior generated corpora have not been regenerated or
requalified. Complete FP/SIMD allocation and all four full audit findings
remain open. This tool repair supplies a prerequisite, not runtime remediation.

**Medium impact:** full ASL1 ambiguity rejection, type checking and new operator
spellings remain outside this legacy parser repair. They do not block the
specified binding tests or parsing of the pinned primary files.

CPU runtime, backend state formats, C ABI, SMP scheduling and HVF production
source are unchanged. Their broad runtime and native-host gates were not rerun
for this standalone parser change. The original checkout, its untracked files
and running guests remain untouched.
