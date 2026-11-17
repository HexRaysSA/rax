# Pinned compiler source-cell witnesses

The C++ oracle reads actual pinned Clang AST declarations and ASTRecordLayout.
The Python evaluator independently resolves 31 source paths; 17 hand-authored
relations and five equal-offset comparisons check its results on x86-64/Linux
and AArch64/Linux. The billion-element array is represented by one symbolic
axis, not a loop over elements. Source positions are UTF-8 byte offsets; geometry
is in bits. These are static compiler observations, never guest execution.

Build and test from the repository root:

```
python3 -B tools/smir-llvm-contract/source_cell_witness.py build \
  --llvm /Users/int/dev/llvm-project --output /tmp/source-cell-oracle-build
cd tools/smir-llvm-contract
SMIR_SOURCE_CELL_ORACLE=/tmp/source-cell-oracle-build/source-cell-oracle \
  python3 -B -m unittest test_source_cell_witness -v
SMIR_SOURCE_CELL_ORACLE=/tmp/source-cell-oracle-build/source-cell-oracle \
  python3 -B -O -m unittest test_source_cell_witness -v
```

Compiler and LLVM revision mismatches fail. There is no silent fallback/skip.
The schema is the exact local grammar in `llvm/source-cell-witness.schema.json`.
All authority flags are false. Public witness hashes are provenance, not actual
SourceStamp, ABI site, TUUID, private source fact or runtime identity.

| Source pattern | Expected identity |
| --- | --- |
| Two inheritance routes to D's virtual V | Equal within D's most-derived domain |
| Two nonvirtual copies of V | Distinct declaration paths |
| Separate D members / D array elements | Separate most-derived domains |
| Empty bases, NUA members, union alternatives at equal offsets | Distinct source cells |
| Complete versus nonvirtual root | Explicit view tags; no view conversion |
| Unknown enclosing most-derived domain at a nonvirtual root | No virtual key/geometry |

A member/record-array-element reached before a virtual edge establishes a known
most-derived class domain. A missing earlier virtual prefix stays unavailable,
even if a later member is encountered. Every later represented malformed edge
still rejects. Declaration qualifiers are recorded; effective expression cv,
mutable access, actual union activity and language lifetime legality are separate.

Scope: root selectors name actual main-file record declarations. Arrays come from
their actual field types. Root variable/primitive/array declarations, templates,
macro declarations and external record definitions are outside this local oracle
surface; no runtime pointer/alias or canonical allocation is inferred. Named and
zero-width bit-fields remain raw compiler observations; addressable-path queries
to them refuse `CELL_BITFIELD_SCOPE`. Oracle scope refusal is distinct from an
actual Clang syntax/type rejection. The ABI source-path resolver has its own
original-RootContext namespaces, portable layout validation and broader subject
coverage; this tool does not replace it.

Assumptions and probes: stable source/compiler context plus source declaration
positions (cross-context keys and deterministic normal/O output); exact AST base
flags/ordinals (wrong-index/flag tests); class-owner reset (members/2x3 arrays);
offsets do not identify cells (five equal-offset pairs); symbolic bounds (1e9,
singleton, zero/bool/out-of-range rejection). Context keys occur in both canonical
and owner patterns. Distinct compiler contexts are distinct witness namespaces.

Traversal is O(raw graph rows plus selected path edges); relation is O(axes).
Compiler frontend/build complexity is separate. Input source is bounded to 1 MiB,
records to 256, type visits to 32768, query steps to 128, axes to 16 and queries
to 4096. Compiler subprocesses have timeouts. Build receipts hash the compiler,
non-system headers and static Clang/existing LLVM libraries before/after. System
SDK/toolchain are not fully attested. Primary identity/license/checksums are in
`provenance.json`; the integrator archives original source files.

High: physical overlap does not establish source identity. Medium: most-derived
class occurrence is separate from allocation/storage ownership. Low: static
target geometry does not admit ABI adjustments, source aliases, live objects,
foreign C++ boundaries, native SMIR, JIT or compiler emission.
