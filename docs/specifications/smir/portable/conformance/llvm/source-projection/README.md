# Pinned original-source projection reference

This package runs two actual pinned Clang AST tools, checks their typed graph
bijection, and derives portable source layouts with the independent existing ABI
model. It constructs a fresh no-code ten-root reference module and runs the
original retained RootContext ABI/execution checks, separate complete reference
linking checks, and same-ledger original source afterguards. A successful report
is immutable UNBOUND data with both authority fields false. It is not a private
Type/ABI/SourceFact, LLVM backend, callable C++ object, or runtime admission.

Build outside both source checkouts:

```
python3 -B tools/smir-llvm-contract/source_projection.py build \
  --llvm /path/to/pinned/llvm-project --output /tmp/new-projection-build
```

The output names `record` and `sidecar` binaries. Pass these paths explicitly:

```
python3 -B tools/smir-llvm-contract/source_projection.py project \
  --request docs/specifications/smir/portable/conformance/llvm/source-projection/coordinates.json \
  --source docs/specifications/smir/portable/conformance/llvm/source-projection/records.cpp \
  --record-oracle /tmp/new-projection-build/record/record-input-witness \
  --sidecar /tmp/new-projection-build/source-projection-sidecar
```

`SMIR_SOURCE_PROJECTION_DIR` selects an optional scratch parent; otherwise the
standard temporary directory honors caller TMPDIR. No consumer writes another
role's coordination directory by default. Build receipt/source/library/binary
identities must match; absence or mismatch is an error, never a skipped test or
native fallback. Compiler subprocess output is read in bounded chunks and capped;
compiler timeouts/resource failures produce no partial result.

From tools/smir-llvm-contract run:

```
python3 -B -m unittest test_source_projection -v
python3 -B -O -m unittest test_source_projection -v
```

`SMIR_SOURCE_PROJECTION_ORACLES` can name the actual build-output JSON to reuse
its binaries; `SMIR_SOURCE_PROJECTION_TEST_DIR` selects the test artifact parent.
Otherwise the tests build actual tools in caller temporary storage. The CLI test
actually invokes both normal and optimized Python child processes and compares
complete output bytes; no compiler or original verifier success is mocked.

The exact closed schema is llvm/source-projection.schema.json, including explicit
pins of the six consumed source schemas. The native sidecar's GitOID40 differs
from SHA-256 identities. Bool precision is1bit with1B object storage. The ten
integer builtin identities come from AST enum kinds; native type spelling is
inspection text. References retain source category despite DataPtr transport.
Records use existing Array(Raw8,portable_size) storage. Incomplete named pointees
have no invented object layout. The actual module has zero functions/symbols/
imports/segments/entrypoints; primitive/record source geometry is not execution.

`coordinates.json` supplies explicit family/minor/personality/site/domain/logical
unit/library/TUUID coordinates. The zero compiler/runtime/build/library domain
identifiers are intentionally opaque SOURCE-AUTHOR TEST LABELS with unknown
artifact provenance; they do not attest actual deployed artifacts. Actual compiler
and oracle hashes are separately observed in output/build receipts. Unit identity
uses the accepted logical unit key and full module family, not source/site hashes.
Named anonymous-namespace and local classes keep actual underlying linkage and
canonical declaration offsets; same-name local classes remain distinct. Qualified
uses retain a single canonical source class identity. No native mangle is used.

`expected.json` contains independently authored geometry/offset expectations.
The source exercises scalar/Bool, nested multidimensional records, NUA empty
members, nonvirtual bases/tail padding, unions, private/local identity, qualified
pointees, incomplete forward declarations, a real lvalue-reference field and a
void pointer. Rvalue-reference field and deleted/unresolved copy examples are
negative because the actual seven-predicate finite copy/destroy profile refuses
them. Those flags are not callable lifecycle permits.

Scope is header-free main-file C++23 at pinned x86_64-linux AST target, same fixed
options in both tools. No plain char, templates, macros, external/unnamed records,
user methods, dynamic/virtual classes, bit-fields, code/member pointers, enum,
_BitInt/vector/atomic/extended FP or C23 projection is claimed. The new tool does
not expand array elements; the primitive1e9-element witness checks bounded ledger
work and constant graph size. Existing independent layout model costs remain
explicit: empty-subobject placement can require charged walks and resource refusal.
No constant-time general record-layout claim is made.

Before/after source/schema/compiler/build identities and genuine canonical quota
checks are mandatory. Tests exercise actual malformed source vs unsupported scope,
copy eligibility, closed schemas, bool-as-ID and Git-width errors, wrong coordinates,
source mutation at the actual afterguard, zero quota before process creation,
wrong schema/binary, input/output immutability and original-owner identity. Primary
sources and licenses are archived through the integrator; system SDK/shared-library
attestation is limited as recorded in build receipts. No native guest/JIT/parallel/
hosted-library/foreign C++ or compiler-freeze qualification follows.

The public `project` reader conservatively refuses any raw `#`, `%:` or `??=`;
any backslash followed by zero or more bytes from space/tab/vertical-tab/form-feed
and then CR or LF; and existing double-underscore reserved tokens. It rejects
these sequences inside comments, ordinary strings and raw strings as well.
This finite byte policy runs before either native tool invocation; it is not a
complete C++ lexer. A header-controlled array bound previously passed the
line-start `#` filter via `%:include`; the public reader now refuses both header
contents before compilation. Standalone legacy raw native oracles are unchanged
and do not inherit this public main-buffer policy.

The original canonical budget charges `work=8*source_bytes+1` and
`copied_bytes=256` before the predicate. A failed charge retains its original
resource exception and starts no compiler process. No quota is enlarged or reset.
The predicate has O(n) work and O(1) auxiliary storage apart from the existing
bounded input and regex implementation. The two pure `ProjectionWireSchema`
methods run without LLVM or native oracles; twenty other methods use genuine
native tools. The new cases include header-array counts4/8, introducers/splices,
conservative literal/comment boundaries and exact original-ledger precharge.

The wrapper is itself an input to the native-pair build receipt. A wrapper edit
therefore requires a fresh actual build of both record and sidecar tools, even
when their C++ sources/options are unchanged. Old receipts are historical and
must not be repinned, pruned or silently reused after this change. Native receipts
and public observations remain unsigned local provenance, without complete
OS/SDK/shared-library/input attestation, source-object authority or execution.
