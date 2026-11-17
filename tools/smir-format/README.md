# Portable SMIR framing and contract accounting tools

These tools implement the legacy experimental 0.1 envelope and separate candidate
0.2/profile 2 framing described in
[the specification](../../docs/specifications/smir/portable/README.md).
The framing and record codecs check representation. The explicitly scoped
reference-validation command composes the actual role-owned ABI, execution and
runtime validators. None of these tools admits production portable execution.

Run from the repository root:

```sh
python3 tools/smir-format/check_spec.py
python3 -m unittest discover -s tools/smir-format -p 'test_*.py' -v
python3 tools/smir-format/codec.py encode module.json --output module.smo
python3 tools/smir-format/codec.py inspect module.smo
python3 tools/smir-format/codec.py encode-candidate candidate.json --output candidate.smo
python3 tools/smir-format/codec.py inspect-candidate candidate.smo
python3 tools/smir-format/codec.py verify-candidate-reference candidate.smo --capability memory
python3 -B tools/smir-format/codec.py run-candidate-reference \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/call42.smo \
  --entry-function 1 --argument-bits 2a000000 \
  --reference-policy docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/policy.json
python3 -B tools/smir-format/smir.py assemble \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/source.json \
  --output /tmp/call42.smo
python3 -B tools/smir-format/smir.py disassemble /tmp/call42.smo --output /tmp/call42.json
```

Encoder JSON contains `kind` (1 object, 2 image), optional `entry` (default
4294967295, no entry), and `sections`, each containing integer `kind`, boolean
`required` and payload `hex`. The golden fixtures additionally wrap this input
as `module` and include independently audited `encoded_hex`.

Candidate framing requires all semantic section IDs 1 through 10, including the
ABI contract at 10. Legacy commands accept only 0.1/profile 1; candidate commands
accept only 0.2/profile 2. No automatic revision conversion occurs. The Rust and
C++ APIs expose separate unverified candidate result types. Empty section payloads
can pass framing and remain invalid executable roots. Candidate framing fixtures
live under `conformance/envelope/candidate/`.

The active root revisions, for section IDs 1 through 10, are
`2 2 2 1 2 1 1 1 1 3`; envelope 0.2/profile 2 remains unchanged. The codec checks
the leading revision word before parsing changed fields. Incompatible old roots
produce `WIRE-REVISION`; there is no inferred upgrade. This cut includes explicit
source call plans, `CodeAddress`, and V3 nominal shape identity. Earlier test
receipts qualify their recorded source cuts.

`verify-candidate-reference` requires complete executable root records, checks
content identity and header/manifest agreement, and composes actual semantic
validators and a single-module deployment plan. Grants come from the repeated
`--capability` options; artifact declarations cannot grant themselves access.
Its initial reference scope rejects external dependencies, COMDAT, native/host
registrations and extra feature requirements explicitly. The JSON report includes
`reference_verified: true` and `production_admitted: false`; it contains no
executable admission token. The identity, service-wrapper and source-storage/TLS
tests exercise this command with complete ten-root candidates and semantic
rejections. Cross-role schema edits require fresh coherent receipts.

`run-candidate-reference` decodes and checks content identity for all ten roots,
invokes the actual ABI and execution verifiers, admits a local module through the
source-backed runtime registry, and executes the actual reference Machine. The
example returns `reference-return`, `bits_le: "2a000000"`, and
`production_admitted: false`. The caller performs a nonnull `code_bind` and an
indirect source call into the identity function. Entry 0 exercises the identity
function directly; changing its argument changes its result.

The required policy file supplies fuel, maximum frames, all four source query
budget dimensions and all five registry quotas. It rejects unknown/duplicate
fields, Boolean counts and negative counts. Public entry parameters and results
are integers of 1 through 64 bits. Each `--argument-bits` supplies exactly
`ceil(width / 8)` little-endian bytes in lowercase hexadecimal; unused high bits
must be zero. Thus Int1 accepts `00` or `01`, and Int9 accepts `ff01` but rejects
`0002`. Void entries take no arguments, and multiple integer results retain their
individual widths. Integer signedness follows the operation, not the text format.
Opaque pointers and code addresses cannot enter or leave through these arguments
or reports. Internal generic calls retain their verified scalar types. Ordinary source
calls support the exact named C23/C++23 signed and unsigned `char`, `short`,
`int`, `long` and `long long` builtin contracts at 8, 16, 32 and 64 bits,
with direct parameters and a scalar or canonical void result. Here `char` means
explicit `signed char` or `unsigned char`; plain `char` remains unsupported.
Source identity, signedness, layout, call-plan and `noundef` checks remain
mandatory even when two source types share a physical integer width. Every
function association, binding plan and source-call plan is checked before the
Machine is constructed. Internal ordinary source pointers support the ten named
integer pointees and `void`, without qualifiers or pointer chains. Every defined
internal DataPtr is Null, produced by typed zero or the existing freeze
refinement; original poison, undef and `noundef` behavior remains observable.
DataPtr bits literals, bitcasts in either direction, integer conversions, address
producers, dereferences and ordered comparisons are refused before the registry
or Machine is constructed. Public parameters and results remain integers. This
finite subset excludes `Some(void)` plans, hidden parameters, varargs,
aggregate/FP source boundaries and native adapters.
The retained source-bound `long` witness is runnable directly:

```sh
python3 -B tools/smir-format/smir.py run \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/ordinary-scalars/long64-source.smo \
  --entry-function 1 --argument-bits ffffffffffffffff \
  --reference-policy docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/policy.json
```

It returns `bits_le: "ffffffffffffffff"` in seven guest steps through a real
source address, binding and indirect call. Twenty-seven public source/CLI methods pass in both normal and optimized
child modes on the recorded 3028-file source cut, including the original 19 and
eight internal Null-pointer methods. All 106 process audits per mode report no
drift or unwatched inputs; the original seven byte-CLI methods also pass in both
modes. This
is finite sequential reference execution; production and compiler gates remain
separate.

The explicit Null wrapper retains the original source-pointer function, call
plan and diamond phi, and adds a distinct integer-result entry:

```sh
python3 -B tools/smir-format/smir.py run \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/null-data/null-diamond.smo \
  --entry-function 1 \
  --reference-policy docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/policy.json
```

It returns `bits_le: "01"` in 14 guest steps through actual address creation,
binding, indirect source entry and completion. The wrapper changes the module's
bytes and identity. The preserved original pointer-entry object remains a static
verification witness. This command issues no memory or pointer-access authority.

All function bodies must pass the closed scalar preflight before execution.
This command supports normal local calls, integer/raw scalar operations and
code-address binding. Storage, imports, dependencies, native domains, source
unwinding, vector groups and generic indirect entry are explicitly unavailable.
Resource refusal and faults return structured diagnostics with a nonzero exit
status. No serialized report grants callable authority, and this reference command
does not run the production RAX engine or a JIT.

The independently retained wide-integer object adds one modulo `2^64`:

```sh
python3 -B tools/smir-format/smir.py run \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/integers/add64.smo \
  --entry-function 2 --argument-bits ffffffffffffffff \
  --reference-policy docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/policy.json
```

It returns `0000000000000000` in four guest steps. Its editable input is
`integers/add64.json`; assembling it preserves the original object bytes.

`smir.py assemble` accepts an editable UTF-8 JSON object containing exactly `sections`
(the ten root records keyed by strings `"1"` through `"10"`) and optional
`metadata` (opaque optional envelope sections). It derives the envelope kind and
entry from the required manifest, emits canonical records and computes content
identity. `disassemble` checks identity and preserves all records and opaque
metadata; reassembly reproduces the same bytes. Both commands check representation
and grant no semantic admission. A malformed SSA program can assemble, then must
fail admission before execution. Input and output must be different files.
`smir.py run` and `smir.py verify` forward the existing reference commands and
retain their explicit policy/grant requirements. Source JSON reads are bounded
to 64 MiB; binary reads and record parsing retain the codec's own bounds.

Run the byte-to-result conformance tests with:

```sh
python3 -B docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/test_reference_cli.py -v
```

The Python `RecordCodec`, Rust `records::Codec` and independent C++ `records::Codec` implement bounded
ordered records, token variants and explicit options. Tests compile schema tables
from each role's candidate JSON, compare decoded values and canonical encoding,
and cover all record variants, the complete ABI fixture and rejection partitions.
Those are representation witnesses; the role verifiers separately check meaning.
Candidate schemas are active contract work and are not frozen by codec agreement.

When compiled with the generated test schema, `cpp_probe.cpp --candidate-records`
accepts a candidate file and independently decodes and canonically re-encodes all
ten roots. It reports `status: decoded-records` and `executable_admitted: false`.
This mode checks framing, payload revisions and ordered representation; content
identity and semantic verification remain separate checks. The unit tests compile
this mode and explicitly exercise that evidence boundary.

The cross-codec tests require Rust 2024 and fail if the compiler/probe cannot
run; they do not silently skip a missing dependency. Files and executables are
temporary. Randomized mutations use seed `0x534d4952`.

For a macOS installation whose default Clang lacks a usable SDK/header setup,
select the configured Apple compiler explicitly:

```sh
CXX=/usr/bin/clang++ python3 -m unittest discover -s tools/smir-format -p 'test_*.py' -v
```

The C++ probe requires a C++20 compiler. Missing compiler/SDK support is a test
failure, not a skipped comparison.

Python JSON encoding rejects Boolean integer IDs, non-Boolean `required` flags,
non-array sections and out-of-range integer fields. C++ encoding is independent
and checked for exact byte equality on each accepted cross-codec input; its
boundary harness also covers sorting, duplicate kinds and allocation limits.
The explicit `conformance/envelope/` corpus includes expected rejection codes
and rationales, in addition to the original golden framing fixtures.

`check_spec.py` checks evidence accounting and reports the compiler gate state.
Use `--require-compiler-freeze` for an actual exit-status gate: it currently fails
because full compiler-facing contracts are incomplete. Seventeen gate regression
tests exercise stale hashes, missing coverage/acknowledgements, skipped witnesses,
case partitions, invalid counts, duplicate JSON keys and path escapes. Four
additional state tests cover withdrawn accounting, contradictory active-digest
claims and the strict active-candidate path. A passing
normal accounting check is not compiler or runtime conformance.

When the manifest explicitly records a withdrawn candidate and no current
candidate, archived component hashes and receipts remain historical. The checker
validates the current registry/schema representation and reports an incomplete
gate; `--require-compiler-freeze` fails. It does not repin the old candidate or
reuse its reviews. An active candidate still requires every exact artifact,
receipt, inventory and named review check.

Compiler accounting revision 2 selects `candidate-registry.json`, including all
ten payload roots and the ABI contract. Schema review states and schema/registry
artifact hashes must qualify alongside every existing component, witness and
cross-role decision. The legacy 0.1 registry retains opaque payload semantics.
