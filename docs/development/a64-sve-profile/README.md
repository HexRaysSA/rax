# Selected SVE admission and normal-execution profile controls

This semantic group is qualified within the software and host scope below.
All four full audit findings remain incomplete.

The pinned Arm A-profile ISA XML revision 2025-12 contains 1,328 canonical
major-2 instruction classes in 894 documents. The generator derives 1,145
classes over 148,146 decode assignments. It accounts separately for 183 classes
whose feature predicates cannot be satisfied by a represented extension set.
No unknown dependent decode construct is accepted implicitly.

The generated table contains 3,303 positive capability clauses, partitioned into
256 buckets with 8,095 entries. Independent tooling checks that each emitted
bucket contains exactly its applicable clauses. Every generated compressed
clause set is checked against every enumerated primary decode assignment.

Instruction allocation, selected capabilities and execution-time access checks
are separate. Missing optional capabilities reject before access traps. Native
admission retains a satisfied capability clause from each original word before
optimization, including the SVE2p1 guard selecting normal access for conditional
predicate instructions, and capability changes alter the native cache key. Scalar SME
length instructions and conditional streaming-predicate instructions retain
their distinct access policies.

`SVE2_AES` selects both `FEAT_SVE_AES` and `FEAT_SVE_PMULL128`. Arm
109697_2025_12_en pages 119-120 makes these features mutually dependent. The
initial proposal for independent flags was falsified by that primary source;
its raw results remain preserved as superseded evidence. The corrected model
uses 13 selectable Boolean parameters and one primary-name alias. Existing
flag positions and the 64-bit feature representation remain unchanged.

## Reproduction

Build the existing ASL parser with its `serde` feature using the repository's
explicit shared Cargo target directory. Then verify the generated table:

```sh
python3 -B tools/execution/a64_sve_admission.py --parser "$CARGO_TARGET_DIR/debug/asl-parser"
python3 -B tools/execution/a64_fpsimd_allocation_tests.py
python3 -B tools/execution/a64_sve_admission_tests.py
python3 -B tools/testgen/a64_sve_dot_expectations.py
```

Generation uses the primary XML package under
`docs/specifications/arm/a64-sve-2025-12/`. Its provenance records the canonical
vendor URL, revision, retained notice, original and reduced archive checksums,
and each retained document's checksum. The saved-intermediate `--ast` path is
accepted only for the pinned normalized source and exact qualified AST hash.

The independent QEMU access and scalar-value oracles use the existing EL3 guest
template and explicit output and scratch directories:

```sh
python3 -B tools/execution/a64_sve_profile_oracle.py \
  --output "$EVIDENCE_ROOT/access" --scratch "$BUILD_TMP" \
  --llvm-mc "$LLVM_MC" --ld-lld "$LD_LLD" --qemu "$QEMU_AARCH64"
python3 -B tools/execution/a64_sve_profile_oracle.py --scalar-values \
  --output "$EVIDENCE_ROOT/values" --scratch "$BUILD_TMP" \
  --llvm-mc "$LLVM_MC" --ld-lld "$LD_LLD" --qemu "$QEMU_AARCH64"
python3 -B tools/execution/a64_sve_profile_oracle.py --conditional-predicates \
  --output "$EVIDENCE_ROOT/predicates" --scratch "$BUILD_TMP" \
  --llvm-mc "$LLVM_MC" --ld-lld "$LD_LLD" --qemu "$QEMU_AARCH64"
```

The current QEMU run passed 51 access/profile cases, 24 scalar-value cases and
four conditional-predicate access cases.
The scalar cases cover signed immediate endpoints, 64-bit wrap, overlapping
registers and SP/XZR semantics with SVL=128 bits. These are independent software
execution results; physical SVE/SME execution is unverified. The QEMU `max`
profile has optional capabilities enabled. Individual optional-feature absence
is checked against primary predicates and focused RAX regressions.

## Validation and remaining qualification

The corrected model passed 35 tooling tests and complete primary derivation /
byte-identical regeneration checks. The historical 879-encoding LLVM sweep
maps to 878 represented entries; the remaining `FMMLA .D` form requires
`FEAT_F64MM`, which is not represented by the configured feature set. This is
allocation/profile evidence and does not assert numerical execution coverage.

The focused Rust admission suite passed 17 tests, including replay of all 51
independent access cases and 24 independent scalar value cases. A real pre-fix
run passed 14 tests and failed the scalar-value replay: `RDSVL X0,#-32` left X0
at zero instead of `0xfffffffffffffe00`. The dedicated scalar handler now
implements RDSVL, ADDSVL and ADDSPL at the fixed implemented SVL of 128 bits,
checks SME permissions, handles SP/XZR correctly, and preserves vector/FP state.

For this implementation, SVL=128 bits gives a vector length of 128/8=16 bytes
and a predicate length of 128/64=2 bytes. Sign-extending the six-bit immediate
gives an integer in [-32,31]. The vector-length displacement is therefore
[-512,496] bytes; the predicate-length displacement is [-64,62] bytes. Address
addition wraps modulo 2^64. These are exact integer operations.

A second real regression passed 16 tests and failed the native admission guard:
an SME2 allocation alternative omitted the SVE2p1 dependency selecting normal
SVE access. The corrected guard rejects an existing region after that feature is
removed. This test carries original SVE admission requirements on a real integer
native positive-control region; it does not execute SVE instructions natively.
This group adds no SVE/SME SMIR lifting. The existing stateless decoder remains
partial, and the lifter retains its unsupported-instruction behavior.

The existing AArch64 CPU test module passed all 342 tests after correcting six
missing capability selections and an unallocated `.Q` DUPQ test input. Its
reserved cases retain their Undefined assertions, and a separate LLVM-encoded
`.D` DUPQ positive control remains reachable.

The first complete ARM integration run exposed 68 historical SDOT/UDOT fixture
assertions that expected allocation for unavailable forms. The pinned base-SVE
diagrams allocate 32/64-bit destinations; a distinct 16-bit form requires
SVE2p3 or SME2p3, absent from that helper profile. A focused correction generator
validates the primary diagrams and 52 independent QEMU observations before
changing those assertions to require Undefined. It preserves all 12 legal
positive test bodies byte for byte. The original full-corpus input and revision
remain unknown; this is a reproducible focused correction. The interpreter
was unchanged, and the completed library result remains valid for its frozen
sources. All corrected owning integration binaries passed.
Across the four oracle matrices, all 131 independent QEMU executions passed.

Three actual file-restoration tests passed for both two and four CPUs. They
preserve selected capability bits and controls, distinguish Undefined from an
SVE access trap before retirement, resume each handler exactly once, and execute
scalar SME instructions with normal SVE present or absent. These use complete
128 MiB fixtures and actual save/load/restore calls. Both private backend
restoration tests also passed; their earlier mistyped zero-test filter is
explicitly excluded from validation evidence.

The full unfiltered serial library passed 11,351 tests with 2 ignored. All 47,875 tests
across the 27 owning integration binaries passed, as did all 223 C API tests. Workspace
formatting, Clippy, all-target build, interpreter-only checking and x86-64
cross-checking passed. The doctest command executed zero tests and ignored five. The two
ignored library tests require an external microkernel fixture; they did not execute.
Cross-checking and software tests do not establish physical Intel or SVE/SME execution.
All four full audit findings remain open. Full streaming mode, ZA state, feature
dependency/ID/system-register consistency, unrepresented extensions, security/debug
controls and complete backend/private/in-flight requirements still require work.
Physical SVE/SME/A32 and physical Intel HVF validation remain unverified.

The generated runtime lookup uses at most 207 clause checks per lookup. Runtime
performance has not been measured. For a class with `d` relevant bits, decode
enumeration costs `O(2^d)` executions of its retained decode slice. Exact prime
cube compression has an exponential worst case; the emitted bucket lookup
avoids running derivation during guest execution.
