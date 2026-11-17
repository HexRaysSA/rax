# Portable C23 record frontend, finite draft r1

This working declaration frontend uses real Clang ASTRecordLayout with the portable TargetInfo at LLVM pin `36763294ef639d8a6a4379d81da653dda1c20686`. It emits closed execution-type and ABI3 nominal/layout/call-plan fragments. The installed scalar frontend's TargetInfo and factory blocks are reused byte for byte and verified before compilation. No host TargetInfo supplies portable geometry. All products remain `unbound`, with source facts, library membership, admission and runtime authority explicitly false.

The owncoord draft requires an absolute `SMIR_RECORD_FRONTEND_FOUNDATION` selecting the ABI/execution tools and schemas. Installed layout derives the repository root; there is no workspace search or fallback. Build outputs must be new directories outside both checkouts. Example:

```sh
export SMIR_RECORD_FRONTEND_FOUNDATION=/Users/int/dev/rax3
python3 -B portable_record_build.py --llvm /Users/int/dev/llvm-project --output /tmp/portable-record-build
python3 -B portable_record_build.py --llvm /Users/int/dev/llvm-project --output /tmp/portable-record-build-opt --optimize
python3 -B portable_record_project.py --native /tmp/portable-record-build/portable-record-frontend --build-receipt /tmp/portable-record-build/build-receipt.json --request request.json > product.json
```

The request has exactly `language` (`c23` or `cpp23`) and `source` (nonempty ASCII, no NUL, at most 1 MiB). For example:

```json
{"language":"c23","source":"struct R { char a; int b; }; struct R copy(struct R, unsigned char);"}
```

With a build receipt the wrapper checks the recorded native build inputs and binary before and after invocation. A failed parse publishes no product; native failures require empty stdout. Without a receipt an explicitly selected binary yields only an unbound observation. Current native builds use the existing pinned static Clang libraries on AArch64 macOS, with a private archive copy excluding the ordinary TargetInfo factory. The LLVM checkout and original archive remain unchanged. This does not establish another host, clean LLVM rebuild, full SDK attestation or guest execution.

## Record contract

Named complete C23 translation-unit structs and unions support 1–64 named ordinary fields: scalar, enum, C23 BitInt, fixed arrays, named records, data/function pointers and the inherited finite numeric vector profile. Record extent is 1–65536 B including tail padding; explicit alignment is a power of two through 65536 B. Types are bounded to 512 canonical nodes and depth 32. Qualifiers and aliases use the actual canonical AST. Self pointers retain their actual source identity.

Actual size, alignment and every field offset are compared against the independent existing `CheckedRecords` calculator before the projector publishes a product. A disagreement produces `PORTABLE_RECORD_LAYOUT_MISMATCH`; geometry is never repaired. Ordinary field width is storage width, so BitInt65 occupies 128 field bits with 8 B alignment. Nested arrays use full element size including tail padding. Unions put every field at bit offset zero and round maximum extent to aggregate alignment.

C metadata uses `data_size = nonvirtual_size = size` and `nonvirtual_align = align`. Raw AST data size is separately reported in `record_observations`; C++-only AST accessors are not used on C records. C++ source trait booleans in record_input are all false, while nominal trivial-copy/destruction flags describe ordinary C value copying. No C++ tail-padding reuse is inferred.

Every record has storage representation `Raw(size*8)` within the current executable width limit of 2^23 bits. The 64 KiB record cap yields 524288 bits. This establishes a storage-type projection, not wider Raw source operation support.

Every by-value record or union parameter is `indirect_copy`, including one-byte aggregates. Every record result uses the first lowered argument as `sret`; it has no execution result. The pointer is obtained from actual ASTContext canonical type construction and points to the exact source record type. `abi_derivations` records each lowering edge. Type relation origins distinguish actual source observation from ABI construction; the same canonical pointer may have both origins. Direct scalar byte parameters/results have noundef=false; indirect pointer arguments have noundef=true. Copy/move/destroy hooks are null for these ordinary C records. Logical copy plans do not establish runtime allocations or effects.

Anonymous records/fields, bitfields (including zero-width), flexible/incomplete arrays, incomplete or empty records, packing, unsupported attributes, C++ classes, references/member pointers, function bodies, templates, variadic types and va_list source use are unavailable before any product. Alignment below natural alignment is rejected by the independent portable layout policy. The pinned Clang rejects BitInt enum underlying types; an explicit negative witness records that upstream gap. Large BitInt ordinary fields are independently exercised.

## Inherited scalar and source profile

LP64 little-endian pointers/long are 64 bits. Plain char is signed; bool has one value bit and one storage byte. Int128 alignment is 16 B. Long double is binary128, precision 113 bits, storage/alignment 16 B. C23 BitInt supports unsigned 1–65535 and signed 2–65535 bits: q=ceil(N/8) B, A=min(8 B,next_power_of_two(q)), S=A*ceil(q/A). Numeric vector lanes are Int8 where scalar byte types and byte-array elements are Raw8; vectors require builtin arithmetic lanes, power-of-two extent at most 64 B. Three-lane vectors remain unavailable in this narrower profile.

The inherited pre-use enum hook selects the first representing int/unsigned int/long/unsigned long, including C23 all-member enum typing. Its unfixed initializer grammar permits integer literals, unary sign and implicit successive values, excluding arbitrary expressions/type queries. Fixed enums retain their actual supported explicit base. C++ scalar/enumeration declarations remain supported; C++ records do not.

Source is an isolated memory VFS file with mtime and SourceDateEpoch zero. Includes, macro actions, line actions and pragmas reject. There is no header manifest, closed CPP06/07 recipe or genuine std::byte declaration membership. Ordinary atomic lock-free macros and builtin queries remain zero; no parallel atomic runtime is implied. The internal va_list placeholder cannot be source-observed.

## Checks and limits

The closed request/projection schemas derive ABI/execution subrecords from current ordered grammars. Existing ABI codecs, independent execution Types/wire and the separate geometry/plan checker validate the fragments. `test_portable_record.py` is a standard-library-only discovery entry and launches `_portable_record_cases.py` in an isolated child. The 67 actual native cases cover inherited scalars plus record layout, boundaries, aggregate passing, typed rejections and forged metadata. A missing explicit native profile yields one unavailable skip. PID, source, Python optimization, absent cache and parent module identities are checked; loader filters that match no tests launch no child.

The suite includes actual source sizeof/alignof/offsetof assertions and independent calculations, with both O0 and O2/NDEBUG native builds and normal/optimized Python. Qualification receipts, rather than this document, record observed results and exact guarded inputs. Relocation checks use copied tools/schemas in a path with spaces, hostile PYTHONPATH, and missing/relative-foundation refusals. Independent geometry and plan checks share the existing nominal fingerprint implementation; this is not a second hash oracle.

Native closure costs O(N+(V+E)log V) excluding Clang parsing/Sema/rendering. Projection is O(V+E) excluding nominal hashing; sealing all roots can require O(V^2*(V+E)log V) work. Storage is O(V+E+label bytes) excluding Clang. Input/output limits and deadlines are reference bounds; the current output size check occurs after subprocess capture. Canonical all-outcome resource accounting and hostile-process memory quotas remain absent.

No source/private issuer, complete module, body lowering, backend, interpreter/JIT, wider Raw source transport, hosted library, foreign C++/EH, parallel execution or full-platform qualification follows from this package. Cross-role ACKs and a new explicit Root path map are required before shared adoption.
