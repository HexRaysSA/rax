# Actual portable type frontend, finite draft r1

This package builds a real out-of-tree Clang TargetInfo and FrontendAction against LLVM source pin `36763294ef639d8a6a4379d81da653dda1c20686`. It parses the original source with the portable LP64/little-endian target, then produces execution type records and ABI3 nominal/layout/call-signature fragments from the actual canonical AST. It never uses a host TargetInfo as the portable target. This is a working declaration/type facet; no function body, backend, TargetMachine, guest execution or source authority is implemented.

All products explicitly say `unbound` and grant no source facts, library membership, semantic admission or runtime authority. Existing source ABI2 admission remains unavailable. The public JSON result cannot become a private source receipt by re-reading it. Complete original module contribution, genuine SourceEvidencePolicy owner/epoch/module qualification, CPP06/07 recipe registration and private issuer require separately assigned implementation.

## Build and run

Installed tools derive the foundation from their repository root. Owncoord drafts require the explicit absolute environment variable `SMIR_TYPE_FRONTEND_FOUNDATION`; there is no workspace search or hardcoded fallback. The selected foundation must contain the exact ABI/execution tools and target schemas and is included in the qualification input guards. For this draft set `SMIR_TYPE_FRONTEND_FOUNDATION=/Users/int/dev/rax3` before running the commands.

The current builder uses the existing pinned built Clang static libraries and exact recorded compiler hash. On this machine it builds an AArch64 macOS tool binary. It does not claim a clean LLVM rebuild, another host build, full SDK attestation or guest native execution. Output directories must be new and outside both source checkouts.

```sh
python3 -B portable_type_build.py --llvm /Users/int/dev/llvm-project --output /tmp/portable-type-build
python3 -B portable_type_build.py --llvm /Users/int/dev/llvm-project --output /tmp/portable-type-build-opt --optimize
```

Input has exactly `language` (`c23` or `cpp23`) and `source` (nonempty ASCII without NUL, at most 1 MiB). CLI JSON input is bounded to 8 MiB and duplicate object fields reject. There are no user target, CPU, driver, plugin, header or module options.

```json
{"language":"c23","source":"unsigned char echo(unsigned char, bool);"}
```

```sh
python3 -B portable_type_project.py --native /tmp/portable-type-build/portable-type-bootstrap --build-receipt /tmp/portable-type-build/build-receipt.json --request request.json > product.json
```

With the build receipt the wrapper rechecks all recorded native build inputs and binary before and after invocation. Without it the result remains an unbound observation of the explicitly selected binary. Errors exit nonzero and publish no JSON product. Native failures must have empty stdout; output is never salvaged from a failed parse.

## Exact finite supported surface

Declarations and type uses support ordinary scalar integer/floating types, bool, signed plain char, C++ distinct wchar/char8/char16/char32, C23 `_BitInt`, named complete enums, data and function pointers, fixed arrays and fixed nonvariadic functions. Qualifiers are carried in nominal records. Typedef/using aliases canonicalize through the real AST. C23 user `char8_t` alias to unsigned char retains that ordinary canonical identity; C++ char8_t is distinct.

C23 `_BitInt(N)` supports unsigned N=1..65535 and signed N=2..65535, with q=ceil(N/8) B, A=min(8 B,next_power_of_two(q)), S=A*ceil(q/A). Thus BitInt65 storage16 B/alignment8 B differs from int128 storage16 B/alignment16 B. Bool has one value bit and one storage byte. Long double is IEEE binary128 with precision113 bits and storage/alignment16 B.

Unfixed enum selection is first representing int, unsigned int, long, unsigned long. The actual AST hook precedes subsequent source parsing. It adjusts integer/promotion type, enumerator APSInt sign/width, initializer cast and final enumerator type (C23 all-member rule included). Its finite initializer grammar permits integer literals with optional unary sign, parentheses/implicit casts/constant wrappers and implicit successive values. Expressions, explicit casts, enum attributes and redeclarations are unavailable. This excludes prehook enum type queries/cache consumers. Fixed enums retain the actual explicit base, including C++ bool; C++ scoped default base is int. Empty C++ unfixed enums choose int. Subsequent source assertions exercise underlying type, size, promotions, comparisons, array selection and calls.

Numeric extension vectors permit builtin arithmetic lanes of 8/16/32/64 integer bits or binary32/64, at least two lanes, total lane extent a power of two and at most64 B. Scalar byte types project to Raw8, while numeric vector lanes project to Int8. Arrays retain Raw8 elements. The portable ABI also specifies padded three-lane vectors; this narrower prototype explicitly rejects them. Bool, BitInt, pointer, scalable and oversized vectors reject.

Every emitted AST canonical type has a nominal/execution/layout/plan relation. Auxiliary numeric vector lane records make the generated execution graph exhaustive as well. Every source function type receives a direct ordinary call plan; byte parameter/results have noundef=false, ordinary numeric/pointer values true. This package supports no aggregate passing/hidden result/lifecycle or varargs plan. IDs are local draft indices, not allocated shared IDs.

Records/classes, references/member pointers, complex/atomic types, function definitions, templates, C++ BitInt, C++ explicit language linkage, anonymous namespaces and unsupported type/ABI attributes are unavailable. Every canonical nested/aliased FunctionProtoType is checked, including unused variadic typedefs. Unsupported warnings become errors after actual diagnostic-option processing; no ignored attribute fallback is allowed. Type attributes are rejected before canonicalization can erase them.

## Preprocessor and runtime boundaries

The sole source file lives in an in-memory VFS at `/rax-source-v1/main.c` or `.cpp`, mtime0, SourceDateEpoch0; no ambient filesystem overlay or includes. Date/time/timestamp assertions run under hostile host timezone/epoch/include variables. Source macro define/undef, pragma, line and include actions reject. The prototype has no header manifest or full CPP06/07 closed recipe reader.

Generic ordinary GCC/Clang lock-free macros are explicitly0. Actual builtin ordinary lock-free query is false. This implements the selected portable target contract; no atomic_flag runtime or parallel implementation is implied. `__CHAR8_TYPE__` is explicitly unsigned char in both languages as the existing contract requires.

An internal void-pointer builtin va_list allows ASTContext construction only. Active expanded builtin va-list/start/arg/end/copy names and every variadic function type reject before output, including alias, typeof/decltype, sizeof, type-trait and macro cases. No source-visible result may rely on that internal placeholder. The required portable array-of-one 32 B/alignment8 B va_list is not implemented.

No genuine pinned std::byte declaration membership is available in this single-file profile. A source-authored std::byte-named enum remains an ordinary numeric enum; its spelling or Clang isStdByteType predicate cannot confer Raw8 privileges.

## Formats and checks

`test_portable_type.py` imports only the Python standard library and registers an isolated child through unittest `load_tests`. It preserves the parent import path and every pre-existing module identity, including ABI candidate.py. `_portable_type_cases.py` contains all42 actual native tests and is not a discovery entry point. Configured `PORTABLE_TYPE_NATIVE` runs all42; absent explicit native profile produces one clearly marked unavailable skip, never a native pass. The child inherits actual Python optimization and an absent cache prefix under -B, records its real PID/source/mode, and cannot reuse a stale result file. `PORTABLE_TYPE_QUALIFICATION` optionally selects the output directory.

`portable_type_request.schema.json` and `portable_type_projection.schema.json` are closed executable JSON schemas. The generator derives the exact ABI and execution subrecord schemas from the current owned shared ordered grammars; no foreign schema is rewritten. The existing dependency-free contract_json validator checks actual outputs. Existing independent execution Types and wire codecs check the real execution root, existing ABI codecs check each nominal/layout/plan, and a separate formula checker validates source geometry, signed-first enums, Raw8/Int8 context, call attributes and exhaustive emitted relations. Nominal definitions are sealed through the existing canonical graph algorithm, without claiming source authority.

The native visitor/type closure uses O(N+(V+E)log V) work for N visited AST nodes and V/E projected type nodes/edges, excluding Clang parsing/Sema and rendering; canonical type closure has at most512 nodes and depth32, and declaration rows at most512. Python projection is O(V+E) excluding canonical nominal hashing. Existing nominal quotient hashing can require O(V*(V+E)log V) work per root and O(V+E+label bytes) storage. Sealing every nominal can therefore require O(V^2*(V+E)log V) work. Independent checks share the installed canonical hash implementation and are not a second hash implementation. Canonical all-path cost accounting, hostile-process memory quotas and complete Clang complexity qualification remain unavailable; a 20 s frontend deadline and bounded input/output checks are reference-tool limits.

Actual final results and input/binary hashes live in the package qualification receipt. Failed builds/trials and superseded receipts remain historical evidence. No broad Cargo, lifted-ISA, runtime, JIT, hosted-library, foreign EH or full-platform result is inferred.
