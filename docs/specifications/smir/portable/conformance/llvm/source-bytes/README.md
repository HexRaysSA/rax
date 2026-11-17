# Native byte-category reference fixtures

These fixtures test an UNBOUND pinned Clang AST observer. They do not issue source,
ABI or runtime facts; selected declarations do not prove exhaustive compilation
coverage. The real library case uses the exact pinned libc++ forward declaration
and definition, not a source-defined std::byte surrogate.

`headers-manifest.json` records every actual input in the selected include closure.
Files are unchanged copies of LLVM36763294ef639d8a6a4379d81da653dda1c20686 libc++
headers plus the actual generated build/include/c++/v1/__config_site snapshot.
The generated config describes that native reference build; it is NOT the portable
sysroot/ABI configuration. Source identity/hash and Apache-2.0 WITH LLVM-exception
notices are retained; see libcxx-LICENSE.TXT. The complete known20-file header/config closure is registered by exact hash in
the wrapper; a self-rehashed modified/missing config is refused before native
parsing. Both canonical-first byte declaration
(offset612) and defining declaration(offset720) must match actual pinned identities.

The test generator binds backend/frontend/projector/sysroot digests to the ACTUAL
native build, wrapper/schema/interpreter and these exact files at run time. No
caller JSON becomes a trusted policy or source proof. Bundles/selectors/results
are written into each run's separate artifact directory; source fixtures stay exact.
`cases.json` uses physical source byte offsets, including #line and macro negatives.

Build and run from a checkout containing the assigned files:

    python3 -B tools/smir-llvm-contract/build_source_byte_categories.py \
      --llvm /path/to/pinned/llvm-project --output /tmp/byte-native-build
    SMIR_BYTE_ORACLE=/tmp/byte-native-build/source-byte-category-oracle \
    SMIR_BYTE_BUILD_RECEIPT=/tmp/byte-native-build/build-receipt.json \
    SMIR_BYTE_ARTIFACT_ROOT=/tmp/byte-native-tests \
    PYTHONPYCACHEPREFIX=/tmp/byte-native-cache \
      python3 -B -m unittest discover -s tools/smir-llvm-contract \
        -p test_source_byte_categories.py -v

Repeat with a new artifact/cache directory and `python3 -O -B`. For the pure-only
profile explicitly load test_source_byte_categories.Pure; native tests require an
actual pinned oracle/receipt and otherwise report a skip, never native success.
`SMIR_BYTE_REFERENCE_PROJECT` selects the actual read-only foundation checkout for
owncoord drafts; installed tools default to their own checkout.

The observer accepts canonical SourceEvidenceBundleV1/CPP07 fixed-clock inputs and
this reference's exact LP64 AST surrogate recipe. Portable smir-source-v1 is rejected
rather than handled by a native target. Modules are unsupported; source absolute,
dot/escaping include paths and over128-component paths are unavailable/resource
boundaries. Macro actions support ASCII identifiers and ordered real preprocessing;
implementation-reserved recipe macro overrides are rejected. Complete transitive
headers/configs must be bundled. No ambient include/module/cache/working-directory
or clock input is used. No LLVM TargetMachine/MIR/body emitter runs.

The native process uses the exact virtual /rax-source-v1 map, mtime0, explicit
SourceDateEpoch0 and real preprocessing callbacks for protected macros/includes.
Physical declaration locations ignore #line presumed display names. Source parse,
layout and categories are actual AST queries. Pointers/vectors/atomics/references
are never unwrapped into byte categories. Bool precision1 is distinct from storage8;
BitInt precision and u64 object-size metrics retain exact JSON integers above2^53.

Reference resource profile: source payload<=1MiB, request<=4MiB, output<=16MiB,
stderr<=64KiB, selectors/files<=4096, visited AST nodes<=100000, native timeout30s.
Logical canonical-B charges precharge input/capture/metadata/sort/hash/output work;
native parsing is separately bounded, not exact CPU/RSS accounting. Runtime binary/
selected shared libraries, wrapper/schema/target/source-budget API and original
selector snapshots have before/after guards. Each file guard uses its captured
size with unbuffered file I/O, reads at most that size plus one prepaid growth
byte (including the underlying file position), and never scans a
newly enlarged file to EOF after canonical resource exhaustion. The receipt guard
reserves its after-scan even when later receipt validation fails. Existing canonical resource objects
propagate unchanged except actual captured drift: CHANGED is primary and chains
the SAME original resource object without rewriting its kind/code/detail.

Assumption register: N1 guarded static libraries correspond to pin (actual compiler/
version/input hashes, no full clean LLVM rebuild); N2 real byte library membership
is both exact first/definition identity (lookalike/user-forward/missing/changed
header controls); N3 native surrogate observations are not portable source semantics
(PortableRecipe refused); N4 guards/quotas remain active in both Python modes
(zero/exact/one-less, changed-on-success/native-error/resource controls). HIGH source
facts cannot come from these rows; MEDIUM actual portable frontend/complete type
projection and source-init/Raw transport remain separate work; LOW no guest/native
runtime/JIT/parallel/host or performance qualification.
