# Original ordinary data-pointer source calls

Explicit source-authored whole objects for the finite ABI-ORDINARY-POINTER-CALLS-01
profile. The Rust ABI test invokes genuine type/ABI factories; independent Python
qualification uses the original whole-root ABI, execution and linking verifiers.
The codec is an encoder, not a semantic oracle. These tests issue no runtime permit.

`original-pointer.source.json` is RUNTIME's original source graph; its generated
`original-pointer-diamond.smo` is byte-identical to the before object: 6558 octets,
SHA-256 aa1261d85724c84b880d3ea37f24692710b1b31ab32c9bb829d57449d5017e3c.
It uses an actual pointer FullFn, original source CallSignature and a DataPtr phi.

The corpus distinguishes ABI phase results from full-object results. Bad body/SSA
cases may have valid ABI facts and still fail actual program verification. Metadata
coverage requires the separate paired RUNTIME package; ABI success alone is not a
full-object or execution claim. Qualified/chained pointers and Some(void) remain
explicit finite-coverage Unknown despite valid Python source semantics.

Regenerate only this new prefix with:

    PYTHONDONTWRITEBYTECODE=1 python3 -B crates/smir-portable/tests/abi/ordinary_pointer_fixtures.py

Verify exact current generator inputs and encoded bytes without writing with:

    PYTHONDONTWRITEBYTECODE=1 python3 -B crates/smir-portable/tests/abi/ordinary_pointer_fixtures.py --check

Old scalar/source-address fixtures, generators, manifests and expected results
are not changed by this package. Manifest hashes identify exact generator inputs;
they do not attest compiler, runtime or library provenance. Portable data-pointer
ABI shape does not prove nonnull, object identity, bounds, lifetime, aliasing or
permission to dereference. No native execution, JIT or parallel runtime is tested.
