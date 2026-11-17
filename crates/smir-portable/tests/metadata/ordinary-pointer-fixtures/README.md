Independent source-authored finite ordinary pointer call witnesses.

Generate with `python3 -B crates/smir-portable/tests/metadata/ordinary_pointer_fixtures.py`.
Use `--check` for nonwriting byte and provenance comparison.

The manifest distinguishes complete static proofs, semantic rejections, and
valid source/transport forms outside the Rust audited profile. Pointer source
pointee/rank/signature identity is preserved despite common DataPtr transport.
No fixture authorizes dereference, source aliases, lifecycle or runtime admission.
The unchanged ABI-owned original-pointer-diamond fixture is tested separately
with its exact 6558-octet SHA-256 before genuine whole-object verification.
