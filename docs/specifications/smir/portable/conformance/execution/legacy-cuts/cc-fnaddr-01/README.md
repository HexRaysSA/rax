# CC-FNADDR-01 legacy corpus preservation

These five generated JSON documents preserve the original experimental source cut
BYTE FOR BYTE, including encoded_hex, original expected outcomes, source hashes,
interpreter identity and oracle scopes. manifest.json is a GENERATED index of547
original cases, not a new format reader or an additional current semantic corpus.

| Preserved file | Cases | JSON bytes |
|---|---:|---:|
| core-cases.json | 258 | 3057250 |
| phase-cases.json | 20 | 335702 |
| embedded-cases.json | 222 | 2675627 |
| capture-cases.json | 12 | 235485 |
| profile-cases.json | 35 | 502029 |

Total original JSON bytes:6806093 B. The manifest records file bytes/SHA256, every
raw case SHA256 and original canonical-case hash, and the exact source/interpreter
identities. Case identity includes file + original index + name; no deduplication.
It also identifies immutable coordination archives by SHA256/member path. All507
recorded producer preimages match the prior qualified source archive exactly.
The exact recorded interpreter binary is retained in the SEM before archive.
Then-current changed sources are separately identified, not mislabeled producers.
Coordination archives are reproducibility artifacts; their presence at a future
checkout is unknown unless retained by the integrator. The five preserved corpus
JSON files remain self-contained raw-byte/outcome evidence without those archives.

Legacy selection is the five explicit names in this manifest. Current semantic
runners use their separately selected current manifests; this directory never
implicitly adds cases through a recursive glob. No source generator, existing
corpus, source hash registration, profile or active schema was regenerated.

Each post-cut wire outcome/current counterpart link is null: UNKNOWN, unreleased
and not tested. Original expected outcomes remain distinct historical assertions.
A future decoder must reject wrong payload revisions before schema-dependent
parsing after envelope framing validation; malformed framing retains priority.
Wire rejection cannot stand in for new-format semantic coverage. No successful
frozen ABI2 reader or automatic missing-field upgrade is introduced here.

Observed preservation checks cover copied bytes,547 raw-case hashes/identities,
all original outcome/scope fields and507 recorded producer preimages. They do not
rerun the historical oracle or establish current execution/native conformance.
The proposed post-cut checker remains outside this seven-path release.
