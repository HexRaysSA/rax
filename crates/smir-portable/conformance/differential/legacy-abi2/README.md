# Historical experimental ABI2 controls

These six immutable files preserve old experimental envelope0.2/profile2 objects.
Object roots1..9 carry payload1 and root10 carries ABI payload2. This directory
adds no reader, successful old-format profile, current corpus case or frozen005
repin. `manifest.json` is evidence metadata, not an executable format/schema.
`expectations.jsonl` retains the exact recipes, raw identities and old outcomes.

| Raw file | Existing producer recipe | Old reference / static | Historical CLI |
|---|---|---|---|
| portable-identity.smo | positive/portable-identity.json | verified / verified | verified-object |
| pure-static-function-address.smo | pure-static/function-address | verified / verified | verified-object |
| pure-static-direct-call.smo | pure-static/direct-call | verified / verified | verified-object |
| function-missing-source-plan.smo | function/missing-source-plan | RT_FUNCTION_SOURCE_PRESENCE / same | semantic RT_FUNCTION_SOURCE_PRESENCE |
| function-undefined-return-local.smo | function/undefined-return-local | ssa_reference:77 / same | semantic ssa_reference |
| scalar-profile-hidden-symbol.smo | scalar-profile/hidden-symbol | verified / verified | unavailable-evidence P2_METADATA_PROFILE_UNAUDITED |

The raw generator is the unchanged differential `oracle.py` functions
`fixture_roots`, `edit`, and actual current-at-preservation `CandidateCodec.encode`.
It loads the original portable-identity source fixture, fills missing roots5/7/9,
normalizes manifest.kind=object/entry=None, applies exactly the named authored
case mutations and seals the actual content identity. No byte/payload corruption,
new current semantic equivalents or repaired stale guards are substituted.
`manifest.json` records original complete recipes, source HEAD and230source/tool/
schema input hashes. Each raw decoded and canonically roundtripped. Two Python
reference processes per raw produced the preserved actual outcomes; none executed
a guest. Framing/decoding alone does not establish those semantic outcomes.

Historical Rust CLI observations use exactly
`/tmp/rax-portable-smir-01/LLVM/p2-cargo-target/debug/smir-inspect`, SHA256
`247f8a37fe6d3aea6f30b5890a4f7732ac9034ff181b733116e585353e0417cc`.
Its source-to-CURRENT-build attribution is **UNATTESTED**. These are observations
of that exact existing binary, not current-source factory/native/runtime evidence.
The Python source/input hashes describe the actual preservation cut separately.
Old004/005test receipts are not proof of the resulting current source tree.

Verify these immutable byte hashes from the RAX checkout root:

```sh
python3 -B - <<'PYVERIFY'
import hashlib, json
from pathlib import Path
folder = Path('crates/smir-portable/conformance/differential/legacy-abi2')
manifest = json.loads((folder / 'manifest.json').read_text())
for entry in manifest['entries']:
    data = (folder / entry['path']).read_bytes()
    assert len(data) == entry['bytes']
    assert hashlib.sha256(data).hexdigest() == entry['sha256']
print('6 historical byte hashes match')
PYVERIFY
```

For the **retained old producer/source cut only**, reference commands were:

```sh
python3 -B crates/smir-portable/tests/differential/oracle.py verify-reference RAW.smo
python3 -B crates/smir-portable/tests/differential/oracle.py verify-static-reference RAW.smo
/tmp/rax-portable-smir-01/LLVM/p2-cargo-target/debug/smir-inspect verify RAW.smo
```

Replace RAW.smo by one explicit path in this directory. After the coherent
migration these commands against new sources need not accept old raw objects.
The historical source checksums/outcomes remain evidence; no fallback old reader
is distributed here. Current corpus generation uses explicit `cases.jsonl` rows
and does not collect this directory. Any future broad `.smo` collection must
explicitly exclude it unless testing historical revision controls.

The root-assigned next migration is separate and inactive at preservation:

| Object roots | Preserved payload | Assigned next payload |
|---|---:|---:|
| 1,2,3,5 | 1 | 2 |
| 4,6,7,8,9 | 1 | 1 |
| 10 | 2 | 3 |

Envelope0.2/profile2 stay unchanged. Live-state payload2 is separately assigned
and is not object root8. Once that coherent cut is active, these valid-framing
old controls must reject incompatible payload revisions before interpreting new
records. That future rejection is **not yet observed by this preservation
package** and counts zero semantic coverage. New source-generated counterparts
must still reach the real source-plan/SSA/profile predicates or exact unavailable
boundary. Do not relabel a revision error as semantic validation.

`legacy_cut.rs` and existing differential integration/corpus/pin files are not
changed by this package. Generic lifted-ISA/legacy0.1 behavior is unaffected by
these unconsumed data files. These commands execute host verifier tools, not a
guest or source program. They establish no native guest execution, new compiler
freeze, P2production profile, installed runtime or whole-platform qualification.

Assumptions: the old producer/input cut stays immutable during copying (hash
before/after); authored recipes remain exact (recipe/base/schema hashes); observed
historical binary is not current build proof (explicit unattested attribution).
Falsifiers are changed source/raw hashes, substituted outcomes, accidental current
corpus inclusion or an added successful old reader. High impact: laundering old
wire rejection into new semantic coverage. Medium: source/corpus drift. Low: no
performance evidence. Artifact storage is proportional to six raw byte lengths
plus retained recipes/provenance; this is no compiler/runtime complexity claim.
