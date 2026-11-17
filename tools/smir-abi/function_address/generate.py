"""Regenerate exactly the four ABI-owned ordinary-address source corpora."""

import hashlib
import json
from pathlib import Path
import sys
from copy import deepcopy

from .fixtures import cases, ordinary, source, seal, source_only
from nominal import ref, some


ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'docs/specifications/smir/portable/conformance/abi/function-address'


def documents():
    result = {name: dict(format='smir-abi-ordinary-address-reference-1', abi_payload_revision=3,
                      scope='Source-authored declarations and comparison oracles; actual admission and runtime entry remain separate',
                      cases=rows) for name, rows in cases().items()}
    sys.path.insert(0, str(ROOT / 'tools/smir-format'))
    from codec import CandidateCodec
    spec = ROOT / 'docs/specifications/smir/portable'
    codec = CandidateCodec({owner: json.loads((spec / 'schema' / owner / 'candidate.json').read_text())
                            for owner in ('execution', 'runtime', 'abi')})

    def encoded(name, roots, expected):
        raw = codec.encode(roots)
        return dict(name=name, expected=expected, encoded_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())

    original = source_only()
    profiles = [encoded('source-only-genuine-all-phase', original, 'verified-object')]
    pointer = deepcopy(original)
    pointer[1]['memory_layouts'].append(dict(id=1000, type=ref(1000), size=8, alignment=8,
        access_bytes=8, fields=[], element=None, stride=0))
    binding = dict(id=3000, nominal=ref(107), execution_layout=ref(1000), kind='object_bytes',
        view_offset_bits=0, view_width_bits=64, required_alignment=8, access_bytes=8,
        fragments=[dict(source_path=[], source_offset_bits=0, execution_offset_bits=0, width_bits=64, role='value')])
    pointer[10]['storage_bindings'] = [binding]
    profiles.append(encoded('source-pointer-object-storage-8B-A8', pointer, 'verified-object'))
    for identifier in (100, 101, 103, 106):
        bad = deepcopy(pointer)
        bad[10]['storage_bindings'][0]['nominal'] = ref(identifier)
        profiles.append(encoded('nonobject-storage-' + str(identifier), bad, 'ABI_CC_INCOMPLETE_VALUE'))
    bad = deepcopy(pointer)
    bad[10]['types'].append(source(110, 'void', flags=['complete']))
    bad[10]['storage_bindings'][0]['nominal'] = ref(110)
    profiles.append(encoded('void-has-no-object-storage', seal(bad), 'ABI_CC_INCOMPLETE_VALUE'))
    bad = deepcopy(original)
    bad[10]['types'].append(source(111, 'record', entity='example.Unrelated'))
    profiles.append(encoded('unrelated-opaque-remains-unavailable', seal(bad), 'P2_ABI_VERIFIER_INCOMPLETE'))
    profiles.append(encoded('extra-call-plan-remains-unavailable', ordinary(), 'P2_ABI_VERIFIER_INCOMPLETE'))
    bad = deepcopy(original)
    next(t for t in bad[10]['types'] if t['id'] == 107)['representation'] = 'value'
    profiles.append(encoded('wrong-source-pointer-representation', seal(bad), 'ABI_CC_TYPE_BINDING'))
    bad = deepcopy(original)
    next(t for t in bad[10]['types'] if t['id'] == 107)['bits'] = 32
    profiles.append(encoded('wrong-source-pointer-width', seal(bad), 'ABI_CC_TYPE_BINDING'))
    bad = deepcopy(original)
    next(t for t in bad[10]['types'] if t['id'] == 106).update(execution=some(ref(12)), representation='signature')
    profiles.append(encoded('unissued-prototype-has-no-default', seal(bad), 'ABI_CC_FUNCTION_DEFAULT'))
    bad = deepcopy(original)
    signature = deepcopy(bad[10]['signatures'][0])
    signature.update(id=202, function_type=ref(106), params=[ref(100)], result=some(ref(100)),
                     lowered_params=[], lowered_results=[])
    # Exact required sret/copy arity reaches the missing source-object layout
    # predicate. These attempted size fields are rejected, not inferred sizeof R.
    for role, mode, index in [('sret', 'sret', None), ('parameter', 'indirect_copy', some(0))]:
        signature['lowered_params'].append(dict(source_index=index, role=role, source_type=ref(100),
            value_type=ref(102), mode=mode, align=4, bytes=4, noundef=True,
            copy=None, move=None, destroy=None))
    bad[10]['signatures'].append(signature)
    profiles.append(encoded('incomplete-byvalue-call-rejected', bad, 'ABI_CC_INCOMPLETE_VALUE'))
    result['source-only']['profile_cases'] = profiles
    return result


def generate():
    OUT.mkdir(parents=True, exist_ok=True)
    result = {}
    for name, document in documents().items():
        raw = (json.dumps(document, indent=2) + '\n').encode('utf8')
        (OUT / (name + '.json')).write_bytes(raw)
        result[name] = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), cases=len(document['cases']))
    return result


if __name__ == '__main__':
    print(json.dumps(generate(), indent=2))
