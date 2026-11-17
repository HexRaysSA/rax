"""Check logical outcomes and exact whole-object bytes without regeneration."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
from codec import CandidateCodec
from candidate.function_address_contract import observe


def main():
    directory = ROOT / 'docs/specifications/smir/portable/conformance/execution/function-addresses'
    logical = json.loads((directory / 'cases.json').read_text())['cases']
    encoded = json.loads((ROOT / 'crates/smir-portable/tests/execution/function-address-cases.json').read_text())['cases']
    schemas = {owner: json.loads((ROOT / f'docs/specifications/smir/portable/schema/{owner}/candidate.json').read_text())
               for owner in ('execution', 'abi', 'runtime')}
    codec = CandidateCodec(schemas)
    if len(logical) != len(encoded):
        raise RuntimeError('case count')
    for case, counterpart in zip(logical, encoded):
        case['sections'] = {int(k): v for k, v in case['sections'].items()}
        if case['id'] != counterpart['name'] or observe(case) != case['expected']:
            raise RuntimeError('semantic counterpart: ' + case['id'])
        wire = bytes.fromhex(counterpart['encoded_hex'])
        if (directory / counterpart['filename']).read_bytes() != wire:
            raise RuntimeError('wire counterpart: ' + case['id'])
        if hashlib.sha256(wire).hexdigest() != counterpart['sha256']:
            raise RuntimeError('wire hash: ' + case['id'])
        if codec.encode(codec.decode(wire).roots) != wire:
            raise RuntimeError('wire canonicality: ' + case['id'])
    print(f'PASS {len(logical)} authored static cases and whole-object codec roundtrips')


if __name__ == '__main__':
    main()
