"""Generate only released SEM fixtures from independently authored expectations."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'tools/smir-format/execution'))
sys.path.insert(0, str(ROOT / 'tools/smir-format'))
sys.path.insert(0, str(ROOT / 'crates/smir-portable/tests/execution'))
from codec import CandidateCodec
from candidate.function_address_contract import cases, observe, source_roots, LITERAL_EXPECTATION_MIGRATION
from oracle_sources import input_sources, input_roots, interpreter_identity

OUTPUT = ROOT / 'docs/specifications/smir/portable/conformance/execution/function-addresses'
RUST = ROOT / 'crates/smir-portable/tests/execution/function-address-cases.json'


def generate():
    schemas = {owner: json.loads((ROOT / f'docs/specifications/smir/portable/schema/{owner}/candidate.json').read_text())
               for owner in ('execution', 'abi', 'runtime')}
    codec = CandidateCodec(schemas)
    logical, encoded = cases(), []
    base = source_roots()
    for case in logical:
        observed = observe(case)
        if observed != case['expected']:
            raise RuntimeError(f"{case['id']}: authored {case['expected']}, observed {observed}")
        sections = deepcopy(case['sections'])
        if case['scope'] == 'execution-local':
            sections = {**deepcopy(base), **sections}
            sections[2]['symbols'] = []
        wire = codec.encode(sections)
        filename = case['id'] + '.smo'
        rust_expected = {'reject-bind-plan-reference': 'P2_LOCAL_REFERENCE',
                         'reject-caller-plan-C-reference': 'P2_LOCAL_REFERENCE',
                         'reject-DEP-nominal-is-not-plan': 'P2_DEPENDENCY_NAMESPACE'}.get(case['id'], case['expected'])
        encoded.append(dict(name=case['id'], oracle_scope=case['scope'], expected=case['expected'],
                            rust_expected=rust_expected,
                            filename=filename, sha256=hashlib.sha256(wire).hexdigest(), encoded_hex=wire.hex()))
        OUTPUT.mkdir(parents=True, exist_ok=True)
        (OUTPUT / filename).write_bytes(wire)
    output_prefix = str(OUTPUT.relative_to(ROOT)) + '/'
    sources = {path: digest for path, digest in input_sources(ROOT, [Path(__file__).resolve()]).items()
               if not path.startswith(output_prefix) and path != str(RUST.relative_to(ROOT))}
    metadata = dict(expectation_migrations=[LITERAL_EXPECTATION_MIGRATION], purpose='Static CodeAddress typing and actual ABI/execution joins only. Local-scope objects are not whole-ABI admitted. No runtime/native/permit authority.',
                    sources=sources, oracle_input_roots=input_roots(), oracle_interpreter=interpreter_identity())
    (OUTPUT / 'cases.json').write_text(json.dumps({**metadata, 'cases': logical}, indent=2) + '\n')
    RUST.write_text(json.dumps({**metadata, 'cases': encoded}, separators=(',', ':')) + '\n')
    print(f'{len(encoded)} authored cases; {sum(c["expected"] == "ok" for c in encoded)} positive; '
          f'{sum(c["expected"] != "ok" for c in encoded)} rejection; no execution qualification')


if __name__ == '__main__':
    generate()
