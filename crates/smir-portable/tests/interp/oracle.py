#!/usr/bin/env python3
"""Run cases on the Python reference machine and print one JSON report each.

    python3 -B oracle.py machine OBJECT < cases.json
    python3 -B oracle.py assemble SOURCE.json EXPECTED.smo

`machine` verifies OBJECT once with the reference verifiers and then runs each
case on a fresh reference Machine in this process. It does not attach the
source registry, so it serves modules whose calls carry no source plan; the
reference CLI's registry setup grows with module size and takes tens of
seconds for a module of twenty functions. Input is a JSON array of
`{"function": id, "arguments": [little-endian hex, ...], "fuel": n,
"max_frames": n}`; output is a JSON array of reports shaped like the CLI's.

`assemble` checks that EXPECTED.smo is exactly SOURCE.json assembled.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'
sys.path[:0] = [str(ROOT / 'tools/smir-format'), str(ROOT / 'tools/smir-format/execution')]

from codec import CandidateCodec  # noqa: E402


def codec():
    return CandidateCodec({owner: json.loads((SPEC / 'schema' / owner / 'candidate.json').read_text())
                           for owner in ('execution', 'runtime', 'abi')})


def machine(path):
    from candidate.context import RootContext
    from candidate.machine import Machine
    from candidate.values import Value

    decoded = codec().decode(Path(path).read_bytes())
    context = RootContext(decoded.roots)
    context.verify_abi()
    context.verify_execution()
    functions = {item['id']: item for item in context.execution_checked.functions_root['functions']}
    reports = []
    for case in json.load(sys.stdin):
        signature = context.types.get(functions[case['function']]['signature'])
        arguments = [Value(reference, 'concrete', int.from_bytes(bytes.fromhex(bits), 'little'))
                     for reference, bits in zip(signature['params'], case['arguments'], strict=True)]
        engine = Machine(context.execution_checked)
        engine.start(case['function'], arguments)
        result = engine.run(fuel=case['fuel'], max_frames=case['max_frames'])
        report = {'status': result['kind'], 'steps': engine.steps}
        if result['kind'] == 'return':
            report['values'] = [
                {'bits_le': value.data.to_bytes((context.types.get(reference)['bits'] + 7) // 8, 'little').hex()}
                if value.state == 'concrete' else {'state': value.state}
                for reference, value in zip(signature['results'], result['values'], strict=True)]
        else:
            report['code'] = result.get('reason', result['kind'])
            for field in ('function', 'block', 'operation'):
                if field in result:
                    report[field] = result[field]
        reports.append(report)
    json.dump(reports, sys.stdout)


def assemble(source, expected):
    import smir
    produced = smir.assemble(json.loads(Path(source).read_text()))
    if produced != Path(expected).read_bytes():
        sys.exit(f'{expected} is not {source} assembled; rerun smir.py assemble')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'machine':
        machine(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == 'assemble':
        assemble(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
