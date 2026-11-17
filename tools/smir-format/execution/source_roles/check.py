"""Check actual full CLI outcomes against independent INT032 fixture expectations."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT / 'docs/specifications/smir/portable'
OUT = SPEC / 'conformance/execution/candidate/source-roles'


def sources():
    roots = [ROOT / 'tools/smir-format', ROOT / 'tools/smir-abi',
             ROOT / 'tools/smir-runtime-contract', SPEC / 'schema']
    paths = {p for base in roots for p in base.rglob('*')
             if p.is_file() and '__pycache__' not in p.parts
             and p.suffix in {'.py', '.json', '.inc'}}
    paths.update([OUT / 'cases.json', *OUT.glob('*.smo')])
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    before = sources()
    manifest = json.loads((OUT / 'cases.json').read_text())
    results = []
    for row in manifest['cases']:
        path = OUT / (row['name'] + '.smo')
        if hashlib.sha256(path.read_bytes()).hexdigest() != row['encoded_sha256']:
            raise ValueError('SEM_SOURCE_FIXTURE_HASH')
        command = [sys.executable, '-B']
        if sys.flags.optimize:
            command.append('-' + 'O' * sys.flags.optimize)
        command += [str(ROOT / 'tools/smir-format/codec.py'), 'verify-candidate-reference', str(path)]
        for cap in row['capabilities']:
            command += ['--capability', cap]
        process = subprocess.run(command, capture_output=True, text=True)
        semantic_codes = ['RT_HELPER_SOURCE_ROLE', 'RT_HELPER_SOURCE_LAYOUT',
                          'RT_HELPER_SOURCE_EXECUTION', 'RT_HELPER_SOURCE_COMPATIBILITY']
        diagnostic = next((code for code in semantic_codes if code in process.stderr), None)
        actual = ('accept' if process.returncode == 0 else
                  'reject' if diagnostic is not None and 'WIRE-' not in process.stderr
                  and 'EVIDENCE_UNAVAILABLE' not in process.stderr
                  and 'RESOURCE' not in process.stderr else 'other_rejection')
        # Only an explicit source-role diagnostic counts as the expected negative.
        # Wire, resource and unavailable-evidence outcomes cannot pass it. Exact
        # per-predicate diagnostic equality remains visible for owner review.
        results.append(dict(name=row['name'], helper=row['helper'], contract=row['contract'],
            expected=row['expected_source_role'], actual=actual,
            matches=(actual == row['expected_source_role'] and
                     diagnostic == row['expected_diagnostic']),
            expected_diagnostic=row['expected_diagnostic'], actual_diagnostic=diagnostic, command=command,
            exit=process.returncode, stdout=process.stdout, stderr=process.stderr))
    after = sources()
    drift = [p for p in sorted(before.keys() | after.keys()) if before.get(p) != after.get(p)]
    receipt = dict(scope='Actual whole-reference static unused imports, all17names/19contracts. No helper/guest/native execution. Only explicit source semantic prefixes count; Wire/resource/missingevidence cannot satisfy source negatives. Exact per-predicate assigned source error codes must match.',
        interpreter=dict(path=str(Path(sys.executable).resolve()), version=sys.version,
                         optimize=sys.flags.optimize,
                         sha256=hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()),
        source_before=before, source_after=after, source_drift=drift,
        matches=sum(r['matches'] for r in results), differences=[r['name'] for r in results if not r['matches']],
        results=results)
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(len(results), 'cases', receipt['matches'], 'match', len(receipt['differences']), 'differ', len(drift), 'source drift')
    for row in results:
        if not row['matches']:
            print(row['name'], 'expected', row['expected'], 'actual', row['actual'], row['stderr'].strip()[:90])
    sys.exit(1 if receipt['differences'] or drift else 0)
