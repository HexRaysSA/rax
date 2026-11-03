"""Verify recorded macOS pipe-close controls without running native code."""

from pathlib import Path
import hashlib
import json


def validate(data):
    assert data['state'] == 'qualified' and data['exit_code'] == 0
    assert data['case_count'] == 16 and len(data['cases']) == 16
    builds = data['builds']
    assert {b['architecture'] for b in builds} == {'arm64', 'x86_64'}
    images = {b['architecture']: b['image_sha256'] for b in builds}
    assert len(images) == len(builds) == 2
    assert all(b['exit_code'] == 0 and not b['stderr'] for b in builds)
    seen = set()
    for case in data['cases']:
        arch, kind = case['architecture'], case['kind']
        vector, suppress = case['vector'], case['suppress_sigpipe']
        key = arch, kind, vector, suppress
        assert key not in seen
        seen.add(key)
        assert arch in images and kind in {'pipe', 'fifo'}
        assert type(vector) is bool and type(suppress) is bool
        assert case['image_sha256'] == images[arch]
        assert case['exit_code'] == 0 and case['stderr'] == ''
        rows = [json.loads(line) for line in case['stdout'].splitlines()]
        results = {r['kind']: r for r in rows}
        assert len(results) == len(rows) == 11
        assert results['writer-was-blocked']['result'] == 1
        assert results['initial-fd-flags']['result'] == 3
        assert results['during-close-fd-flags']['result'] == -1
        assert results['during-close-fd-flags']['errno'] == 9
        assert results['during-close-duplicate']['result'] == (4 if kind == 'pipe' else 5)
        assert results['close-result']['result'] == 0
        assert results['write-result']['result'] == (-1 if kind == 'pipe' else 1)
        assert results['write-result']['errno'] == (32 if kind == 'pipe' else 0)
        assert results['observed-sigpipe']['result'] == int(kind == 'pipe' and not suppress)
        filled = results['filled-bytes']['result']
        assert 0 < filled <= 1024 * 1024
        assert results['received-bytes']['result'] == filled + int(kind == 'fifo')
        assert results['last-byte']['result'] == (46 if kind == 'pipe' else 65)
        if kind == 'pipe':
            assert results['closer-was-blocked']['result'] == 0
        else:
            # The wait-state observer may time out even while close retains
            # its descriptor. Slot reservation and joined return are direct.
            assert results['closer-was-blocked']['result'] in {1, -1}
    assert len(seen) == 16


def main():
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    bindings = json.loads((here / 'bindings-v1.json').read_text())
    for name, digest in bindings['inputs'].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    data = json.loads((here / 'native-signal-v1.json').read_text())
    assert data['source_sha256'] == hashlib.sha256(
        (here / 'native-pipe-close-signal-v1.c').read_bytes()).hexdigest()
    validate(data)
    print('verified: 16 native pipe/FIFO close and SIGPIPE controls')


if __name__ == '__main__':
    main()
