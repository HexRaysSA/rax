"""Verify the preserved native guarded-descriptor records without native APIs."""

from pathlib import Path
import hashlib
import json


def main():
    base = Path(__file__).resolve().parent
    manifest = json.loads((base / 'payload-sha256-v2.json').read_text())
    for name, expected in manifest.items():
        path = base / name
        assert base in path.resolve().parents and not path.is_symlink(), name
        raw = path.read_bytes()
        assert len(raw) == expected['bytes'], name
        assert hashlib.sha256(raw).hexdigest() == expected['sha256'], name
    receipt = json.loads((base / 'policy-receipt-v2.json').read_text())
    assert receipt['exit_code'] == 0 and receipt['state'] == 'finished'
    source = base / 'policy-probe-v2.c'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == receipt['source_sha256']
    projections = []
    counts = []
    for identity in receipt['architectures']:
        architecture = identity['architecture']
        raw = (base / ('policy-records-' + architecture + '-v2.json')).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == identity['records_sha256']
        records = json.loads(raw)
        assert records['architecture'] == architecture
        assert records['image_sha256'] == identity['image_sha256']
        cases = records['cases']
        assert len(cases) == identity['cases'] == 113
        assert [case['case'] for case in cases] == list(range(113))
        assert sum(case['exit_code'] == -9 for case in cases) == identity['killed_cases'] == 35
        assert sum(case['synchronous_guard_observed'] for case in cases) == identity['synchronous_guard_cases']
        projection = []
        for case in cases:
            packets = [row for row in case['records'] if row['kind'] == 'guard-exception']
            assert bool(packets) == case['synchronous_guard_observed']
            assert not packets or case['exit_code'] == -9
            for packet in packets:
                assert packet['exception'] == 12 and packet['count'] == 2
                assert int(packet['code'], 16) >> 61 == 2
                assert packet['subcode'] == '0x1122334455667788'
            observed = {key: case[key] for key in
                        ['case', 'operation', 'guard_flags', 'argument', 'exit_code']}
            observed.update(records=[row for row in case['records']
                                     if row['kind'] not in ['guard-exception', 'guard-reply']],
                            file_after=case.get('file_after'))
            projection.append(observed)
        projections.append(projection)
        counts.append({'architecture': architecture, 'cases': len(cases),
                       'killed': identity['killed_cases'],
                       'synchronous_packets': identity['synchronous_guard_cases']})
    assert len(projections) == 2 and projections[0] == projections[1]
    print(json.dumps({'verified_payloads': len(manifest), 'policy': counts,
                      'operation_results_equal': True,
                      'scope': 'Frozen native acquisition records; no emulator conformance claim.'}))


if __name__ == '__main__':
    main()
