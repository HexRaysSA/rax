#!/usr/bin/env python3
"""Verify retained native FIFO observations and their source provenance."""
import hashlib
import json
from pathlib import Path


def main():
    directory = Path(__file__).resolve().parent

    def load(name):
        return json.loads((directory / name).read_text())

    def digest(name):
        return hashlib.sha256((directory / name).read_bytes()).hexdigest()

    for entry in load('references/provenance.json'):
        assert digest('references/' + entry['retained_path']) == entry['sha256']

    native = load('native-fifo-readiness-v6.json')
    assert native['exit_code'] == 0
    assert native['source_sha256'] == digest('capture-readiness-v6.py')
    records = native['records']
    assert len(records) == 10
    by_state = {item['state']: item for item in records}
    for name in ['never_had_writer', 'empty_with_writer',
                 'empty_before_first_eof_read', 'empty_after_first_eof_read',
                 'repeated_blocking_eof']:
        item = by_state[name]
        assert item['poll_result'] == item['poll_events'] == item['poll_errno'] == 0
        assert item['kqueue'] == []
        assert item['select_readable'] == (name == 'empty_before_first_eof_read')
    assert by_state['never_had_writer']['read_result'] == []
    assert by_state['repeated_blocking_eof']['read_result'] == []
    repeated = [r for r in records if r['state'] == 'repeated_nonblocking_eof']
    assert [r['iteration'] for r in repeated] == [0, 1, 2]
    assert all(r['read_result'] == [] and not r['select_readable'] for r in repeated)
    for name in ['data_with_writer', 'data_after_writer_close']:
        assert by_state[name]['poll_result'] == 1
        assert by_state[name]['poll_events'] & 1
        assert by_state[name]['select_readable']

    for architecture in ['arm64', 'x86_64']:
        for version, source in [('v1', 'close-thread-state-v1.c'),
                                ('v2', 'held-close-thread-state-v2.c'),
                                ('v3', 'held-close-thread-state-v3.c')]:
            prefix = 'close-thread-state' if version == 'v1' else 'held-close-thread-state'
            observation = load(f'{prefix}-{architecture}-{version}.json')
            assert observation['exit_code'] == 0
            assert observation['source_sha256'] == digest(source)
            entries = observation['records']
            states = [e['result'] for e in entries if e['kind'] == 'close-thread-run-state']
            assert 4 in states
            values = {e['kind']: e for e in entries}
            assert values['writer-was-blocked']['result'] == 1
            assert values['write-result']['result'] == 1
            assert values['close-result']['result'] == 0
            assert values['received-bytes']['result'] == values['filled-bytes']['result'] + 1
            assert values['last-byte']['result'] == ord('A')
            if version != 'v1':
                assert values['completed-held-close-run-state']['result'] == 3
                assert values['completed-held-close-run-state']['errno'] == 1
                assert values['close-user-done-while-held']['result'] == 0
            if version == 'v3':
                held = [e for e in entries if e['kind'] == 'held-close-run-state']
                assert len(held) == 32
                assert held[-1]['result'] == 4
                assert all(e['errno'] == 1 for e in held)
    abort = load('native-abort-fifo-control-v1.json')
    assert abort['source_sha256'] == digest('native-abort-fifo-control-v1.c')
    assert len(abort['observations']) == 4
    observed = set()
    for observation in abort['observations']:
        assert observation['exit_code'] == 0 and observation['stderr'] == ''
        values = json.loads(observation['stdout'])
        observed.add((observation['architecture'], values['safe_abort']))
        assert values['waiting_before'] == 1 and values['abort_return'] == 0
        assert values['flags_before'] == values['flags_after'] == 0
        if values['safe_abort']:
            assert values['completed_by_abort'] == 0
            assert values['read_result'] == values['read_errno'] == 0
        else:
            assert values['completed_by_abort'] == 1
            assert values['read_result'] == -1 and values['read_errno'] == 4
    assert observed == {(arch, safe) for arch in ['arm64', 'x86_64'] for safe in [0, 1]}

    signal = load('native-held-signal-read-v1.json')
    assert signal['source_sha256'] == digest('native-held-signal-read-v1.c')
    assert [item['architecture'] for item in signal['observations']] == ['arm64', 'x86_64']
    for observation in signal['observations']:
        assert observation['exit_code'] == 0 and observation['stderr'] == ''
        values = json.loads(observation['stdout'])
        assert values['read_wait'] == values['close_wait'] == 1
        assert values['signal_sent'] == 0
        assert values['close_completed_while_reader_held'] == 1
        assert values['read_user_done_while_held'] == values['handler_while_held'] == 0
        assert values['read_result'] == -1 and values['read_errno'] == 4
        assert values['close_result'] == values['close_errno'] == 0
        assert values['handler_after_resume'] == 1

    build = load('fifo-runtime-build-v1.json')
    runtime = load('fifo-runtime-records-v1.json')
    assert build['source_sha256'] == runtime['source_sha256'] == digest('fifo-runtime-v1.c')
    assert set(build['images']) == {'arm64', 'x86_64'}
    assert runtime['sysroot_supplied'] is False
    assert len(runtime['cases']) == 4
    assert {(case['architecture'], case['vector']) for case in runtime['cases']} == {
        (arch, vector) for arch in ['arm64', 'x86_64'] for vector in [False, True]
    }
    expected = ['never-writer-eof=0'] * 3 + [
        'empty-zero-read=0', 'reader-blocked=1', 'child-exit=0',
        'read-result=1', 'read-errno=0', 'read-byte=120', 'shared-nonblock=1',
    ] + ['after-writer-eof=0'] * 3
    for case in runtime['cases']:
        assert case['native_exit'] == case['guest_exit'] == 0
        assert case['native_stdout'] == case['guest_stdout'] == expected
    print('Verified 10 readiness observations, 6 close-state captures, '
          '6 interruption controls, 4 runtime comparisons, and 4 primary references.')


if __name__ == '__main__':
    main()
