"""Verify native query provenance, geometry, payload identity and counterexamples."""
from pathlib import Path
import hashlib
import json
import re
import struct

ROOT = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(name):
    return json.loads((ROOT / name).read_text())


def dumps(stdout, name):
    rows = []
    for line in stdout.splitlines():
        if not line.startswith(f'dump name={name} '):
            continue
        match = re.search(r'requested=(\d+) ok=(\d+) error=(\d+) got=(\d+) hex=([0-9A-F]+)$', line)
        assert match, line[:120]
        wanted, ok, error, got = map(int, match.groups()[:4])
        data = bytes.fromhex(match[5])
        assert ok == 1 and error == 0 and wanted == got == len(data)
        rows.append(data)
    return rows


def verify(version, suffix='', status=0, natural_exit=41, payload='native-user-information-v1.bin', fixed_count=None):
    build = load(f'native-build-v{version}.json')
    receipt = load(f'native-receipt-v{version}{suffix}.json')
    source = (ROOT / f'native-base-csr-info-v{version}.cpp').read_bytes()
    assert build['source_sha256'] == receipt['source_sha256'] == digest(source)
    assert build['image_sha256'] == receipt['image_sha256']
    assert len(build['commands']) == 2 and all(row['exit_code'] == 0 for row in build['commands'])
    assert receipt['ntdll_sha256'] == load('profile-v1.json')['ntdll_sha256']
    assert receipt['native_validation_jobs_restarted'] is False
    assert not receipt['stderr']
    stdout = receipt['stdout']
    assert digest(stdout.encode()) == receipt['stdout_sha256']
    complete = re.search(r'complete installed=1 entered=(\d+) returned=(\d+) exit=(\d+)', stdout)
    assert complete and complete[1] == complete[2] and int(complete[3]) == natural_exit
    assert receipt['exit_code'] == (0 if natural_exit == 41 else 22)
    if suffix:
        assert receipt['subject'] == 'S-1-5-18' and 'controller-session=0' in stdout
    else:
        assert receipt['subject'] == 'S-1-5-21-432357189-4232641918-3742464398-1000'
        assert 'controller-session=1' in stdout
    if version == 1:
        assert int(complete[1]) == 1
        assert not dumps(stdout, 'send-message')
        return []
    before = dumps(stdout, 'base-info-before')
    after = dumps(stdout, 'base-info-after')
    sends = dumps(stdout, 'send-message')
    replies = dumps(stdout, 'receive-after')
    headers = dumps(stdout, 'base-capture-before')
    assert len(before) == len(after) == len(sends) == len(replies) == len(headers)
    for initial, final, send, reply, header in zip(before, after, sends, replies, headers):
        assert len(initial) == len(final) == 1660
        assert len(send) == len(reply) == 80
        assert send[:8] == bytes.fromhex('2800500000000000')
        assert reply[:8] == bytes.fromhex('2800500002000000')
        assert struct.unpack_from('<I', send, 48)[0] == 0x1001B
        assert send[52:64] == bytes(12)
        assert struct.unpack_from('<I', reply, 48)[0] == 0x1001B
        assert struct.unpack_from('<I', reply, 52)[0] == status
        capture, = struct.unpack_from('<Q', send, 40)
        information, size = struct.unpack_from('<QQ', send, 64)
        assert information == capture + 40 and size == 1660
        assert reply[64:] == send[64:]
        assert len(header) == 40
        assert struct.unpack_from('<I', header)[0] == 1704
        assert struct.unpack_from('<I', header, 16)[0] == 1
        assert struct.unpack_from('<Q', header, 24)[0] == 0
        assert struct.unpack_from('<Q', header, 32)[0] == 64
        if status:
            assert final == initial
        else:
            assert final == (ROOT / payload).read_bytes()
    for line in stdout.splitlines():
        if line.startswith('return ') and 'NtAlpcSendWaitReceivePort' in line:
            assert line.endswith('status=00000000')
    fixed = [line for line in stdout.splitlines() if line.startswith('fixed-base-query ')]
    expected = fixed_count if fixed_count is not None else (0 if version == 2 else 1 if natural_exit != 41 else 2)
    assert len(fixed) == expected
    for line in fixed:
        assert f'status={status:08X} reply={status:08X} bytes=1660' in line
        # V5 child stdio can interleave with parent debug records. The parent
        # captured each full buffer while the child was stopped, and the child
        # compares the complete bytes before its natural exit41.
        if version < 5:
            data = bytes.fromhex(line.split('data=')[1])
            assert len(data) == 1660
            if not status:
                assert data == (ROOT / payload).read_bytes()
    return after


def main():
    profile = load('profile-v1.json')
    assert digest((ROOT / 'native-user-information-v1.bin').read_bytes()) == profile['information_sha256']
    verify(1)
    assert len(verify(2)) == 1
    assert len(verify(3)) == 3
    assert len(verify(3, '-system', 0xC0000001, 48)) == 1
    assert len(verify(4, '-system', payload='native-system-information-v1.bin')) == 2
    assert len(verify(5, '-system', payload='native-system-information-v1.bin', fixed_count=6)) == 6
    stdout = load('native-receipt-v4-system.json')['stdout']
    initial = dumps(stdout, 'base-info-before')
    assert initial == [bytes([0xA5]) * 1660, bytes([0x5A]) * 1660]
    print('verified: public/fixed user NLS identity; SYSTEM failure and later blank replies across six input patterns; exact native packet/capture provenance')


if __name__ == '__main__':
    main()
