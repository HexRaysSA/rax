"""Verify frozen fixed-NLS evidence with the Python standard library."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import zipfile

ROOT = Path(__file__).resolve().parent
ARCHIVE = '714de11a095fde6b2408952d4d02f83bb007f08305e6452f72cadd94712c9992'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-archive', type=Path)
    args = parser.parse_args()
    frozen = json.loads((ROOT / 'frozen-inputs-v1.json').read_text())
    assert frozen['source_archive_sha256'] == ARCHIVE
    for name, item in frozen['files'].items():
        path = ROOT / name
        assert path.resolve().is_relative_to(ROOT) and not path.is_symlink()
        assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256'], name
    receipt = json.loads((ROOT / 'native-receipt-v1.json').read_text())
    data = json.loads((ROOT / 'records-v1.json').read_text())
    assert receipt['state'] == 'finished' and receipt['exit_code'] == 0 and not receipt['failures']
    assert receipt['inputs_unchanged'] and data['source_archive_sha256'] == ARCHIVE
    assert [r['architecture'] for r in receipt['reports']] == ['arm64', 'x64', 'x86']
    assert data['cases'] == {'arm64': 33000, 'x64': 33000, 'x86': 33000}
    for report, machine in zip(receipt['reports'], [0xAA64, 0x8664, 0x14C]):
        label = report['architecture']
        image = ROOT / ('native-nls-tree-v1-' + label + '.exe')
        pe = image.read_bytes()
        offset = struct.unpack_from('<I', pe, 0x3C)[0]
        assert pe[:2] == b'MZ' and pe[offset:offset + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', pe, offset + 4)[0] == machine
        assert len(pe) == report['image_bytes'] and sha(image) == report['image_sha256']
        assert report['keys'] == 48 and report['cases'] == 33000
        assert report['strict_handle_equality'] and report['handles_before'] == report['handles_after']
        snapshots = report['handle_snapshots']
        assert [s['phase'] for s in snapshots] == ['initial', 'before', 'after']
        assert snapshots[1]['count'] == snapshots[2]['count']
        assert sorted(snapshots[1]['entries'], key=lambda e: int(e['handle'], 16)) == sorted(
            snapshots[2]['entries'], key=lambda e: int(e['handle'], 16))
        assert report['provider_before'] == report['provider_after']
        assert report['provider_before']['kernel'] == [10, 0, 29698]
        assert report['provider_before']['native_machine'] == 0xAA64
        assert report['provider_before']['provider_pe_machine'] == (0x14C if label == 'x86' else 0xAA64)
        for view in ['0', '256', '512']:
            nodes = data['observations'][label][view]
            assert len(nodes) == 16
            assert sum(len(n['values']) for n in nodes) == 584
            assert sum(len(n['children']) for n in nodes) == 15
            assert sum(sum(len(bytes.fromhex(v['name_utf16'])) + len(bytes.fromhex(v['data']))
                           for v in n['values']) for n in nodes) == 21492
            assert sum(sum(len(bytes.fromhex(r)) for r in n['records'].values()) for n in nodes) == 4990
            for node in nodes:
                assert sorted(map(int, node['records'])) == [0, 1, 2, 3, 4, 5, 6, 8]
                assert node['view'] == int(view)
                assert len(node['children']) == node['expected_children']
                assert len(node['values']) == node['expected_values']
                assert len(node['tails']) == 2 and set(node['tails']) <= {'raw', 'zero_odd'}
    payloads = None
    if args.native_archive:
        assert sha(args.native_archive) == ARCHIVE
        with zipfile.ZipFile(args.native_archive) as archive:
            inventory = json.loads(archive.read('archive-manifest.json'))
            assert len(archive.namelist()) == len(set(archive.namelist())) == len(inventory) + 1
            for name, item in inventory.items():
                digest = hashlib.sha256()
                size = 0
                with archive.open(name) as stream:
                    for block in iter(lambda: stream.read(1 << 20), b''):
                        size += len(block)
                        digest.update(block)
                assert size == item['bytes'] and digest.hexdigest() == item['sha256'], name
            assert archive.read('receipt-nls-tree-v3.json') == (ROOT / 'native-receipt-v1.json').read_bytes()
            for name in ['probe-v1.c', 'handle-snapshot-v3.h', 'CMakeLists.txt']:
                assert archive.read('source/' + name) == (ROOT / name).read_bytes()
            assert archive.read('controller-nls-tree-v3.py') == (ROOT / 'capture-v1.py').read_bytes()
            payloads = len(inventory)
    print(json.dumps({'verified_inputs': len(frozen['files']), 'native_cases': 99000,
                      'keys_per_view': 16, 'values_per_view': 584,
                      'native_archive_payloads': payloads}, sort_keys=True))


if __name__ == '__main__':
    main()
