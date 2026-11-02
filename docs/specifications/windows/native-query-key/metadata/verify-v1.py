"""Verify frozen native metadata inputs using only the Python standard library."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import zipfile

ROOT = Path(__file__).resolve().parent
GUARDS = '9f43ae1666ac8acf9350f14fd4cbf09589a383aa74838944dfc8dec6443e54b0'
FIXTURES = '5f01da0971a38b40b1f996c9cb68a7ee8bdd6d8a0b578aa09459938ae99da582'
TAGS = 'aa0009702a422d83a75b42eef75d9436d0c727283532bc4654d5887c779540fb'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()

def native_archive(path, expected):
    assert sha(path) == expected
    with zipfile.ZipFile(path) as archive:
        inventory = json.loads(archive.read('archive-manifest.json'))
        assert len(archive.namelist()) == len(set(archive.namelist())) == len(inventory) + 1
        for name, item in inventory.items():
            h = hashlib.sha256(); size = 0
            with archive.open(name) as stream:
                for block in iter(lambda: stream.read(1 << 20), b''):
                    size += len(block); h.update(block)
            assert size == item['bytes'] and h.hexdigest() == item['sha256'], name
    return len(inventory)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--guards-native-archive', type=Path)
    parser.add_argument('--fixture-native-archive', type=Path)
    parser.add_argument('--tags-native-archive', type=Path)
    args = parser.parse_args()
    frozen = json.loads((ROOT / 'frozen-inputs-v1.json').read_text())
    assert frozen['sources'] == {'guards_v3_archive': GUARDS, 'fixture_v2_archive': FIXTURES}
    for name, item in frozen['files'].items():
        path = ROOT / name
        assert path.resolve().is_relative_to(ROOT) and not path.is_symlink()
        assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256'], name
    receipt = json.loads((ROOT / 'native-receipt-v3.json').read_text())
    assert receipt['state'] == 'finished' and receipt['exit_code'] == 0 and not receipt['failures']
    records = json.loads((ROOT / 'records-v1.json').read_text())
    assert records['source_archive_sha256'] == GUARDS
    assert [r['architecture'] for r in receipt['reports']] == ['arm64', 'x64', 'x86']
    for report, machine in zip(receipt['reports'], [0xAA64, 0x8664, 0x14C]):
        label = report['architecture']; image = ROOT / ('native-metadata-guards-v3-' + label + '.exe')
        data = image.read_bytes(); offset = struct.unpack_from('<I', data, 0x3C)[0]
        assert data[:2] == b'MZ' and data[offset:offset + 4] == b'PE\0\0'
        assert struct.unpack_from('<H', data, offset + 4)[0] == machine
        assert len(data) == report['image_bytes'] and sha(image) == report['image_sha256']
        assert report['records'] == report['warmup_records'] == 66110
        assert report['strict_handle_equality'] and report['handles_before'] == report['handles_after']
        assert report['provider_before'] == report['provider_after']
        assert report['provider_before']['kernel'] == [10, 0, 29698]
        assert report['provider_before']['native_machine'] == 0xAA64
        assert records['observations'][label]['provider'] == report['provider_before']
        sizes = [len(bytes.fromhex(records['observations'][label]['records'][str(c)])) for c in range(9)]
        assert sizes == [40, 48, 44, 130, 40, 12, 4, 4, 4]
    tags_root = ROOT / 'tags-v4'
    tags_manifest = json.loads((tags_root / 'frozen-inputs-v4.json').read_text())
    assert tags_manifest['source_archive_sha256'] == TAGS
    for name, item in tags_manifest['files'].items():
        path = tags_root / name
        assert path.resolve().is_relative_to(tags_root) and not path.is_symlink()
        assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256'], name
    tags = json.loads((tags_root / 'observations-v4.json').read_text())
    assert tags['archive_sha256'] == TAGS and tags['native_queries'] == 243 and tags['native_tag_mutations'] == 24
    assert len(tags['observations']) == 3
    for observed in tags['observations']:
        assert len(observed['before']) == 9 and len(observed['after']) == 72
        assert observed['setter']['mapped_provider_utf16'] == observed['provider']['mapped_provider_utf16']
        assert sha(tags_root / ('native-metadata-tags-v4-' + observed['architecture'] + '.exe')) == observed['image_sha256']
        for record in observed['after']:
            assert record['set_status'] == record['status'] == 0
            if record['class'] == 7:
                assert bytes.fromhex(record['bytes']) == (record['input'] & 0xFFFF).to_bytes(4, 'little')
            else:
                assert record['bytes'] == observed['before'][record['class']]['bytes']
    external = {}
    for name, path, expected in [('guards', args.guards_native_archive, GUARDS), ('fixtures', args.fixture_native_archive, FIXTURES), ('tags', args.tags_native_archive, TAGS)]:
        if path:
            external[name] = native_archive(path, expected)
    print(json.dumps({'verified_frozen_inputs': len(frozen['files']) + len(tags_manifest['files']), 'measured_guard_cases': 198330,
                      'native_kernel': [10, 0, 29698], 'native_machine': 'ARM64',
                      'external_archive_payloads': external}, sort_keys=True))

if __name__ == '__main__':
    main()
