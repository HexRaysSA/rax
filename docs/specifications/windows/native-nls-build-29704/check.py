"""Verify the exact 29704 profile, or project its retained native archive."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import importlib.util
import json
import struct
import sys
import zipfile
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
ARCHIVE_SHA256 = '849615ebc07095d6aa6face0f4316a5f311179230ab33d160f56259b77b86573'
ARCHIVE_BYTES = 9081555
ARCHES = ('arm64', 'x64', 'x86', 'x86-laa')

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def published(name):
    if name.startswith('.task-evidence/windows29704-nls-v1/'):
        return 'docs/specifications/windows/native-nls-build-29704/captured-29704-v1/' + Path(name).name
    return name

def collect(path):
    require(path.stat().st_size == ARCHIVE_BYTES and digest(path.read_bytes()) == ARCHIVE_SHA256, 'retained archive identity')
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        manifest = json.loads(bundle.read('archive-manifest.json'))
        require(len(names) == len(set(names)) == len(manifest) + 1, 'unique complete archive')
        require(set(names) == set(manifest) | {'archive-manifest.json'}, 'complete manifest')
        for name, expected in manifest.items():
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and '..' not in relative.parts, 'member path')
            raw = bundle.read(name)
            require(len(raw) == expected['bytes'] and digest(raw) == expected['sha256'], name)
        d = json.loads(bundle.read('records/nls-current29704-v1-tests-receipt-resume-v7.json'))
        binding = json.loads(bundle.read('records/native-source-v2.json'))
        for row in binding['inputs']:
            raw = bundle.read(row['package_name'])
            require(len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'native input identity')
        for name, expected in binding['source_frame'].items():
            require(digest(bundle.read('source/' + name)) == expected, 'archive source')
            require(digest((REPO / published(name)).read_bytes()) == expected, 'retained source')
        for case in binding['programs']:
            image = bundle.read(case['package_name'])
            require(len(image) == case['image']['bytes'] and digest(image) == case['image']['sha256'], 'executable identity')
            pe = struct.unpack_from('<I', image, 60)[0]
            require(image[pe:pe + 4] == b'PE\x00\x00', 'PE signature')
            expected = 43620 if case['arch'] == 'arm64' else 34404 if case['arch'] == 'x64' else 332
            require(struct.unpack_from('<H', image, pe + 4)[0] == expected, 'process machine')
            if case['arch'] == 'x86-laa' and (not case['kind'].startswith('identity-')):
                require(struct.unpack_from('<H', image, pe + 22)[0] & 32, 'LAA executable')
        require([row['label'] for row in d['runs']] == [case['architecture'] for case in binding['programs']], 'all native calls in bound order')
        h = lambda b: hashlib.sha256(b).hexdigest()
        assert d['phase'] == 'finished' and (not d.get('error')) and (d['native_kernel'] == '10.0.29704.0') and (d['native_update_revision'] == 1010) and d['inputs_unchanged'] and d['images_unchanged']
        assert len(d['runs']) == 25 and all((row['exit_code'] == 0 and row['stderr_bytes'] == 0 for row in d['runs']))
        spec = importlib.util.spec_from_file_location('nls_prior', REPO / 'docs/specifications/windows/native-nls-build-29695/check.py')
        prior = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(prior)
        runs = {row['label']: row for row in d['runs']}
        payloads = {}
        profiles = []
        leaves = {}
        providers = {}
        files = {}
        for row in d['captured_files']:
            raw = base64.b64decode(row['data_base64'], validate=True)
            assert len(raw) == row['bytes'] and h(raw) == row['sha256']
            files[row['path']] = raw
        for arch in ['arm64', 'x64', 'x86', 'x86-laa']:
            for kind in ['leaf', 'initialize', 'protect', 'mui']:
                row = runs[arch + '-' + kind]
                raw = base64.b64decode(row['stdout_base64'], validate=True)
                assert len(raw) == row['stdout_bytes'] and h(raw) == row['stdout_sha256']
                text = raw.decode('ascii')
                if kind == 'leaf':
                    leaves[arch] = [prior.fields(line) for line in text.splitlines() if line.startswith('leaf ')]
                    assert len(leaves[arch]) == 3
                    if arch.startswith('x86'):
                        assert bytes.fromhex(leaves[arch][0]['hex'])[12:15] == b'\xc2\x0c\x00'
                else:
                    canonical = {'initialize': prior.initialize, 'protect': prior.protection, 'mui': prior.mui}[kind]
                    fresh = canonical(text)
                    old = canonical(prior.prior(arch, kind))
                    same = fresh == old
                    delta = [i for i, (a, b) in enumerate(zip(fresh, old)) if a != b]
                    profiles.append(dict(arch=arch, kind=kind, rows=len(fresh), canonical_sha256=prior.signature(fresh), prior_equal=same, differing_rows=delta, native_stdout_sha256=h(raw)))
                if kind == 'mui':
                    payload = base64.b64decode(row['payload']['data_base64'], validate=True)
                    assert len(payload) == row['payload']['bytes'] and h(payload) == row['payload']['sha256']
                    payloads[arch] = dict(bytes=len(payload), sha256=h(payload))
            before = base64.b64decode(runs[arch + '-identity-before']['stdout_base64'], validate=True)
            after = base64.b64decode(runs[arch + '-identity-after']['stdout_base64'], validate=True)
            assert before == after
            text = before.decode('ascii')
            rows = [prior.fields(line) for line in text.splitlines()]
            identity = next((row for row in rows if 'native-machine' in row))
            assert int(identity['native-machine'], 16) == 43620

            def decode(name):
                encoded = next((row['hex'] for row in rows if row.get('name') == name))
                return ''.join((chr(int(encoded[i:i + 4], 16)) for i in range(0, len(encoded), 4)))
            mapped = decode('mapped-provider')
            logical = decode('logical-provider')
            drive = decode('drive-target')
            assert mapped.startswith(drive + '\\')
            physical = logical[:2] + mapped[len(drive):]
            selected = next((path for path in files if path.lower() == physical.lower()))
            provider = h(files[selected])
            expected = '0c8ad1faabdc67afad52c037897a1edbe8c69733aede303c0fa9d1dd6ccde0f7' if arch.startswith('x86') else '62f49d5ba98285e9997cc47c7710ab1d1390506c0a3fda96736783aefd42b3b1'
            assert provider == expected
            providers[arch] = dict(logical_path=logical, mapped_path=mapped, physical_path=physical, sha256=provider, before_after_equal=True, identity_sha256=h(before))
        row = runs['arm64-generation']
        generation = []
        for line in base64.b64decode(row['stdout_base64'], validate=True).decode('ascii').splitlines():
            if not line.startswith('generation '):
                continue
            f = prior.fields(line)
            raw = bytes.fromhex(f.pop('hex'))
            assert int(f['bytes']) == len(raw)
            assert int(f['shared-before']) == int(f['payload-generation']) == int(f['shared-after'])
            assert h(raw) == payloads['arm64']['sha256']
            generation.append(dict(**{k: int(v) for k, v in f.items()}, sha256=h(raw)))
        assert len(generation) == 3 and len(set(((p['bytes'], p['sha256']) for p in payloads.values()))) == 1
        locale_path = next((p for p in files if p.lower().endswith('locale.nls')))
        locale = files[locale_path]
        profile = dict(schema=1, kernel=[10, 0, 29704], update_revision=1010, native_machine=43620, scope='One ARM64 kernel, ARM64/AMD64 compatibility/x86 compatibility/x86-LAA controls; no independent AMD64 kernel or mutation claim.', profiles=profiles, leaves=leaves, payloads=payloads, generation=generation, providers=providers, locale_nls=dict(bytes=len(locale), sha256=h(locale), mapped_bytes=(len(locale) + 4095) // 4096 * 4096), sources={published(name): value for name, value in binding['source_frame'].items()}, source_origins={published(name): name for name in binding['source_frame']}, native_inputs_unchanged=True, native_runs=25)
        profile['archive'] = dict(bytes=ARCHIVE_BYTES, sha256=ARCHIVE_SHA256, payloads=len(manifest))
        profile['samples'] = [{key: row[key] for key in ('architecture', 'arch', 'kind', 'package_name', 'image')} for row in binding['programs']]
        return profile

def verify(record):
    require(record['kernel'] == [10, 0, 29704] and record['native_machine'] == 43620 and (record['update_revision'] == 1010), 'finite native profile')
    require(record['native_inputs_unchanged'] and record['native_runs'] == 25, 'native input stability')
    for name, expected in record['sources'].items():
        require(digest((REPO / name).read_bytes()) == expected, 'retained source ' + name)
    spec = importlib.util.spec_from_file_location('nls_prior', HERE.parent / 'native-nls-build-29695/check.py')
    prior = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prior)
    require(len(record['profiles']) == 12 and len(record['samples']) == 25, 'complete finite profile')
    expected_pairs = {(arch, kind) for arch in ARCHES for kind in ('initialize', 'protect', 'mui')}
    require({(row['arch'], row['kind']) for row in record['profiles']} == expected_pairs, 'complete semantic pairs')
    for row in record['profiles']:
        canonical = {'initialize': prior.initialize, 'protect': prior.protection, 'mui': prior.mui}[row['kind']]
        old = canonical(prior.prior(row['arch'], row['kind']))
        require(row['prior_equal'] and (not row['differing_rows']) and (len(old) == row['rows']) and (prior.signature(old) == row['canonical_sha256']), 'retained native equality')
    require(set(record['leaves']) == set(ARCHES), 'four process export profiles')
    for arch, rows in record['leaves'].items():
        require(len(rows) == 3, 'three exports')
        if arch.startswith('x86'):
            require(bytes.fromhex(rows[0]['hex'])[12:15] == b'\xc2\x0c\x00', 'x86 RET12')
    require(len(record['generation']) == 3 and set(record['payloads']) == set(ARCHES), 'generation/profile coverage')
    payloads = set(((p['bytes'], p['sha256']) for p in record['payloads'].values()))
    require(payloads == {(1232, '845ec214cfa8cdafe3c6cac5d86923e8429c9093e4641094879d2e53be7ceaef')}, 'exact cross-process payload identity')
    for row in record['generation']:
        require(row['shared-before'] == row['payload-generation'] == row['shared-after'] == 1, 'shared/payload generation')
        require((row['bytes'], row['sha256']) in payloads, 'independent generation capture')
    require(set(record['providers']) == set(ARCHES), 'four physical provider profiles')
    for arch, row in record['providers'].items():
        expected = 'sychpe32' if arch.startswith('x86') else 'system32'
        require('\\' + expected + '\\' in row['physical_path'].lower() and row['before_after_equal'], 'physical provider binding')
        provider_hash = '0c8ad1faabdc67afad52c037897a1edbe8c69733aede303c0fa9d1dd6ccde0f7' if arch.startswith('x86') else '62f49d5ba98285e9997cc47c7710ab1d1390506c0a3fda96736783aefd42b3b1'
        require(row['sha256'] == provider_hash, 'exact physical provider identity')
    require(record['locale_nls'] == dict(bytes=862808, mapped_bytes=864256, sha256='00d972d678db02525b731e1286e8daf53e87e5cbc58edcaf90de4222470a639a'), 'locale file and mapping identity')
    for name, original, old, new in [('initialize-x86-print-v2.cpp', 'native-nls-initialize-v2.cpp', 'mbi.BaseAddress, mbi.AllocationBase, mbi.RegionSize, mbi.State,', 'mbi.BaseAddress, mbi.AllocationBase, static_cast<size_t>(mbi.RegionSize), mbi.State,'), ('protect-x86-print-v2.cpp', 'native-nls-initialize-protection-v2.cpp', 'original, base, size, old,', 'original, base, static_cast<size_t>(size), old,')]:
        raw = (HERE.parent / 'native-nls-build-29695' / original).read_text()
        require(raw.count(old) == 1 and (HERE / 'captured-29704-v1' / name).read_text() == raw.replace(old, new), 'printing-only derivation')
    require(record['archive'] == dict(bytes=ARCHIVE_BYTES, sha256=ARCHIVE_SHA256, payloads=82), 'archive provenance')

def main():
    require(__debug__, 'optimized validation rejected')
    if len(sys.argv) == 2:
        record = collect(Path(sys.argv[1]))
        verify(record)
        print(json.dumps(record, indent=2))
    else:
        require(len(sys.argv) == 1, 'usage: check.py [retained-native-results.zip]')
        record = json.loads((HERE / 'profile-29704-v1.json').read_text())
        verify(record)
        print('Verified 29704: 316 initialization, 48 protection/free, 6720 MUI rows, 12 leaves, 3 generation captures and 8 provider observations')
if __name__ == '__main__':
    main()
