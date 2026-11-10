"""Verify frozen native pagefile controls; optionally inspect their raw archive."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = "4a5e69a4c3aa8b81adbee0ff2fa25f42d0adf52cc7a89df83962aa72ca3d575a"
HELPER_SHA256 = "9e595cfb3584baba0e36bee3a0e8a1cb17574bac68d2a79cb29d6bb69b73d511"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def verify_archive(path, profile):
    raw = path.read_bytes()
    require(identity(raw) == {k: profile['archive'][k] for k in ('bytes', 'sha256')},
            'retained archive identity')
    spec = importlib.util.spec_from_file_location('native_pagefile_projection', HERE / 'projection_v1.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        manifest = json.loads(z.read('archive-manifest.json'))
        require(len(manifest) == 16 and len(z.namelist()) == 17
                and set(z.namelist()) == set(manifest) | {'archive-manifest.json'}
                and z.testzip() is None, 'complete payload inventory')
        for name, expected in manifest.items():
            require(identity(z.read(name)) == expected, 'payload: ' + name)
        source = z.read('source/pagefile-options-v1.cpp')
        require(source == (HERE / profile['source']['file']).read_bytes(), 'executed control source')
        binding_raw = z.read('binding/native-source-v1.json')
        binding = json.loads(binding_raw)
        receipt_raw = z.read('receipt/native-receipt-v1.json')
        receipt = json.loads(receipt_raw)
        require(receipt['source_sha256'] == identity(binding_raw)['sha256'], 'launch binding')
        require(receipt['phase'] == 'finished' and not receipt.get('error')
                and not receipt.get('producer_failed') and receipt['images_unchanged']
                and not receipt['native_validation_jobs_restarted'], 'original acquisition verdict')
        require(receipt['native_kernel'] == '10.0.29704.0'
                and receipt['installed_images'] == profile['held_installed_images'], 'native identity')
        post = json.loads(z.read('receipt/native-post-capture-input-hashes-v1.json'))
        require(post['original_receipt_sha256'] == identity(receipt_raw)['sha256']
                and post['binding_sha256'] == identity(binding_raw)['sha256'], 'post-capture binding')
        require(len(post['inputs']) == 6 and all(x['matches'] for x in post['inputs']),
                'post-capture input identities')
        expected = {x['package_name']: {k: x[k] for k in ('bytes', 'sha256')}
                    for x in binding['inputs']}
        require({x['name']: {k: x[k] for k in ('bytes', 'sha256')} for x in post['inputs']} == expected,
                'same before/after inputs')
        build = json.loads(z.read('build/build-v3.json'))
        require(build['state'] == 'finished' and len(build['commands']) == 7
                and all(x['exit_code'] == 0 for x in build['commands']), 'strict completed builds')
        package = z.read('package/executed-inputs.zip')
        require(identity(package) == binding['package'], 'executed package')
        with zipfile.ZipFile(io.BytesIO(package)) as inputs:
            require(set(inputs.namelist()) == set(expected), 'exact executed input inventory')
            for name, expected_identity in expected.items():
                require(identity(inputs.read(name)) == expected_identity, 'executed input: ' + name)
            require(inputs.read('pagefile-options.cpp') == source, 'packaged source')
            require(inputs.read('build-v3.json') == z.read('build/build-v3.json'), 'packaged build')
            require(len(binding['programs']) == len(receipt['runs']) == 4, 'four original producers')
            for program, run in zip(binding['programs'], receipt['runs'], strict=True):
                name = program['architecture']
                require(name in profile['profiles'] and run['label'] == name
                        and run['arguments'] == program['arguments'] == ''
                        and run['exit_code'] == run['stderr_bytes'] == 0
                        and run['stderr_sha256'] == identity(b'')['sha256'], 'original producer verdict')
                stdout = base64.b64decode(run['stdout_base64'], validate=True)
                require(identity(stdout) == {k[7:]: run[k] for k in ('stdout_bytes', 'stdout_sha256')}
                        and stdout == z.read('stdout/' + name + '.log'), 'complete raw stdout')
                projected = helper.projection(stdout)
                selected = profile['profiles'][name]
                require(projected['cases'] == profile['cases']
                        and all(projected[k] == selected[k] for k in ('kernel', 'alias', 'lifetime')),
                        'independent scalar/geometry/lifetime projection')
                image = inputs.read(program['package_name'])
                require(image == z.read('images/' + name + '.exe')
                        and identity(image) == {k: program['image'][k] for k in ('bytes', 'sha256')}
                        and identity(image) == {k: build['images'][name][k] for k in ('bytes', 'sha256')},
                        'executed image identity')
                require(image[:2] == b'MZ', 'DOS signature')
                pe = struct.unpack_from('<I', image, 0x3c)[0]
                require(image[pe:pe + 4] == b'PE\0\0'
                        and struct.unpack_from('<H', image, pe + 4)[0] == selected['pe_machine']
                        and bool(struct.unpack_from('<H', image, pe + 22)[0] & 0x20)
                        == selected['large_address_aware'], 'actual PE ABI and address-width policy')


def main():
    require(len(sys.argv) in (1, 2), 'usage: verify-v1.py [native-pagefile-options-29704-v1.zip]')
    raw = (HERE / 'profile-29704-v1.json').read_bytes()
    require(identity(raw)['sha256'] == PROFILE_SHA256, 'frozen profile identity')
    profile = json.loads(raw)
    require(identity((HERE / profile['source']['file']).read_bytes())
            == {k: profile['source'][k] for k in ('bytes', 'sha256')}, 'published control source')
    require(identity((HERE / 'projection_v1.py').read_bytes())['sha256'] == HELPER_SHA256,
            'independent projector identity')
    require(len(profile['cases']) == 138 and len(profile['profiles']) == 4
            and profile['native_cases'] == 552
            and profile['portable_replay_zero_bits_zero_cases'] == 496, 'bounded profile inventory')
    if len(sys.argv) == 2:
        verify_archive(Path(sys.argv[1]), profile)
        print('Verified original four producers, 552 observations, 264 releases and all input/image bindings.')
    else:
        print('Verified frozen profile, source and projector. Separate raw archive was not checked.')


if __name__ == '__main__':
    main()
