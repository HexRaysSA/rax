"""Independent bundle framing/config/control and system-zstd media/RAM comparison."""

from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def framing(raw, wire):
    r = wire(raw)
    assert r.take(8) == b'RAXCKPT\0' and r.integer(4) == 8 and r.take(4) == b'RXS8'
    count = r.integer(4)
    assert count in [6, 7, 9]
    parts = {}
    for _ in range(count):
        kind, schema, length = r.integer(4), r.integer(4), r.integer(8)
        assert kind not in parts and kind in range(1, 10)
        assert schema == (2 if kind == 1 else 1)
        assert length <= 65 * 1024**2
        parts[kind] = r.take(length)
    assert r.offset == len(raw)
    return parts


def control(raw, index, wire, runtime, models):
    r = wire(raw)
    assert r.take(8) == b'RAXPCS01'
    assert r.integer(1) == int(index >= 2)
    bridge = r.take(r.integer(4))
    expected = bytearray(runtime.bridge(1 if index >= 2 else 0))
    if index == 1:
        expected[8:12] = bytes(4)
    assert bridge == expected
    media = []
    if index >= 2:
        records = runtime.expected(1, False, models)
        size = 16384 if index >= 3 else 0
        ro = index == 4
        n, a = bytearray(records['nvme.bin']), bytearray(records['ahci.bin'])
        struct.pack_into('<QB', n, 16, size, int(ro))
        struct.pack_into('<QB', a, 16, size, int(ro))
        if size:
            struct.pack_into('<III', a, 66, 0x40, 0x101, 0x133)
            a[94] = 1
        records['nvme.bin'], records['ahci.bin'] = bytes(n), bytes(a)
        for name in ['e1000.bin', 'uhci.bin', 'nvme.bin', 'ahci.bin', 'ac97.bin']:
            assert r.take(r.integer(4)) == records[name], (index, name)
        for device in ['nvme', 'ahci']:
            length, protection, digest = r.integer(8), r.integer(1), r.take(32)
            assert (length, protection) == (size, int(ro))
            wanted = (
                b''
                if not size
                else bytes([0xA3 if device == 'nvme' else 0xB9]) * size
                if ro
                else bytes(((i * 17) ^ 0x5A) & 255 for i in range(size))
                if device == 'nvme'
                else bytes(((i * 31) ^ 0xC3) & 255 for i in range(size))
            )
            assert hashlib.sha256(wanted).digest() == digest
            media.append(
                dict(
                    device=device,
                    bytes=wanted,
                    sha256=digest.hex(),
                    read_only=bool(protection),
                )
            )
    assert r.offset == len(raw)
    return media


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.repo.resolve(), args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [
        'src/vm/snapshot.rs',
        'src/vm/snapshot/bundle.rs',
        'src/vm/snapshot/pci.rs',
        'src/vm/snapshot/codec.rs',
        'src/vm/snapshot/config_v1.rs',
        'src/vm/snapshot/legacy.rs',
        'src/config/storage.rs',
        'src/vm/runtime/pci_state.rs',
        'tests/suites/vm/checkpoint_pci.rs',
        'tools/checkpoint/bundle_guest.rs',
        'tools/checkpoint/bundle_oracle.py',
        'tools/checkpoint/codec_oracle.py',
        'tools/checkpoint/runtime_pci_oracle.py',
        'tools/checkpoint/pci_endpoint_oracle.py',
    ]
    before = {n: sha(root / n) for n in sources}
    codec = load(root / 'tools/checkpoint/codec_oracle.py')
    runtime = load(root / 'tools/checkpoint/runtime_pci_oracle.py')
    models = load(root / 'tools/checkpoint/pci_endpoint_oracle.py')
    library = out / 'librax.rlib'
    shutil.copyfile(args.target_dir / 'debug/librax.rlib', library)
    commands = []
    env = os.environ.copy()
    env['CARGO_MANIFEST_DIR'] = str(root)

    def run(name, command):
        start = time.monotonic()
        result = subprocess.run(
            command, cwd=root, env=env, capture_output=True, timeout=60
        )
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        commands.append(
            dict(
                name=name,
                args=command,
                code=result.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert result.returncode == 0, (name, result.stderr[-2000:])
        return result.stdout

    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(root / 'tools/checkpoint/bundle_guest.rs'),
            '--extern',
            'rax=' + str(library),
            '-L',
            'dependency=' + str(args.target_dir / 'debug/deps'),
            '-o',
            str(out / 'publish'),
        ],
    )
    run('publish', [str(out / 'publish'), str(out)])
    zstd = shutil.which('zstd')
    assert zstd
    run('zstd-version', [zstd, '--version'])
    cases, totals = (
        [],
        dict(
            sections=0,
            control_bytes=0,
            media_bytes=0,
            ram_bytes=0,
            media_digests=0,
            image_bindings=0,
            missing_source_paths=0,
        ),
    )
    for index in range(6):
        path = out / f'case-{index}.rxc'
        parts = framing(path.read_bytes(), codec.Wire)
        wanted_order = (
            [1, 2, 3, 4, 5]
            + ([7] if index else [])
            + ([8, 9] if index >= 2 else [])
            + [6]
        )
        assert list(parts) == wanted_order
        totals['sections'] += len(parts)
        cfg = codec.config(parts[1])
        assert (
            cfg['arch'],
            cfg['backend'],
            cfg['memory'],
            cfg['vcpus'],
            cfg['pci'],
            cfg['cmdline'],
        ) == (0, 1, 131072, 1, int(index >= 2), 'checkpoint-bundle-oracle')
        assert not Path(cfg['kernel']).exists()
        totals['missing_source_paths'] += 1
        assert struct.unpack('<QQQ', parts[2]) == (123456789, 987654321, 131072)
        assert int.from_bytes(parts[3][:4], 'little') == 0
        if index < 3:
            assert cfg['storage'] == [None, None]
        else:
            mode = {3: 2, 4: 0, 5: 1}[index]
            for binding, value in zip(cfg['storage'], [0xA3, 0xB9]):
                assert (
                    binding['mode'] == mode
                    and binding['bytes'] == binding['max_bytes'] == 16384
                )
                assert (
                    binding['sha256']
                    == hashlib.sha256(bytes([value]) * 16384).hexdigest()
                )
                assert not Path(binding['path']).exists()
                totals['image_bindings'] += 1
                totals['missing_source_paths'] += 1
        artifacts = {path.name: sha(path)}
        for kind, raw in parts.items():
            name = f'case-{index}-section-{kind}.bin'
            (out / name).write_bytes(raw)
            artifacts[name] = sha(out / name)
        ram = run(
            f'ram-{index}',
            [
                zstd,
                '--quiet',
                '--decompress',
                '--stdout',
                str(out / f'case-{index}-section-6.bin'),
            ],
        )
        assert ram == bytes([0x6B]) * 131072
        totals['ram_bytes'] += len(ram)
        if index:
            media = control(parts[7], index, codec.Wire, runtime, models)
            totals['control_bytes'] += len(parts[7])
            for kind, expected in zip([8, 9], media):
                actual = run(
                    f'media-{index}-{kind}',
                    [
                        zstd,
                        '--quiet',
                        '--decompress',
                        '--stdout',
                        str(out / f'case-{index}-section-{kind}.bin'),
                    ],
                )
                assert actual == expected['bytes']
                assert hashlib.sha256(actual).hexdigest() == expected['sha256']
                totals['media_bytes'] += len(actual)
                totals['media_digests'] += 1
        cases.append(dict(index=index, artifacts=artifacts, config=cfg))
    assert before == {n: sha(root / n) for n in sources}
    report = dict(cases=6, **totals, failed=0)
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                source_sha256=before,
                library_sha256=sha(library),
                commands=commands,
                cases=cases,
                report=report,
                result='independent_bundle_framing_control_media_and_ram_match',
                scope='Typed deterministic serialization fixtures and separate Python/system-zstd expectations; no guest CPU, full-VM resume or native hypervisor proof.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
