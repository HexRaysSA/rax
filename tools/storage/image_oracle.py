"""Compare public raw-image APIs with independent Python byte/file contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import struct
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def operations():
    rng = random.Random(0x52415870)
    result = []
    for index in range(512):
        op = index % 3
        length = rng.choice([0, 1, 2, 511, 512, 1024, 4096]) if op != 2 else 0
        offset = rng.choice([0, 1, 4094, 8192, 16383, 16384, (1 << 64) - 1])
        if index % 4 == 0:
            offset = rng.randrange(16384)
        data = bytes(rng.getrandbits(8) for _ in range(length)) if op == 0 else b''
        result.append((op, offset, length, data))
    result.append((3, 512, 0, b''))
    result.extend([(0, 0, 512, bytes([0x75]) * 512), (1, 0, 512, b''), (2, 0, 0, b'')])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--repo', type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    here = Path(__file__).resolve().parent
    if here.parents[1] != repo:
        raise ValueError('Use the selected checkout tool')
    out = args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    marker = out / '.rax-image-oracle'
    if any(out.iterdir()) and (
        not marker.is_file() or marker.read_text() != 'version=1\n'
    ):
        raise ValueError('Use empty or owned evidence directory')
    marker.write_text('version=1\n')
    sources = [
        'src/devices/virtio/block_image.rs',
        'tools/storage/image_guest.rs',
        'tools/storage/image_oracle.py',
    ]
    bound = {n: sha(repo / n) for n in sources}
    library = args.target_dir.resolve() / 'debug/librax.rlib'
    digest = sha(library)
    shutil.copyfile(library, out / 'librax.rlib')
    manifest = {
        'source_sha256': bound,
        'library_sha256': digest,
        'commands': [],
        'cases': [],
    }

    def run(name, cmd, cwd=out):
        start = time.monotonic()
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, timeout=60, check=False
        )
        (cwd / (name + '.stdout')).write_bytes(result.stdout)
        (cwd / (name + '.stderr')).write_bytes(result.stderr)
        manifest['commands'].append(
            {
                'name': name,
                'args': cmd,
                'code': result.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(f'{name} failed; diagnostics retained')

    run(
        'build',
        [
            'rustc',
            '+stable',
            '--edition=2024',
            str(here / 'image_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '-L',
            'dependency=' + str(args.target_dir.resolve() / 'debug/deps'),
            '-o',
            str(out / 'image-guest'),
        ],
    )
    total = 0
    compared = 0
    errors = 0
    ops = operations()
    for mode in range(3):
        case = out / f'case-{mode}'
        case.mkdir(exist_ok=True)
        initial = bytes((i * 17 ^ i >> 9) & 255 for i in range(16384))
        raw = struct.pack('<8sIQI', b'RAXIMG01', mode, 16384, len(ops))
        raw += b''.join(
            struct.pack('<IQI', op, offset, length) + data
            for op, offset, length, data in ops
        )
        (case / 'input.bin').write_bytes(raw)
        (case / 'initial.raw').write_bytes(initial)
        (case / 'disk.raw').write_bytes(initial)
        run('execute', [str(out / 'image-guest'), str(case)], case)
        records = (case / 'records.bin').read_bytes()
        assert records[:8] == b'IMGREC01' and struct.unpack_from('<I', records, 8)[
            0
        ] == len(ops)
        cache = bytearray(initial)
        host = bytearray(initial)
        at = 12
        statuses = []
        for step, (op, offset, length, data) in enumerate(ops):
            status = 0
            if op == 3:
                host = host[:offset]
            elif op == 2:
                status = 3 if mode == 1 and len(host) != len(cache) else 0
            elif offset + length > len(cache) or offset + length >= 1 << 64:
                status = 1
            elif mode == 0:
                status = 2
            elif mode == 1 and len(host) != len(cache):
                status = 3
            else:
                replacement = data if op == 0 else bytes(length)
                cache[offset : offset + length] = replacement
                if mode == 1:
                    host[offset : offset + length] = replacement
            got, cache_size, host_size = struct.unpack_from('<BII', records, at)
            at += 9
            assert got == status, (mode, step, 'status', got, status)
            assert (cache_size, host_size) == (len(cache), len(host))
            assert records[at : at + cache_size] == cache, (mode, step, 'cache')
            at += cache_size
            assert records[at : at + host_size] == host, (mode, step, 'host')
            at += host_size
            compared += cache_size + host_size
            errors += int(status != 0)
            statuses.append(status)
        assert at == len(records)
        assert (case / 'cache.raw').read_bytes() == cache
        assert (case / 'disk.raw').read_bytes() == host
        manifest['cases'].append(
            {
                'mode': mode,
                'operations': len(ops),
                'statuses': statuses,
                'artifacts': {
                    n: sha(case / n)
                    for n in [
                        'input.bin',
                        'initial.raw',
                        'disk.raw',
                        'cache.raw',
                        'records.bin',
                    ]
                },
            }
        )
        total += len(ops)
    assert sha(library) == digest and bound == {n: sha(repo / n) for n in sources}
    manifest['report'] = {
        'modes': 3,
        'operations': total,
        'cache_and_host_bytes': compared,
        'expected_errors': errors,
        'failed': 0,
    }
    manifest['result'] = 'independent_image_operation_records_match'
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest['report']))


if __name__ == '__main__':
    main()
