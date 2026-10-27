"""Independent required-region framing, system-zstd and restored-byte comparison."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(directory, zstd):
    layouts = [
        [(0, 4096)],
        [(0, 4096), (0x40000000, 8192), (0x80000000, 4096)],
        [(0, 8192), (0x100000000, 12288)],
        [(i * 8192, 4096) for i in range(128)],
    ]
    rows = []
    total_bytes = total_regions = total_sections = 0
    for index, layout in enumerate(layouts):
        file = directory / f'case-{index}.rxc'
        raw = file.read_bytes()
        assert raw[:16] == b'RAXCKPT\0' + struct.pack('<I', 8) + b'RXS8'
        count = struct.unpack_from('<I', raw, 16)[0]
        assert count == 7
        at, parts, order = 20, {}, []
        for _ in range(count):
            kind, schema, length = struct.unpack_from('<IIQ', raw, at)
            assert kind not in parts and schema == (2 if kind == 1 else 1)
            at += 16
            assert length <= len(raw) - at
            parts[kind] = raw[at : at + length]
            order.append(kind)
            at += length
        assert at == len(raw) and order == [1, 2, 3, 4, 5, 10, 6]
        region = parts[10]
        assert region[:8] == b'RAXRAM01'
        assert struct.unpack_from('<I', region, 8)[0] == len(layout)
        payload_at = 12 + 56 * len(layout)
        expected_all, metadata = bytearray(), []
        for slot, (address, size) in enumerate(layout):
            start, length, digest, compressed = struct.unpack_from(
                '<QQ32sQ', region, 12 + slot * 56
            )
            assert (start, length) == (address, size)
            expected = bytes(
                (((i * 17) + slot * 31 + index * 7) & 255) ^ 0x5A for i in range(size)
            )
            assert digest == hashlib.sha256(expected).digest()
            frame = region[payload_at : payload_at + compressed]
            assert len(frame) == compressed
            result = subprocess.run(
                [zstd, '-d', '-q', '-c'], input=frame, capture_output=True, timeout=30
            )
            assert result.returncode == 0 and result.stdout == expected, (
                index,
                slot,
                result.stderr,
            )
            payload_at += compressed
            expected_all.extend(expected)
            metadata.append(
                dict(
                    start=start,
                    bytes=length,
                    sha256=digest.hex(),
                    compressed_bytes=compressed,
                )
            )
        assert payload_at == len(region)
        restored = directory / f'case-{index}.restored'
        assert restored.read_bytes() == expected_all
        base = subprocess.run(
            [zstd, '-d', '-q', '-c'], input=parts[6], capture_output=True, timeout=30
        )
        assert base.returncode == 0 and base.stdout == expected_all[:4096]
        total_bytes += len(expected_all)
        total_regions += len(layout)
        total_sections += count
        rows.append(
            dict(
                index=index,
                regions=metadata,
                artifacts={p.name: sha(p) for p in [file, restored]},
            )
        )
    return dict(
        cases=4,
        regions=total_regions,
        sections=total_sections,
        physical_bytes=total_bytes,
        restored_bytes=total_bytes,
        reported_projection_bytes=4 * 4096,
        digests=total_regions,
        failed=0,
    ), rows


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
        'src/vm/snapshot/physical_memory.rs',
        'src/vm/snapshot/bundle.rs',
        'src/vm/snapshot/stream.rs',
        'src/vm/snapshot/pci.rs',
        'src/vm/snapshot/codec.rs',
        'tests/suites/vm/checkpoint_physical_memory.rs',
        'tools/checkpoint/physical_memory_guest.rs',
        'tools/checkpoint/physical_memory_oracle.py',
    ]
    before = {n: sha(root / n) for n in sources}
    library = out / 'librax.rlib'
    shutil.copyfile(args.target_dir / 'debug/librax.rlib', library)
    env = os.environ.copy()
    env['CARGO_MANIFEST_DIR'] = str(root)
    commands = []
    for name, command in [
        (
            'build',
            [
                'rustc',
                '+stable',
                '--edition=2024',
                str(root / 'tools/checkpoint/physical_memory_guest.rs'),
                '--extern',
                'rax=' + str(library),
                '-L',
                'dependency=' + str(args.target_dir / 'debug/deps'),
                '-o',
                str(out / 'publish'),
            ],
        ),
        ('publish', [str(out / 'publish'), str(out)]),
    ]:
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
    zstd = shutil.which('zstd')
    assert zstd
    report, cases = verify(out, zstd)
    assert (out / 'publish.stdout').read_text().splitlines() == [
        f"{row['index']}\t{len(row['regions'])}\t{sum(r['bytes'] for r in row['regions'])}"
        for row in cases
    ]
    assert before == {n: sha(root / n) for n in sources}
    manifest = dict(
        result='all_physical_regions_and_projections_match_independent_bytes',
        report=report,
        cases=cases,
        commands=commands,
        source_sha256=before,
        library_sha256=sha(library),
        system_zstd=zstd,
        scope='Synthetic mapped-region bytes and actual public file/restore APIs; no guest execution or complete VM/native transaction claim.',
    )
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
