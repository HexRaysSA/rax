#!/usr/bin/env python3
"""Check the product-published checkpoint framing with an independent parser."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Wire:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        end = self.offset + length
        assert end <= len(self.data)
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def integer(self, width):
        return int.from_bytes(self.take(width), 'little')

    def text(self):
        return self.take(self.integer(8)).decode('utf-8')

    def optional(self, read):
        tag = self.integer(1)
        assert tag in [0, 1]
        return read() if tag else None


def config(data):
    # Config schema1 uses fixed-width bincode primitives in this published order.
    r = Wire(data)
    result = dict(
        arch=r.integer(4), backend=r.integer(4), memory=r.integer(8), vcpus=r.integer(1)
    )
    result['kernel'] = r.text()
    result['initrd'] = r.optional(r.text)
    result['cmdline'] = r.text()
    result['hexagon_isa'] = r.integer(4)
    result['hexagon_endian'] = r.integer(4)
    result['hexagon_entry'] = r.optional(lambda: r.integer(8))
    result['hexagon_load'] = r.optional(lambda: r.integer(8))
    result['arm_models'] = [r.integer(4) for _ in range(4)]
    result['arm_entry'] = r.optional(lambda: r.integer(8))
    result['arm_load'] = r.optional(lambda: r.integer(8))
    result['dtb'] = r.optional(r.text)
    result['pci'] = r.integer(1)
    assert result['pci'] in [0, 1] and r.offset == len(data)
    return result


def parse(data):
    r = Wire(data)
    assert r.take(8) == b'RAXCKPT\0'
    assert r.integer(4) == 8 and r.take(4) == b'RXS8'
    count = r.integer(4)
    assert count == 6
    sections = {}
    for _ in range(count):
        kind, schema, length = r.integer(4), r.integer(4), r.integer(8)
        assert kind in range(1, 7) and kind not in sections and schema == 1
        assert length <= (1024 * 1024 if kind == 1 else 16 * 1024 * 1024)
        sections[kind] = r.take(length)
    assert r.offset == len(data) and set(sections) == set(range(1, 7))
    return sections


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    args = p.parse_args()
    root, out = args.repo.resolve(), args.work_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source_names = [
        'src/config/runtime.rs',
        'src/vm/snapshot.rs',
        'src/vm/snapshot/codec.rs',
        'src/vm/snapshot/legacy.rs',
        'tools/checkpoint/codec_guest.rs',
        'tools/checkpoint/codec_oracle.py',
    ]
    before = {n: sha(root / n) for n in source_names}
    library = args.target_dir / 'debug/librax.rlib'
    assert library.is_file(), (
        'Build the current product library before running the oracle.'
    )
    shutil.copyfile(library, out / 'librax.rlib')
    commands = []

    def run(name, command):
        start = time.monotonic()
        r = subprocess.run([str(v) for v in command], capture_output=True, timeout=60)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        commands.append(
            dict(
                name=name,
                args=[str(v) for v in command],
                code=r.returncode,
                seconds=time.monotonic() - start,
            )
        )
        assert r.returncode == 0, (name, r.stderr.decode(errors='replace')[-2000:])
        return r.stdout

    binary = out / 'publish'
    binary.unlink(missing_ok=True)
    run(
        'product-build',
        [
            'rustc',
            '+stable',
            '--edition',
            '2024',
            root / 'tools/checkpoint/codec_guest.rs',
            '--extern',
            f'rax={out / "librax.rlib"}',
            '-L',
            f'dependency={args.target_dir / "debug/deps"}',
            '-o',
            binary,
        ],
    )
    run('publish', [binary, out])
    zstd = shutil.which('zstd')
    assert zstd
    reports = []
    for i, (arch, cpu) in enumerate([(0, 0), (2, 2), (7, 5)]):
        for pci in [0, 1]:
            path = out / f'case-{i}-{pci}.rxc'
            parts = parse(path.read_bytes())
            cfg = config(parts[1])
            assert (
                cfg['arch'],
                cfg['backend'],
                cfg['memory'],
                cfg['vcpus'],
                cfg['pci'],
            ) == (arch, 1, 4096, 1, pci), cfg
            assert cfg['kernel'] == str(out / 'kernel.input')
            assert cfg['cmdline'] == 'checkpoint-wire-oracle' and cfg['initrd'] is None
            assert all(
                cfg[n] is None
                for n in [
                    'hexagon_entry',
                    'hexagon_load',
                    'arm_entry',
                    'arm_load',
                    'dtb',
                ]
            )
            assert struct.unpack('<QQQ', parts[2]) == (
                123456789 + i,
                987654321 + i,
                4096,
            )
            assert int.from_bytes(parts[3][:4], 'little') == cpu
            compressed = out / f'case-{i}-{pci}.zst'
            compressed.write_bytes(parts[6])
            memory = run(
                f'decompress-{i}-{pci}',
                [zstd, '--quiet', '--decompress', '--stdout', compressed],
            )
            assert memory == bytes([0x30 + i + pci]) * 4096
            reports.append(
                dict(
                    file=path.name,
                    arch=arch,
                    cpu_tag=cpu,
                    pci=bool(pci),
                    memory_bytes=len(memory),
                    sha256=sha(path),
                )
            )
    assert before == {n: sha(root / n) for n in source_names}
    assert sha(library) == sha(out / 'librax.rlib')
    report = dict(
        cases=len(reports),
        sections=len(reports) * 6,
        memory_bytes=sum(r['memory_bytes'] for r in reports),
        failed=0,
    )
    (out / 'manifest.json').write_text(
        json.dumps(
            dict(
                result='independent_framing_and_memory_match',
                report=report,
                cases=reports,
                source_sha256=before,
                library_sha256=sha(out / 'librax.rlib'),
                commands=commands,
                scope='Public product writer plus independent byte/config/framing parser and separate system zstd decoder. Serialization fixtures do not establish complete device/private-state or boot closure.',
            ),
            indent=2,
        )
        + '\n'
    )
    print(json.dumps(report))


if __name__ == '__main__':
    main()
