"""Independently parse controller wire state and checkpoint continuation effects."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import time
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Wire:
    def __init__(self, data):
        self.data, self.at = data, 0

    def integer(self, width):
        end = self.at + width
        assert end <= len(self.data)
        value = int.from_bytes(self.data[self.at : end], 'little')
        self.at = end
        return value

    def boolean(self):
        value = self.integer(1)
        assert value in [0, 1]
        return bool(value)

    def end(self):
        assert self.at == len(self.data)


def queue(r):
    return {
        'base': r.integer(8),
        'size': r.integer(4),
        'tail': r.integer(4),
        'head': r.integer(4),
        'phase': r.boolean(),
        'cqid': r.integer(2),
        'active': r.boolean(),
    }


def q(base=0, size=0, tail=0, head=0, phase=False, cqid=0, active=False):
    return {
        'base': base,
        'size': size,
        'tail': tail,
        'head': head,
        'phase': phase,
        'cqid': cqid,
        'active': active,
    }


def nvme(data):
    assert len(data) == 353 and data[:8] == b'RAXNVM01'
    r = Wire(data)
    r.at = 8
    result = {'base': r.integer(8), 'media': r.integer(8), 'ro': r.boolean()}
    result.update({name: r.integer(4) for name in ['cc', 'csts', 'intms', 'aqa']})
    result.update(
        {
            'asq': r.integer(8),
            'acq': r.integer(8),
            'maximum': r.integer(2),
            'locked': r.boolean(),
        }
    )
    result['queues'] = [queue(r) for _ in range(12)]
    result['ien'] = [r.boolean() for _ in range(5)]
    r.end()
    return result


def nvme_expected(index, continued):
    large = index == 4
    sq = q(
        0x1000,
        4096 if large else 8,
        0 if large else 2,
        0 if large else 2,
        False,
        0,
        True,
    )
    cq = q(
        0x80000 if large else 0x2000,
        4096 if large else 8,
        0 if large else 2,
        0 if large else 2,
        True,
        0,
        True,
    )
    queues = [sq, cq] + [q() for _ in range(10)]
    if not large:
        head, tail = (1, 1) if index == 1 else (1, 2) if index == 2 else (0, 0)
        queues[3] = q(
            0x3000, 4, tail, 2 if continued and index == 2 else head, False, 1, True
        )
        queues[8] = q(
            0x4000,
            2 if index == 2 else 4,
            0 if continued and index == 2 else 1 if index in [1, 2] else 0,
            1 if continued and index == 2 else 0,
            not (continued and index == 2),
            1,
            True,
        )
    return {
        'base': 0x10000000,
        'media': 4096,
        'ro': index == 3,
        'cc': 0x00460001,
        'csts': 1,
        'intms': 0,
        'aqa': 0x0FFF0FFF if large else 0x00070007,
        'asq': 0x1000,
        'acq': 0x80000 if large else 0x2000,
        'maximum': 4,
        'locked': not large,
        'queues': queues,
        'ien': [False, not large, False, False, False],
    }


def ahci(data):
    assert len(data) == 112 and data[:8] == b'RAXAHC01'
    r = Wire(data)
    r.at = 8
    result = {
        'base': r.integer(8),
        'media': r.integer(8),
        'ro': r.boolean(),
        'ghc': r.integer(4),
        'is': r.integer(4),
        'slots': r.integer(4),
        'pending': r.boolean(),
        'clb': r.integer(8),
        'fb': r.integer(8),
    }
    result['port'] = {
        name: r.integer(4)
        for name in [
            'is',
            'ie',
            'cmd',
            'tfd',
            'sig',
            'ssts',
            'sctl',
            'serr',
            'sact',
            'ci',
        ]
    }
    result.update(
        {
            'present': r.boolean(),
            'fatal': r.boolean(),
            'current': r.integer(1),
            'next': r.integer(1),
            'command': r.integer(1),
            'device': r.integer(1),
            'lba': r.integer(8),
            'count': r.integer(4),
        }
    )
    r.end()
    return result


def ahci_expected(index, continued):
    completed = index == 5 or index == 7 and continued
    fatal = index == 6
    port = {
        'is': 0x40000000 if fatal else 33 if completed else 0,
        'ie': 0xFFFFFFFF,
        'cmd': 0x10 if index == 7 and not continued else 0x11,
        'tfd': 0x441 if fatal else 0x40,
        'sig': 0x101,
        'ssts': 0x133,
        'sctl': 0,
        'serr': 0,
        'sact': 0,
        'ci': (1 << 31) | int(continued)
        if fatal
        else 1
        if index == 7 and not continued
        else 0,
    }
    return {
        'base': 0x10000000,
        'media': 4096,
        'ro': index == 8,
        'ghc': 0x80000002,
        'is': int(fatal or completed),
        'slots': 32,
        'pending': fatal or completed,
        'clb': 0x1000,
        'fb': 0x2000,
        'port': port,
        'present': True,
        'fatal': fatal,
        'current': 31 if fatal else 17 if index == 5 else 0,
        'next': 0,
        'command': 0xFF if fatal else 0x35 if completed else 0,
        'device': 0x40 if fatal or completed else 0,
        'lba': 3 if index == 5 else 1 if completed else 0,
        'count': 1 if fatal else 0,
    }


def media_expected(index, continued):
    media = bytearray(
        [0x61 if index == 3 else 0x42 if index == 8 else 0xA3 if index < 5 else 0xB9]
        * 4096
    )
    if index == 2:
        media[:512] = bytes([0x27]) * 512
        if continued:
            media[512:1024] = bytes([0x39]) * 512
    if index == 5:
        media[1024:1536] = bytes([0x67]) * 512
    if index == 7 and continued:
        media[:512] = bytes([0x27]) * 512
    return media


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, required=True)
    a = p.parse_args()
    repo, out = a.repo.resolve(), a.work_dir.resolve()
    here = Path(__file__).resolve().parent
    if here.parents[1] != repo:
        raise ValueError('Use selected checkout tool')
    out.mkdir(parents=True, exist_ok=True)
    marker = out / '.rax-controller-oracle'
    if any(out.iterdir()) and (
        not marker.is_file() or marker.read_text() != 'version=1\n'
    ):
        raise ValueError('Use empty or owned evidence directory')
    marker.write_text('version=1\n')
    names = [
        'src/devices/nvme.rs',
        'src/devices/nvme/checkpoint.rs',
        'src/devices/ahci.rs',
        'src/devices/ahci/checkpoint.rs',
        'src/devices/virtio/block_image.rs',
        'src/devices/checkpoint_wire.rs',
        'tests/suites/devices/controller_checkpoint.rs',
        'tools/storage/controller_guest.rs',
        'tools/storage/controller_oracle.py',
    ]
    bound = {n: sha(repo / n) for n in names}
    library = a.target_dir.resolve() / 'debug/librax.rlib'
    digest = sha(library)
    shutil.copyfile(library, out / 'librax.rlib')
    manifest = {
        'source_sha256': bound,
        'library_sha256': digest,
        'commands': [],
        'cases': [],
    }

    def run(name, command):
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, timeout=60, check=False)
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        manifest['commands'].append(
            {
                'name': name,
                'args': command,
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
            str(here / 'controller_guest.rs'),
            '--extern',
            'rax=' + str(out / 'librax.rlib'),
            '-L',
            'dependency=' + str(a.target_dir.resolve() / 'debug/deps'),
            '-o',
            str(out / 'publish'),
        ],
    )
    run('publish', [str(out / 'publish'), str(out)])
    control_bytes = media_bytes = ram_bytes = 0
    for index in range(9):
        case = out / f'case-{index}'
        records = []
        for continued in [False, True]:
            prefix = 'continued-' if continued else ''
            control = (case / (prefix + 'control.bin')).read_bytes()
            parsed = nvme(control) if index < 5 else ahci(control)
            expected = (
                nvme_expected(index, continued)
                if index < 5
                else ahci_expected(index, continued)
            )
            assert parsed == expected, (
                index,
                continued,
                'controller',
                parsed,
                expected,
            )
            media = (case / (prefix + 'media.raw')).read_bytes()
            assert media == media_expected(index, continued), (
                index,
                continued,
                'media',
            )
            ram = (case / (prefix + 'ram.raw')).read_bytes()
            assert len(ram) == 0x20000
            if continued and index == 2:
                cid, status = struct.unpack_from('<HH', ram, 0x401C)
                assert (cid, status >> 1) == (0x101, 0)
            if continued and index == 7:
                assert struct.unpack_from('<I', ram, 0x1004)[0] == 512
            control_bytes += len(control)
            media_bytes += len(media)
            ram_bytes += len(ram)
            records.append(parsed)
        manifest['cases'].append(
            {
                'index': index,
                'states': records,
                'artifacts': {
                    n: sha(case / n)
                    for n in [
                        'control.bin',
                        'media.raw',
                        'ram.raw',
                        'continued-control.bin',
                        'continued-media.raw',
                        'continued-ram.raw',
                    ]
                },
            }
        )
    assert bound == {n: sha(repo / n) for n in names} and sha(library) == digest
    manifest['report'] = {
        'cases': 9,
        'continuation_events': 3,
        'control_bytes': control_bytes,
        'media_bytes': media_bytes,
        'ram_bytes': ram_bytes,
        'failed': 0,
    }
    manifest['result'] = 'independent_controller_state_and_continuation_match'
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest['report']))


if __name__ == '__main__':
    main()
