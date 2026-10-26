#!/usr/bin/env python3
"""Retain real modern virtio-MMIO split-ring records from QEMU AArch64 guests."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time

RAM = 0x40100000
INDIRECT = 1 << 28
NAMES = [
    'direct-read',
    'indirect-read',
    'mixed-read',
    'indirect-write',
    'mixed-write',
    'wrapper-write-ignored',
    'fragmented-header-read',
    'fragmented-header-write',
    'combined-streams',
    'nonlinear-indices',
    'unused-indirect-entries',
    'indirect-flush',
    'fragmented-id',
    'fragmented-data',
    'zero-length-buffers',
    'full-length-chain',
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def initial_disk():
    return bytes(i * 37 & 255 for i in range(4096))


def make_input(index):
    commands = []
    disk = bytearray(initial_disk())
    indirect = index != 0

    def request(kind, mode, sector=0):
        nonlocal disk
        writes = []
        outputs = []
        header = struct.pack('<IIQ', kind, 0, sector)
        payload = bytes([0xAB]) * 512
        status = 0x6000

        def put(offset, data):
            writes.append((offset, data))

        def descriptor(table, i, addr, length, flags, nxt):
            put(table + 16 * i, struct.pack('<QIHH', RAM + addr, length, flags, nxt))

        put(0x3000, header)
        put(0x4000, payload if kind == 1 else bytes([0xEE]) * 513)
        put(status, b'\xff')
        data_len = 20 if kind == 8 else 512
        buffers = [(0x3000, 16, False)]
        if kind != 4:
            buffers.append((0x4000, data_len, kind != 1))
        buffers.append((status, 1, True))
        if mode in ['fragmented-header-read', 'fragmented-header-write']:
            put(0x9000, header[:7])
            suffix = header[7:] + (payload if kind == 1 else b'')
            put(0xA000, suffix)
            buffers = [(0x9000, 7, False), (0xA000, len(suffix), False)]
            if kind == 0:
                buffers.append((0x4000, 513, True))
                status = 0x4200
            else:
                buffers.append((status, 1, True))
        elif mode == 'combined-streams':
            if kind == 1:
                put(0x9000, header + payload)
                buffers = [(0x9000, 528, False), (status, 1, True)]
            else:
                buffers = [(0x3000, 16, False), (0x4000, 513, True)]
                status = 0x4200
        elif mode == 'fragmented-id':
            buffers = [(0x3000, 16, False), (0x4000, 7, True), (0x4007, 14, True)]
            status = 0x4014
        elif mode == 'fragmented-data':
            buffers = [
                (0x3000, 16, False),
                (0x4000, 13, True),
                (0x400D, 255, True),
                (0x410C, 244, True),
                (status, 1, True),
            ]
        elif mode == 'zero-length-buffers':
            buffers = [(0x3000, 16, False), (0xB000, 0, False)] + buffers[1:]
        elif mode == 'full-length-chain':
            buffers = (
                [(0x3000 + i, 1, False) for i in range(13)]
                + [(0x300D, 3, False)]
                + buffers[1:]
            )
        table = 0x7003 if indirect else 0
        start = 0
        if mode in ['mixed-read', 'mixed-write']:
            descriptor(0, 0, *buffers[0][:2], 1, 1)
            buffers = buffers[1:]
            start = 1
        indices = (
            [0, 3, 1] if mode == 'nonlinear-indices' else list(range(len(buffers)))
        )
        for i, (address, length, writable) in enumerate(buffers):
            flags = (2 if writable else 0) | (1 if i + 1 < len(buffers) else 0)
            descriptor(
                table,
                indices[i],
                address,
                length,
                flags,
                indices[i + 1] if i + 1 < len(buffers) else 0,
            )
        if indirect:
            entries = 32 if mode == 'unused-indirect-entries' else max(indices) + 1
            descriptor(
                0,
                start,
                table,
                entries * 16,
                4 | (2 if mode == 'wrapper-write-ignored' else 0),
                0,
            )
        outputs.append((status, b'\x00'))
        if kind == 0:
            outputs.append((0x4000, bytes(disk[sector * 512 : sector * 512 + 512])))
        elif kind == 8:
            outputs.append((0x4000, b'rax-virtio-blk' + bytes(6)))
        elif kind == 1:
            disk[sector * 512 : sector * 512 + 512] = payload
        used_len = 1 + (data_len if kind in [0, 8] else 0)
        commands.append((writes, outputs, used_len))

    kind = 1 if index in [3, 4, 7, 8] else 4 if index == 11 else 8 if index == 12 else 0
    request(kind, NAMES[index], 1 if kind == 1 else 0)
    if kind == 1:
        request(0, 'direct-read', 1)
        request(0, 'direct-read', 0)
    raw = bytearray(
        b'VIOIN001'
        + struct.pack('<II', (INDIRECT if indirect else 0) | 512, len(commands))
    )
    expected = bytearray()
    for i, (writes, outputs, used_len) in enumerate(commands):
        raw += struct.pack('<I', len(writes))
        for offset, data in writes:
            raw += struct.pack('<II', offset, len(data)) + data
            raw += bytes(-len(data) % 4)
        raw += struct.pack('<II', 0, len(outputs))
        for offset, data in outputs:
            raw += struct.pack('<II', offset, len(data))
        expected += struct.pack('<IIIII', 0, used_len, i + 1, 1, 15)
        expected += b''.join(data for _, data in outputs)
    return bytes(raw), bytes(expected), bytes(disk), len(commands)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--library', type=Path)
    parser.add_argument('--dependency-dir', type=Path)
    args = parser.parse_args()
    root, work = args.repo.resolve(), args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    library = args.library or args.target_dir / 'debug/librax.rlib'
    dependencies = args.dependency_dir or args.target_dir / 'debug/deps'
    assert library.is_file(), (
        'Build the current product library before running the oracle.'
    )
    commands = []

    def run(name, command, cwd=work, timeout=60, allowed_codes=(0,)):
        start = time.monotonic()
        result = subprocess.run(
            [str(v) for v in command],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        (work / (name + '.stdout')).write_bytes(result.stdout)
        (work / (name + '.stderr')).write_bytes(result.stderr)
        commands.append(
            {
                'name': name,
                'command': [str(v) for v in command],
                'code': result.returncode,
                'seconds': time.monotonic() - start,
            }
        )
        assert result.returncode in allowed_codes, (
            name,
            result.stderr.decode(errors='replace')[-2000:],
        )
        return result.stdout

    compare = work / 'compare'
    compare.unlink(missing_ok=True)
    run(
        'owning-build',
        [
            'rustc',
            '+stable',
            '--edition',
            '2024',
            root / 'tools/virtio-diff/indirect_compare.rs',
            '--extern',
            f'rax={library}',
            '-L',
            f'dependency={dependencies}',
            '-o',
            compare,
        ],
    )
    qemu = shutil.which('qemu-system-aarch64')
    assert qemu
    cases = []
    for index, name in enumerate(NAMES):
        case = work / f'case-{index:02d}'
        case.mkdir(exist_ok=True)
        raw, expected, disk, count = make_input(index)
        (case / 'input.bin').write_bytes(raw)
        (case / 'expected.bin').write_bytes(expected)
        (case / 'expected-media.bin').write_bytes(disk)
        (case / 'disk.raw').write_bytes(initial_disk())
        shutil.copyfile(root / 'tools/virtio-diff/indirect_guest.s', case / 'guest.s')
        run(
            f'assemble-{index}',
            [
                args.llvm_bin / 'llvm-mc',
                '-triple=aarch64-none-elf',
                '-filetype=obj',
                'guest.s',
                '-o',
                'guest.o',
            ],
            cwd=case,
        )
        run(
            f'link-{index}',
            [
                args.llvm_bin / 'ld.lld',
                '-Ttext=0x40080000',
                '-e',
                '_start',
                'guest.o',
                '-o',
                'guest.elf',
            ],
            cwd=case,
        )
        run(
            f'qemu-{index}',
            [
                qemu,
                '-machine',
                'virt',
                '-cpu',
                'max',
                '-m',
                '64M',
                '-accel',
                'tcg',
                '-display',
                'none',
                '-monitor',
                'none',
                '-serial',
                f'file:{case / "records.bin"}',
                '-no-reboot',
                '-global',
                'virtio-mmio.force-legacy=false',
                '-drive',
                f'file={case / "disk.raw"},format=raw,if=none,id=disk',
                '-device',
                'virtio-blk-device,drive=disk,serial=rax-virtio-blk',
                '-semihosting-config',
                'enable=on,target=native',
                '-kernel',
                case / 'guest.elf',
            ],
            timeout=30,
            allowed_codes=(0, 1) if index in [2, 4, 14] else (0,),
        )
        frame = (case / 'records.bin').read_bytes()
        assert (
            frame[:8] == b'RAXVIOI1' and struct.unpack_from('<I', frame, 8)[0] == count
        ), (name, frame)
        low, high, maximum = struct.unpack_from('<III', frame, 12)
        assert low & (INDIRECT | 512) == INDIRECT | 512 and high & 1 and maximum >= 16
        if index in [2, 4, 14]:
            assert frame[24:] == b'VIOFAIL!'
            message = (
                'virtio: zero sized buffers are not allowed'
                if index == 14
                else 'virtio-blk missing headers'
            )
            assert (
                work / f'qemu-{index}.stderr'
            ).read_text() == f'qemu-system-aarch64: {message}\n'
            assert (case / 'disk.raw').read_bytes() == initial_disk()
        elif index == 12:
            assert frame[24:] == expected[:-5] + bytes([0xEE]) * 5
            assert (case / 'disk.raw').read_bytes() == disk
        else:
            assert frame[24:] == expected, (name, frame[24:].hex(), expected.hex())
            assert (case / 'disk.raw').read_bytes() == disk, name
        cases.append(
            {
                'index': index,
                'name': name,
                'commands': count,
                'frame_bytes': len(frame),
                'feature_words': [low, high],
                'queue_max': maximum,
                'artifacts': {p.name: sha(p) for p in case.iterdir() if p.is_file()},
            }
        )
    report = json.loads(run('product-compare', [compare, work]))
    assert report['cases'] == len(NAMES) and report['failed'] == 0, report
    source_paths = [
        'src/devices/virtio/mod.rs',
        'src/devices/virtio/queue.rs',
        'src/devices/virtio/blk.rs',
        'src/devices/virtio/blk/request.rs',
        'tests/suites/devices/virtio_indirect.rs',
        'tools/virtio-diff/indirect_guest.s',
        'tools/virtio-diff/indirect_compare.rs',
    ]
    manifest = {
        'result': 'shared_contract_verified_with_explicit_reference_differences',
        'cases': cases,
        'report': report,
        'reference_differences': {
            'mixed_chain_rejected': [2, 4],
            'id_padding_untouched': [12],
            'zero_length_buffer_rejected': [14],
        },
        'commands': commands,
        'tool_sha256': sha(Path(__file__)),
        'source_sha256': {p: sha(root / p) for p in source_paths},
        'qemu_version': subprocess.check_output(
            [qemu, '--version'], text=True
        ).splitlines()[0],
        'reference_scope': 'QEMU TCG guest execution and owning product source replay; no native hypervisor execution.',
    }
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
