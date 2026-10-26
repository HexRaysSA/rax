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


def validate_reference(index, case, frame, expected, disk, work, count):
    assert (
        frame[:8] == b'RAXVIOI1' and struct.unpack_from('<I', frame, 8)[0] == count
    ), (NAMES[index], frame)
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
        assert frame[24:] == expected, (NAMES[index], frame[24:].hex(), expected.hex())
        assert (case / 'disk.raw').read_bytes() == disk, NAMES[index]


SOURCE_PATHS = [
    'src/devices/virtio/mod.rs',
    'src/devices/virtio/queue.rs',
    'src/devices/virtio/blk.rs',
    'src/devices/virtio/blk/request.rs',
    'src/devices/virtio/blk/ranges.rs',
    'tests/suites/devices/virtio_indirect.rs',
    'tools/virtio-diff/indirect_guest.s',
    'tools/virtio-diff/indirect_compare.rs',
    'tools/virtio-diff/indirect_oracle.py',
    'tools/virtio-diff/guest_oracle.py',
]


def main():
    from guest_oracle import run_corpus

    run_corpus(
        names=NAMES,
        make_input=make_input,
        initial_disk=initial_disk,
        validate_reference=validate_reference,
        allowed_codes=lambda i: (0, 1) if i in [2, 4, 14] else (0,),
        comparison_source='tools/virtio-diff/indirect_compare.rs',
        source_paths=SOURCE_PATHS,
        tool_path=Path(__file__),
        reference_differences=dict(
            mixed_chain_rejected=[2, 4],
            id_padding_untouched=[12],
            zero_length_buffer_rejected=[14],
        ),
    )


if __name__ == '__main__':
    main()
