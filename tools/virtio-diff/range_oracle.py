#!/usr/bin/env python3
"""Execute virtio Discard/Write Zeroes requests and full media reads under QEMU."""

from __future__ import annotations
from pathlib import Path
import struct
from guest_oracle import run_corpus

RAM = 0x40100000
NAMES = [
    'zeroes',
    'zeroes-unmap',
    'discard',
    'zeroes-overlap',
    'discard-page',
    'fragmented-ranges',
    '256-ranges',
    'out-of-range',
    'zeroes-reserved',
    'discard-unmap',
    'zeroes-all',
    'zero-count',
    'count-overflow',
    'discard-reserved',
    'partial-record',
    'combined-ranges',
]


def initial_disk():
    return bytes((i * 17 & 255) ^ 0xA5 for i in range(16384))


def make_input(index):
    disk = bytearray(initial_disk())
    commands = []

    def ranges(kind, entries, status=0, split=None, raw=None):
        writes = []

        def put(offset, data):
            writes.append((offset, data))

        def descriptor(i, address, length, flags, nxt):
            put(
                0x7003 + i * 16, struct.pack('<QIHH', RAM + address, length, flags, nxt)
            )

        metadata = (
            raw
            if raw is not None
            else b''.join(struct.pack('<QII', *entry) for entry in entries)
        )
        put(0x3000, struct.pack('<IIQ', kind, 0, 0))
        put(0x8000, metadata)
        put(0x6000, b'\xff')
        buffers = [(0x3000, 16, False)]
        if split is None:
            buffers.append((0x8000, len(metadata), False))
        else:
            put(0xA003, metadata[split:])
            buffers.extend(
                [(0x8000, split, False), (0xA003, len(metadata) - split, False)]
            )
        buffers.append((0x6000, 1, True))
        for i, (address, length, writable) in enumerate(buffers):
            descriptor(
                i,
                address,
                length,
                (2 if writable else 0) | (1 if i + 1 < len(buffers) else 0),
                i + 1,
            )
        put(0, struct.pack('<QIHH', RAM + 0x7003, len(buffers) * 16, 4, 0))
        commands.append((writes, [(0x6000, bytes([status]))], 1))
        if status == 0:
            for sector, count, _ in entries:
                disk[sector * 512 : (sector + count) * 512] = bytes(count * 512)

    if index == 0:
        ranges(13, [(3, 2, 0)])
    elif index == 1:
        ranges(13, [(3, 2, 1)])
    elif index == 2:
        ranges(11, [(5, 1, 0)])
    elif index == 3:
        ranges(13, [(8, 2, 0), (1, 3, 0), (3, 2, 0), (8, 2, 0)])
    elif index == 4:
        ranges(11, [(8, 8, 0)])
    elif index == 5:
        ranges(13, [(7, 2, 0)], split=7)
    elif index == 6:
        ranges(13, [(1, 1, 0)] * 255 + [(30, 2, 0)])
    elif index == 7:
        ranges(13, [(32, 1, 0)], status=1)
    elif index == 8:
        ranges(13, [(1, 1, 2)], status=2)
    elif index == 9:
        ranges(11, [(1, 1, 1)], status=2)
    elif index == 10:
        ranges(13, [(0, 32, 0)])
    elif index == 11:
        ranges(13, [(32, 0, 0)])
    elif index == 12:
        ranges(13, [(0, 0xFFFFFFFF, 0)], status=1)
    elif index == 13:
        ranges(11, [(1, 1, 0x80000000)], status=2)
    elif index == 14:
        ranges(13, [], status=1, raw=bytes(15))
    elif index == 15:
        ranges(13, [(8, 8, 0)])
        ranges(11, [(8, 8, 0)])
        ranges(13, [(24, 8, 1)])
    else:
        raise AssertionError(index)
    # Read the complete namespace into a separate, non-overlapping buffer.
    writes = [
        (0x3000, struct.pack('<IIQ', 0, 0, 0)),
        (0x6000, b'\xff'),
        (0x10000, bytes([0xEE]) * 16384),
    ]
    for i, address, length, flags, nxt in [
        (0, 0x3000, 16, 1, 1),
        (1, 0x10000, 16384, 3, 2),
        (2, 0x6000, 1, 2, 0),
    ]:
        writes.append((i * 16, struct.pack('<QIHH', RAM + address, length, flags, nxt)))
    commands.append((writes, [(0x6000, b'\0'), (0x10000, bytes(disk))], 16385))
    raw = bytearray(
        b'VIOIN001'
        + struct.pack('<II', (1 << 28) | (1 << 13) | (1 << 14), len(commands))
    )
    expected = bytearray()
    for i, (writes, outputs, length) in enumerate(commands):
        raw += struct.pack('<I', len(writes))
        for offset, data in writes:
            raw += struct.pack('<II', offset, len(data)) + data + bytes(-len(data) % 4)
        raw += struct.pack('<II', 0, len(outputs))
        for offset, data in outputs:
            raw += struct.pack('<II', offset, len(data))
        expected += struct.pack('<IIIII', 0, length, i + 1, 1, 15) + b''.join(
            data for _, data in outputs
        )
    return bytes(raw), bytes(expected), bytes(disk), len(commands)


def validate_reference(index, case, frame, expected, disk, work, count):
    assert frame[:8] == b'RAXVIOI1' and struct.unpack_from('<I', frame, 8)[0] == count
    low, high, maximum = struct.unpack_from('<III', frame, 12)
    assert low & 0x10006000 == 0x10006000 and high & 1 and maximum >= 16
    limits = struct.unpack_from('<6I', frame, 24)
    assert limits[0] >= 32 and limits[1] >= 1 and limits[3] >= 32 and limits[4] >= 1
    assert (
        limits[1] == limits[4] == 1
        and limits[0] == limits[3] == 4194303
        and limits[5] == 1
    ), limits
    actual = (case / 'disk.raw').read_bytes()
    if index == 14:
        assert frame[48:] == b'VIOFAIL!'
        assert (
            (work / f'qemu-{index}.stderr').read_text()
            == 'qemu-system-aarch64: virtio-blk discard/write_zeroes header too short\n'
        )
        assert actual == initial_disk()
    elif index in [3, 6]:
        assert actual == initial_disk()
        # These inputs exceed this reference's advertised segment/sector limit,
        # while remaining part of the product's larger configured profile.
        canonical = bytearray(expected)
        canonical[20] = 2
        canonical[-16384:] = actual
        assert frame[48:] == canonical, (
            NAMES[index],
            frame[48:80].hex(),
            canonical[:32].hex(),
        )
    elif index in [2, 4]:
        # Discard permits retaining or deallocating complete logical blocks.
        # Every byte outside the requested ranges must remain identical.
        initial = initial_disk()
        start, end = (5 * 512, 6 * 512) if index == 2 else (8 * 512, 16 * 512)
        for offset in range(0, len(actual), 512):
            block = actual[offset : offset + 512]
            assert block == initial[offset : offset + 512] or (
                start <= offset < end and block == bytes(512)
            )
        reference_expected = expected[:-16384] + actual
        assert frame[48:] == reference_expected
    else:
        assert frame[48:] == expected, (
            NAMES[index],
            frame[48:80].hex(),
            expected[:32].hex(),
        )
        assert actual == disk, NAMES[index]


SOURCE_PATHS = [
    'src/devices/virtio/mod.rs',
    'src/devices/virtio/queue.rs',
    'src/devices/virtio/blk.rs',
    'src/devices/virtio/blk/request.rs',
    'src/devices/virtio/blk/ranges.rs',
    'tests/suites/devices/virtio_ranges.rs',
    'tests/suites/devices/virtio_indirect.rs',
    'tools/virtio-diff/range_oracle.py',
    'tools/virtio-diff/range_compare.rs',
    'tools/virtio-diff/guest_oracle.py',
    'tools/virtio-diff/indirect_guest.s',
]


def main():
    run_corpus(
        names=NAMES,
        make_input=make_input,
        initial_disk=initial_disk,
        validate_reference=validate_reference,
        allowed_codes=lambda i: (0, 1) if i == 14 else (0,),
        comparison_source='tools/virtio-diff/range_compare.rs',
        source_paths=SOURCE_PATHS,
        tool_path=Path(__file__),
        reference_differences=dict(
            discard_advisory_cases=[2, 4],
            advertised_limit_cases=[3, 6],
            malformed_reference_fatal_cases=[14],
        ),
        drive_options=',discard=unmap',
    )


if __name__ == '__main__':
    main()
