#!/usr/bin/env python3
"""Independent native NUMA byte/fault model; no implementation imports."""
from pathlib import Path

OK, SHORT, AV, ALIGN, GUARD = '00000000', 'C0000004', 'C0000005', '80000002', '80000001'
PAGE, LIMIT = 4096, 0x7FFFFFFF0000


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fields(line):
    pairs = [item.split('=', 1) for item in line.split()]
    require(all(len(pair) == 2 for pair in pairs), 'malformed fields')
    require(len({pair[0] for pair in pairs}) == len(pairs), 'duplicate fields')
    return dict(pairs)


class Fault(Exception):
    pass


class Region:
    def __init__(self, base):
        self.base = base
        self.data = bytearray(b'\xA5' * (8 * PAGE))
        self.prot = ['rw'] * 8


class Memory:
    def __init__(self):
        self.regions = [Region(base) for base in (0x100000, 0x200000, 0x300000)]

    def locate(self, address):
        for region in self.regions:
            if 0 <= address - region.base < len(region.data):
                return region, address - region.base
        raise Fault(AV)

    def probe(self, address, size, write=False):
        end = address + size
        while address < end:
            region, offset = self.locate(address)
            index = offset // PAGE
            protection = region.prot[index]
            if protection == 'guard':
                region.prot[index] = 'rw'
                raise Fault(GUARD)
            if protection == 'none' or write and protection == 'ro':
                raise Fault(AV)
            address = min(end, region.base + (index + 1) * PAGE)

    def read(self, address, size):
        self.probe(address, size)
        region, offset = self.locate(address)
        return bytes(region.data[offset:offset + size])

    def write(self, address, data):
        self.probe(address, len(data), True)
        region, offset = self.locate(address)
        region.data[offset:offset + len(data)] = data

    def safe(self, address, size):
        try:
            region, offset = self.locate(address)
        except Fault:
            return b''
        index = offset // PAGE
        if region.prot[index] in ('guard', 'none'):
            return b''
        last = index + 1
        while last < 8 and region.prot[last] == region.prot[index]:
            last += 1
        return bytes(region.data[offset:min(offset + size, last * PAGE)])


def setup(row, width):
    memory = Memory()
    relationship, mode, offset = (int(row[key]) for key in ('relationship', 'mode', 'offset'))
    ip, op, rp = (region.base + 128 for region in memory.regions)
    memory.write(ip, relationship.to_bytes(4, 'little'))
    inp, out, ret = memory.regions
    if mode == 1: ip = 0
    elif mode == 2: ip = 1
    elif mode == 3: op = 0
    elif mode == 4: op = 1
    elif mode == 5: rp = 0
    elif mode == 6: rp = 1
    elif mode == 7:
        ip += offset
        memory.write(ip, relationship.to_bytes(4, 'little'))
    elif mode == 8: op += offset
    elif mode == 9: rp += offset
    elif mode == 10: inp.prot[0] = 'none'
    elif mode == 11: out.prot[0] = 'ro'
    elif mode == 12: ret.prot[0] = 'ro'
    elif mode == 13: inp.prot[0] = 'guard'
    elif mode == 14: out.prot[0] = 'guard'
    elif mode == 15: ret.prot[0] = 'guard'
    elif mode == 16:
        ip = inp.base + PAGE - offset
        memory.write(ip, relationship.to_bytes(4, 'little')[:min(offset, 4)])
        inp.prot[1] = 'none'
    elif mode in (17, 28):
        out.prot[1] = 'none' if mode == 17 else 'ro'
        op = out.base + PAGE - offset
    elif mode == 18: rp = op
    elif mode == 19: op = ip
    elif mode == 20: rp = ip
    elif mode == 21: op, rp = 0, 1
    elif mode == 22: ip, op, rp = 0, 0, 1
    elif mode == 23:
        ip += 1
        memory.write(ip, relationship.to_bytes(4, 'little'))
        op = 0
    elif mode == 24: inp.prot[0], op = 'none', 0
    elif mode == 25: inp.prot[0], rp = 'none', 1
    elif mode == 26: rp = op + offset
    elif mode == 27:
        ret.prot[1] = 'none'
        rp = ret.base + PAGE - offset
    elif 29 <= mode <= 36:
        addresses = [offset, -4, 0x7FFFFFFC, 0xFFFFFFFC, 0x7FFFFFFEFFFC,
                     0x7FFFFFFFFFFC, 0x7FFFFFFF0000, 0x800000000000]
        ip = addresses[mode - 29] & ((1 << (width * 8)) - 1)
    return memory, ip, op, rp


def record(width, relationship):
    if relationship == 4:
        data = bytearray(72 + width)
        data[:4] = (4).to_bytes(4, 'little')
        data[8:12] = bytes([1, 0, 1, 0])
        data[32:34] = bytes([8, 8])
        data[72] = 255
    else:
        data = bytearray(8 + 24 + width + 8)
        # Header8 + node prefix24 + affinity(width+8).
        require(len(data) == (48 if width == 8 else 44), 'layout extent')
        data[:4] = (1).to_bytes(4, 'little')
        data[30:32] = (1).to_bytes(2, 'little')
        data[32] = 255
    data[4:8] = len(data).to_bytes(4, 'little')
    return bytes(data)


def execute(memory, ip, op, rp, row, width):
    input_bytes, output_bytes = (int(row[key]) for key in ('input-bytes', 'output-bytes'))
    try:
        if not ip or not input_bytes: return 'C000000D'
        if ip % 4: return ALIGN
        if width == 8:
            if ip + input_bytes > LIMIT: return AV
            if output_bytes:
                if op % 4: return ALIGN
                if op + output_bytes > LIMIT: return AV
                memory.probe(op, output_bytes, True)
            if rp: memory.probe(rp, 4, True)
        if input_bytes < 4: return 'C000000D'
        relationship = int.from_bytes(memory.read(ip, 4), 'little')
        require(relationship in (1, 4, 6), 'unsupported replay relationship')
        data = record(width, relationship)
        if output_bytes < len(data):
            if rp: memory.write(rp, len(data).to_bytes(4, 'little'))
            return SHORT
        if width == 8:
            memory.write(op, data)
        elif relationship != 4:
            for offset, value in [(8, bytes(4)), (12, bytes(16)), (28, bytes(2)),
                                  (30, bytes([1, 0])), (32, bytes(8)), (40, bytes(4)),
                                  (36, bytes(2)), (32, bytes([255, 0, 0, 0])), (0, data[:8])]:
                memory.write(op + offset, value)
        else:
            for offset, value in [(8, data[8:12]), (12, bytes(16)), (28, bytes(4)),
                                  (32, bytes([8])), (33, bytes([8])), (72, data[72:76]),
                                  (34, bytes(38)), (0, data[:4]), (4, data[4:8])]:
                memory.write(op + offset, value)
        if rp: memory.write(rp, len(data).to_bytes(4, 'little'))
        return OK
    except Fault as fault:
        return str(fault)


def replay(row, width, state):
    memory, ip, op, rp = state
    status = execute(memory, ip, op, rp, row, width)
    prefix = f'case {row["case"]}, width {width}'
    require(row['status'] == status, prefix + ' status: ' + str((row['status'], status)))
    returned = memory.safe(rp, 4) if rp else b''
    length = int.from_bytes(returned, 'little')
    capture = max(length, 96) if int(status, 16) < 0x80000000 and returned and length <= 32768 else 96
    output, backing = memory.safe(op, capture), memory.safe(memory.regions[2].base + 128, 16)
    for name, data in [('output', output), ('result-backing', backing)]:
        require(row[name + '-read'] == str(int(bool(data))), prefix + ' read ' + name)
        require(int(row[name + '-captured-bytes']) == len(data), prefix + ' extent ' + name)
        require(bytes.fromhex(row[name]) == data, prefix + ' bytes ' + name)
    require(row['returned-read'] == str(int(bool(returned))), prefix + ' returned read')
    require(int(row['returned-captured-bytes']) == len(returned), prefix + ' returned extent')
    require(int(row['returned'], 16) == length, prefix + ' returned value')


def profile(directory, arch):
    width = 4 if arch.startswith('x86') else 8
    lines = (directory / f'native-numa-node-probe-{arch}.log').read_text().splitlines()
    require(lines[0] == f'profile width={width} page=4096 processor-count=8 processor-mask=FF', 'profile identity')
    require(lines[-1] == 'complete cases=349', 'incomplete capture')
    rows = [fields(line) for line in lines if line.startswith('case=')]
    require(len(rows) == 349 and [int(row['case']) for row in rows] == list(range(349)), 'ordinal coverage')
    require(all(row['exception'] == OK and int(row['width']) == width for row in rows), 'external exception/width')
    replayed = 0
    for row in rows:
        for name in ['output', 'result-backing']:
            require(len(bytes.fromhex(row[name])) == int(row[name + '-captured-bytes']), 'capture extent')
        if int(row['class']) != 107 or int(row['relationship']) not in (1, 4, 6): continue
        if row['repeat'] == '0': state = setup(row, width)
        replay(row, width, state)
        replayed += 1
    guards = [fields(line[12:]) for line in lines if line.startswith('range-guard ')]
    expected = [] if width == 4 else [dict(role=str(role), width='8', status=GUARD if role == 2 else AV,
                           exception=OK, guard='0' if role == 2 else '256') for role in range(3)]
    require(guards == expected, 'upper guard consumption')
    return len(rows) + len(guards), replayed + len(guards)


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    for arch in ('arm64', 'x64', 'x86', 'x86-laa'):
        print(arch, profile(root, arch))
