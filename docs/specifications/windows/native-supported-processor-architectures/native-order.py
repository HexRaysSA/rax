import ctypes as ct
import json
import sys
from pathlib import Path

assert sys.getwindowsversion().build == 29708
assert ct.sizeof(ct.c_void_p) == 8
kernel = ct.WinDLL('kernel32', use_last_error=True)
ntdll = ct.WinDLL('ntdll')
query = ntdll.NtQuerySystemInformationEx
query.argtypes = [ct.c_uint32, ct.c_void_p, ct.c_uint32, ct.c_void_p, ct.c_uint32, ct.c_void_p]
query.restype = ct.c_uint32
kernel.GetCurrentProcessId.restype = ct.c_uint32
kernel.OpenProcess.argtypes = [ct.c_uint32, ct.c_int, ct.c_uint32]
kernel.OpenProcess.restype = ct.c_void_p
kernel.CreateEventW.argtypes = [ct.c_void_p, ct.c_int, ct.c_int, ct.c_wchar_p]
kernel.CreateEventW.restype = ct.c_void_p
kernel.CloseHandle.argtypes = [ct.c_void_p]
kernel.DuplicateHandle.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_void_p), ct.c_uint32, ct.c_int, ct.c_uint32]

rows = []
def sample(name, handle=0, nbytes=8, capacity=16, input_kind='normal', output_kind='normal', length_kind='normal'):
    source = (ct.c_uint64 * 6)(handle)
    target = (ct.c_uint64 * 6).from_buffer_copy(b'\xa5' * 48)
    required = ct.c_uint32(0xa5a5a5a5)
    s = ct.addressof(source)
    t = ct.addressof(target)
    r = ct.addressof(required)
    inputs = {'normal': s, 'misaligned': s + 4, 'unmapped': 0x10000, 'null': None}
    outputs = {'normal': t, 'misaligned': t + 1, 'unmapped': 0x10000, 'null': None, 'input': s}
    lengths = {'normal': r, 'unmapped': 0x10000, 'null': None, 'output': t, 'end-output': t + 16, 'input': s}
    status = query(230, inputs[input_kind], nbytes, outputs[output_kind], capacity, lengths[length_kind])
    rows.append(dict(name=name, capacity=capacity, input_kind=input_kind, output_kind=output_kind, length_kind=length_kind,
                     status=status, returned=required.value, input=bytes(source).hex(), output=bytes(target).hex()))

pid = kernel.GetCurrentProcessId()
for access in (0, 1, 0x400, 0x1000):
    handle = kernel.OpenProcess(access, 0, pid)
    if not handle:
        real = ct.c_void_p()
        current = ct.c_void_p(-1)
        if not kernel.DuplicateHandle(current, current, current, ct.byref(real), access, 0, 0):
            rows.append(dict(name=f'process-access-{access:#x}', open_error=ct.get_last_error()))
            continue
        handle = real.value
    try:
        sample(f'process-access-{access:#x}', handle)
    finally:
        assert kernel.CloseHandle(handle)
event = kernel.CreateEventW(None, 1, 0, None)
assert event
try:
    sample('wrong-type', event)
finally:
    assert kernel.CloseHandle(event)
for name, case in (
        ('short-input-bad-destination', dict(nbytes=4, output_kind='unmapped')),
        ('short-input-misaligned', dict(nbytes=4, input_kind='misaligned')),
        ('short-input-bad-return', dict(nbytes=4, length_kind='unmapped')),
        ('unmapped-input-misaligned-output', dict(input_kind='unmapped', output_kind='misaligned')),
        ('unmapped-input-bad-output', dict(input_kind='unmapped', output_kind='unmapped')),
        ('unmapped-input-bad-return', dict(input_kind='unmapped', length_kind='unmapped')),
        ('invalid-handle-bad-output', dict(handle=0xf1234560, output_kind='unmapped')),
        ('invalid-handle-misaligned-output', dict(handle=0xf1234560, output_kind='misaligned')),
        ('invalid-handle-bad-return', dict(handle=0xf1234560, length_kind='unmapped')),
        ('short-output-bad-destination', dict(capacity=4, output_kind='unmapped')),
        ('short-output-misaligned', dict(capacity=4, output_kind='misaligned')),
        ('zero-output-misaligned', dict(capacity=0, output_kind='misaligned')),
        ('zero-output-bad-return', dict(capacity=0, length_kind='unmapped')),
        ('adequate-output-bad-return', dict(capacity=16, length_kind='unmapped')),
        ('output-alias-input', dict(handle=(1 << 64)-1, output_kind='input')),
        ('return-alias-input', dict(handle=(1 << 64)-1, length_kind='input')),
        ('return-alias-output', dict(length_kind='output')),
        ('return-alias-output-tail', dict(length_kind='end-output')),
        ('short-output-return-alias', dict(capacity=4, length_kind='output')),
    ):
    sample(name, **case)
with Path(__file__).with_name('result.json').open('x') as out:
    json.dump(rows, out, indent=2)
