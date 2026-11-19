import ctypes as ct
import json,sys
from pathlib import Path
assert sys.getwindowsversion().build==29708
assert ct.sizeof(ct.c_void_p)==8
ntdll=ct.WinDLL('ntdll')
query=ntdll.NtQuerySystemInformationEx
query.argtypes=[ct.c_uint32,ct.c_void_p,ct.c_uint32,ct.c_void_p,ct.c_uint32,ct.c_void_p]
query.restype=ct.c_uint32
rows=[]
def sample(subject, nbytes, capacity, input_adjust=0, output_adjust=0, omit_return=False):
    source=(ct.c_uint64*2)()
    if subject=='pseudo-current':
        source[0]=(1<<64)-1
    elif subject=='invalid-ordinary':
        source[0]=0xf1234560
    target=(ct.c_uint64*6).from_buffer_copy(b'\xa5'*48)
    required=ct.c_uint32(0xa5a5a5a5)
    given=ct.addressof(source)+input_adjust if subject!='missing' else None
    dest=(ct.addressof(target)+output_adjust) if capacity else None
    address=ct.byref(required) if not omit_return else None
    status=query(230,given,nbytes,dest,capacity,address)
    rows.append(dict(subject=subject,input_length=nbytes,capacity=capacity,input_adjust=input_adjust,
                     output_adjust=output_adjust,omit_return=omit_return,status=status,
                     returned=required.value,observed=bytes(target).hex()))
for subject in ('zero','pseudo-current','invalid-ordinary'):
    for capacity in (0,1,4,8,12,15,16,17,32):
        sample(subject,8,capacity)
for subject in ('missing','zero'):
    for nbytes in (0,4,7,8,9,16):
        sample(subject,nbytes,16)
for alignment in (1,2,4):
    sample('zero',8,16,input_adjust=alignment)
    sample('zero',8,16,output_adjust=alignment)
for capacity in (0,16,32):
    sample('zero',8,capacity,omit_return=True)
with Path(__file__).with_name('result.json').open('x') as out:
    json.dump(rows,out,indent=2)
