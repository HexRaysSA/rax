import ctypes as ct
import json
import sys
from pathlib import Path

assert sys.getwindowsversion().build == 29708 and ct.sizeof(ct.c_void_p) == 8
kernel = ct.WinDLL('kernel32')
user = ct.WinDLL('user32')
win = ct.WinDLL('win32u')
ntdll = ct.WinDLL('ntdll')
query = win.NtUserFindExistingCursorIcon
query.argtypes = [ct.c_void_p] * 3
query.restype = ct.c_void_p
ntdll.RtlSetLastWin32Error.argtypes = [ct.c_uint32]
ntdll.RtlGetLastWin32Error.restype = ct.c_uint32
ntdll.RtlSetLastWin32ErrorAndNtStatusFromNtStatus.argtypes = [ct.c_uint32]
ntdll.RtlGetLastNtStatus.restype = ct.c_uint32
kernel.VirtualAlloc.argtypes = [ct.c_void_p, ct.c_size_t, ct.c_uint32, ct.c_uint32]
kernel.VirtualAlloc.restype = ct.c_void_p
kernel.VirtualProtect.argtypes = [ct.c_void_p, ct.c_size_t, ct.c_uint32, ct.POINTER(ct.c_uint32)]
kernel.VirtualFree.argtypes = [ct.c_void_p, ct.c_size_t, ct.c_uint32]

class Name(ct.Structure):
    _fields_ = [('length', ct.c_uint16), ('maximum', ct.c_uint16), ('buffer', ct.c_void_p)]

import itertools
buf = ct.create_unicode_buffer('USER32')
other = ct.create_unicode_buffer('missing')
module = Name(12,14,ct.addressof(buf))
missing = Name(14,16,ct.addressof(other))
rows=[]
def sample(label,m,r,a):
    ntdll.RtlSetLastWin32ErrorAndNtStatusFromNtStatus(0xc0000034)
    ntdll.RtlSetLastWin32Error(0x5aa5)
    value=query(m,r,a) or 0
    rows.append(dict(label=label,value=value,error=ntdll.RtlGetLastWin32Error(),status=ntdll.RtlGetLastNtStatus()))
    return value
def args(hint,selector,flags=(0,0,0)):
    return (ct.c_uint32*6)(hint,0,selector,*flags)
def addr(obj):
    return ct.addressof(obj)
r=Name(0,0,32512)
a=args(0,1)
arrow=sample(['arrow'],addr(module),addr(r),addr(a))
assert arrow
for kind in (0,1,2,3,4,5,6,7,8,0xf,0x10,0x20,0x100,0x10000,0x80000000,0xffffffff):
    for hint in (0,arrow):
        a=args(hint,kind)
        sample(['selector',kind,hint],addr(module),addr(r),addr(a))
for ordinal,kind in itertools.product((32512,32513,32514,32515,32516,32640,32646,32650,32651),(1,3)):
    r=Name(0,0,ordinal)
    for flags in itertools.product((0,1,32),(0,1,32),(0,1,32)):
        a=args(0,kind,flags)
        sample(['properties',ordinal,kind,*flags],addr(module),addr(r),addr(a))
for label,descriptor in [('good',Name(0,0,32512)),('bad-name',Name(1,2,addr(buf))),('bad-addr',Name(2,2,0x10000)),('bad-desc',None)]:
    empty=Name(0,0,addr(buf))
    bad=Name(1,2,addr(buf))
    null=Name(0,0,0)
    for mcase,m in [('good',addr(module)),('null',0),('null-buf',addr(null)),('unmapped',0x10000),('empty',addr(empty)),('odd',addr(bad))]:
        for hcase,a in [('no-hint',args(0,1)),('valid',args(arrow,1)),('invalid',args(0xffff1234,1)),('null',None)]:
            sample(['order',label,mcase,hcase],m,addr(descriptor) if descriptor is not None else 0,addr(a) if a is not None else 0)
r=Name(0,0,32512)
a=args(0,1)
page=4096
for permit in (1,0x104):
    for component,source in (('module',module),('resource',r),('request',a)):
        for prefix in (0,1,4,8,12,15,16,20,23,24,25,28):
            if prefix > ct.sizeof(source): continue
            base=kernel.VirtualAlloc(None,2*page,0x3000,4)
            assert base
            try:
                near=base+page-prefix
                ct.memmove(near,addr(source),ct.sizeof(source))
                old=ct.c_uint32()
                assert kernel.VirtualProtect(base+page,page,permit,ct.byref(old))
                ptrs = {'module':(near,addr(r),addr(a)),'resource':(addr(module),near,addr(a)),'request':(addr(module),addr(r),near)}
                sample(['boundary',permit,component,prefix],*ptrs[component])
            finally:
                assert kernel.VirtualFree(base,0,0x8000)
with Path(__file__).with_name('result.json').open('x') as out:
    json.dump(rows,out,separators=(',',':'))
