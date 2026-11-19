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
ids=[32512,32513,32514,32515,32516,0x7fff]
handles={}
for ordinal,kind in itertools.product(ids,(1,3)):
    r=Name(0,0,ordinal)
    a=args(0,kind)
    value=sample(['catalog',ordinal,kind],addr(module),addr(r),addr(a))
    if value:
        handles[(ordinal,kind)]=value
for ordinal,kind in itertools.product(ids,(0,1,2,3,4)):
    r=Name(0,0,ordinal)
    for key,hint in list(handles.items())+[(('absent',0),0xffff1234)]:
        for flags in ((0,0,0),(0,1,0),(0x8000,0,0)):
            a=args(hint,kind,flags)
            sample(['hint',ordinal,kind,*key,*flags],addr(module),addr(r),addr(a))
            if ordinal in (32512,0x7fff) and kind in (1,3):
                sample(['wrong-module',ordinal,kind,*key,*flags],addr(missing),addr(r),addr(a))
r=Name(0,0,32512)
a=args(0,1)
for offset in range(1,8):
    for name,objects in (('module',(module,r,a)),('resource',(r,module,a)),('request',(a,module,r))):
        source, *_=objects
        scratch=ct.create_string_buffer(ct.sizeof(source)+16)
        shifted=addr(scratch)+offset
        ct.memmove(shifted,addr(source),ct.sizeof(source))
        pointers = {'module':(shifted,addr(r),addr(a)), 'resource':(addr(module),shifted,addr(a)), 'request':(addr(module),addr(r),shifted)}
        sample(['unaligned',name,offset],*pointers[name])
for length,maximum in itertools.product((0,1,2,12,13),(0,1,2,12,13,14)):
    pointer=ct.addressof(buf)
    m=Name(length,maximum,pointer)
    res=Name(length,maximum,pointer)
    h=args(handles[(32512,1)],1)
    sample(['module-shape',length,maximum],addr(m),addr(r),addr(a))
    sample(['resource-shape',length,maximum],addr(module),addr(res),addr(h))
with Path(__file__).with_name('result.json').open('x') as out:
    json.dump(rows,out,separators=(',',':'))
