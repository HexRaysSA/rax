#!/usr/bin/env python3
"""Independent replay of original build29683 allocation observations."""
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parent
OK='00000000'; INVALID='C000000D'; ACCESS='C0000005'; ALIGN='80000002'; GUARD='80000001'

def rows(kind,profile,count,release_status=True):
    records=[dict(item.split('=',1) for item in line.split()) for line in (ROOT/f'native-allocate-ex-{kind}{profile}.log').read_text().splitlines()]
    assert len(records)==count,(kind,profile,len(records))
    for row in records:
        assert row['width']==('4' if profile.startswith('x86') else '8')
        if 'exception' in row:assert row['exception']==OK,row
        if 'freed' in row and release_status:assert row['freed']==OK,row
    return records

def check(row,status):assert row['status']==status,row

total=0
for profile in ['arm64','x86','x86-laa','x64']:
    wow=profile.startswith('x86'); data=rows('',profile,53);total+=len(data)
    invalid={'null-parameters','unknown-type','duplicate-address','numa-invalid','reserved-type-bits','bad-parameters-zero-count','align-page','align-nonpower','low-unaligned','high-unaligned','high-max','range-inverted','range-too-small','zero-size','invalid-flags','fixed-nonzero-requirements'}
    for r in data:
        name=r['case'];status=OK
        if name in invalid:status=INVALID
        elif name in {'bad-parameters','bad-requirements','unaligned-parameters','unaligned-requirements'}:status=ACCESS if wow and name.startswith('bad-') else (OK if wow else ALIGN)
        elif name=='null-requirements':status=ACCESS
        elif name=='invalid-protect':status='C0000045'
        elif name=='bad-array-count':status=INVALID if int(r['count'])==0 or wow and int(r['count'])>6 else (ACCESS if wow else ALIGN)
        elif wow and name in {'range-bottom','range-top','range-aligned'}:status='C0000017' # Original samples: constrained interval already occupied.
        check(r,status)
        if status==OK:
            base=int(r['base'],16);size=int(r['size'],16);requested=int(r['requested'],16)
            assert base>=65536 and base%65536==0,r
            assert size==(requested+4095)&~4095 if name!='fixed-unaligned' else size==8192,r
            assert r['freed']==OK,r
            assert r['state']==('00001000' if int(r['flags'],16)&0x1000 else '00002000'),r
            alignment=int(r['align'],16)
            if alignment:assert base%alignment==0,r
            low=int(r['low'],16);high=int(r['high'],16)
            if low:assert base>=low,r
            if high:assert base+size-1<=high,r
            if name=='range-top':assert base==0x1ff0000,r
            if name.startswith('fixed-'):assert base==0x20000000,r
    data=rows('fault-',profile,51);total+=len(data)
    invalid={'bad-flags-parameters-null','duplicate-numa','duplicate-attributes','numa-unspecified','attributes-unknown','attributes-ec-code','requirements-low-above-limit','requirements-size-overflow','valid-array-count'}
    success={'base-unaligned','size-unaligned','requirements-high-limit'}
    for r in data:
        name=r['case'];status=ACCESS
        if name in invalid:status=INVALID
        if name in success:status=OK
        if name in {'base-guard','size-guard','parameters-guard','requirements-guard'}:status=GUARD
        if wow and name=='size-guard':status=ACCESS
        if profile=='x64' and name in {'base-guard','size-guard'}:status=OK
        if name in {'handle-null','handle-invalid'}:status='C0000008'
        if name=='handle-thread':status='C0000024'
        if wow and name=='bad-count-base-null':status=INVALID
        if profile=='x86-laa' and name=='requirements-low-above-limit':status=OK
        check(r,status)
        if name=='size-readonly':assert (int(r['base'],16)!=0)==wow,r
        if 'guard' in name:assert r['page-protect']=='00000004',r
        if status==OK or wow and name=='size-readonly':assert r['freed']==OK,r
    data=rows('order-',profile,21);total+=len(data)
    for r in data:
        name=r['case'];status=INVALID
        if name in {'count-six-inaccessible-aligned','unknown-type-before-inaccessible-second','requirements-before-inaccessible-second','base-null-size-guard','size-readonly-invalid-type','base-readonly-invalid-type'}:status=ACCESS
        if name in {'count-seven-inaccessible-aligned','count-seven-accessible-prefix'}:status=INVALID if wow else ACCESS
        if name=='unaligned-array-invalid-flags':status=INVALID if wow else ALIGN
        if name=='invalid-handle-unaligned-array':status='C0000008' if wow else ALIGN
        if name=='invalid-handle-invalid-range':status='C0000008'
        if name=='base-guard-size-null':status=ACCESS if profile=='x64' else GUARD
        if name=='x86-pointer-padding':status=ACCESS if wow else OK
        if name=='large-alignment' and profile=='x86-laa':status=OK
        check(r,status)
        if name=='base-null-size-guard':assert r['page-protect']==('00000004' if wow else '00000104'),r
        if status==OK:assert r['freed']==OK,r
    print(f'{profile}: 125 observations verified')
assert total==500
print('500 native calls verified; dynamic default addresses are checked by bounds/alignment, not host ASLR constants')

for profile in ['arm64','x86','x86-laa','x64']:
    data=rows('padding-aligned-',profile,8,release_status=False)
    cases=set()
    for r in data:
        flags=int(r['flags'],16);payload=int(r['payload'],16)
        assert flags in {0x2000,0x3000} and payload in {0,1,1<<32,0xffffffff00000000},r
        assert (flags,payload) not in cases,r
        cases.add((flags,payload))
        # This oracle reports BOOL freed=1, rather than the other helpers' NTSTATUS.
        assert r['freed']=='1' and r['error']=='0',r
        assert r['type']=='2' and int(r['size'],16)==4096,r
        check(r,OK if payload==0 else INVALID)
        if payload==0:
            assert int(r['base'],16)>=65536 and int(r['base'],16)%65536==0,r
            assert int(r['state'],16)==(0x1000 if flags&0x1000 else 0x2000),r
        else:
            assert int(r['base'],16)==0 and int(r['state'],16)==0,r
    assert len(cases)==8
    print(f'{profile}: 8 aligned NUMA payload observations verified')
print('32 additional aligned NUMA calls verified; zero controls pass with reserve and reserve-plus-commit')

additional=32
for profile in ['arm64','x86','x86-laa','x64']:
    wow=profile.startswith('x86')
    data=rows('parameter-alignment-',profile,12,release_status=False)
    assert {(int(r['kind']),int(r['shift'])) for r in data}=={(k,s) for k in [1,2,5] for s in [0,1,4,8]}
    for r in data:
        misaligned=int(r['shift'])%8!=0
        check(r,ALIGN if misaligned and (not wow or r['kind']!='1') else OK)
        assert r['freed']=='1' and int(r['size'],16)==4096,r
        assert (int(r['base'],16)!=0)==(r['status']==OK),r
    additional+=len(data)
    for suffix,first,count in [('parameter-mixed-',0,72),('parameter-mixed-extra-',18,60)]:
        data=rows(suffix,profile,count,release_status=False)
        assert {(int(r['mode']),int(r['shift'])) for r in data}=={(m,s) for m in range(first,first+count//4) for s in [0,1,4,8]}
        for r in data:
            mode=int(r['mode']);misaligned=int(r['shift'])%8!=0
            if not wow and misaligned:status=ALIGN
            elif wow:
                if mode in {0,1,2,3}:status=OK
                elif mode==4:status=ALIGN if misaligned else OK
                elif mode in {9,10,11,15,16,17,24,25,26,27,28,29,30,31,32}:status=ACCESS
                elif mode in {12,18,19,20,21}:status=ALIGN if misaligned else INVALID
                else:status=INVALID
            else:
                if mode in {0,1,2,3,4}:status=OK
                elif mode in {9,10,17,25,26,30,31}:status=ACCESS
                elif mode==11:status=ALIGN
                else:status=INVALID
            check(r,status)
            assert r['freed']=='1' and int(r['size'],16)==4096,r
            assert (int(r['base'],16)!=0)==(status==OK),r
        additional+=len(data)
    for suffix,faults in [('numa-order-',3),('numa-order-protection-',4)]:
        data=rows(suffix,profile,2*4*faults,release_status=False)
        assert {(int(r['kind']),int(r['handle']),int(r['fault'])) for r in data}=={(k,h,f) for k in [2,5] for h in range(4) for f in range(faults)}
        for r in data:
            kind=int(r['kind']);handle=int(r['handle']);fault=int(r['fault'])
            if fault==1 and (kind==2 or wow):status=ACCESS
            elif kind==5:status=INVALID
            else:status=[INVALID,'C0000008','C0000024','C0000022'][handle]
            check(r,status)
            assert r['freed']=='1' and int(r['size'],16)==4096 and int(r['base'],16)==0,r
        additional+=len(data)
assert additional==832
print('1332 native calls verified, including WoW64 capture, alignment and NUMA/access/protection precedence')

# MEM_EXTENDED_PARAMETER's address-requirements payload remains a full64-bit
# pointer in WoW64; native conversion must not discard its upper bytes.
for profile in ['arm64','x86','x86-laa','x64']:
    path=ROOT/('native-allocate-ex-pointer-upper-probe-'+profile+'.log')
    entries=[dict(re.findall(r'([a-z-]+)=([^ ]+)',line)) for line in path.read_text().splitlines() if line.startswith('width=')]
    assert len(entries)==6,(profile,len(entries))
    for row in entries:
        equal=int(row['pointer'],16)==int(row['payload'],16)
        assert int(row['status'],16)==(0 if equal else 0xC0000005),row
        assert row['size']=='1000' and row['freed']=='1',row
        assert (int(row['base'],16)!=0)==equal,row
print('24 additional full64-bit pointer-payload observations verified; 1356 total native calls')
