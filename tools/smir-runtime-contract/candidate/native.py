"""Exact logical foreign-CPU checkpoint validation (R019 revision3).

Not FXSAVE bytes and not execution or a native unwind implementation.
"""
import struct

from .errors import require
from .wire import validate_shape


def validate(context, *, isa, objects, thread_tls, unwind_rows):
    validate_shape('runtime_native_context', context)
    selected=context['isa']
    require(selected==isa and context['profile']==selected+'_v1', 'RT_NATIVE_PROFILE')
    raw={name:bytes.fromhex(context[name]) for name in ['integer','vector','control','x87','tls','opaque_extension']}
    require(not raw['opaque_extension'], 'RT_NATIVE_EXTENSION')
    if selected=='x86_64':
        require([len(raw[n]) for n in ['integer','vector','control','x87','tls']]==
                [128,256,16,112,32], 'RT_NATIVE_EXTENT')
        require(raw['control'][12:]==bytes(4) and raw['x87'][104:]==bytes(8)
                and raw['tls'][28:]==bytes(4),'RT_NATIVE_RESERVED')
        fop=struct.unpack_from('<H',raw['x87'],86)[0]
        require(fop&~0x7ff==0,'RT_NATIVE_X87_OPCODE')
        sp=struct.unpack_from('<Q',raw['integer'],4*8)[0]
        # Entire 80-bit physical images and full tags retained, including empty
        # register payloads, MMX aliases and unsupported encodings.
    elif selected=='aarch64':
        require([len(raw[n]) for n in ['integer','vector','control','x87','tls']]==
                [256,512,16,0,16], 'RT_NATIVE_EXTENT')
        require(raw['control'][12:]==bytes(4), 'RT_NATIVE_RESERVED')
        nzcv=struct.unpack_from('<I',raw['control'])[0]
        require(nzcv&~0xf0000000==0, 'RT_NATIVE_NZCV')
        sp=struct.unpack_from('<Q',raw['integer'],31*8)[0]
        require(sp%16==0,'RT_NATIVE_STACK_ALIGNMENT')
    else:
        require(False, 'RT_NATIVE_ISA')
    require(thread_tls==context['tls'],'RT_NATIVE_TLS')
    code=objects.get(context['code_object'])
    stack=objects.get(context['stack_object'])
    require(code is not None and code['live'] and code['kind']=='native_code' and
            code['generation']==context['code_generation'] and
            code['address']<=context['pc']<code['address']+code['size'], 'RT_NATIVE_CODE_LEASE')
    require(stack is not None and stack['live'] and stack['kind']=='stack' and
            stack['generation']==context['stack_generation'] and
            stack['address']<=sp<=stack['address']+stack['size'], 'RT_NATIVE_STACK_LEASE')
    key=context['code_object'],context['code_generation'],context['unwind_row']
    row=unwind_rows.get(key)
    require(row is not None and row['lower']<=context['pc']<row['upper'] and
            row['profile']==context['profile'], 'RT_NATIVE_CFI_ROW')
    return context


def x87_logical(context, index):
    require(context['isa']=='x86_64' and type(index) is int and 0<=index<8,'RT_NATIVE_X87_INDEX')
    raw=bytes.fromhex(context['x87'])
    require(len(raw)==112,'RT_NATIVE_EXTENT')
    top=(struct.unpack_from('<H',raw,82)[0]>>11)&7
    physical=(top+index)%8
    return raw[10*physical:10*(physical+1)]


def mmx(context,index):
    require(context['isa']=='x86_64' and type(index) is int and 0<=index<8,'RT_NATIVE_X87_INDEX')
    raw=bytes.fromhex(context['x87'])
    require(len(raw)==112,'RT_NATIVE_EXTENT')
    return raw[10*index:10*index+8]
