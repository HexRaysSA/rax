"""INT011 candidate arena registration and module-qualified nominal va_arg.

Independent byte pack/cursor model; source frontend has already performed the
pinned default promotions. Image.origins preserves opaque admitted byte-origin
facts; this tool never constructs a live pointer/token from numeric payload bits.
"""
from dataclasses import dataclass
import struct

from layout import align_up, require
from nominal import ref

HEADER=struct.Struct('<IIQQQ')


@dataclass(frozen=True)
class Image:
    data: bytes
    origins: tuple = ()  # (byte offset, opaque admitted origin) pairs


class Arenas:
    def __init__(self,graph,backing_fact):
        self.graph=graph
        self.backing_fact=backing_fact
        self.registrations={}
        self.activations={}
        self.next_cookie=1

    def pack(self,*,owner,recipe,entries,area,object_id,generation,c_linkage=False):
        require(len(entries)==len(recipe['params']),'ABI_CC_VARARGS_PLAN')
        require(area>0 and area%8==0,'ABI_CC_VARARGS_ALIGNMENT')
        payload=bytearray();origins=[]
        for entry,formal in zip(entries,recipe['params']):
            require(set(entry)=={'declaration','image'},'ABI_CC_VARARGS_PLAN')
            nominal=ref(entry['declaration'])
            require(self.graph.compatible(nominal,formal['type'],owner,owner),'ABI_CC_VARARGS_PLAN')
            layout=self.graph.layout(nominal,owner)
            typ=self.graph.resolve(nominal,owner)[1]
            require(typ['kind'] not in ('void','array','function','reference','handle','snapshot'),
                    'ABI_CC_VARARGS_TYPE')
            require(typ['kind']!='record' or {'trivial_copy','trivial_destroy'}<=set(typ['flags']),
                    'ABI_CC_VARARGS_NONTRIVIAL')
            # Promotions are a frontend requirement; detect the common malformed
            # plans rather than silently promoting a binary payload here.
            if typ['kind']=='scalar':
                require(typ['identity']['entity'] not in {'bool','char','signed char','unsigned char',
                    'short','unsigned short','float','char8_t','char16_t','wchar_t','char32_t'},
                    'ABI_CC_VARARGS_UNPROMOTED')
            require(typ['kind']!='enum' or 'scoped' in typ['flags'],'ABI_CC_VARARGS_UNPROMOTED')
            image=entry['image'];require(isinstance(image,Image) and len(image.data)==layout['size'],'ABI_CC_VARARGS_SIZE')
            mask=self.graph.value_mask(nominal,owner)
            canonical=bytes(value&bits for value,bits in zip(image.data,mask))
            begin=len(payload)
            require(area%layout['align']==0,'ABI_CC_VARARGS_ALIGNMENT')
            at=align_up(begin+32,layout['align']);end=align_up(at+layout['size'],8)
            require(end<=1024*1024,'ABI_CC_VARARGS_REFERENCE_RESOURCE')
            payload.extend(HEADER.pack(entry['declaration'],0,layout['size'],layout['align'],end))
            payload.extend(bytes(at-len(payload)));payload.extend(canonical);payload.extend(bytes(end-len(payload)))
            seen=set()
            for offset,origin in image.origins:
                require(type(offset) is int and 0<=offset<len(canonical) and offset not in seen and mask[offset]==255,
                        'ABI_CC_VARARGS_ORIGIN')
                seen.add(offset);origins.append((at+offset,origin))
        fact=self.backing_fact(object_id)
        require(fact['live'] and fact['generation']==generation and fact['base']==area and
                len(payload)<=fact['size'] and area+fact['size']<1<<64,'ABI_CC_VARARGS_BACKING')
        require(area not in self.registrations,'ABI_CC_VARARGS_REPLAY')
        registration={'owner':owner,'area':area,'object':object_id,'generation':generation,
                      'image':Image(bytes(payload),tuple(origins)),'c_linkage':c_linkage}
        self.registrations[area]=registration
        return registration['image']

    def start(self,*,area,bytes_,thread,activation,generation):
        registration=self.registrations.get(area)
        require(registration is not None and len(registration['image'].data)==bytes_,'ABI_CC_VARARGS_REGISTRATION')
        self._backing(registration)
        require(thread>0 and activation>0 and generation>0,'ABI_CC_VARARGS_ACTIVATION')
        cookie=self.next_cookie;self.next_cookie+=1
        require(cookie<1<<64,'ABI_CC_VARARGS_RESOURCE')
        self.activations[cookie]=(thread,activation,generation,registration)
        return Cursor(self,cookie,area,0,bytes_)

    def _backing(self,registration):
        fact=self.backing_fact(registration['object'])
        require(fact['live'] and fact['generation']==registration['generation'] and
                fact['base']==registration['area'] and len(registration['image'].data)<=fact['size'],
                'ABI_CC_VARARGS_BACKING')

    def revoke(self,thread,activation,generation):
        self.activations={cookie:value for cookie,value in self.activations.items()
                          if value[:3]!=(thread,activation,generation)}


@dataclass
class Cursor:
    arenas: Arenas
    cookie: int
    area: int
    cursor: int
    limit: int

    def copy(self):
        return Cursor(self.arenas,self.cookie,self.area,self.cursor,self.limit)

    def end(self):
        self.cookie=self.area=self.cursor=self.limit=0

    def arg(self,expected,*,owner,thread,activation,generation,decode_value):
        """Read using the cookie OWNER scope, independently of the visitor.

        The runtime helper resolves this original tuple from the process cookie
        registry. It is not the executing visitor's current scope. Owner revoke
        invalidates every copy; borrowing never extends that activation lifetime.
        Shared cursor mutation requires ordinary source synchronization.
        """
        entry=self.arenas.activations.get(self.cookie)
        require(entry is not None and entry[:3]==(thread,activation,generation),'ABI_CC_VARARGS_ACTIVATION')
        registration=entry[3];self.arenas._backing(registration)
        image=registration['image'];data=image.data
        require(self.area==registration['area'] and self.limit==len(data) and self.cursor%8==0 and
                0<=self.cursor<=self.limit-32,'ABI_CC_VARARGS_BOUNDS')
        declaration,reserved,size,align,next_=HEADER.unpack_from(data,self.cursor)
        actual=ref(declaration);graph=self.arenas.graph
        wanted=graph.layout(expected,owner);layout=graph.layout(actual,registration['owner'])
        require(reserved==0 and (size,align)==(layout['size'],layout['align']) and self.area%align==0,
                'ABI_CC_VARARGS_HEADER')
        at=align_up(self.cursor+32,align);end=align_up(at+size,8)
        require(next_==end<=self.limit and not any(data[self.cursor+32:at]) and not any(data[at+size:end]),
                'ABI_CC_VARARGS_BOUNDS')
        payload=data[at:at+size]
        mask=graph.value_mask(actual,registration['owner'])
        require(all(value&~bits==0 for value,bits in zip(payload,mask)),'ABI_CC_VARARGS_PADDING')
        compatible=graph.data_boundary_compatible(expected,actual,owner,registration['owner']) if registration['c_linkage'] else \
                   graph.compatible(expected,actual,owner,registration['owner'])
        _,a=graph.resolve(actual,registration['owner']);_,b=graph.resolve(expected,owner)
        if not compatible and a['kind']==b['kind']=='scalar' and a['bits']==b['bits'] and a['signed']!=b['signed']:
            unsigned_to_signed={'unsigned char':'signed char','unsigned short':'short','unsigned int':'int',
                'unsigned long':'long','unsigned long long':'long long','unsigned __int128':'__int128'}
            names={a['identity']['entity'],b['identity']['entity']}
            corresponding=any(names=={u,s} for u,s in unsigned_to_signed.items())
            compatible=corresponding and int.from_bytes(payload,'little')<1<<(a['bits']-1)
        if not compatible and a['kind']==b['kind']=='bitint' and a['bits']==b['bits'] and a['signed']!=b['signed']:
            compatible=int.from_bytes(payload,'little')<1<<(a['bits']-1)
        if not compatible and a['kind']==b['kind']=='pointer' and len(a['elements'])==len(b['elements'])==1:
            ac=graph.resolve(a['elements'][0],registration['owner'])[1]
            bc=graph.resolve(b['elements'][0],owner)[1]
            names={ac['identity']['entity'],bc['identity']['entity']}
            compatible=names=={'void','char'}
        require(compatible and size==wanted['size'] and align==wanted['align'],'ABI_CC_VARARGS_TYPE_MISMATCH')
        origins=tuple((offset-at,origin) for offset,origin in image.origins if at<=offset<at+size)
        value=decode_value(expected,Image(payload,origins),owner)
        self.cursor=next_
        return value
