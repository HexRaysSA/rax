"""Independent draft GenericItanium layout over source facts; no loader/runtime.

Isolated ABI2 stage0 model. Wire qref/owner binding and complete semantic input
validation belong to the separate checked source-graph adapter.
"""
from dataclasses import dataclass, field

MAX_OBJECT=(1<<61)-1
class ModelError(ValueError):pass
class ResourceError(ModelError):pass
class Budget:
    def __init__(self,work=1_000_000,memory=64*1024*1024):self.remaining=work;self.bytes=memory
    def reserve(self,n):
        if n<0 or n>self.bytes:raise ResourceError('layout memory limit')
        self.bytes-=n
    def work(self,n=1):
        if n<0 or n>self.remaining:raise ResourceError('layout work limit')
        self.remaining-=n

def ru(n,a):
    if a<1 or a&(a-1):raise ModelError('alignment')
    v=(n+a-1)//a*a
    if v>MAX_OBJECT*8:raise ModelError('extent')
    return v

@dataclass
class Layout:
    size:int;align:int;data_size:int;nvsize:int;nvalign:int
    fields:list=field(default_factory=list)
    bases:dict=field(default_factory=dict)
    vbases:dict=field(default_factory=dict)
    primary:object=None
    primary_virtual:bool=False
    largest_empty:int=0
    own_vptr:bool=False

@dataclass(eq=False)
class BaseInfo:
    name:str;virtual:bool
    bases:list=field(default_factory=list)
    primary:object=None
    derived:object=None

@dataclass(frozen=True)
class ScalarType:
    size: int
    align: int
    value_bits: int = 0
    integral: bool = False

@dataclass(frozen=True)
class RecordType:
    # Actual owner-qualified, top-cv-erased declaration identity from a binder.
    key: object

@dataclass(frozen=True)
class ArrayType:
    element: object
    count: int | None

class Model:
    """Geometry over resolved source facts, not wire/issuer authority.

    Keys and type objects come from a separate checked source graph. This core
    never parses C++ spellings or erases qualifiers inside compound types.
    """
    def __init__(self, records, budget=None):
        self.records=records;self.budget=budget or Budget();self.cache={};self.active=set()
    def array(self, typ):
        if not isinstance(typ,ArrayType) or typ.count is None:return None
        count=typ.count;elem=typ.element
        while isinstance(elem,ArrayType):
            if elem.count is None:raise ModelError('nested flexible array')
            count*=elem.count;elem=elem.element
        return elem,count
    def type_layout(self, typ):
        self.budget.work()
        if isinstance(typ,ScalarType):
            if not (0<typ.size<=MAX_OBJECT and 0<typ.align<=65536 and typ.align&(typ.align-1)==0):raise ModelError('source scalar geometry')
            return Layout(typ.size,typ.align,typ.size,typ.size,typ.align)
        if isinstance(typ,RecordType):return self.layout(typ.key)
        if isinstance(typ,ArrayType):
            item=self.type_layout(typ.element)
            if typ.count is None:return Layout(0,item.align,0,0,item.align)
            size=item.size*typ.count
            if typ.count<=0 or size>MAX_OBJECT:raise ModelError('array extent')
            return Layout(size,item.align,size,size,item.align)
        raise ModelError('unresolved source type')
    def record_type(self, typ):
        if isinstance(typ,RecordType):
            if typ.key not in self.records:raise ModelError('missing record declaration')
            return typ.key
        return None
    def base_element_record(self, typ):
        while isinstance(typ,ArrayType):typ=typ.element
        return self.record_type(typ)
    def layout(self, key):
        self.budget.work()
        if key in self.cache:return self.cache[key]
        if key in self.active:raise ModelError('byvalue cycle')
        if key not in self.records:raise ModelError('unknown source record')
        if len(self.active)>=128:raise ResourceError('layout graph depth')
        self.budget.reserve(512)
        self.active.add(key)
        try:
            result=Builder(self,key).run();self.cache[key]=result;return result
        finally:self.active.remove(key)

class EmptyMap:
    def __init__(self,builder,largest):
        self.b=builder;self.m=builder.m;self.largest=largest;self.entries=set();self.maximum=-1
    def clear(self,name,offset):
        self.m.budget.work()
        return not self.m.records[name]['empty'] or (name,offset) not in self.entries
    def add(self,name,offset):
        self.m.budget.work()
        if self.m.records[name]['empty']:
            if (name,offset) not in self.entries:self.m.budget.reserve(96)
            self.entries.add((name,offset));self.maximum=max(self.maximum,offset)
    def check_base(self,info,offset):
        if offset>self.maximum:return True
        if not self.clear(info.name,offset):return False
        l=self.m.layout(info.name)
        for idx,child in info.bases:
            if not child.virtual and not self.check_base(child,offset+l.bases[idx]):return False
        if info.primary and info.primary.derived is info:
            if not self.check_base(info.primary,offset):return False
        for f,pos in zip(self.m.records[info.name]['fields'],l.fields):
            if f['bit_width'] is None and not self.check_field(f['type'],offset+pos//8):return False
        return True
    def update_base(self,info,offset,overlapping):
        if not overlapping and offset>=self.largest:return
        self.add(info.name,offset);l=self.m.layout(info.name)
        for idx,child in info.bases:
            if not child.virtual:self.update_base(child,offset+l.bases[idx],overlapping)
        if info.primary and info.primary.derived is info:self.update_base(info.primary,offset,overlapping)
        for f,pos in zip(self.m.records[info.name]['fields'],l.fields):
            if f['bit_width'] is None:self.update_field(f['type'],offset+pos//8,overlapping)
    def try_base(self,info,offset):
        if self.largest==0:return True
        if not self.check_base(info,offset):return False
        self.update_base(info,offset,self.m.records[info.name]['empty']);return True
    def check_complete(self,name,most,offset):
        if offset>self.maximum:return True
        if not self.clear(name,offset):return False
        l=self.m.layout(name)
        for idx,base in enumerate(self.m.records[name]['bases']):
            if not base['virtual'] and not self.check_complete(base['type'].key,most,offset+l.bases[idx]):return False
        if name==most:
            for vb,pos in l.vbases.items():
                if not self.check_complete(vb,most,offset+pos):return False
        for f,pos in zip(self.m.records[name]['fields'],l.fields):
            if f['bit_width'] is None and not self.check_field(f['type'],offset+pos//8):return False
        return True
    def update_complete(self,name,most,offset,overlapping):
        if not overlapping and offset>=self.largest:return
        self.add(name,offset);l=self.m.layout(name)
        for idx,base in enumerate(self.m.records[name]['bases']):
            if not base['virtual']:self.update_complete(base['type'].key,most,offset+l.bases[idx],overlapping)
        if name==most:
            for vb,pos in l.vbases.items():self.update_complete(vb,most,offset+pos,overlapping)
        for f,pos in zip(self.m.records[name]['fields'],l.fields):
            if f['bit_width'] is None:self.update_field(f['type'],offset+pos//8,overlapping)
    def check_field(self,typ,offset):
        if offset>self.maximum:return True
        rec=self.m.record_type(typ)
        if rec:return self.check_complete(rec,rec,offset)
        ar=self.m.array(typ)
        if not ar:return True
        rec=self.m.record_type(ar[0])
        if not rec:return True
        stride=self.m.layout(rec).size
        count=min(ar[1],max(0,(self.maximum-offset)//stride+1))
        self.m.budget.work(count)
        return all(self.check_complete(rec,rec,offset+i*stride) for i in range(count))
    def update_field(self,typ,offset,overlapping):
        if not overlapping and offset>=self.largest:return
        rec=self.m.record_type(typ)
        if rec:self.update_complete(rec,rec,offset,overlapping);return
        ar=self.m.array(typ)
        if not ar:return
        rec=self.m.record_type(ar[0])
        if not rec:return
        stride=self.m.layout(rec).size;count=ar[1]
        if not overlapping:count=min(count,max(0,(self.largest-1-offset)//stride+1))
        # Fail before count-dependent work/allocation, never silently skip it.
        self.m.budget.work(count)
        for i in range(count):self.update_complete(rec,rec,offset+i*stride,overlapping)
    def try_field(self,f,offset):
        if not self.check_field(f['type'],offset):return False
        self.update_field(f['type'],offset,f['no_unique_address']);return True

class Builder:
    def __init__(self,m,name):
        self.m=m;self.name=name;self.r=m.records[name];self.union=self.r['kind']=='union'
        self.cpp=self.r.get('language','cpp23')=='cpp23'
        self.m.budget.work(len(self.r['fields'])+len(self.r['bases']))
        self.m.budget.reserve(128*(len(self.r['fields'])+len(self.r['bases'])))
        self.align=self.r.get('explicit_align') or 1;self.size=0;self.data=0;self.padded=0;self.unfilled=0
        self.fields=[];self.bases={};self.vbases={};self.primary=None;self.primary_virtual=False;self.own_vptr=False
        self.virtual_infos={};self.nonvirtual_infos={};self.indirect=set();self.visited=set()
        self.largest=0
        for b in self.r['bases']:
            n=b['type'].key;l=m.layout(n)
            self.largest=max(self.largest,l.size if m.records[n]['empty'] else l.largest_empty)
        for f in self.r['fields']:
            n=m.base_element_record(f['type'])
            if n:
                l=m.layout(n);self.largest=max(self.largest,l.size if m.records[n]['empty'] else l.largest_empty)
        self.empty=EmptyMap(self,self.largest)
    def choose_primary(self):
        if not self.r['dynamic']:return
        seen=set()
        def indirect(n):
            if n in seen:return
            seen.add(n);l=self.m.layout(n)
            if l.primary_virtual:self.indirect.add(l.primary)
            for b in self.m.records[n]['bases']:indirect(b['type'].key)
        for b in self.r['bases']:indirect(b['type'].key)
        for b in self.r['bases']:
            n=b['type'].key
            if not b['virtual'] and self.m.records[n]['dynamic']:self.primary=n;return
        first=None
        def select(n):
            nonlocal first
            for b in self.m.records[n]['bases']:
                c=b['type'].key;l=self.m.layout(c)
                if b['virtual'] and self.m.records[c]['dynamic'] and l.nvsize==8:
                    if first is None:first=c
                    if c not in self.indirect:return c
                value=select(c)
                if value:return value
            return None
        self.primary=select(self.name) or first;self.primary_virtual=self.primary is not None
    def info(self,name,virtual):
        self.m.budget.work()
        if virtual and name in self.virtual_infos:return self.virtual_infos[name]
        self.m.budget.reserve(256)
        obj=BaseInfo(name,virtual)
        if virtual:self.virtual_infos[name]=obj
        layout=self.m.layout(name);primary=layout.primary if layout.primary_virtual else None;prior=None
        if primary:
            prior=self.virtual_infos.get(primary)
            if prior and prior.derived:primary=None
            elif prior:obj.primary=prior;prior.derived=obj
        obj.bases=[(i,self.info(b['type'].key,b['virtual'])) for i,b in enumerate(self.m.records[name]['bases'])]
        if primary and prior is None:
            obj.primary=self.virtual_infos[primary];obj.primary.derived=obj
        return obj
    def add_primary_offsets(self,info,offset):
        if info.primary and info.primary.derived is info:
            if info.primary.name in self.vbases:raise ModelError('duplicate primary virtual placement')
            self.vbases[info.primary.name]=offset;self.add_primary_offsets(info.primary,offset)
        l=self.m.layout(info.name)
        for idx,child in info.bases:
            if not child.virtual:self.add_primary_offsets(child,offset+l.bases[idx])
    def place_base(self,info):
        l=self.m.layout(info.name);empty=self.m.records[info.name]['empty'];self.align=max(self.align,l.nvalign)
        if empty and self.empty.try_base(info,0):self.size=max(self.size,l.size*8);return 0
        offset=ru((self.data+7)//8,l.nvalign)
        while not self.empty.try_base(info,offset):self.m.budget.work();offset+=l.nvalign
        if empty:self.size=max(self.size,(offset+l.size)*8)
        else:self.data=(offset+l.nvsize)*8;self.size=max(self.size,self.data)
        return offset
    def place_virtual(self,info):
        offset=self.place_base(info);self.vbases[info.name]=offset;self.add_primary_offsets(info,offset)
    def place_nonvirtual(self,idx,info):
        offset=self.place_base(info);self.bases[idx]=offset;self.add_primary_offsets(info,offset)
    def layout_bases(self):
        self.choose_primary()
        for idx,b in enumerate(self.r['bases']):
            n=b['type'].key;info=self.info(n,b['virtual'])
            if not b['virtual']:self.nonvirtual_infos[idx]=info
        if self.primary:
            if self.primary_virtual:
                info=self.virtual_infos[self.primary];info.derived=None;self.indirect.add(self.primary);self.visited.add(self.primary);self.place_virtual(info)
            else:
                idx=next(i for i,b in enumerate(self.r['bases']) if not b['virtual'] and b['type'].key==self.primary)
                self.place_nonvirtual(idx,self.nonvirtual_infos[idx])
        elif self.r['dynamic']:
            self.own_vptr=True;self.align=max(self.align,8);self.size=self.data=64
        for idx,b in enumerate(self.r['bases']):
            if not b['virtual'] and not (self.primary==b['type'].key and not self.primary_virtual):self.place_nonvirtual(idx,self.nonvirtual_infos[idx])
    def field(self,f):
        self.m.budget.work();l=self.m.type_layout(f['type']);w=f['bit_width']
        if w is not None:
            typ=f['type']
            if not isinstance(typ,ScalarType) or not typ.integral:raise ModelError('bitfield nonintegral')
            if w<0 or w>MAX_OBJECT*8 or (w==0 and f['name'] is not None):raise ModelError('bitfield width')
            if not self.cpp and w>typ.value_bits:raise ModelError('C bitfield width')
            if f['explicit_align'] is not None:raise ModelError('bitfield alignas')
            offset=0 if self.union else self.data-self.unfilled
            if w>l.size*8:
                a=max(s for s in (1,2,4,8,16) if s*8<=w)
                offset=0 if self.union else ru(self.data,a*8);self.align=max(self.align,a)
            else:
                if w==0 or offset%(l.align*8)+w>l.size*8:offset=ru(offset,l.align*8)
                if f['name'] is not None:self.align=max(self.align,l.align)
            self.fields.append(offset)
            if self.union:self.data=max(self.data,ru(w,8))
            else:self.data=ru(offset+w,8);self.unfilled=self.data-offset-w
            self.size=max(self.size,self.data);return
        self.unfilled=0
        rec=self.m.record_type(f['type']);overlap=f['no_unique_address'] and rec is not None
        empty=overlap and self.m.records[rec]['empty'];align=max(l.align,f['explicit_align'] or 1)
        offset=0 if self.union or empty else (self.data+7)//8;offset=ru(offset,align)
        if not self.union:
            while not self.empty.try_field(f,offset):
                self.m.budget.work()
                offset=ru((self.data+7)//8,align) if offset==0 and self.data else offset+align
        self.fields.append(offset*8);self.align=max(self.align,align)
        if empty:self.size=max(self.size,(offset+l.size)*8)
        else:
            effective=max(l.nvsize,l.data_size) if overlap else l.size
            self.data=max(self.data,effective*8) if self.union else (offset+effective)*8
            self.size=max(self.size,self.data);self.padded=max(self.padded,offset+l.size)
    def layout_virtuals(self,name):
        l=None if name==self.name else self.m.layout(name)
        primary=self.primary if l is None else l.primary;pv=self.primary_virtual if l is None else l.primary_virtual
        for b in self.m.records[name]['bases']:
            self.m.budget.work();n=b['type'].key
            if b['virtual'] and (primary!=n or not pv) and n not in self.indirect and n not in self.visited:
                self.visited.add(n);self.place_virtual(self.virtual_infos[n])
            if self.m.layout(n).vbases:self.layout_virtuals(n)
    def run(self):
        self.layout_bases()
        for f in self.r['fields']:self.field(f)
        nvsize=(self.size+7)//8;nvalign=self.align
        self.layout_virtuals(self.name)
        if self.size==0 and self.cpp and self.r['empty']:self.size=8
        self.size=max(self.size,self.padded*8);size=ru(self.size,self.align*8)//8
        data=(self.data+7)//8
        if not self.cpp or self.r['pod03']:data=nvsize=size
        if size<1 or size>MAX_OBJECT or not 0<=data<=size or not 0<=nvsize<=size:raise ModelError('record extent')
        return Layout(size,self.align,data,nvsize,nvalign,self.fields,self.bases,self.vbases,self.primary,self.primary_virtual,self.largest,self.own_vptr)
