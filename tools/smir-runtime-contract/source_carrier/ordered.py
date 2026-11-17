"""Metered ordered record interpreter; structural data only."""
from dataclasses import dataclass
import hashlib,json,re
from .bindings import PROJECT,check_budget
from .errors import CarrierError,need
@dataclass(frozen=True)
class Limits:
    max_bytes:int=16*1024*1024
    max_nodes:int=1_000_000
    max_list:int=65536
    max_string:int=1024*1024
    max_depth:int=128

class OrderedCodec:
    """Separate explicit ordered interpreter with canonical aggregate options."""
    def __init__(self,budget,limits=Limits()):
        check_budget(budget);self.budget=budget;self.limits=limits
        need(type(limits)is Limits and all(type(x)is int and x>=0 for x in vars(limits).values())and limits.max_depth<=128,'V3_LIMIT_POLICY')
        p=PROJECT/'docs/specifications/smir/portable/schema/runtime/source_carrier_records.json';size=p.stat().st_size;need(size<=2**20,'V3_SCHEMA_BOUND')
        budget.charge(work=8*(size+1),edges=size+1,copied_bytes=16*(size+1))
        with p.open('rb')as stream:raw=stream.read(size+1)
        need(len(raw)==size,'V3_SCHEMA_CHANGED');need(hashlib.sha256(raw).hexdigest()=='c64512a81e9716f1870e77c266d9de8aebf2b6ee7779f5dd44fb33a9aa8f9cb0','V3_SCHEMA_IDENTITY');self.grammar=json.loads(raw)
        self.records=self.grammar['records'];self.caps=self.grammar['field_caps'];self.rules=self.grammar['source_scalar_rules']
        need(self.records['runtime_symbols']['fields'][:2]==[['payload_revision','u32'],['manifest','module_manifest']] and self.records['module_manifest']['fields'][0]==['identity','digest32'],'V3_MANIFEST_SCHEMA')
        self.nodes=0
    def visit(self,depth):
        self.budget.charge(work=2,edges=1,copied_bytes=64);self.nodes+=1
        need(self.nodes<=self.limits.max_nodes and depth<=min(self.limits.max_depth,self.budget.max_depth),'V3_RESOURCE')
    def scalar(self,path,value):
        rule=self.rules.get(path,{})
        if 'const'in rule:need(type(value)is type(rule['const'])and value==rule['const'],'V3_CONSTANT',path)
        if 'enum'in rule:need(any(type(value)is type(x)and value==x for x in rule['enum']),'V3_ENUM',path)
        if rule.get('type')=='integer':need(type(value)is int and rule['minimum']<=value<=rule['maximum'],'V3_INTEGER',path)
    def encode(self,kind,value):
        need(type(kind)is str and len(kind)<=128,'V3_SCHEMA');self.nodes=0;output=bytearray()
        def append(raw):
            need(len(raw)<=self.limits.max_bytes-len(output),'V3_RESOURCE')
            self.budget.charge(work=len(raw),copied_bytes=len(raw));output.extend(raw)
        def emit(kind,value,depth,path=''):
            self.visit(depth)
            if kind.startswith('vec:'):
                cap=self.caps.get(path,{});need(type(value)is list,'V3_TYPE',path)
                need(cap.get('minimum',0)<=len(value)<=min(self.limits.max_list,cap.get('maximum',2**32-1)),'V3_COUNT',path)
                append(len(value).to_bytes(4,'little'))
                for item in value:emit(kind[4:],item,depth+1,path+'[]')
            elif kind.startswith('opt:'):
                append(b'\0'if value is None else b'\1')
                if value is not None:
                    need(type(value)is dict and set(value)=={'some'},'V3_OPTION',path)
                    emit(kind[4:],value['some'],depth+1,path)
            elif re.fullmatch('[ui](8|16|32|64)',kind):
                size=int(kind[1:])//8;signed=kind[0]=='i';lo=-(1<<(8*size-1))if signed else 0;hi=(1<<(8*size-int(signed)))-1
                need(type(value)is int and lo<=value<=hi,'V3_INTEGER',path);self.scalar(path,value);append(value.to_bytes(size,'little',signed=signed))
            elif kind=='bool':
                need(type(value)is bool,'V3_TYPE',path);self.scalar(path,value);append(bytes([int(value)]))
            elif kind in('token','utf8'):
                need(type(value)is str,'V3_TYPE',path)
                maximum=min(self.limits.max_string,63 if kind=='token'else 2**32-1)
                need(len(value)<=maximum,'V3_RESOURCE')
                self.budget.charge(work=8*(len(value)+1),copied_bytes=4*(len(value)+1))
                self.scalar(path,value)
                if kind=='token':need(re.fullmatch('[a-z][a-z0-9_]{0,62}',value,re.ASCII)is not None,'V3_TOKEN')
                length=0
                for char in value:
                    point=ord(char);need(not 0xd800<=point<=0xdfff,'V3_TEXT')
                    length+=1 if point<0x80 else 2 if point<0x800 else 3 if point<0x10000 else 4
                prefix=1 if kind=='token'else 4
                need(length<=maximum and length+prefix<=self.limits.max_bytes-len(output),'V3_RESOURCE')
                raw=value.encode('ascii'if kind=='token'else'utf8','strict');append(length.to_bytes(prefix,'little'));append(raw)
            elif kind in('hex','digest32','bytes'):
                if kind=='bytes':
                    need(type(value)is bytes,'V3_TYPE');length=len(value);raw=value
                else:
                    need(type(value)is str and len(value)%2==0,'V3_HEX');length=len(value)//2
                prefix=0 if kind=='digest32'else 4
                need(length+prefix<=self.limits.max_bytes-len(output),'V3_RESOURCE')
                if kind=='digest32':need(length==32,'V3_DIGEST')
                if kind!='bytes':
                    self.budget.charge(work=8*(len(value)+1),copied_bytes=length)
                    need(re.fullmatch('(?:[0-9a-f]{2})*',value,re.ASCII)is not None,'V3_HEX');raw=bytes.fromhex(value)
                if kind!='digest32':append(length.to_bytes(4,'little'))
                append(raw)
            else:
                need(kind in self.records and type(value)is dict,'V3_TYPE',kind);record=self.records[kind];tag=record.get('discriminator');prefix=kind
                if tag is not None:
                    selected=value.get(tag);need(type(selected)is str and selected in record['variants'],'V3_TAG',kind);layout=record['variants'][selected];prefix+='.'+selected;emit('token',selected,depth+1)
                else:layout=record['fields']
                need(len(value)==len(layout)+int(tag is not None),'V3_FIELDS',kind)
                self.budget.charge(work=4*(len(layout)+1),copied_bytes=128*(len(layout)+1))
                need(set(value)=={name for name,_ in layout}|({tag}if tag is not None else set()),'V3_FIELDS',kind)
                for name,type_ in layout:emit(type_,value[name],depth+1,prefix+'.'+name)
        emit(kind,value,0);self.budget.charge(work=len(output),copied_bytes=len(output));return bytes(output)
    def decode(self,kind,payload):
        need(type(kind)is str and len(kind)<=128,'V3_SCHEMA');need(type(payload)is bytes and len(payload)<=self.limits.max_bytes,'V3_RESOURCE');self.nodes=0;cursor=0
        def take(size):
            nonlocal cursor
            need(0<=size<=len(payload)-cursor,'V3_TRUNCATED');self.budget.charge(work=size,copied_bytes=size);out=payload[cursor:cursor+size];cursor+=size;return out
        def number(size,signed=False):return int.from_bytes(take(size),'little',signed=signed)
        def read(kind,depth,path=''):
            self.visit(depth)
            if kind.startswith('vec:'):
                count=number(4);cap=self.caps.get(path,{})
                need(cap.get('minimum',0)<=count<=min(self.limits.max_list,self.limits.max_nodes,cap.get('maximum',2**32-1)),'V3_COUNT',path)
                self.budget.charge(work=count,edges=count,copied_bytes=8*count)
                return [read(kind[4:],depth+1,path+'[]')for _ in range(count)]
            if kind.startswith('opt:'):
                tag=number(1);need(tag<=1,'V3_OPTION');return {'some':read(kind[4:],depth+1,path)}if tag else None
            if re.fullmatch('[ui](8|16|32|64)',kind):
                value=number(int(kind[1:])//8,kind[0]=='i');self.scalar(path,value);return value
            if kind=='bool':
                value=number(1);need(value<=1,'V3_BOOLEAN');return bool(value)
            if kind in('token','utf8'):
                length=number(1 if kind=='token'else 4);need(length<=self.limits.max_string,'V3_RESOURCE');raw=take(length)
                self.budget.charge(work=4*(length+1),copied_bytes=4*(length+1))
                try:value=raw.decode('ascii'if kind=='token'else'utf8','strict')
                except UnicodeError as error:raise CarrierError('V3_TEXT')from error
                if kind=='token':need(re.fullmatch('[a-z][a-z0-9_]{0,62}',value,re.ASCII)is not None,'V3_TOKEN')
                self.scalar(path,value);return value
            if kind in('hex','digest32','bytes'):
                length=32 if kind=='digest32'else number(4);raw=take(length)
                if kind=='bytes':return raw
                self.budget.charge(work=2*length,copied_bytes=2*length);return raw.hex()
            need(kind in self.records,'V3_SCHEMA');record=self.records[kind];tag=record.get('discriminator');result={};prefix=kind
            if tag is not None:
                value=read('token',depth+1);need(value in record['variants'],'V3_TAG',kind);layout=record['variants'][value];result[tag]=value;prefix+='.'+value
            else:layout=record['fields']
            self.budget.charge(work=len(layout),edges=len(layout),copied_bytes=64*len(layout))
            for name,type_ in layout:result[name]=read(type_,depth+1,prefix+'.'+name)
            return result
        value=read(kind,0);need(cursor==len(payload),'V3_TRAILING');return value
