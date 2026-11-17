"""Registered scalar-only application primitives and exactly-once host calls.

Registration is a trusted HOST API action. No guest file contains a callback,
registers a descriptor, grants host_value, or overrides portable services.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from threading import Lock

from .errors import option, require
from .wire import PRIMITIVES, records, encode, decode, validate_shape

ROOT=Path(__file__).resolve().parents[3]


def descriptor_digest(payload):
    require(type(payload) is bytes,'RT_HOST_DESCRIPTOR_BYTES')
    return hashlib.sha256(b'SMIR-HOST-V1\0'+payload).hexdigest()


def execution_root(payload):
    source=json.loads((ROOT/'docs/specifications/smir/portable/schema/execution/candidate.json').read_text())['records']
    merged=dict(source)
    for key,value in records().items():
        require(key not in merged or merged[key]==value,'RT_HOST_SCHEMA_CONFLICT')
        merged[key]=value
    codec=PRIMITIVES.RecordCodec(merged)
    try:
        result=codec.decode('execution_types',payload)
        require(codec.encode('execution_types',result)==payload,'RT_HOST_NONCANONICAL_TYPES')
    except PRIMITIVES.RecordError as error:
        require(False,'RT_HOST_TYPE_BYTES',str(error))
    return result


@dataclass(frozen=True)
class Registration:
    descriptor: dict
    types: object
    signature: dict
    callback: object
    digest: str


class Registry:
    def __init__(self,types_factory):
        self.types_factory=types_factory
        self.registrations={}

    def register(self,payload,callback):
        document=decode('runtime_host_descriptor',payload)
        require(document['revision']==1 and document['version']>0,'RT_HOST_VERSION')
        require(document['namespace'] and not document['namespace'].startswith('smir.') and
                '\0' not in document['namespace'] and document['name'] and '\0' not in document['name'],
                'RT_HOST_NAME')
        root=execution_root(bytes.fromhex(document['types']))
        require(root['payload_revision']==2 and not root['memory_layouts'],'RT_HOST_TYPES')
        types=self.types_factory(root)
        reference={'module':{'kind':'self'},'id':document['signature']}
        signature=types.get(reference)
        require(signature['kind']=='function' and signature['cc']=='portable' and not signature['variadic'],
                'RT_HOST_SIGNATURE')
        require(all(types.get(ref)['kind'] in {'int','float','raw'}
                    for ref in signature['params']+signature['results']),'RT_HOST_VALUE_ONLY')
        require(callable(callback),'RT_HOST_CALLBACK')
        digest=descriptor_digest(payload)
        key=document['namespace'],document['name'],document['version'],digest
        require(key not in self.registrations,'RT_HOST_DUPLICATE')
        registration=Registration(document,types,signature,callback,digest)
        self.registrations[key]=registration
        return registration

    def admit(self,imported,resolve_type):
        validate_shape('runtime_import',imported)
        require(imported['kind']=='host' and imported['capability']=='host_value','RT_HOST_IMPORT')
        key=imported['namespace'],imported['name'],imported['version'],imported['descriptor']
        require(key in self.registrations,'RT_HOST_UNREGISTERED')
        registration=self.registrations[key]
        actual=resolve_type(imported['signature'])
        expected={'module':{'kind':'self'},'id':registration.descriptor['signature']}
        require(actual['identity']==registration.types.digest(expected),'RT_HOST_SIGNATURE_MISMATCH')
        return registration


@dataclass(frozen=True)
class ResultValue:
    call: object
    index: int
    bits: bytes


@dataclass(frozen=True)
class ReturnPacket:
    call: object
    values: tuple


class Call:
    """Scalar capture+private factory; callback outside lock; O(total value bytes).

    kernel integration must first validate actual source live values/registry and
    pass exact widths/kinds/noundef from admitted signature. No pointer alternative.
    """
    def __init__(self,arguments,params,results):
        require(len(arguments)==len(params),'RT_HOST_ARGUMENT_ARITY')
        self.arguments=tuple(self._capture(value,spec) for value,spec in zip(arguments,params))
        self.results=tuple(results)
        self.state='new'
        self.entries=0
        self.publications=0
        self.packet=None
        self.error=None
        self.deferred=False
        self._lock=Lock()
        self._values={}
        self._packets={}

    @staticmethod
    def _capture(value,spec):
        require(spec['kind'] in {'int','float','raw'} and spec['bits']>0,'RT_HOST_VALUE_ONLY')
        width=spec['bits'];size=(width+7)//8
        payload=value['payload']
        kind=payload['kind']
        if kind in {'poison','undef'}:
            require(not spec['noundef'],'RT_HOST_NOUNDEF')
            return bytes(size)
        require(kind in {'scalar','raw'},'RT_HOST_VALUE_ONLY')
        bits=bytes.fromhex(payload['bits'])
        require(len(bits)==size and int.from_bytes(bits,'little')<(1<<width),'RT_HOST_VALUE_BITS')
        if kind=='raw':
            require(not payload['origins'],'RT_HOST_ORIGINS')
            poison=bytes.fromhex(payload['poison']);undef=bytes.fromhex(payload['undef'])
            require(len(poison)==len(undef)==size and all(not(p&u) for p,u in zip(poison,undef)),
                    'RT_HOST_VALUE_BITS')
            require((int.from_bytes(poison,'little')|int.from_bytes(undef,'little'))<1<<width,
                    'RT_HOST_VALUE_BITS')
            require(not spec['noundef'] or not any(poison+undef),'RT_HOST_NOUNDEF')
            bits=bytes(b&~(p|u) for b,p,u in zip(bits,poison,undef))
        return bits

    def result_bits(self,index,bits):
        require(self.state in {'entered','pending'},'RT_HOST_CALL_STATE')
        require(type(index) is int and 0<=index<len(self.results),'RT_HOST_RESULT_INDEX')
        spec=self.results[index]
        require(spec['kind'] in {'int','float','raw'} and type(bits) is bytes and
                len(bits)==(spec['bits']+7)//8 and int.from_bytes(bits,'little')<1<<spec['bits'],
                'RT_HOST_RESULT_BITS')
        value=ResultValue(self,index,bits)
        self._values[id(value)]=value
        return value

    def returned(self,values):
        require(self.state in {'entered','pending'},'RT_HOST_CALL_STATE')
        require(len(values)==len(self.results) and all(isinstance(value,ResultValue) and
                value.call is self and value.index==index and self._values.get(id(value)) is value
                for index,value in enumerate(values)),
                'RT_HOST_RETURN_TYPES')
        packet=ReturnPacket(self,tuple(values))
        self._packets[id(packet)]=packet
        return packet

    def enter(self,callback):
        with self._lock:
            require(self.state=='new','RT_HOST_REPLAY')
            self.state='entered';self.entries+=1
        # No registry or scheduler lock held across host callback.
        try:
            packet=callback(self,self.arguments)
        except Exception:
            # Models the provider's INSIDE-ABI containing shim. Native C++
            # noexcept/Rust extern-C unwinding may terminate before an outer
            # runtime catch and is outside the valid callback contract.
            from .services import errno_tables
            self.fail(errno_tables()['portable']['EIO'])
            return
        if packet is None:
            with self._lock:
                if self.state=='entered':self.state='pending'
        else:self.complete(packet)

    def complete(self,packet):
        require(isinstance(packet,ReturnPacket) and packet.call is self and
                self._packets.get(id(packet)) is packet,'RT_HOST_RETURN_PACKET')
        with self._lock:
            require(self.state in {'entered','pending','abandoned'},'RT_HOST_REPLAY')
            if self.state=='abandoned':
                self.state='abandoned_done'
            else:
                self.packet=packet;self.state='ready'

    def fail(self,status):
        from .services import errno_tables
        require(type(status) is int and status in set(errno_tables()['portable'].values()),'RT_HOST_ERROR')
        with self._lock:
            require(self.state in {'entered','pending','abandoned'},'RT_HOST_REPLAY')
            if self.state=='abandoned':self.state='abandoned_done'
            else:self.error=status;self.state='failed'

    def cancel(self):
        with self._lock:
            if self.state=='new':
                self.state='cancelled';return True
            self.deferred=True
            return False

    def publish(self):
        with self._lock:
            require(self.state=='ready' and self.publications==0,'RT_HOST_COMMIT')
            self.publications+=1;self.state='committed'
            return tuple(value.bits for value in self.packet.values)

    def abandon(self):
        with self._lock:
            require(self.state in {'new','entered','pending','ready','failed'},'RT_HOST_REPLAY')
            self.state=('abandoned' if self.state in {'entered','pending'} else 'abandoned_done')
            self.packet=None
