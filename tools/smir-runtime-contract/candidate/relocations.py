"""Whole-staged typed relocation oracle, identified R039 REV4 DRAFT.

Actual selected target/placement/generation facts come from a trusted resolver.
Only a private issued ticket publishes bytes, shadow, origins and exposures.
"""
from copy import deepcopy
from dataclasses import dataclass
from threading import Lock

from .errors import exact, option, require, some

LIMIT=2**64
KINDS={'data_address','data_integer','tls_offset','function_token','import_token','function_integer','import_integer','code_address'}
INTEGER_KINDS={'data_integer','function_integer','import_integer'}


def tls_layout(segments):
    cursor=0;placements={}
    require([s['id'] for s in segments]==sorted({s['id'] for s in segments}),'RT_TLS_LAYOUT_ORDER')
    for segment in segments:
        align=segment['alignment'];size=len(bytes.fromhex(segment['initial']))+segment['zero_fill']
        require(align>0 and align&(align-1)==0,'RT_TLS_LAYOUT_ALIGNMENT')
        cursor=(cursor+align-1)&-align
        require(cursor+size<=LIMIT-1,'RT_TLS_LAYOUT_RESOURCE')
        placements[segment['id']]=cursor
        cursor+=size
    return placements,cursor


def bounds(value):
    if value is None:return None
    value=option(value)
    if value['empty']:return (1,0)
    return value['lower'],LIMIT if value['upper_is_limit'] else value['upper']


def interval(value):
    if value is None:return None
    lower,upper=value
    if lower>upper or upper<0 or lower>=LIMIT:
        return some({'lower':0,'upper':0,'upper_is_limit':False,'empty':True})
    lower,upper=max(0,lower),min(LIMIT,upper)
    return some({'lower':lower,'upper':0 if upper==LIMIT else upper,
                 'upper_is_limit':upper==LIMIT,'empty':False})


def validate_step(step):
    exact(step,['offset','check_base','flags','inrange'],'RT_PATCH_STEP_FIELDS')
    require(type(step['offset']) is int and -2**63<=step['offset']<2**63,'RT_PATCH_ADDEND')
    require(step['flags']==sorted(set(step['flags'])) and
            set(step['flags'])<={'inbounds','nuw','nusw'},'RT_PATCH_FLAGS')
    require(type(step['check_base']) is bool and (not step['check_base'] or 'inbounds' in step['flags']),
            'RT_PATCH_CHECK_BASE')
    span=option(step['inrange'])
    if span is not None:
        exact(span,['lower','upper'],'RT_PATCH_INRANGE_FIELDS')
        require(all(type(span[k]) is int and -2**63<=span[k]<2**63 for k in span) and
                span['lower']<=span['upper'],'RT_PATCH_INRANGE_BOUNDS')


def offset(pointer,step,target):
    """Independent constant GEP step; exact result-base clarification pending S."""
    value,restriction,poison=pointer
    if poison:return pointer
    delta=step['offset'];mathematical=value+delta;flags=set(step['flags'])
    if ('nuw' in flags and value+delta%LIMIT>=LIMIT) or (
            flags&{'nusw','inbounds'} and not 0<=mathematical<LIMIT):return 0,None,True
    result=mathematical%LIMIT
    if 'inbounds' in flags and (delta!=0 or step['check_base']):
        if target.get('weak_null') or not (target['object_base']<=value<=target['object_base']+target['object_size'] and
                                          target['object_base']<=result<=target['object_base']+target['object_size']):
            return 0,None,True
    span=option(step['inrange'])
    if span is not None:
        # Relative RESULT, then clip bounds rather than wrap the bounds themselves.
        restricted=bounds(interval((result+span['lower'],result+span['upper'])))
        if restriction is not None:
            before=bounds(restriction)
            restricted=max(before[0],restricted[0]),min(before[1],restricted[1])
        restriction=interval(restricted)
    return result,restriction,False


def remove_origins(origins,start,end):
    result=[]
    for origin in origins:
        lo,hi=origin['offset'],origin['offset']+origin['length']
        if end<=lo or hi<=start:result.append(origin);continue
        if lo<start:result.append({**origin,'length':start-lo})
        if end<hi:result.append({**origin,'offset':end,'length':hi-end,
                                'source_bit':origin['source_bit']+end-lo})
    return result


@dataclass(frozen=True)
class Ticket:
    registry: object
    identity: int


class Registry:
    def __init__(self,images,generations,*,max_integer_bits=2**23):
        self.images=deepcopy(images);self.generations=dict(generations)
        self.exposed=set();self.exposed_code=set();self.bindings=[];self.revision=1
        self._prepared={};self._next=1;self._lock=Lock()
        self.max_integer_bits=max_integer_bits

    def prepare(self,records,resolve):
        """O(P^2+patched bytes), O(source bytes+P). No externally visible effects."""
        with self._lock:
            staged=deepcopy(self.images);generations=dict(self.generations);revision=self.revision
        ranges={};exposures=set();code_exposures=set();bindings=[]
        for record in records:
            exact(record,['source_kind','source','offset','width','integer_bits','kind','target','addend','derivation','check_base','flags','inrange'],
                  'RT_PATCH_FIELDS')
            final={'offset':record['addend'],'check_base':record['check_base'],
                   'flags':record['flags'],'inrange':record['inrange']}
            steps=[*record['derivation'],final]
            require(len(steps)<=4096,'RT_PATCH_RESOURCE')
            for step in steps:validate_step(step)
            source=record['source_kind'],record['source']
            require(source in staged,'RT_PATCH_SOURCE')
            kind=record['kind'];require(kind in KINDS,'RT_PATCH_KIND')
            width=record['width'];precision=record['integer_bits'];at=record['offset'];image=staged[source]
            require(type(width) is int and 0<width<2**32 and type(at) is int and
                    0<=at and at+width<=len(image['bytes']),'RT_PATCH_BOUNDS')
            if kind in INTEGER_KINDS:
                require(type(precision) is int and 0<precision<2**32 and width==(precision+7)//8,
                        'RT_PATCH_INTEGER_WIDTH')
                require(precision<=self.max_integer_bits,'RT_PATCH_RESOURCE')
            else:require(precision==0 and width in {4,8},'RT_PATCH_UNUSED_INTEGER_WIDTH')
            require(all(at+width<=a or b<=at for a,b in ranges.setdefault(source,[])),'RT_PATCH_OVERLAP')
            ranges[source].append((at,at+width))
            if kind=='code_address':
                require(width==8 and precision==0 and record['addend']==0 and
                        not record['derivation'] and not record['check_base'] and
                        not record['flags'] and record['inrange'] is None,'RT_CODE_RELOCATION')
                # Static validity does not make a dictionary resolver an
                # AddressAuthority/WeakAbsent issuer. No staged bytes escape.
                from .requirements import RuntimeUnavailable
                raise RuntimeUnavailable('code_address_unavailable', 'actual selected address issuer required')
            target=resolve(record['target'])
            domain={'data_address':'data','data_integer':'data','tls_offset':'tls',
                    'function_token':'function','import_token':'import',
                    'function_integer':'function','import_integer':'import'}[kind]
            require(target['kind']==domain and target['live'],'RT_PATCH_TARGET')
            weak=target.get('weak_null',False)
            if not weak:
                require(target['generation']==generations.get(target['owner']),'RT_PATCH_GENERATION')
                bindings.append(deepcopy(target))
            restriction=None;poison=False;origin=None
            if kind in {'data_address','data_integer'}:
                require(kind=='data_integer' or width==8,'RT_PATCH_POINTER_WIDTH')
                value=0 if weak else target['value']
                restriction=None if weak else target['restriction']
                for step in steps:value,restriction,poison=offset((value,restriction,poison),step,target)
                if kind=='data_integer' and not poison:
                    require(restriction is None,'RT_PATCH_INRANGE_EXPOSURE')
                    if not weak:exposures.add((target['object'],target['object_generation']))
                    value&=(1<<precision)-1
                elif kind=='data_address' and not poison and (not weak or restriction is not None):
                    origin={'object':None if weak else some(target['object']),
                            'generation':0 if weak else target['object_generation'],'domain':'data'}
            else:
                require(not record['derivation'] and not record['check_base'] and not record['flags'] and record['inrange'] is None,
                        'RT_PATCH_UNUSED_POINTER_OPTIONS')
                if kind=='tls_offset':
                    require(not weak,'RT_PATCH_WEAK_TLS')
                    binding=target['tls_binding']
                    require(binding=={'module':target['owner'],'generation':target['generation'],
                                      'segment':binding['segment'],'offset':target['value']},'RT_PATCH_TLS_BINDING')
                    value=target['value']+record['addend']
                else:
                    require((kind in INTEGER_KINDS or width==8 and record['addend']==0) and
                            (weak or target['portable']),'RT_PATCH_CODE_TOKEN')
                    value=0 if weak else target['value']
                    require(weak or 0<value<LIMIT,'RT_PATCH_CODE_TOKEN')
                    if kind in INTEGER_KINDS:
                        value=((value&((1<<precision)-1))+record['addend'])%2**precision
                        if not weak:code_exposures.add((target['object'],target['object_generation']))
                    elif not weak:origin={'object':some(target['object']),'generation':target['object_generation'],'domain':'code'}
                require(0<=value<1<<(8*width),'RT_PATCH_OVERFLOW')
            image['bytes'][at:at+width]=(0 if poison else value).to_bytes(width,'little')
            shadow=((1<<precision)-1).to_bytes(width,'little') if poison and kind in INTEGER_KINDS else bytes([255 if poison else 0])*width
            image['poison'][at:at+width]=shadow
            image['undef'][at:at+width]=bytes(width)
            image['origins']=remove_origins(image['origins'],at*8,(at+width)*8)
            if origin is not None:
                image['origins'].append({**origin,'offset':at*8,'length':64,'pointer_bits':value,
                                         'source_bit':0,'range':restriction})
                image['origins'].sort(key=lambda o:o['offset'])
        with self._lock:
            require(self._next<LIMIT-1,'RT_PATCH_RESOURCE')
            ticket=Ticket(self,self._next);self._next+=1
            self._prepared[id(ticket)]=(ticket,revision,generations,staged,exposures,code_exposures,bindings)
            return ticket

    def commit(self,ticket):
        with self._lock:
            require(isinstance(ticket,Ticket) and ticket.registry is self and id(ticket) in self._prepared and
                    self._prepared[id(ticket)][0] is ticket,'RT_PATCH_TRANSACTION_AUTHORITY')
            _,revision,generations,images,exposures,code_exposures,bindings=self._prepared[id(ticket)]
            require(revision==self.revision and generations==self.generations,'RT_PATCH_TRANSACTION_STALE')
            require(self.revision<LIMIT-1,'RT_PATCH_RESOURCE')
            self.images=images;self.exposed|=exposures;self.exposed_code|=code_exposures;self.bindings+=bindings
            self.revision+=1;del self._prepared[id(ticket)]
