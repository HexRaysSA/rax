"""Unbound sequential protocol witness; no SourceFacts/private issuer/runtime authority.

Scope: one quiescent union, its original tracked allocation, no in-construction phase.
Bound: <=32768 physical bits per modeled object. O(bits+origin spans) time,
O(bits+spans) space; logical preflight costs are illustrative, not a cost profile.
Actual core stores/bulk operations use the verified independent Machine/Memory.
"""
from .bootstrap import initialize
initialize()
from dataclasses import dataclass, field
from candidate.raw import Raw, Span
from candidate.machine import Machine
from candidate.verify import verify
from candidate.type_system import ref, Types
from candidate.values import Value, Pointer, from_raw
MODE={'alignment':1,'volatile':False,'order':'none','failure_order':'none',
      'scope':'process','elementwise':False}

def _machine():
    # Authored generic execution fixture, independently verified before use.
    types={'payload_revision':2,'types':[
        {'id':0,'kind':'int','bits':1},{'id':1,'kind':'int','bits':8},
        {'id':2,'kind':'int','bits':32},{'id':3,'kind':'int','bits':64},
        {'id':7,'kind':'data_ptr','space':'guest_data'},
        {'id':15,'kind':'function','params':[],'results':[ref(2)],'variadic':False,
         'param_noundef':[],'result_noundef':[True],'cc':'portable'},
        {'id':17,'kind':'raw','bits':8}],
        'memory_layouts':[{'id':0,'type':ref(17),'size':1,'access_bytes':1,
                           'alignment':1,'fields':[],'element':None,'stride':0}]}
    functions={'payload_revision':2,'functions':[
        {'id':0,'signature':ref(15),'abi_signature':None,'params':[],'entry':0,
         'escape':'propagate','no_return':False,'blocks':[
             {'id':0,'phis':[],'ops':[
                 {'op':'constant','results':[{'id':0,'type':ref(2)}],
                  'operands':[],'literal':{'kind':'bits','value':'2a000000'}}],
              'term':{'op':'return','values':[0]}}]}]}
    return Machine(verify(types,functions,{'payload_revision':1,'functions':[]}))

def _storage():
    return {'type':ref(17),'layout':ref(0),'nominal':None,'abi_binding':None,'bytes':1}
from record_layout.materialization import _api

MAX_BITS=32768

def reject(code):raise ValueError(code)
def mask(width):return (1<<width)-1

def ledger(budget):
    if type(budget) is not _api().SourceQueryBudget:reject('budget_reference')

@dataclass(frozen=True)
class SourceValue:
    raw:Raw
    indeterminate:int=0
    source_fact_authority:bool=field(default=False,init=False)
    runtime_authority:bool=field(default=False,init=False)
    def __post_init__(self):
        if type(self.raw) is not Raw or type(self.indeterminate) is not int or not 0<=self.indeterminate<=mask(self.raw.width):reject('source_value_shape')
    def freeze(self):return SourceValue(self.raw.freeze(),self.indeterminate)
    def numeric(self,*,types,reference):
        """Source-I guard then actual core Raw->Int conversion; returns core Value.

        Preserves actual core poison/undef/range behavior. This is a conversion,
        not a complete language numeric operation or any private source fact.
        Actual destination types must be supplied; no implicit ABI/default width.
        """
        if self.indeterminate:reject('source_indeterminate_numeric_use')
        if (type(types) is not Types or types.get(reference)['kind']!='int'
                or types.width(reference)!=self.raw.width):reject('numeric_destination')
        return from_raw(types,reference,self.raw)

@dataclass(frozen=True)
class Handle:
    serial:int

@dataclass(frozen=True)
class Prepared:
    serial:int

@dataclass(frozen=True)
class Ticket:
    serial:int

@dataclass(frozen=True)
class Cell:
    generation:int
    live:bool
    arm:str

class World:
    source_fact_authority=False
    semantic_admission=False
    runtime_authority=False
    cost_profile_qualified=False
    def __init__(self,size=8):
        if type(size) is not int or not 1<=size<=MAX_BITS//8:reject('object_extent')
        self.machine=_machine();self.base=self.machine.memory.allocate(size,1)
        self._allocation=self.base
        self.size=size;self.init={self.base.origin:mask(size*8)}
        self.cells={};self.active=None;self.cursor=0;self.serial=0
        self.prepared={};self.tickets={};self.handles={};self.effect_frontier=None
        self.store_op={'op':'store','results':[],'operands':[], 'storage':_storage(),'mode':dict(MODE)}
    def pointer(self,offset=0):
        p=self.base
        return Pointer(p.address+offset,p.origin,p.generation,p.domain,p.access_range)
    def _new(self,kind):
        self.serial+=1;return kind(self.serial)
    def _record(self,table,token):
        entry=table.get(id(token))
        if entry is None or entry[0] is not token:reject('foreign_or_cloned_reference')
        return entry[1]
    def _require_modeled(self,pointer):
        # This model owns exactly its original allocation, never every valid
        # physical allocation in the Machine. Unknown init state is not zero.
        original=self._allocation
        if (type(pointer) is not Pointer or pointer.origin!=original.origin
                or pointer.generation!=original.generation or pointer.domain!=original.domain
                or pointer.origin not in self.init):
            reject('unmodeled_allocation')
    def _bits(self,pointer,width):
        self._require_modeled(pointer)
        item,offset=self.machine.memory.guard(pointer,width//8)
        return self.init[pointer.origin]>> (offset*8)&mask(width)
    def _assign(self,pointer,width,state):
        # Called only after successful preflight/core commit; no allocation oracle.
        self._require_modeled(pointer)
        item=self.machine.memory.objects[pointer.origin];start=(pointer.address-item['address'])*8
        old=self.init[pointer.origin];self.init[pointer.origin]=(old&~(mask(width)<<start))|(state<<start)
    def load(self,pointer,size):
        self._require_modeled(pointer)
        raw=self.machine.memory.raw_load(pointer,size);i=self._bits(pointer,raw.width);spans=[]
        for span in raw.origins:
            start=None
            for bit in range(span.offset,span.offset+span.length+1):
                keep=bit<span.offset+span.length and not (i>>bit)&1
                if keep and start is None:start=bit
                if not keep and start is not None:
                    spans.append(Span(start,bit-start,span.pointer,span.source+start-span.offset));start=None
        return SourceValue(Raw(raw.width,raw.bits,raw.poison&~i,tuple(spans),raw.undef|i),i)
    def store(self,pointer,value):
        if type(value) is not SourceValue or value.raw.width!=8:reject('scalar_store_shape')
        self._require_modeled(pointer)
        self.machine.memory_operation(self.store_op,[Value(ref(7),'concrete',pointer),Value(ref(17),'concrete',value.raw)])
        self._assign(pointer,8,value.indeterminate)
    def copy(self,destination,source,count,*,overlap=False):
        if type(count) is not int or not 0<count<=self.size:reject('copy_extent')
        self._require_modeled(destination);self._require_modeled(source)
        # Initialization and physical storage both snapshot before either write.
        self.machine.memory.guard(destination,count,write=True)
        snapshot=self._bits(source,count*8)
        self.machine.memory.bulk('memmove' if overlap else 'memcpy',destination,source,count,1,False)
        self._assign(destination,count*8,snapshot)
    def prospective(self,arm):
        """FIRST-birth handle, even if unused through that birth. No latest-path lookup."""
        if type(arm) is not str:reject('arm_shape')
        h=self._new(Handle);c=self.cells.get(arm)
        generation=c.generation if c and c.live else (c.generation+1 if c else 1)
        self.handles[id(h)]=(h,(arm,generation));return h
    def resolve(self,handle):
        arm,generation=self._record(self.handles,handle);c=self.cells.get(arm)
        if c is None or not c.live or c.generation!=generation:reject('stale_or_unborn_handle')
        return arm,generation
    def preflight(self,arm,offset,value,*,budget):
        ledger(budget)
        if self.effect_frontier is not None:reject('assignment_in_progress')
        if type(arm) is not str or not arm:reject('arm_shape')
        if type(offset) is not int or type(value) is not SourceValue or value.raw.width!=8:reject('assignment_shape')
        pointer=self.pointer(offset)
        self._require_modeled(pointer)
        self.machine.memory.guard(pointer,1,write=True)
        # Reserve all model transition/output storage before any cell/frontier mutation.
        budget.charge(work=8,edges=2,copied_bytes=256)
        p=self._new(Prepared)
        self.prepared[id(p)]=(p,dict(arm=arm,pointer=pointer,value=value,budget=budget,cursor=self.cursor,used=False))
        return p
    def commit(self,prepared,*,budget):
        entry=self._record(self.prepared,prepared)
        if budget is not entry['budget']:reject('budget_changed')
        if entry['used'] or self.effect_frontier is not None or self.cursor!=entry['cursor']:reject('prepare_replay_or_frontier')
        # Revalidate a mutable physical guard at the transition frontier.
        self._require_modeled(entry['pointer'])
        self.machine.memory.guard(entry['pointer'],1,write=True)
        arm=entry['arm'];old=self.cells.get(arm)
        if old is None or not old.live:
            if self.active is not None:
                prior=self.cells[self.active];self.cells[self.active]=Cell(prior.generation,False,prior.arm)
            self.cells[arm]=Cell(1 if old is None else old.generation+1,True,arm)
            self.init[self.base.origin]=mask(self.size*8)
        self.active=arm;entry['used']=True;self.cursor+=1
        t=self._new(Ticket);self.tickets[id(t)]=(t,dict(entry=entry,state='prepared',parked=False,fault=None))
        self.effect_frontier=t;return t
    def _ticket(self,ticket,budget):
        e=self._record(self.tickets,ticket)
        if budget is not e['entry']['budget']:reject('budget_changed')
        if self.effect_frontier is not ticket:reject('ticket_frontier')
        return e
    def execute_store(self,ticket,*,budget):
        e=self._ticket(ticket,budget)
        if e['state']!='prepared' or e['parked']:reject('effect_replay_or_stage')
        try:self.store(e['entry']['pointer'],e['entry']['value'])
        except Exception as error:
            e['state']='fault';e['fault']=error;raise
        e['state']='committed'
    def park(self,ticket,*,budget):
        e=self._ticket(ticket,budget)
        if e['parked'] or e['state'] not in ('prepared','committed'):reject('park_stage')
        e['parked']=True
    def resume(self,ticket,*,budget):
        e=self._ticket(ticket,budget)
        if not e['parked']:reject('resume_stage')
        e['parked']=False
    def complete(self,ticket,*,budget):
        e=self._ticket(ticket,budget)
        if e['state']!='committed' or e['parked']:reject('completion_stage')
        e['state']='normal';self.cursor+=1;self.effect_frontier=None
    def cancel(self,ticket,*,budget):
        e=self._ticket(ticket,budget)
        if e['state']=='normal':reject('cancel_stage')
        e['state']='terminal';e['parked']=False;self.effect_frontier=None
        # Cancellation retains already-created generations and committed writes.
    def end(self,arm):
        c=self.cells.get(arm)
        if c is None or not c.live:reject('end_stage')
        self.cells[arm]=Cell(c.generation,False,arm)
        if self.active==arm:self.active=None
