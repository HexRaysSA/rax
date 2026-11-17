"""Finite authored two-level data/protocol model; all source authority is false."""
from dataclasses import dataclass,replace
from union_prestore.model import SourceValue,_machine,_storage,MODE,mask,_api
from candidate.raw import Raw,Span
from candidate.values import Value,Pointer
from candidate.type_system import ref
from candidate.memory import GuestFault

U64=(1<<64)-1
OUTER=('aggregate','alternate')
INNER=('left','right')

class Refusal(ValueError):
    def __init__(self,code,kind='semantic'):
        self.code,self.kind=code,kind
        super().__init__(code)

def fail(code,kind='semantic'):raise Refusal(code,kind)

@dataclass(frozen=True)
class Index:
    value:int
    bits:int=128
    signed:bool=False
    bound:int=1

def checked_index(index):
    if type(index)is not Index or type(index.value)is not int or type(index.bits)is not int or type(index.signed)is not bool or type(index.bound)is not int:fail('index_shape')
    if not 1<=index.bits<=256 or not 1<=index.bound<=U64:fail('index_profile','unavailable')
    low=-(1<<(index.bits-1)) if index.signed else 0
    high=(1<<(index.bits-1))-1 if index.signed else (1<<index.bits)-1
    if not low<=index.value<=high:fail('original_precision_value')
    if index.value<0:fail('negative_index')
    if index.value>U64:fail('index_not_u64')
    if index.value>=index.bound:fail('index_bounds')
    return index.value

@dataclass(frozen=True)
class WindowRef:serial:int
@dataclass(frozen=True)
class Designation:serial:int
@dataclass(frozen=True)
class Prepared:serial:int
@dataclass(frozen=True)
class Ticket:serial:int
@dataclass(frozen=True)
class Candidate:
    node:str
    arm:str
    index:Index
    pointer:object=None
    phase:str='quiescent'
@dataclass(frozen=True)
class Arm:
    name:str
    generation:int=0
    live:bool=False
    init:object=None
    parent:int=0
    container:int=0
@dataclass(frozen=True)
class State:
    outer:tuple=(Arm('aggregate'),Arm('alternate'))
    inner:tuple=(Arm('left'),Arm('right'))
    outer_active:object=None
    inner_active:object=None
    container_generation:int=0
    container_parent:int=0
    container_live:bool=False
    version:int=0
    known:bool=True
@dataclass(frozen=True)
class Window:
    pointer:Pointer
    logical_index:int
    bound:int
@dataclass(frozen=True)
class Target:
    window:WindowRef
    outer_arm:str
    outer_generation:int
    container_generation:int=0
    inner_arm:object=None
    inner_generation:int=0
@dataclass(slots=True)
class Entry:
    window:WindowRef
    candidates:tuple
    before:State
    committed:State
    stored:State
    unknown:State
    pointer:Pointer
    value:SourceValue
    budget:object
    start_cursor:int
    commit_cursor:int
    complete_cursor:int
    ticket:Ticket
    used:bool=False
@dataclass(slots=True)
class Progress:
    entry:Entry
    stage:str='prepared'
    parked:bool=False
    current:object=None
    core_effect:object=None
    error:object=None

def arm(state,name,inner=False):
    records=state.inner if inner else state.outer
    return records[(INNER if inner else OUTER).index(name)]

def updated(records,item):return tuple(item if a.name==item.name else a for a in records)

def interval(old,start,width,new):return (old&~(mask(width)<<start))|(new<<start)

class NestedWorld:
    source_fact_authority=False
    semantic_admission=False
    runtime_authority=False
    cost_profile_qualified=False
    def __init__(self,*,budget,max_generation=U64,max_windows=4):
        if type(budget)is not _api().SourceQueryBudget:fail('budget_reference')
        if type(max_generation)is not int or not 1<=max_generation<=U64 or type(max_windows)is not int or not 1<=max_windows<=8:fail('limits')
        self.budget=budget;self.max_generation=max_generation;self.max_windows=max_windows
        self.machine=_machine();self.windows={};self.states={};self.handles={};self.plans={};self.tickets={}
        self.ref_serial=0;self.cursor=0;self.active=None
        self.store_op={'op':'store','results':[],'operands':[],'storage':_storage(),'mode':dict(MODE)}
    def _budget(self,b):
        if b is not self.budget or type(b)is not _api().SourceQueryBudget:fail('budget_changed')
    def _new(self,kind):
        if self.ref_serial==U64:fail('reference_exhaustion','unavailable')
        self.ref_serial+=1;return kind(self.ref_serial)
    def _lookup(self,table,token):
        pair=table.get(id(token))
        if pair is None or pair[0] is not token:fail('foreign_or_cloned_reference')
        return pair[1]
    def register(self,*,logical_index=0,bound=1,budget):
        self._budget(budget)
        if self.active is not None or len(self.windows)>=self.max_windows:fail('window_capacity','unavailable')
        index=checked_index(Index(logical_index,128,False,bound))
        budget.charge(work=8,edges=4,copied_bytes=256)
        pointer=self.machine.memory.allocate(16,1)
        token=self._new(WindowRef);self.windows[id(token)]=(token,Window(pointer,index,bound));self.states[id(token)]=State();return token
    def _state(self,window):
        self._lookup(self.windows,window)
        s=self.states.get(id(window))
        if type(s)is not State or not s.known:fail('model_state_unknown','unavailable')
        if tuple(a.name for a in s.outer)!=OUTER or tuple(a.name for a in s.inner)!=INNER:fail('model_state_shape')
        for inner,records,width in [(False,s.outer,128),(True,s.inner,64)]:
            for a in records:
                if type(a)is not Arm or type(a.generation)is not int or not 0<=a.generation<=self.max_generation:fail('model_generation')
                if a.generation==0:
                    if a.live or a.init is not None:fail('model_unborn_state')
                elif type(a.init)is not int or not 0<=a.init<=mask(width):fail('model_init_unknown','unavailable')
        if s.outer_active not in (*OUTER,None) or s.inner_active not in (*INNER,None):fail('model_active_shape')
        if sum(a.live for a in s.outer)!=int(s.outer_active is not None):fail('model_outer_state')
        if s.outer_active is not None and not arm(s,s.outer_active).live:fail('model_outer_state')
        if s.container_live:
            if s.outer_active!='aggregate' or s.container_generation<=0 or s.container_parent!=arm(s,'aggregate').generation:fail('model_container_state')
        elif s.inner_active is not None:fail('model_container_state')
        if sum(a.live for a in s.inner)!=int(s.inner_active is not None):fail('model_inner_state')
        if s.inner_active is not None:
            child=arm(s,s.inner_active,True)
            if not child.live or child.parent!=s.container_parent or child.container!=s.container_generation:fail('model_inner_state')
            if arm(s,'aggregate').init&mask(64)!=child.init:fail('model_init_composition')
        return s
    def pointer(self,window,offset=0):
        w=self._lookup(self.windows,window)
        if type(offset)is not int:fail('offset_shape')
        return self.machine.memory.offset(w.pointer,offset,False,False,False)
    def _allocation(self,window,pointer):
        w=self._lookup(self.windows,window);base=w.pointer
        if type(pointer)is not Pointer or (pointer.origin,pointer.generation,pointer.domain)!=(base.origin,base.generation,base.domain):fail('unmodeled_allocation')
        return w
    def _candidate_guards(self,window,candidates,byte):
        w=self._lookup(self.windows,window)
        if type(candidates)is not tuple or not 1<=len(candidates)<=2 or type(byte)is not int:fail('candidate_shape')
        for i,c in enumerate(candidates):
            if type(c)is not Candidate or c.node!=('outer' if i==0 else 'inner') or c.arm not in (OUTER if i==0 else INNER):fail('candidate_route')
            value=checked_index(c.index)
            if value!=(w.logical_index if i==0 else 0) or c.index.bound!=(w.bound if i==0 else 1):fail('logical_window_mismatch')
            if c.phase!='quiescent':fail('phase_assumption_unavailable','unavailable')
        if len(candidates)==2 and candidates[0].arm!='aggregate':fail('nested_parent_route')
        if not 0<=byte<(8 if len(candidates)==2 else 16):fail('leaf_bounds')
        pointers=[]
        for i,c in enumerate(candidates):
            p=w.pointer if c.pointer is None else c.pointer
            self._allocation(window,p)
            self.machine.memory.guard(p,16 if i==0 else 8,write=i==len(candidates)-1)
            if p.address!=w.pointer.address:fail('candidate_storage_route')
            pointers.append(p)
        leaf=self.machine.memory.offset(pointers[-1],byte,False,False,False)
        self.machine.memory.guard(leaf,1,write=True)
        return leaf
    def _next(self,value):
        if value>=self.max_generation:fail('generation_exhaustion','unavailable')
        return value+1
    def _transition(self,s,candidates):
        root=candidates[0].arm;current=arm(s,root)
        if not current.live:
            outer=tuple(replace(a,live=False) if a.live else a for a in s.outer)
            inner=tuple(replace(a,live=False) if a.live else a for a in s.inner)
            fresh=Arm(root,self._next(current.generation),True,mask(128))
            s=replace(s,outer=updated(outer,fresh),inner=inner,outer_active=root,inner_active=None,container_live=root=='aggregate')
            if root=='aggregate':s=replace(s,container_generation=self._next(s.container_generation),container_parent=fresh.generation)
        if len(candidates)==2:
            name=candidates[1].arm;child=arm(s,name,True)
            if not child.live:
                inner=tuple(replace(a,live=False) if a.live else a for a in s.inner)
                fresh=Arm(name,self._next(child.generation),True,mask(64),arm(s,'aggregate').generation,s.container_generation)
                outer=arm(s,'aggregate');outer=replace(outer,init=interval(outer.init,0,64,mask(64)))
                s=replace(s,inner=updated(inner,fresh),outer=updated(s.outer,outer),inner_active=name)
        if s.version>U64-2:fail('version_exhaustion','unavailable')
        return replace(s,version=s.version+1)
    def _assigned(self,s,offset,width,state):
        if s.outer_active is None:fail('no_live_root_view','unavailable')
        if s.version==U64:fail('version_exhaustion','unavailable')
        if s.outer_active=='aggregate' and offset<8 and s.inner_active is None:fail('no_live_inner_view','unavailable')
        root=arm(s,s.outer_active);root=replace(root,init=interval(root.init,offset*8,width,state));s=replace(s,outer=updated(s.outer,root))
        if s.inner_active is not None and offset<8:
            n=min(width,64-offset*8);child=arm(s,s.inner_active,True)
            child=replace(child,init=interval(child.init,offset*8,n,state&mask(n)));s=replace(s,inner=updated(s.inner,child))
        return replace(s,version=s.version+1)
    def _target(self,s,window,outer,inner=None):
        root=arm(s,outer)
        if s.outer_active!=outer or not root.live:fail('stale_or_unborn_designation')
        if inner is None:return Target(window,outer,root.generation)
        if outer!='aggregate' or not s.container_live or s.inner_active!=inner:fail('stale_or_unborn_designation')
        child=arm(s,inner,True)
        return Target(window,outer,root.generation,s.container_generation,inner,child.generation)
    def prospective(self,window,outer='aggregate',inner=None,*,budget):
        self._budget(budget);s=self._state(window)
        if len(self.handles)>=64:fail('designation_capacity','unavailable')
        if outer not in OUTER or inner not in (*INNER,None) or inner is not None and outer!='aggregate':fail('designation_route')
        root=arm(s,outer);rg=root.generation if root.live else self._next(root.generation)
        cg=ig=0
        if inner is not None:
            child=arm(s,inner,True)
            current=root.live and s.container_live and s.container_parent==rg
            cg=s.container_generation if current else self._next(s.container_generation)
            ig=child.generation if current and child.live else self._next(child.generation)
        budget.charge(work=4,edges=2,copied_bytes=96)
        token=self._new(Designation);self.handles[id(token)]=(token,Target(window,outer,rg,cg,inner,ig));return token
    def resolve(self,designation):
        target=self._lookup(self.handles,designation);s=self._state(target.window)
        w=self._lookup(self.windows,target.window);self.machine.memory.guard(w.pointer,0)
        if self._target(s,target.window,target.outer_arm,target.inner_arm)!=target:fail('stale_or_unborn_designation')
        return target
    def preflight(self,window,candidates,value,*,byte=0,designation=None,budget):
        self._budget(budget)
        if self.active is not None:fail('assignment_in_progress')
        if len(self.plans)>=64:fail('plan_capacity','unavailable')
        if type(value)is not SourceValue or value.raw.width!=8:fail('scalar_value_shape')
        before=self._state(window);pointer=self._candidate_guards(window,candidates,byte)
        budget.charge(work=32+24*len(candidates)+len(self.tickets),edges=8+4*len(candidates),copied_bytes=256+192*len(candidates)+16*len(self.tickets))
        committed=self._transition(before,candidates)
        if designation is not None:
            target=self._lookup(self.handles,designation)
            expected=self._target(committed,window,candidates[0].arm,candidates[1].arm if len(candidates)==2 else None)
            if target!=expected:fail('stale_or_wrong_designation')
        stored=self._assigned(committed,byte,8,value.indeterminate)
        unknown=replace(committed,known=False)
        if self.cursor>U64-2:fail('cursor_exhaustion','unavailable')
        if self.ref_serial>U64-2:fail('reference_exhaustion','unavailable')
        p=self._new(Prepared);t=self._new(Ticket)
        e=Entry(window,candidates,before,committed,stored,unknown,pointer,value,budget,self.cursor,self.cursor+1,self.cursor+2,t)
        self.plans[id(p)]=(p,e);return p
    def commit(self,prepared,*,budget):
        self._budget(budget);e=self._lookup(self.plans,prepared)
        if e.budget is not budget:fail('budget_changed')
        if e.used or self.active is not None or self.cursor!=e.start_cursor or self._state(e.window)is not e.before:fail('stale_prepare_or_frontier')
        self._candidate_guards(e.window,e.candidates,e.pointer.address-self._lookup(self.windows,e.window).pointer.address)
        progress=Progress(e,current=e.committed);tickets=dict(self.tickets);tickets[id(e.ticket)]=(e.ticket,progress)
        e.used=True;self.tickets=tickets;self.states[id(e.window)]=e.committed;self.cursor=e.commit_cursor;self.active=e.ticket
        return e.ticket
    def _progress(self,ticket,budget):
        self._budget(budget);p=self._lookup(self.tickets,ticket)
        if self.active is not ticket:fail('ticket_frontier')
        if p.entry.budget is not budget:fail('budget_changed')
        return p
    def execute_store(self,ticket,*,budget):
        p=self._progress(ticket,budget);e=p.entry
        if p.stage!='prepared' or p.parked:fail('effect_replay_or_stage')
        if self._state(e.window)is not p.current:fail('source_version_changed')
        try:self.machine.memory_operation(self.store_op,[Value(ref(7),'concrete',e.pointer),Value(ref(17),'concrete',e.value.raw)])
        except GuestFault as error:p.stage='fault';p.error=error;raise
        except Exception as error:
            self.states[id(e.window)]=e.unknown;p.stage='host_fault_unknown_commit';p.error=error;raise
        self.states[id(e.window)]=e.stored;p.current=e.stored;p.core_effect=self.machine.memory.effects[-1];p.stage='stored'
    def park(self,ticket,*,budget):
        p=self._progress(ticket,budget)
        if p.parked or p.stage not in ('prepared','stored'):fail('park_stage')
        p.parked=True
    def resume(self,ticket,*,budget):
        p=self._progress(ticket,budget)
        if not p.parked or self._state(p.entry.window)is not p.current:fail('resume_stage')
        self.machine.memory.guard(self._lookup(self.windows,p.entry.window).pointer,0)
        p.parked=False
    def complete(self,ticket,*,budget):
        p=self._progress(ticket,budget)
        if p.stage!='stored' or p.parked or self._state(p.entry.window)is not p.current:fail('completion_stage')
        self.cursor=p.entry.complete_cursor;p.stage='normal';self.active=None
    def cancel(self,ticket,*,budget):
        p=self._progress(ticket,budget);p.stage='terminal';p.parked=False;self.active=None
    def expire_model_state(self,window):
        s=self._state(window);self.states[id(window)]=replace(s,known=False)
    def _data(self,window,offset,count,write=False):
        if type(offset)is not int or type(count)is not int or not 0<=offset<=16 or not 1<=count<=16 or offset+count>16:fail('data_shape')
        s=self._state(window)
        if s.outer_active is None:fail('no_live_root_view','unavailable')
        p=self.pointer(window,offset);self._allocation(window,p);self.machine.memory.guard(p,count,write=write)
        return s,p
    def load(self,window,offset,count,*,budget):
        self._budget(budget);s,p=self._data(window,offset,count)
        budget.charge(work=count*8,copied_bytes=32+count*24)
        raw=self.machine.memory.raw_load(p,count);i=arm(s,s.outer_active).init>>(offset*8)&mask(count*8);spans=[]
        for span in raw.origins:
            begin=None
            for bit in range(span.offset,span.offset+span.length+1):
                keep=bit<span.offset+span.length and not(i>>bit)&1
                if keep and begin is None:begin=bit
                if not keep and begin is not None:
                    spans.append(Span(begin,bit-begin,span.pointer,span.source+begin-span.offset));begin=None
        return SourceValue(Raw(raw.width,raw.bits,raw.poison&~i,tuple(spans),raw.undef|i),i)
    def store_value(self,window,offset,value,*,budget):
        self._budget(budget)
        if self.active is not None:fail('assignment_in_progress')
        if type(value)is not SourceValue or value.raw.width!=8:fail('scalar_value_shape')
        s,p=self._data(window,offset,1,True);budget.charge(work=16,edges=2,copied_bytes=256)
        after=self._assigned(s,offset,8,value.indeterminate);unknown=replace(s,known=False)
        try:self.machine.memory_operation(self.store_op,[Value(ref(7),'concrete',p),Value(ref(17),'concrete',value.raw)])
        except GuestFault:raise
        except Exception:self.states[id(window)]=unknown;raise
        self.states[id(window)]=after
    def copy(self,destination,dst,source,src,count,*,overlap=False,budget):
        self._budget(budget)
        if self.active is not None:fail('assignment_in_progress')
        target,p=self._data(destination,dst,count,True);origin,q=self._data(source,src,count)
        budget.charge(work=32+count*8,edges=4,copied_bytes=256+count*24)
        snapshot=arm(origin,origin.outer_active).init>>(src*8)&mask(count*8)
        after=self._assigned(target,dst,count*8,snapshot);unknown=replace(target,known=False)
        try:self.machine.memory.bulk('memmove' if overlap else 'memcpy',p,q,count,1,False)
        except GuestFault:raise
        except Exception:self.states[id(destination)]=unknown;raise
        self.states[id(destination)]=after
