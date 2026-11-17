"""Logical interpreter/JIT state-transfer validation and private handoff authority.

All Registry maps/callbacks are runtime-owned admitted facts. Returned validated
metadata is not an executable admission token. No raw snapshot restore API exists.
"""
from copy import deepcopy
from dataclasses import dataclass, field
from threading import Lock

from .errors import option, require, unique
from .flow import Flow
from .fenv import mask
from . import journals, native
from .wire import encode, validate_shape


def completion(operation,verified):
    if operation['op'] in {'throw','rethrow','resume','cleanup_return'}:return 'raises'
    if operation['op']=='terminate':return 'terminal'
    target=operation.get('helper',operation.get('target'))
    if type(target) is dict and target.get('kind')=='import':
        reference=target['import'];module=reference['module']
        key=('self',reference['id']) if module['kind']=='self' else ('dependency',module['slot'],reference['id'])
        require(key in verified.dependencies.imports,'RT_TICKET_ADMITTED_IMPORT')
        binding=verified.dependencies.imports[key]
        if binding['kind']=='internal':
            from .helpers import helper
            return helper(binding['name'])['completion']
        if binding['kind']=='service':
            from .services import service
            return 'terminal' if service(binding['name'])['terminal'] else 'returns'
    return 'returns'


@dataclass
class Registry:
    process: int
    thread: int
    epoch: int
    memory_generation: int
    modules: dict
    objects: dict
    handles: dict
    leases: dict
    # Actual type/provenance validator, admitted nominal/program resolvers.
    value_check: object
    nominal: object
    program: object
    # Runtime-selected immutable exception action plans, never from file bytes.
    unwind_plans: dict
    bridge_contracts: dict
    thread_tls: dict
    unwind_rows: dict
    worker: object = None
    ownership: str = 'parked'
    transfer: object = None
    lock: object = field(default_factory=Lock)
    lifetimes: dict = field(default_factory=dict)
    partials: dict = field(default_factory=dict)

    def values(self,module,values,activation):
        for value in values:self.value_check(module,value,self.thread,activation)

    def retained(self,identifiers):
        require(len(identifiers)==len(set(identifiers)),'RT_LEASE_DUPLICATE')
        for identity in identifiers:
            require(identity in self.leases and self.leases[identity]['live'] and
                    self.leases[identity]['process']==self.process,'RT_LEASE')

    def exception(self,identity):
        require(identity in self.handles and self.handles[identity]['kind']=='exception' and
                self.handles[identity]['live'] and self.handles[identity]['thread']==self.thread,
                'RT_LIVE_EXCEPTION')

    def types_equal(self,module,before,after):
        return self.modules[module]['verified'].types.equal(before,after)


def module_frame(frame,registry):
    owner=registry.modules.get(frame['module'])
    require(owner is not None and owner['generation']==frame['generation'] and
            owner['binding_generation']==frame['binding_generation'] and owner['pins']>0,
            'RT_FRAME_GENERATION')
    verified=owner['verified']
    functions=unique(verified.functions_root['functions'],'id')
    require(frame['function'] in functions,'RT_FRAME_FUNCTION')
    function=functions[frame['function']]
    exceptions=next((item for item in verified.exceptions_root['functions'] if item['function']==frame['function']),
                    {'actions':[],'regions':[]})
    flow=Flow(function,exceptions)
    expected=flow.frontier(frame['position'])
    locals_=unique(frame['locals'],'id','RT_FRAME_LOCAL_DUPLICATE')
    require(list(locals_)==sorted(locals_) and locals_.keys()==expected.keys(),'RT_FRAME_LIVE_SET')
    for identity,local in locals_.items():
        require(verified.types.equal(expected[identity],local['value']['type']),'RT_FRAME_LOCAL_TYPE')
        registry.values(frame['module'],[local['value']],frame['activation'])
    require(frame['status'] in {'running','suspended','blocked','unwinding','ready'},'RT_FRAME_STATUS')
    objects=set()
    for allocation in frame['allocations']:
        identity=allocation['object']
        require(identity not in objects,'RT_FRAME_ALLOCATION_DUPLICATE')
        objects.add(identity)
        current=registry.objects.get(identity)
        require(current is not None and current['generation']==allocation['generation'] and
                current['address']==allocation['address'] and current['size']==allocation['extent'],
                'RT_FRAME_ALLOCATION')
        require(allocation['kind'] in {'stack','temporary','varargs'} and
                allocation['lifetime'] in {'live','ended','revoked'} and
                current['live']==(allocation['lifetime']=='live'),'RT_FRAME_LIFETIME')
        align=allocation['alignment']
        require(align>0 and align&(align-1)==0 and allocation['address']%align==0 and
                0<allocation['address'] and allocation['address']+allocation['extent']<=2**64-1,
                'RT_SOURCE_OBJECT_LIMIT')
    operation=flow.operation(frame['position'])
    ticket=option(frame['ticket'])
    if ticket is not None:
        require(ticket['id']>0 and ticket['before']==frame['position'] and
                ticket['state'] in {'prepared','running','blocked','completed','raised','cancelled'},
                'RT_TICKET_FRONTIER')
        reference=option(ticket['helper'])
        target=operation.get('helper',operation.get('target'))
        if reference is not None:
            require(type(target) is dict and target['kind']=='import' and
                    target['import']==reference,'RT_TICKET_HELPER')
        else:
            require(not(type(target) is dict and target['kind']=='import'),'RT_TICKET_HELPER')
        before=frame['position']
        returns=completion(operation,verified)=='returns'
        if operation['op']=='invoke':
            normal={'block':operation['normal']['target'],'operation':0,'predecessor':{'some':before['block']}}
            unwind={'block':operation['unwind']['target'],'operation':0,'predecessor':{'some':before['block']}}
            declarations=operation['normal']['results']
        elif operation['op'] in {'throw','rethrow','resume','cleanup_return','terminate'}:
            normal,unwind,declarations=None,None,[]
        else:
            require(before['operation']<len(flow.blocks[before['block']]['ops']),'RT_TICKET_OPERATION')
            normal={**before,'operation':before['operation']+1}
            unwind=None
            declarations=operation['results']
        require(option(ticket['normal'])==(normal if returns else None) and
                option(ticket['unwind'])==unwind,'RT_TICKET_CONTINUATION')
        private=unique(ticket['results'],'id')
        if ticket['state']=='completed':
            require(returns,'RT_TICKET_NONRETURNING_COMPLETED')
            require(private.keys()=={d['id'] for d in declarations},'RT_TICKET_RESULTS')
            for declaration in declarations:
                value=private[declaration['id']]['value']
                require(verified.types.equal(value['type'],declaration['type']),'RT_TICKET_RESULT_TYPE')
                registry.values(frame['module'],[value],frame['activation'])
        else:require(not private,'RT_TICKET_EARLY_RESULTS')
        exception=option(ticket['exception'])
        require((exception is not None)==(ticket['state']=='raised'),'RT_TICKET_EXCEPTION')
        if exception is not None:registry.exception(exception)
        require(ticket['cancellation'] in {'none','requested','deferred'},'RT_TICKET_CANCELLATION')
        if operation['op'] in {'memcpy','memmove','memset'}:
            value=locals_[operation['operands'][2]]['value']['payload']
            require(value['kind']=='scalar','RT_TICKET_LENGTH')
            count=int.from_bytes(bytes.fromhex(value['bits']),'little')
            require(ticket['committed_bytes']<=count and ticket['direction'] in {'forward','backward'},
                    'RT_TICKET_PREFIX')
            require(operation['op']=='memmove' or ticket['direction']=='forward','RT_TICKET_DIRECTION')
        else:require(ticket['committed_bytes']==0 and ticket['direction']=='none','RT_TICKET_UNUSED_PREFIX')
    progress=option(frame['progress'])
    if progress is not None:
        mode=operation.get('mode',{})
        require(mode.get('elementwise') and mode['order']!='seq_cst' and
                operation['op'] in {'atomic_load','atomic_store','atomic_rmw'},'RT_ELEMENTWISE_OPERATION')
        require(progress['activation']==frame['activation'] and progress['block']==frame['position']['block']
                and progress['operation']==frame['position']['operation'],'RT_ELEMENTWISE_FRONTIER')
        vector=verified.types.get(operation['storage']['type'])
        prefix=progress['next_lane']
        require(vector['kind']=='vector' and prefix<=vector['count'],'RT_ELEMENTWISE_PREFIX')
        expected_inputs=[locals_[identity]['value'] for identity in operation['operands']]
        require(progress['inputs']==expected_inputs,'RT_ELEMENTWISE_INPUTS')
        require(len(progress['observed'])==(0 if operation['op']=='atomic_store' else prefix),
                'RT_ELEMENTWISE_OBSERVED')
        for value in progress['observed']:
            require(verified.types.equal(value['type'],vector['element']),'RT_ELEMENTWISE_TYPE')
        registry.values(frame['module'],progress['observed'],frame['activation'])
    return flow


def validate(document,registry):
    validate_shape('runtime_live_state',document)
    thread=document['thread']
    require(document['payload_revision']==2 and thread['payload_revision']==1,'RT_LIVE_REVISION')
    require((thread['process'],thread['thread'],thread['epoch'],thread['memory_generation'])==
            (registry.process,registry.thread,registry.epoch,registry.memory_generation),'RT_LIVE_EPOCH')
    require(option(thread['worker']) == registry.worker, 'RT_LIVE_WORKER')
    require(thread['fenv']['rounding'] in {'nearest_even','toward_zero','upward','downward'} and
            thread['fenv']['traps']==0 and 0<=thread['diagnostic_policy']<=31,'RT_LIVE_FENV')
    mask(thread['fenv']['flags'])
    frames=unique(thread['frames'],'activation','RT_FRAME_ACTIVATION')
    require(all(identity>0 for identity in frames),'RT_FRAME_ACTIVATION')
    flows={identity:module_frame(frame,registry) for identity,frame in frames.items()}
    lifetime_table=unique(document['lifetimes'],'id','RT_LIFETIME_DUPLICATE')
    for identity,certificate in lifetime_table.items():
        require(identity in registry.lifetimes and certificate==registry.lifetimes[identity],
                'RT_LIFETIME_SNAPSHOT_AUTHORITY')
        registry.retained(certificate['leases'])
    partial_table=unique(document['partial_objects'],'id','RT_PARTIAL_DUPLICATE')
    for identity,builder in partial_table.items():
        require(identity in registry.partials and builder==registry.partials[identity],
                'RT_PARTIAL_SNAPSHOT_AUTHORITY')
        registry.retained(builder['leases'])
    journals.validate(document['journals'],thread=registry.thread,highwater=thread['journal_sequence'],
                      modules=registry.modules,objects=registry.objects,handles=registry.handles,
                      program=registry.program,nominal=registry.nominal,
                      value_check=lambda module,value,activation:registry.values(module,[value],activation),
                      type_equal=registry.types_equal,lifetimes=lifetime_table,partials=partial_table)
    journal_table=unique(document['journals'],'id')
    for journal in journal_table.values():registry.retained(journal['leases'])
    bridges=unique(document['bridges'],'id')
    unwinds=unique(document['unwinds'],'id')
    for frame in frames.values():
        require(set(frame['journals'])<=journal_table.keys(),'RT_FRAME_JOURNAL')
        require(option(frame['bridge']) is None or option(frame['bridge']) in bridges,'RT_FRAME_BRIDGE')
        require(option(frame['unwind_state']) is None or option(frame['unwind_state']) in unwinds,'RT_FRAME_UNWIND')
        if frame['exception'] is not None:registry.exception(option(frame['exception']))
        for name in ['normal','unwind']:
            continuation=option(frame[name])
            if continuation is not None:
                require(continuation['activation'] in frames and continuation['activation']!=frame['activation'],
                        'RT_FRAME_CONTINUATION')
                flows[continuation['activation']].frontier(continuation['position'])
    for unwind in unwinds.values():
        require(unwind['activation'] in frames and unwind['thread']==registry.thread,'RT_UNWIND_OWNER')
        frame=frames[unwind['activation']]
        require(unwind['generation']==frame['generation'],'RT_UNWIND_GENERATION')
        registry.exception(unwind['exception']);registry.retained(unwind['leases'])
        key=unwind['activation'],unwind['exception']
        require(key in registry.unwind_plans,'RT_UNWIND_PLAN')
        plan=registry.unwind_plans[key]
        require([a['id'] for a in unwind['actions']]==[a['id'] for a in plan['actions']] and
                unwind['handler']==plan['handler'] and unwind['next_action']<=len(unwind['actions']),
                'RT_UNWIND_ACTION_ORDER')
        for index,(action,expected) in enumerate(zip(unwind['actions'],plan['actions'])):
            require(action['program']==expected['program'] and action['recipe']==expected['recipe'] and
                    action['captures']==expected['captures'],'RT_UNWIND_CAPTURE')
            require(action['journal'] in journal_table,'RT_UNWIND_JOURNAL')
            require(action['phase'] in {'ready','running','suspended','completed','raised'},'RT_UNWIND_ACTION_PHASE')
            require(index>=unwind['next_action'] or action['phase']=='completed','RT_UNWIND_REPLAY')
            require(index<=unwind['next_action'] or action['phase']=='ready','RT_UNWIND_FUTURE_ACTION')
            registry.values(frame['module'],[item['value'] for item in action['captures']],frame['activation'])
        require(unwind['phase'] in {'search','cleanup','selected','propagating','terminated'},'RT_UNWIND_PHASE')
        if unwind['adapter'] is not None:module_frame(option(unwind['adapter']),registry)
    for bridge in bridges.values():
        validate_bridge(bridge,frames,journal_table,registry)
    for checkpoint in document['nonlocals']:
        require(checkpoint['process']==registry.process and checkpoint['thread']==registry.thread and
                checkpoint['activation'] in frames,'RT_NONLOCAL_OWNER')
        require(checkpoint['generation']==frames[checkpoint['activation']]['generation'],'RT_NONLOCAL_GENERATION')
        saved=unique(checkpoint['frames'],'activation')
        require(checkpoint['activation'] in saved and set(saved)<=frames.keys(),'RT_NONLOCAL_DEAD_ACTIVATION')
        for frame in saved.values():module_frame(frame,registry)
        require(set(checkpoint['journals'])<=journal_table.keys(),'RT_NONLOCAL_JOURNAL')
        signal=option(checkpoint['signal_mask'])
        require(signal is None or len(bytes.fromhex(signal))==128,'RT_NONLOCAL_SIGNAL_MASK')
        registry.retained(checkpoint['leases'])
    return document


def validate_bridge(bridge,frames,journals_,registry):
    require(bridge['activation'] in frames and bridge['thread']==registry.thread,'RT_BRIDGE_OWNER')
    frame=frames[bridge['activation']]
    require(bridge['generation']==frame['generation'] and bridge['id'] in registry.bridge_contracts,
            'RT_BRIDGE_GENERATION')
    contract=registry.bridge_contracts[bridge['id']]
    require(contract['descriptor']==bridge['descriptor'],'RT_BRIDGE_DESCRIPTOR')
    stage=bridge['stage']
    require(stage in {'prepared','converting_arguments','foreign_running','foreign_suspended',
                      'foreign_returned','converting_result','cleanup','unwinding','committed','failed'},
            'RT_BRIDGE_STAGE')
    require(bridge['foreign_entries'] in {0,1} and bridge['normal_publications'] in {0,1},'RT_BRIDGE_REPLAY')
    require((bridge['foreign_entries']==0)==(stage in {'prepared','converting_arguments'}),'RT_BRIDGE_ENTRY')
    require((bridge['normal_publications']==1)==(stage=='committed'),'RT_BRIDGE_PUBLICATION')
    registry.retained(bridge['leases'])
    require(bridge['source_journal'] in journals_ and bridge['target_journal'] in journals_,'RT_BRIDGE_JOURNAL')
    target=bridge['target']
    require(registry.modules[frame['module']]['verified'].types.get(target['type'])['kind']=='raw',
            'RT_BRIDGE_TARGET_IMAGE')
    # Raw image checks reuse the exact execution raw live-value protocol.
    registry.values(frame['module'],[{'type':target['type'],'payload':{'kind':'raw',**{
        name:target[name] for name in ['bits','poison','undef','origins']}}}],frame['activation'])
    source=option(bridge['source'])
    if source is not None:
        require(stage in {'cleanup','committed'},'RT_BRIDGE_EARLY_SOURCE')
        require(len(source['values'])==len(contract['results']),'RT_BRIDGE_RESULT_ARITY')
        for value,expected in zip(source['values'],contract['results']):
            require(registry.types_equal(frame['module'],value['type'],expected),'RT_BRIDGE_RESULT_TYPE')
        registry.values(frame['module'],source['values'],frame['activation'])
    if stage=='committed':
        require(source is not None and all(journals_[j]['state']['stage']=='destroyed' for j in
                    [bridge['source_journal'],bridge['target_journal']]),'RT_BRIDGE_CLEANUP_BEFORE_RESULT')
    cpu=option(bridge['cpu'])
    if stage in {'foreign_running','foreign_suspended'}:require(cpu is not None,'RT_BRIDGE_CPU_REQUIRED')
    if cpu is not None:
        native.validate(cpu,isa=contract['isa'],objects=registry.objects,
                        thread_tls=registry.thread_tls[contract['isa']],unwind_rows=registry.unwind_rows)
    if bridge['adapter_frame'] is not None:module_frame(option(bridge['adapter_frame']),registry)
    if bridge['exception'] is not None:registry.exception(option(bridge['exception']))


class Handoff:
    """Private runtime-issued frozen image; O(encoded bytes), exactly one resume."""
    def __init__(self,document,registry):
        with registry.lock:
            require(registry.ownership == 'parked' and registry.worker is None and
                    registry.transfer is None, 'RT_HANDOFF_SOURCE_NOT_PARKED')
            validate(document,registry)
            self._image=encode('runtime_live_state',document)
            self._epoch=registry.epoch
            self._owner=registry.process,registry.thread
            self._consumed=False
            self._lock=Lock()
            registry.ownership='in_transfer'
            registry.transfer=self

    def resume(self,document,registry,worker):
        require(type(worker) is int and worker > 0, 'RT_HANDOFF_WORKER')
        with self._lock, registry.lock:
            require(not self._consumed,'RT_HANDOFF_REPLAY')
            require(self._owner==(registry.process,registry.thread) and self._epoch==registry.epoch,
                    'RT_HANDOFF_EPOCH')
            require(registry.ownership == 'in_transfer' and registry.transfer is self,
                    'RT_HANDOFF_OWNER')
            require(self._image==encode('runtime_live_state',document),'RT_HANDOFF_CHANGED_IMAGE')
            validate(document,registry)
            self._consumed=True
            registry.ownership='running'
            registry.transfer=None
            registry.epoch+=1
            registry.worker=worker
            result=deepcopy(document)
            result['thread']['epoch']=registry.epoch
            result['thread']['worker']={'some':worker}
            return result

    def cancel(self,registry):
        with self._lock, registry.lock:
            require(not self._consumed and registry.transfer is self and
                    registry.ownership == 'in_transfer', 'RT_HANDOFF_OWNER')
            self._consumed=True
            registry.transfer=None
            registry.ownership='parked'
