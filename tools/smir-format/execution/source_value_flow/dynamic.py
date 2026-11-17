"""UNBOUND actual-core event/birth prototype; never private SOURCE facts."""
from dataclasses import dataclass
from threading import Lock

from candidate.source_data_projection import source_api
from candidate.type_system import key
from candidate.values import well_defined,validate
from source_value_flow.contract import check, parse

_REF_KEY=object()


class _Opaque:
    __slots__=()
    def __new__(cls,token=None):
        if token is not _REF_KEY:raise TypeError('runtime-owned actual core reference')
        return object.__new__(cls)


class EntryReservation(_Opaque):pass
class Reservation(_Opaque):pass
class Event(_Opaque):pass
class Birth(_Opaque):pass


@dataclass(frozen=True)
class Limits:
    max_events:int=4096
    max_births:int=65536
    max_serial:int=2**64-1


def fail(code,detail='',kind='semantic'):
    raise source_api().SourceDataError(kind,code,detail)


class UnboundFlowRuntime:
    """Public MODEL masks plus private genuine local-core event custody only."""
    def __init__(self,owner,assertion_bytes,*,parameter_masks,limits,budget):
        if type(budget)is not source_api().SourceQueryBudget:fail('UNBOUND_FLOW_BUDGET')
        if type(limits)is not Limits or any(type(x)is not int or x<=0 for x in
            (limits.max_events,limits.max_births,limits.max_serial))or limits.max_serial>=2**64 or limits.max_events>=2**32 or limits.max_births>=2**32:
            fail('UNBOUND_FLOW_LIMITS')
        self.observation=check(owner,assertion_bytes,budget=budget)
        assertion=parse(assertion_bytes,budget)
        self.owner,self._budget,self._limits=owner,budget,limits
        self.function_id=assertion['function']['id']
        function=owner.functions[key(assertion['function'])]
        if type(parameter_masks)is not tuple or len(parameter_masks)!=len(function['params']):
            fail('UNBOUND_FLOW_PARAMETER_MASK')
        self.parameter_masks={}
        for row,parameter in zip(parameter_masks,function['params']):
            if type(row)is not tuple or len(row)!=2 or type(row[0])is not int or type(row[1])is not int:
                fail('UNBOUND_FLOW_PARAMETER_MASK')
            width=owner.types.width(parameter['type'])
            if row[0]!=parameter['id']or not 0<=row[1]<1<<width:fail('UNBOUND_FLOW_PARAMETER_MASK')
            self.parameter_masks[row[0]]=row[1]
        allowed={'constant','copy','bitcast','freeze','select','i_sub','icmp'}
        for block in function['blocks']:
            if block['term']['op']not in {'jump','cbranch','return'}:fail('UNBOUND_FLOW_BODY_UNAVAILABLE',kind='unavailable')
            for node in block['ops']:
                if node['op']not in allowed:fail('UNBOUND_FLOW_BODY_UNAVAILABLE',kind='unavailable')
            declarations=list(function['params'])+[p['result']for p in block['phis']]
            declarations += [d for node in block['ops']for d in node['results']]
            for declaration in declarations:
                typ=owner.types.get(declaration['type'])
                if not(typ['kind']=='raw'and typ['bits']==8 or typ['kind']=='int'and typ['bits']in(1,8,64)):
                    fail('UNBOUND_FLOW_BODY_UNAVAILABLE',kind='unavailable')
        self.machine=None;self.epoch=1;self._expired=False;self._lock=Lock();self._dispatch_lock=Lock()
        self._entries={};self._reservations={};self._events={};self._births={};self._frames={}
        self._published=[];self.pending=None;self._park_kind=None
        self.selection_uses=0;self.computations=0

    @property
    def budget(self):return self._budget

    @property
    def limits(self):return self._limits

    def _issuer(self,machine,issuer,budget):
        from candidate.machine import Machine,_UNBOUND_FLOW_ISSUER
        if type(machine)is not Machine or issuer is not _UNBOUND_FLOW_ISSUER or budget is not self.budget:
            fail('UNBOUND_FLOW_ISSUER')
        if self.machine is not machine or self._expired:fail('UNBOUND_FLOW_EPOCH')

    def _attach(self,machine,*,issuer,budget):
        from candidate.machine import Machine,_UNBOUND_FLOW_ISSUER
        if type(machine)is not Machine or issuer is not _UNBOUND_FLOW_ISSUER or budget is not self.budget:
            fail('UNBOUND_FLOW_ISSUER')
        if self.machine is not None or machine.stack or machine.finished is not None or machine._source_runtime is not None:
            fail('UNBOUND_FLOW_ATTACHMENT')
        self.owner.assert_snapshot()
        if machine.admitted.types_root!=self.owner.sections[1]or machine.admitted.functions_root!=self.owner.sections[3]:
            fail('UNBOUND_FLOW_ORIGINAL')
        self.machine=machine

    def _assert_original(self):
        self.owner.assert_snapshot()
        machine=self.machine
        if machine is not None:
            if (machine.admitted.types_root!=self.owner.sections[1]
                    or machine.admitted.functions_root!=self.owner.sections[3]):
                fail('UNBOUND_FLOW_ORIGINAL')
            actual=next(f for f in machine.admitted.functions_root['functions']if f['id']==self.function_id)
            if machine.functions.get(self.function_id)is not actual:fail('UNBOUND_FLOW_ORIGINAL')

    def _reserve(self,nin,nout,serial):
        if len(self._published)>=self.limits.max_events or len(self._births)+nout>self.limits.max_births:
            fail('UNBOUND_FLOW_CAPACITY',kind='resource')
        if nout and serial+nout>self.limits.max_serial:fail('UNBOUND_FLOW_SERIAL',kind='resource')
        self.budget.charge(work=512+128*(nin+nout),edges=16+8*(nin+nout),
                           copied_bytes=1024+512*(nin+nout))
        self._assert_original()

    def _prepare_entry(self,machine,function,arguments,*,issuer,budget):
        self._issuer(machine,issuer,budget)
        if function is not machine.functions.get(self.function_id)or machine.stack or self._frames:
            fail('UNBOUND_FLOW_ENTRY')
        if machine.activation>=2**64-1:fail('UNBOUND_FLOW_ACTIVATION',kind='resource')
        self._reserve(len(arguments),len(function['params']),0)
        ref=EntryReservation(_REF_KEY)
        self._entries[ref]=dict(machine=machine,function=function,arguments=tuple(arguments),
            activation=machine.activation+1,generation=object(),epoch=self.epoch,
            definitions=tuple(function['params']),stage='reserved',
            capacity=dict(values_in=len(arguments),births_in=0,values_out=len(function['params']),
                          births_out=len(function['params']),events=1))
        return ref

    def _finish_entry(self,reservation,machine,frame,*,issuer,budget):
        self._issuer(machine,issuer,budget)
        row=self._entries.get(reservation)if type(reservation)is EntryReservation else None
        if row is None or row['stage']!='reserved'or frame.activation!=row['activation']or frame.function is not row['function']:
            fail('UNBOUND_FLOW_ENTRY_REFERENCE')
        values=tuple(frame.values[d['id']]for d in row['definitions'])
        if any(a is not b for a,b in zip(values,row['arguments'])):fail('UNBOUND_FLOW_ENTRY_REFERENCE')
        row.update(stage='completed',frame=frame)
        event=self._new_event(row,frame,'parameters',(),(),values,row['definitions'],
                              tuple(self.parameter_masks[d['id']]for d in row['definitions']),None,None,None)
        return event

    def _publish_entry(self,machine,frame,event,*,issuer,budget):
        self._issuer(machine,issuer,budget)
        row=self._event(event)
        if row['kind']!='parameters'or row['frame']is not frame or row['stage']!='completed'or self._frames:
            fail('UNBOUND_FLOW_ENTRY_REFERENCE')
        if machine.activation+1!=frame.activation:fail('UNBOUND_FLOW_ENTRY_REFERENCE')
        with self._lock:
            machine.activation=frame.activation
            self._frames[id(frame)]=dict(frame=frame,generation=row['generation'],serial=0,current={},
                                         activation=frame.activation,values=frame.values)
            self._commit_births(row)

    def _assert_value_births(self,state):
        values=state['frame'].values;current=state['current']
        if len(values)!=len(current)or any(type(i)is not int or i not in current for i in values):
            fail('UNBOUND_FLOW_VALUE_BIRTH')
        for identifier,birth in current.items():
            data=self._births.get(birth)
            if (data is None or data['definition']!=identifier or data['frame']is not state['frame']
                    or data['generation']is not state['generation']or data['activation']!=state['activation']
                    or data['epoch']!=self.epoch or values[identifier]is not data['value']):
                fail('UNBOUND_FLOW_VALUE_BIRTH')

    def _frame(self,machine,frame,issuer,budget):
        self._issuer(machine,issuer,budget)
        row=self._frames.get(id(frame))
        if (row is None or row['frame']is not frame or not machine.stack or machine.stack[-1]is not frame
                or row['activation']!=frame.activation or row['values']is not frame.values
                or frame.function is not machine.functions.get(self.function_id)):
            fail('UNBOUND_FLOW_FRAME')
        self._assert_value_births(row)
        return row

    def _prepare(self,machine,frame,kind,node,definitions,*,issuer,budget):
        state=self._frame(machine,frame,issuer,budget)
        if self.pending is not None:fail('UNBOUND_FLOW_PENDING')
        block=next(b for b in frame.function['blocks']if b['id']==frame.block)
        if kind=='phi_batch':
            if frame.position!=-1 or node is not block:fail('UNBOUND_FLOW_FRONTIER')
        elif not 0<=frame.position<len(block['ops'])or node is not block['ops'][frame.position]:
            fail('UNBOUND_FLOW_FRONTIER')
        if kind=='select'and frame.values[node['operands'][0]].state=='poison':
            fail('UNBOUND_FLOW_MODEL_STATE_UNAVAILABLE',kind='unavailable')
        operands=()if kind=='phi_batch'else tuple(node['operands'])
        if node.get('op')=='bitcast'and definitions:
            out=machine.types.get(definitions[0]['type']);inp=machine.types.get(frame.values[operands[0]].type)
            if out['kind']=='raw'and inp['kind']=='int':
                birth=state['current'].get(operands[0]);data=self._births.get(birth)
                if data is None or data['mask']!=255 or not well_defined(machine.types,frame.values[operands[0]]):
                    fail('UNBOUND_FLOW_MODEL_STATE_UNAVAILABLE',kind='unavailable')
                kind='numeric_to_byte'
        nin=len(definitions)if kind=='phi_batch'else len(operands)
        self._reserve(nin,len(definitions),state['serial'])
        inputs=tuple(state['current'][i]for i in operands)
        values=tuple(frame.values[i]for i in operands)
        ref=Reservation(_REF_KEY)
        self._reservations[ref]=dict(machine=machine,frame=frame,activation=frame.activation,
            generation=state['generation'],epoch=self.epoch,frontier=(frame.block,frame.position),
            kind=kind,node=node,definitions=tuple(definitions),input_ids=operands,
            inputs=inputs,values=values,selection=None,stage='reserved',computed=False,
            capacity=dict(values_in=nin,births_in=nin,values_out=len(definitions),
                          births_out=len(definitions),events=1))
        return ref

    def _note_scalar_selection(self,reservation,original,observed,index,*,issuer,budget):
        row=self._reservation(reservation);self._frame(row['machine'],row['frame'],issuer,budget)
        if row['kind']!='select'or row['selection']is not None or index not in (1,2)or original is not row['values'][0]:
            fail('UNBOUND_FLOW_SELECTION')
        row['selection']=(original,observed,index,row['inputs'][index]);self.selection_uses+=1

    def _reservation(self,ref):
        row=self._reservations.get(ref)if type(ref)is Reservation else None
        if row is None or row['epoch']!=self.epoch or self._expired:fail('UNBOUND_FLOW_RESERVATION')
        return row

    def _finish(self,reservation,actual_inputs,actual_outputs,predecessor,*,issuer,budget):
        row=self._reservation(reservation);state=self._frame(row['machine'],row['frame'],issuer,budget)
        if row['stage']!='reserved'or row['frontier']!=(row['frame'].block,row['frame'].position):fail('UNBOUND_FLOW_FRONTIER')
        if not row['computed']:
            row['computed']=True;self.computations+=1
        if len(actual_outputs)!=len(row['definitions']):fail('UNBOUND_FLOW_OUTPUT')
        for declaration,value in zip(row['definitions'],actual_outputs):
            validate(row['machine'].types,value,row['machine'].handles)
            if not row['machine'].types.equal(declaration['type'],value.type):fail('UNBOUND_FLOW_OUTPUT')
        if row['kind']=='phi_batch':
            inputs=tuple(state['current'][i]for i in actual_inputs)
            values=tuple(actual_outputs)
            if any(value is not self._births[birth]['value']for birth,value in zip(inputs,values)):
                fail('UNBOUND_FLOW_VALUE_BIRTH')
            masks=tuple(self._births[b]['mask']for b in inputs)
        else:
            inputs,values=row['inputs'],row['values'];op=row['node']['op']
            old_masks=tuple(self._births[b]['mask']for b in inputs)
            if op=='constant':
                width=row['machine'].types.width(actual_outputs[0].type)
                masks=((1<<width)-1 if well_defined(row['machine'].types,actual_outputs[0])else 0,)
            elif op in {'copy','freeze','bitcast'}:masks=(old_masks[0],)
            elif op=='select':
                if row['selection']is None:fail('UNBOUND_FLOW_SELECTION')
                masks=(self._births[row['selection'][3]]['mask'],)
            else:
                full=all(mask==(1<<row['machine'].types.width(value.type))-1 for mask,value in zip(old_masks,values))
                masks=tuple((1<<row['machine'].types.width(v.type))-1 if full else 0 for v in actual_outputs)
        event=self._new_event(row,row['frame'],row['kind'],inputs,values,tuple(actual_outputs),
                              row['definitions'],masks,predecessor,row['selection'],row['frontier'])
        row['stage']='completed'
        return event

    def _new_event(self,reservation,frame,kind,inputs,values,outputs,definitions,masks,predecessor,selection,frontier):
        state=self._frames.get(id(frame));serial=state['serial']if state else 0
        births=[]
        for offset,(d,value,mask)in enumerate(zip(definitions,outputs,masks),1):
            coordinate=({'parameter':d['id']}if kind=='parameters'else
                {'block':frame.block,'phi_result':d['id']}if kind=='phi_batch'else
                {'block':frame.block,'operation':frame.position,'result':d['id']})
            b=Birth(_REF_KEY);births.append((b,dict(machine=self.machine,frame=frame,epoch=self.epoch,
                activation=frame.activation,generation=reservation['generation'],serial=serial+offset,
                definition=d['id'],coordinate=coordinate,value=value,mask=mask,kind=kind)))
        event=Event(_REF_KEY)
        self._events[event]=dict(machine=self.machine,frame=frame,epoch=self.epoch,
            generation=reservation['generation'],kind=kind,inputs=inputs,input_values=values,
            outputs=outputs,definitions=definitions,births=tuple(births),predecessor=predecessor,
            selection=selection,frontier=frontier,stage='completed',first_serial=serial+1 if births else None,
            capacity=reservation['capacity'])
        return event

    def _event(self,event):
        row=self._events.get(event)if type(event)is Event else None
        if row is None or row['epoch']!=self.epoch or self._expired:fail('UNBOUND_FLOW_EVENT_REFERENCE')
        return row

    def _validate_event(self,event,machine,frame,*,issuer,budget):
        state=self._frame(machine,frame,issuer,budget);row=self._event(event)
        if (row['machine']is not machine or row['frame']is not frame or row['frontier']!=(frame.block,frame.position)
                or row['generation']is not state['generation']):
            fail('UNBOUND_FLOW_EVENT_REFERENCE')
        return row

    def _commit_births(self,row):
        state=self._frames[id(row['frame'])]
        for ref,birth in row['births']:
            self._births[ref]=birth;state['current'][birth['definition']]=ref;state['serial']=birth['serial']
        row['stage']='published';self._published.append(row)

    def _publish(self,machine,frame,event,*,issuer,budget):
        row=self._validate_event(event,machine,frame,issuer=issuer,budget=budget)
        if row['stage']not in {'completed','resumable'}:fail('UNBOUND_FLOW_EVENT_REFERENCE')
        self._assert_original()
        with self._lock:
            frame.values.update({d['id']:v for d,v in zip(row['definitions'],row['outputs'])})
            self._commit_births(row)
            self.pending=None

    def request_park_after_next_completion(self,kind):
        if type(kind)is not str or kind not in {'ordinary','noop','phi_batch','select','freeze','literal','numeric_to_byte'}or self._park_kind is not None or self.pending is not None:
            fail('UNBOUND_FLOW_PARK')
        self._park_kind=kind

    def _park(self,event):
        row=self._event(event)
        if self._park_kind!=row['kind']:return False
        self._park_kind=None;row['stage']='parked';self.pending=event;return True

    def resume_completed(self,event,*,budget):
        if budget is not self.budget:fail('UNBOUND_FLOW_BUDGET')
        row=self._event(event)
        if self.pending is not event or row['stage']!='parked':fail('UNBOUND_FLOW_RESUME')
        frame=row['frame'];state=self._frames.get(id(frame))
        if (state is None or state['frame']is not frame or frame.activation!=state['activation']
                or frame.values is not state['values']or not self.machine.stack or self.machine.stack[-1]is not frame
                or row['frontier']!=(frame.block,frame.position)or row['generation']is not state['generation']):
            fail('UNBOUND_FLOW_EVENT_REFERENCE')
        self._assert_value_births(state)
        row['stage']='resumable'

    def expire(self):
        self._expired=True;self.epoch+=1

    def _control(self,machine,frame,*,issuer,budget):
        self._frame(machine,frame,issuer,budget);self._assert_original()

    def birth(self,frame,identifier):
        state=self._frames.get(id(frame))
        if state is None or state['frame']is not frame:fail('UNBOUND_FLOW_FRAME')
        self._assert_value_births(state)
        return state['current'][identifier]

    def describe_birth(self,ref):
        row=self._births.get(ref)if type(ref)is Birth else None
        if row is None or row['epoch']!=self.epoch or self._expired:fail('UNBOUND_FLOW_BIRTH_REFERENCE')
        return dict(serial=row['serial'],definition=row['definition'],coordinate=dict(row['coordinate']),mask=row['mask'],kind=row['kind'])

    def describe_event(self,event):
        row=self._event(event)
        return dict(kind=row['kind'],stage=row['stage'],first_output_serial=row['first_serial'],
                    outputs=len(row['outputs']),selected_index=row['selection'][2]if row['selection']else None,
                    capacity=dict(row['capacity']))

    def counts(self):
        return dict(published=len(self._published),births=len(self._births),events=len(self._events),
            computations=self.computations,selection_uses=self.selection_uses,
            serials=tuple(state['serial']for state in self._frames.values()),
            source_facts_issued=False,source_admission_passed=False,runtime_permission=False)
