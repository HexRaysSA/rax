"""Actual evaluator attachment and process reservations; no public-frame factory."""
import sys
B=sys.modules['_rax_smir_code_addresses_v1']._base
A=lambda:sys.modules['_rax_smir_code_addresses_v1']


class MachineMethods:
    def attach_legacy(self,source,*,budget):
        self._check(budget)
        original_activation=B.hook('legacy_code_activation')(source,budget=budget)
        activation=self.attach_activation(original_activation,budget=budget)
        active=self._activation(activation,budget)
        B.hook('validate_legacy_code_source')(source,activation=original_activation,budget=budget)
        details=B.hook('legacy_code_details')(source,activation=original_activation,budget=budget)
        B.require(set(details)=={'state','bits','domain','reservation','invalid'},'RT_CODE_REFERENCE')
        state=details['state'];bits=details['bits'];target=None
        B.require(state in ('concrete','poison','undef'),'RT_CODE_REFERENCE')
        B.require((type(bits) is int and 0<=bits<2**64) if state=='concrete' else bits is None,
                  'RT_CODE_REFERENCE')
        reservation=details['reservation']
        if state=='concrete' and bits and details['invalid'] is None and details['domain']=='code':
            reserved=self._row(reservation,A().CodeReservation)
            B.require(reserved['kind']=='function' and reserved['bits']==bits and
                reserved['owner'] is active['owner'],'RT_CODE_REFERENCE')
            attachment=self._row(reserved['attachment'],A().MachineAttachment)
            B.require(attachment['source'] is active['context'],'RT_CODE_CONTEXT')
            owner=self._source(reserved['owner'],budget)
            source_record=owner['source'].record('function',reserved['reference'],budget=budget)
            record=B.plain(source_record.record,budget)
            budget.charge(work=4,edges=4,copied_bytes=256)
            with self._lock:
                key=reserved['key'];target=self._targets.get(key)
                if target is None:
                    if len(self._targets)>=self._policy.max_targets:
                        B.fail('RT_CODE_RESOURCE','legacy target metadata','resource')
                    target=self._issue(A().SelectedTarget,owner=reserved['owner'],key=key,
                        namespace='function',reference=reserved['reference'],record=record,
                        original_reference=source_record.original_reference,deployment=None,source_record=source_record)
                    self._targets[key]=target
        B.hook('validate_legacy_code_source')(source,activation=original_activation,budget=budget)
        budget.charge(work=2,edges=4,copied_bytes=192)
        with self._lock:
            return self._issue(A().LegacyCodeRef,source=source,activation=activation,state=state,bits=bits,
                target=target,permit=None,reservation=reservation,invalid=details['invalid'],domain=details['domain'])

    def _entry_source(self,entry):
        row=self._row(entry,A().EntryRef)
        return self._row(row['owner'],A().OwnerRef)['source']

    def _entry_function(self,entry):
        row=self._row(entry,A().EntryRef)
        return self._row(row['target'],A().SelectedTarget)['source_record'].original_reference

    def _entry_definition(self,entry):
        row=self._row(entry,A().EntryRef)
        return self._row(row['target'],A().SelectedTarget)['source_record'].record

    def attach_machine(self,machine,source,*,budget):
        self._check(budget)
        B.SEM.validate_source_registry_context(source,budget=budget)
        B.hook('validate_source_machine')(machine,source=source,budget=budget)
        owner=self.register_source(source,budget=budget)
        budget.charge(work=len(self._attachments)+4,edges=2,copied_bytes=192)
        with self._lock:
            self._open(owner)
            for attachment in self._attachments:
                old=self._row(attachment)
                if old['machine'] is machine:
                    B.require(old['source'] is source and old['owner'] is owner,
                              detail='original Machine owner generation cannot be rebound')
                    self._open(old['owner'])
                    return attachment
            B.require(not machine.code_pointers and not machine.labels,
                      detail='prepublished legacy registrations cannot be remapped')
            attachment=self._issue(A().MachineAttachment,machine=machine,source=source,owner=owner)
            self._attachments.append(attachment);return attachment

    def reserve_function(self,attachment,reference,*,budget):
        self._check(budget);row=self._row(attachment,A().MachineAttachment)
        B.hook('validate_source_machine')(row['machine'],source=row['source'],budget=budget)
        function=row['source'].record('function',reference,budget=budget)
        original=B.plain(function.original_reference,budget)
        owner=self._source(row['owner'],budget);self._open(row['owner'])
        key=(row['owner'],owner['generation'],'function',original['id'])
        bits=self._pool.reserve(key,budget=budget)
        budget.charge(work=2,edges=3,copied_bytes=128)
        with self._lock:
            self._open(row['owner'])
            return self._issue(A().CodeReservation,bits=bits,key=key,attachment=attachment,
                source=row['source'],owner=row['owner'],kind='function',reference=original)

    def reserve_label(self,attachment,function,block,*,budget):
        self._check(budget);row=self._row(attachment,A().MachineAttachment)
        B.hook('validate_source_machine')(row['machine'],source=row['source'],budget=budget)
        original=row['source'].record('function',function,budget=budget)
        record=original.record;budget.work(len(record['blocks']))
        B.require(type(block) is int and any(v['id']==block for v in record['blocks']),'RT_CODE_REFERENCE')
        owner=self._source(row['owner'],budget);self._open(row['owner'])
        key=(row['owner'],owner['generation'],'label',original.original_reference['id'],block)
        bits=self._pool.reserve(key,budget=budget);budget.charge(work=2,edges=3,copied_bytes=128)
        with self._lock:
            self._open(row['owner'])
            return self._issue(A().CodeReservation,bits=bits,key=key,attachment=attachment,
                source=row['source'],owner=row['owner'],kind='label',reference=function,block=block)

    def attach_activation(self,source,*,budget):
        self._check(budget)
        # This accessor is a canonical privately issued SEM fact, validated below.
        context=B.hook('source_activation_context')(source,budget=budget)
        owner=self.register_source(context,budget=budget)
        B.hook('validate_source_activation')(source,source=context,budget=budget)
        budget.charge(work=len(self._activations)+4,edges=4,copied_bytes=256)
        with self._lock:
            self._open(owner)
            for activation in self._activations:
                if self._row(activation)['source'] is source:return activation
            if len(self._activations)>=self._policy.max_activations:
                B.fail('RT_CODE_RESOURCE','activations','resource')
            activation=self._issue(A().ActivationRef,source=source,owner=owner,context=context)
            self._activations.append(activation);return activation

    def _activation(self,activation,budget):
        row=self._row(activation,A().ActivationRef)
        B.hook('validate_source_activation')(row['source'],source=row['context'],budget=budget)
        self._source(row['owner'],budget)
        return row

    def _observe(self,activation,operation,value,budget,plan=None):
        row=self._activation(activation,budget)
        B.hook('validate_source_observation')(row['source'],operation,value,plan=plan,budget=budget)
        return row

    def finish_entry(self,entry,*,outcome,budget):
        self._check(budget)
        while True:
            row=self._row(entry,A().EntryRef)
            B.require(row['state']=='active','RT_CODE_ENTRY_REPLAY')
            commit=B.hook('prepare_source_entry_commit')(outcome,entry=entry,budget=budget)
            other_lock=B.hook('source_entry_commit_lock')(commit)
            validate=B.hook('validate_source_entry_commit_locked')
            consume=B.hook('consume_source_entry_commit_locked')
            budget.charge(work=8,edges=2,copied_bytes=64)
            # Compute logical post-state before either one-shot consumption.
            with self._lock:
                owner=self._row(row['owner'],A().OwnerRef);version=owner['active']
                B.require(version>0,'RT_CODE_ENTRY_STATE');next_active=version-1
            locks=sorted((self._lock,other_lock),key=id)
            with locks[0]:
                with locks[1]:
                    B.require(self._row(entry)['state']=='active','RT_CODE_ENTRY_REPLAY')
                    if owner['active']!=version:
                        # Another real entry changed this owner's count. Keep
                        # both original outcomes untouched and charge the retry.
                        continue
                    validate(commit,entry=entry)
                    consume(commit)
                    row['state']='finished';owner['active']=next_active
                    return
