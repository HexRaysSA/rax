"""Actual fixed-link weak absence reservations, not executable admission."""
from dataclasses import dataclass
from copy import deepcopy

from .errors import option, require
from .linking import bind_deployment, family


@dataclass(frozen=True)
class WeakNull:
    issuer: object
    consumer: str
    reference: dict
    domain: str


class Symbols:
    def __init__(self,contexts,selection,deployment,execution_equal,nominal_compatible,
                 signature_compatible=None,data_compatible=None,address_compatible=None):
        self.contexts=dict(contexts);self.selection=selection
        self.modules={owner:context.sections[2] for owner,context in contexts.items()}
        for context in self.contexts.values():context.assert_snapshot()
        self.binding=bind_deployment(self.modules,deployment,execution_equal,nominal_compatible,
            signature_compatible=signature_compatible,data_compatible=data_compatible,
            address_compatible=address_compatible)
        self._selection_snapshot=deepcopy(selection.__dict__)
        self._binding_snapshot=deepcopy(self.binding)
        self._contexts_snapshot=dict(self.contexts)
        self.issued={};self.origins={}

    def _absence(self,consumer,reference):
        require(self.selection.__dict__==self._selection_snapshot and self.binding==self._binding_snapshot and
                self.contexts.keys()==self._contexts_snapshot.keys() and all(self.contexts[a] is context
                    for a,context in self._contexts_snapshot.items()),'RT_WEAK_SELECTION')
        # Absence depends on the entire accepted deployment, including provider
        # roots which contain no matching export. Recheck every proof input.
        for root in self.contexts.values():root.assert_snapshot()
        context=self.contexts[consumer];context.assert_snapshot()
        module=reference['module']
        if module['kind']=='dependency':
            slot=next((d for d in context.sections[2]['manifest']['dependencies'] if d['slot']==module['slot']),None)
            require(slot is not None,'RT_WEAK_DECLARATION')
            declared=next((d for d in slot['declarations'] if d['id']==reference['id']),None)
            require(declared is not None and declared['weak'] and declared['kind'] in {'function','symbol'},
                    'RT_WEAK_DECLARATION')
            kind='function' if declared['kind']=='function' else declared['symbol_kind']
            require(kind!='tls','RT_DEPLOY_WEAK_TLS')
            key=consumer,module['slot'],reference['id']
            require(key in self.binding['bindings'] and self.binding['bindings'][key] is None,'RT_WEAK_PRESENT')
        else:
            require(module['kind']=='self','RT_WEAK_REFERENCE')
            declared=context.runtime_symbol(reference)
            require(declared['binding'] in {'weak','external_weak'} and declared['definition'] is None and
                    declared['fallback'] is None,'RT_WEAK_DECLARATION')
            kind=declared['kind'];require(kind!='tls','RT_DEPLOY_WEAK_TLS')
            expected=family(context.sections[2]['manifest']['key'])
            for owner,root in self.modules.items():
                self.contexts[owner].assert_snapshot()
                if family(root['manifest']['key'])!=expected:continue
                for symbol in root['symbols']:
                    if (symbol['namespace'],symbol['name'],symbol['kind'],symbol['source_linkage'])==(
                        declared['namespace'],declared['name'],kind,declared['source_linkage']):
                        require(option(symbol['definition']) is None,'RT_WEAK_PRESENT')
        return 'code' if kind in {'function','import'} else 'data'

    def reserve_weak(self,consumer_context,reference):
        owners=[owner for owner,context in self.contexts.items() if context is consumer_context]
        require(len(owners)==1,'RT_WEAK_CONSUMER')
        consumer=owners[0];domain=self._absence(consumer,reference)
        reservation=WeakNull(self,consumer,deepcopy(reference),domain)
        self.issued[id(reservation)]=reservation
        self.origins[id(reservation)]=(consumer_context,deepcopy(reference))
        return reservation

    def verify_weak(self,reservation,consumer_context,reference):
        require(isinstance(reservation,WeakNull) and reservation.issuer is self and
                self.issued.get(id(reservation)) is reservation,'RT_WEAK_AUTHORITY')
        original_context,original_reference=self.origins[id(reservation)]
        require(original_context is consumer_context and reservation.reference==reference==original_reference,
                'RT_WEAK_CONSUMER')
        require(self._absence(reservation.consumer,reference)==reservation.domain,'RT_WEAK_DOMAIN')
        return reservation.domain
