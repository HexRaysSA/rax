"""DRAFT_UNFROZEN actual source-backed reference code registry.

No native entry, private Rust fact, host callback or production runtime issuer.
"""
import importlib.util
from pathlib import Path
import sys
import weakref
from threading import RLock

if __name__!='_rax_smir_code_addresses_v1':raise ImportError('CODE_REGISTRY_MODULE_IDENTITY')
_HERE=Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location(__name__+'._base',_HERE/'code_registry/base.py')
_base=importlib.util.module_from_spec(_spec);sys.modules[_spec.name]=_base;_spec.loader.exec_module(_base)


class CodeRegistryError(Exception):
    __slots__=('_kind','_code','_detail')
    def __init__(self,kind,code,detail=''):
        if hasattr(self,'_kind'):raise AttributeError('immutable registry error')
        if kind not in ('semantic','unavailable','resource') or type(code) is not str or type(detail) is not str:
            raise TypeError('registry error fields')
        object.__setattr__(self,'_kind',kind);object.__setattr__(self,'_code',code);object.__setattr__(self,'_detail',detail)
        super().__init__(code)
    def __setattr__(self,n,v):
        if n in ('kind','code','detail','_kind','_code','_detail'):raise AttributeError('immutable registry error')
        super().__setattr__(n,v)
    def __delattr__(self,n):raise AttributeError('immutable registry error')
    kind=property(lambda s:s._kind);code=property(lambda s:s._code);detail=property(lambda s:s._detail)


_POLICIES=weakref.WeakValueDictionary()


class RegistryPolicy:
    __slots__=('max_targets','max_permits','max_roots','max_activations','max_snapshots','__weakref__')
    def __init__(self,*,max_targets,max_permits,max_roots,max_activations,max_snapshots):
        values=dict(max_targets=max_targets,max_permits=max_permits,max_roots=max_roots,
            max_activations=max_activations,max_snapshots=max_snapshots)
        if any(hasattr(self,n) for n in values):raise AttributeError('immutable registry policy')
        for n,v in values.items():
            if type(v) is not int or not 0<=v<2**64:raise CodeRegistryError('semantic','RT_CODE_POLICY')
        for n,v in values.items():object.__setattr__(self,n,v)
        _POLICIES[id(self)]=self
    def __setattr__(self,n,v):raise AttributeError('immutable registry policy')
    def __delattr__(self,n):raise AttributeError('immutable registry policy')


class _Handle:
    __slots__=('_registry','__weakref__')
    def __new__(cls,*a,**kw):raise CodeRegistryError('semantic','RT_CODE_CONSTRUCTOR')
    def __init__(self,*a,**kw):raise CodeRegistryError('semantic','RT_CODE_CONSTRUCTOR')
    def __setattr__(self,n,v):raise AttributeError('immutable registry handle')
    def __delattr__(self,n):raise AttributeError('immutable registry handle')
    def __copy__(self):self._registry._row(self);return self
    def __deepcopy__(self,memo):return self.__copy__()
    def _diagnostic(self,name):return self._registry._row(self)[name]


for _name in ('OwnerRef','DeploymentRef','SelectedTarget','WeakAbsent','ProviderMissing','NativeBridgeMissing',
              'AddressLane','BoundLane','BindingPermit','ActivationRef','LegacyCodeRef','EntryRef',
              'HolderRef','RootRef','CaptureRef','MachineAttachment','CodeReservation','RetirementRef','RetirementStatus'):
    globals()[_name]=type(_name,(_Handle,),{'__module__':__name__,'__slots__':()})
for _cls in (AddressLane,BoundLane):
    _cls.state=property(lambda s:s._diagnostic('state'))
    _cls.bits=property(lambda s:s._registry._bits(s))
    _cls.width=property(lambda s:64)
    _cls.target=property(lambda s:s._diagnostic('target'))
BoundLane.permit=property(lambda s:s._diagnostic('permit'))
BindingPermit.identity=property(lambda s:s._diagnostic('id'))
SelectedTarget.generation=property(lambda s:s._registry._row(s._diagnostic('owner'),OwnerRef)['generation'])
SelectedTarget.source=property(lambda s:s._registry._row(s._diagnostic('owner'),OwnerRef)['source'])
SelectedTarget.function=property(lambda s:s._diagnostic('source_record').original_reference)
SelectedTarget.definition=property(lambda s:s._diagnostic('source_record').record)
CodeReservation.generation=property(lambda s:s._diagnostic('key')[1])
CodeReservation.bits=property(lambda s:s._diagnostic('bits'))
EntryRef.target=property(lambda s:s._diagnostic('target'))
EntryRef.source=property(lambda s:s._registry._entry_source(s))
EntryRef.function=property(lambda s:s._registry._entry_function(s))
EntryRef.definition=property(lambda s:s._registry._entry_definition(s))
RetirementStatus.phase=property(lambda s:s._diagnostic('phase'))
_HANDLE_TYPES=frozenset(v for v in globals().values() if isinstance(v,type) and v is not _Handle and issubclass(v,_Handle))

_core=_base.load(__name__+'._core','tools/smir-runtime-contract/source_roles/code_registry/core.py')
IntegerLane=sys.modules['_rax_smir_code_values_v1'].IntegerLane


class CodeRegistry(_core.Registry):
    pass


_CODE_ADDRESSES_READY=True
