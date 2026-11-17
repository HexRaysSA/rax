"""Private charged primitives for the canonical draft reference registry."""
from collections.abc import Mapping
import importlib.util
from pathlib import Path
import sys
from threading import RLock

ROOT=Path(__file__).resolve().parents[4]
LOAD_LOCK=RLock()


def load(name,relative,package=False):
    path=(ROOT/relative).resolve()
    with LOAD_LOCK:
        existing=sys.modules.get(name)
        if existing is not None:
            if Path(getattr(existing,'__file__','')).resolve()!=path:
                raise RuntimeError('CODE_REGISTRY_MODULE_IDENTITY: '+name)
            return existing
        spec=importlib.util.spec_from_file_location(name,path,
            submodule_search_locations=[str(path.parent)] if package else None)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        try:spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:del sys.modules[name]
            raise
        return module


SD=load('_rax_smir_source_data_v1','tools/smir-runtime-contract/source_roles/source_data.py')
CALL=load('_rax_smir_source_call_v1','tools/smir-format/execution/candidate/source_call_projection.py')
SEM=load('_rax_smir_source_registry_v1','tools/smir-format/execution/candidate/source_registry_projection.py')
ABI=load('_rax_smir_registry_abi_function_address','tools/smir-abi/function_address/__init__.py',True)
MODEL=load(ABI.__name__+'.model','tools/smir-abi/function_address/model.py')
SHAPE=load(ABI.__name__+'.execution_compare','tools/smir-abi/function_address/execution_compare.py')
SITE=load('_rax_smir_registry_pinned_site','tools/smir-abi/site_config.py')
SITE_IDENTITY=SITE.identity()  # Fixed ABI baseline; not a file-provided identity.
RUNTIME=load('_rax_smir_registry_runtime','tools/smir-runtime-contract/candidate/__init__.py',True)
LINK=load(RUNTIME.__name__+'.linking','tools/smir-runtime-contract/candidate/linking.py')
SELECT=load(RUNTIME.__name__+'.selection','tools/smir-runtime-contract/candidate/selection.py')


def api():return sys.modules['_rax_smir_code_addresses_v1']


def fail(code,detail='',kind='semantic'):
    raise api().CodeRegistryError(kind,code,detail)


def require(condition,code='RT_CODE_CONTEXT',detail=''):
    if not condition:fail(code,detail)


def unavailable(detail):fail('code_address_unavailable',detail,'unavailable')


def ledger(budget):
    if type(budget) is not SD.SourceQueryBudget:
        raise SD.SourceDataError('resource','SOURCE_DATA_BUDGET')
    return budget


def plain(value,budget,depth=1):
    budget.work(1)
    if depth>budget.max_depth:fail('RT_CODE_RESOURCE','copy depth','resource')
    if isinstance(value,Mapping):
        budget.charge(work=len(value),edges=len(value),copied_bytes=64+32*len(value))
        return {k:plain(v,budget,depth+1) for k,v in value.items()}
    if type(value) in (list,tuple):
        budget.charge(work=len(value),edges=len(value),copied_bytes=16+8*len(value))
        return [plain(v,budget,depth+1) for v in value]
    if type(value) is str:
        budget.work(len(value));budget.reserve_bytes(4*len(value))
    else:budget.reserve_bytes(8)
    return value


def ref(identifier):return {'module':{'kind':'self'},'id':identifier}
def option(value):return None if value is None else value['some']


def hook(name):
    method=getattr(SEM,name,None)
    if method is None:unavailable('actual SEM '+name+' producer required')
    return method
