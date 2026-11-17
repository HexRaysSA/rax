"""Path-checked framing and canonical existing source-budget identity."""
from pathlib import Path
import sys
from .errors import need
PROJECT=Path(__file__).resolve().parents[3]
def _load(name,path):
    import importlib.util
    path=path.resolve();loaded=sys.modules.get(name)
    if loaded is not None:
        need(type(getattr(loaded,'__file__',None))is str and Path(loaded.__file__).resolve()==path,'V3_IMPORT_CONTEXT',name)
        return loaded
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    try:spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name)is module:del sys.modules[name]
        raise
    return module

def source_api():
    return _load('_rax_smir_source_data_v1',PROJECT/'tools/smir-runtime-contract/source_roles/source_data.py')

class _Checker:
    # Genuine-v2 comparison only. Structural import never imports checker/context
    # or touches the parent's generic codec/sys.path namespace.
    def __getattr__(self,name):
        import importlib
        previous=list(sys.path)
        try:
            path=PROJECT/'tools/smir-runtime-contract'
            sys.path.insert(0,str(path));module=importlib.import_module('source_contracts.checker')
            need(Path(module.__file__).resolve()==(path/'source_contracts/checker.py').resolve(),'V3_IMPORT_CONTEXT')
            return getattr(module,name)
        finally:sys.path[:]=previous

C=_Checker()
envelope=_load('_rax_smir_source_carrier_envelope',PROJECT/'tools/smir-format/codec.py')

def check_budget(budget):
    need(type(budget)is source_api().SourceQueryBudget,'V3_BUDGET_CLASS')
