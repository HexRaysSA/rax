"""S-PROD014 ABI callback transport and actual RootContext source boundaries.

Reference views grant no private facts, relocation or execution authority. The
subprocess uses real ten-root declarations and SEM/R source-data implementations,
keeping their `candidate` package separate from the ABI candidate.py module.
"""
from dataclasses import fields
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from candidate import Context, verify
from candidate_fixtures import build, context
from nominal import ref

ROOT = Path(__file__).resolve().parents[3]
SHARED = ROOT / 'tools/smir-runtime-contract/source_roles/source_data.py'
EXECUTION = ROOT / 'tools/smir-format/execution'
NAME = '_rax_smir_source_data_v1'


def shared():
    if NAME in sys.modules:
        if Path(sys.modules[NAME].__file__).resolve() != SHARED.resolve():
            raise RuntimeError('source-data module identity/path mismatch')
    else:
        specification = importlib.util.spec_from_file_location(NAME, SHARED)
        module = importlib.util.module_from_spec(specification)
        sys.modules[NAME] = module
        specification.loader.exec_module(module)
    return sys.modules[NAME]


def with_source(original, **changes):
    values = {field.name: getattr(original, field.name) for field in fields(Context)}
    values.update(changes)
    return Context(**values)


ROOT_BOUNDARY = r'''
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from candidate.context import RootContext
from candidate.type_system import ref
from test_candidate_context import roots

ROOT=Path.cwd().parents[2]
path=ROOT/'tools/smir-runtime-contract/source_roles/source_data.py'
name='_rax_smir_source_data_v1'
if name not in sys.modules:
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
M=sys.modules[name]

checks=[]
rejection_codes=[]

def check(value, detail):
    if not value:raise RuntimeError(detail)
    checks.append(str(detail))

def ledger(**changes):
    policy=dict(max_work=100_000_000,max_edges=5_000_000,
                max_copied_bytes=100_000_000,max_depth=128)
    policy.update(changes)
    return M.SourceQueryBudget(**policy)

def rejected(code, action, kind=None):
    try:action()
    except Exception as error:
        check(getattr(error,'code',None)==code,(code,type(error).__name__,str(error)))
        if kind is not None:check(getattr(error,'kind',None)==kind,'wrong error kind')
        rejection_codes.append(code)
        return
    raise RuntimeError('unexpected acceptance: '+code)

def document():
    sections=roots()
    # This fixture intentionally supplies actual empty roots, not API defaults.
    sections.setdefault(5, {'payload_revision':2,'relocations':[],'constant_initializers':[]})
    sections.setdefault(7, {'payload_revision':1,'segments':[]})
    sections.setdefault(9, {'payload_revision':1,'capabilities':['memory'],'requirements':[],'limits':[]})
    check(set(sections)==set(range(1,11)),'expected actual ten-root source fixture')
    extent=16+(1<<40)
    sections[1]['types'].append({'id':330,'kind':'array','element':ref(9),'count':extent})
    sections[4]['segments'].append({'id':331,'layout':None,'nominal':None,'abi_binding':None,
        'alignment':8,'mutable':False,'initial':'61626364'+'00'*12,'poison':'00'*16,
        'undef':'00'*16,'zero_fill':1<<40,'zero_shadow':'defined'})
    sections[2]['symbols'].append({'id':330,'namespace':'example','name':'source_data_boundary',
        'kind':'data','source_linkage':'none','binding':'weak','visibility':'default',
        'execution':ref(330),'nominal':None,'abi_signature':None,
        'definition':{'some':{'kind':'data','segment':331}},'size':{'some':extent},
        'alignment':8,'comdat':None,'fallback':None})
    sections[5]['relocations'].append({'source_kind':'data','source':331,'offset':8,'width':8,
        'integer_bits':0,'kind':'data_address','target':ref(330),'addend':0,
        'derivation':[],'check_base':False,'flags':[],'inrange':None})
    return sections

sections=document();source=RootContext(sections)
check(source.source_stamp is None,'eager source stamp')
source.verify_abi()
check(source.source_stamp is None,'ordinary ABI verification prepared source data')
abi_module=sys.modules['rax_abi_candidate_contract']
# Actual Context callback transport, not a dictionary pretending to be a view.
plain=abi_module.Context('boundary',source.abi_execution,source.symbol,source.metadata,
    {},{},lambda r:{},lambda r:{},{},source.memory_layout)
check(plain.source_data is None and plain.source_stamp is None and plain.source_budget is None,
      'new fields acquired defaults')
quota=ledger();stamp=source.prepare_source_data(budget=quota)
bridge=abi_module.Context('boundary',source.abi_execution,source.symbol,source.metadata,
    {},{},lambda r:{},lambda r:{},{},source.memory_layout,
    source_data=source.source_data,source_stamp=stamp,source_budget=quota)
view=bridge.source_data(ref(330),4,8,budget=bridge.source_budget)
check(type(view) is M.LocalSourceData and view.stamp is bridge.source_stamp,'wrong class/stamp')
check(view.symbol==('self',330) and view.storage==('self',331),'wrong original namespace')
check(view.read(0,8,budget=quota)==bytes(8),'raw bytes unexpectedly relocated')
check(len(view.patches)==1 and (view.patches[0].start,view.patches[0].end)==(8,16),
      'partial intersecting patch was clipped or omitted')
check(view.patches[0].record.field('kind')=='data_address','wrong frozen leaf')
check(view.symbol_record.field('binding')=='weak','declared weak binding lost')
tail=bridge.source_data(ref(330),16,1<<40,budget=quota)
check(len(tail.prefix)==0 and tail.zero_tail_bytes==1<<40,'zero tail expanded')
check(tail.read((1<<40)-8,8,budget=quota)==bytes(8),'bounded tail read failed')
rejected('SOURCE_DATA_CONTEXT',lambda:view.read(0,8,budget=ledger()),'semantic')
other=RootContext(deepcopy(sections));other_quota=ledger()
other_stamp=other.prepare_source_data(budget=other_quota)
check(other_stamp is not stamp,'equal-byte contexts share stamp')
rejected('SOURCE_DATA_CONTEXT',lambda:other.source_data(ref(330),0,8,budget=quota),'semantic')
source.sections[4]['segments'][-1]['initial']='62626364'+'00'*12
rejected('context_snapshot_changed',lambda:view.read(0,1,budget=quota),'semantic')
zero=RootContext(document())
rejected('SOURCE_DATA_RESOURCE',lambda:zero.prepare_source_data(budget=ledger(max_work=0)),
         'resource')
check(zero.source_stamp is None,'failed prepare published stamp')
missing=document();del missing[5]
missing_context=RootContext(missing);missing_quota=ledger()
missing_context.prepare_source_data(budget=missing_quota)
rejected('SOURCE_DATA_EVIDENCE_UNAVAILABLE',
         lambda:missing_context.source_data(ref(330),0,4,budget=missing_quota),'unavailable')
poisoned=document();poisoned[4]['segments'][-1]['poison']='00'*15+'01'
poison_context=RootContext(poisoned);poison_quota=ledger()
poison_context.prepare_source_data(budget=poison_quota)
rejected('RT_METADATA_INITIALIZED_READONLY',
         lambda:poison_context.source_data(ref(330),0,4,budget=poison_quota))
print(json.dumps({'checks':len(checks),'rejections':len(rejection_codes),'rejection_codes':rejection_codes,'tail_bytes':1<<40,
    'scope':'Actual ten-root reference callback/views only; no private factory, relocation or execution grant.'}))
'''


class SourceDataBoundaryTests(unittest.TestCase):
    def test_noncpp_verifier_never_prepares_or_queries_source_data(self):
        document, evidence = build()
        original = context(document, evidence)
        self.assertIsNone(original.source_data)
        self.assertIsNone(original.source_stamp)
        self.assertIsNone(original.source_budget)

        def forbidden(*arguments, **keywords):
            self.fail('existing ABI verification unexpectedly queried source data')

        verify(document, with_source(original, source_data=forbidden))

    def test_exact_shared_errors_survive_context_callback_unchanged(self):
        module = shared()
        document, evidence = build()
        original = context(document, evidence)
        quota = module.SourceQueryBudget(max_work=1, max_edges=1,
                                        max_copied_bytes=1, max_depth=1)
        for kind, code in [('semantic', 'SOURCE_DATA_CONTEXT'),
                           ('unavailable', 'SOURCE_DATA_EVIDENCE_UNAVAILABLE'),
                           ('resource', 'SOURCE_DATA_RESOURCE')]:
            error = module.SourceDataError(kind, code, 'ABI transport')

            def reject(*arguments, **keywords):
                raise error

            wrapped = with_source(original, source_data=reject,
                                  source_stamp=None, source_budget=quota)
            with self.assertRaises(module.SourceDataError) as caught:
                wrapped.source_data(ref(1), 0, 8, budget=quota)
            self.assertIs(caught.exception, error)
            self.assertEqual((caught.exception.kind, caught.exception.code), (kind, code))

    def test_programming_error_is_not_normalized_into_missing_evidence(self):
        document, evidence = build()
        error = RuntimeError('actual callback implementation fault')

        def reject(*arguments, **keywords):
            raise error

        wrapped = with_source(context(document, evidence), source_data=reject)
        with self.assertRaises(RuntimeError) as caught:
            wrapped.source_data(ref(1), 0, 8, budget=None)
        self.assertIs(caught.exception, error)

    def test_actual_ten_root_views_context_budget_and_symbolic_tail(self):
        process = subprocess.run([sys.executable, '-c', ROOT_BOUNDARY], cwd=EXECUTION,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1', 'PYTHONPATH':str(EXECUTION)},
            text=True, capture_output=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        observation = json.loads(process.stdout)
        self.assertGreaterEqual(observation['checks'], 15)
        self.assertEqual(observation['rejections'], 6)
        self.assertEqual(observation['rejection_codes'], ['SOURCE_DATA_CONTEXT',
            'SOURCE_DATA_CONTEXT', 'context_snapshot_changed', 'SOURCE_DATA_RESOURCE',
            'SOURCE_DATA_EVIDENCE_UNAVAILABLE', 'RT_METADATA_INITIALIZED_READONLY'])
        self.assertEqual(observation['tail_bytes'], 1 << 40)
