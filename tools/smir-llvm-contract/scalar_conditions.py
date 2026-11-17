"""Actual original source-condition observation, draft; no source admission."""
from pathlib import Path
from dataclasses import dataclass, field
import hashlib
import inspect
import json
import os
import re
import sys
import tempfile
import weakref
HERE = Path(__file__).resolve().parent
PROJECT = Path(os.environ.get('SCALAR_REFERENCE_PROJECT', str(HERE.parents[1]))).resolve()
sys.path.insert(0, str(PROJECT / 'tools/smir-llvm-contract'))
import semantic_observation as A
if Path(A.__file__).resolve() != PROJECT / 'tools/smir-llvm-contract/semantic_observation.py':
    raise ValueError('SCALAR_IMPORT_CONTEXT')
SCHEMA = Path(os.environ.get('SCALAR_REFERENCE_SCHEMA', str(PROJECT / 'docs/specifications/smir/portable/llvm/scalar-alignment.schema.json')))
SCHEMA_SHA = '8e9fc405c84b56ceb967589ce20487166a2dc9b15cd1fda3b65283a977d7c9e4'
PIN, COMPILER = (A.PIN, A.COMPILER)
read, file_hash, load_json, canonical, digest, need = (A.read, A.file_hash, A.load_json, A.canonical, A.digest, A.need)
_ISSUED = weakref.WeakKeyDictionary()

class AlignmentError(ValueError):

    def __init__(self, code, detail='', kind='semantic'):
        self.code, self.detail, self.kind = (code, detail, kind)
        super().__init__(code + ': ' + detail)

def require(ok, code, detail='', kind='semantic'):
    if not ok:
        raise AlignmentError(code, detail, kind)

def ledger(budget):
    require(type(budget) is A.R.apis()[4].SourceQueryBudget, 'SCALAR_BUDGET_CLASS', kind='resource')

def schema(budget):
    raw = read(SCHEMA, 1 << 20, budget)
    require(digest(raw) == SCHEMA_SHA, 'SCALAR_SCHEMA_IDENTITY')
    return (load_json(raw), raw)

def require_issued(value, witness, budget):
    ledger(budget)
    require(type(value) is ConditionWitness, 'SCALAR_SOURCE_CONDITIONS_UNAVAILABLE', kind='unavailable')
    budget.charge(work=8 * (len(_ISSUED) + 1) ** 2, edges=2, copied_bytes=128)
    row = _ISSUED.get(value)
    require(row is not None and row[0] is value.data and (row[1] is witness) and (row[2] is budget) and (value.witness is witness) and (value.ledger is budget), 'SCALAR_CONDITION_ISSUANCE')
    require(type(witness) is A.ObservationWitness, 'SCALAR_ORIGINAL_AST')
    A.ObservationWitness.report(witness, budget=budget)
    return value

@dataclass(frozen=True, eq=False)
class ConditionWitness:
    data: object
    witness: object
    ledger: object = field(repr=False)
    executable: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)

    def report(self, *, budget):
        require_issued(self, self.witness, budget)
        return A.thaw(self.data, budget)

def native_identity(oracle, budget):
    p = Path(oracle).resolve()
    receipt = p.parent / 'build-receipt.json'
    raw = read(receipt, 4 << 20, budget)
    d = load_json(raw)
    need(type(d.get('exit')) is int and d['exit'] == 0 and (d.get('llvm_pin') == PIN), 'CEW_PROVENANCE', 'actual native build receipt')
    need(type(d) is dict and set(d) == {'format', 'llvm_pin', 'compiler', 'command', 'exit', 'input_hashes', 'drift', 'scope', 'binary'} and (d['format'] == 'draft-scalar-condition-native-build'), 'CEW_PROVENANCE', 'closed native receipt')
    need(type(d['compiler']) is dict and set(d['compiler']) == {'path', 'sha256', 'version'} and (type(d['compiler']['path']) is str) and (type(d['compiler']['version']) is str) and (PIN in d['compiler']['version']), 'CEW_PROVENANCE', 'compiler record')
    need(d['compiler']['sha256'] == COMPILER, 'CEW_PROVENANCE', 'compiler pin')
    need(type(d['binary']) is dict and set(d['binary']) == {'path', 'sha256'} and (type(d['binary']['sha256']) is str) and re.fullmatch('[0-9a-f]{64}', d['binary']['sha256']), 'CEW_PROVENANCE', 'binary record')
    need(type(d['command']) is list and 0 < len(d['command']) <= 4096 and all((type(x) is str and len(x) <= 4096 for x in d['command'])) and (d['drift'] == []) and (type(d['scope']) is str), 'CEW_PROVENANCE', 'build fields')
    inputs = d.get('input_hashes')
    need(type(inputs) is dict and 0 < len(inputs) <= 8192, 'CEW_PROVENANCE', 'native inputs')
    from candidate import factory_meter as M
    M.collection(budget, len(inputs), 4096)
    paths = set()
    for name, h in inputs.items():
        need(type(name) is str and type(h) is str and re.fullmatch('[0-9a-f]{64}', h) and Path(name).is_absolute(), 'CEW_PROVENANCE', 'native input record')
        resolved = str(Path(name).resolve())
        need(resolved not in paths, 'CEW_PROVENANCE', 'duplicate native input path')
        paths.add(resolved)
        need(file_hash(name, budget) == h, 'CEW_PROVENANCE', 'native build input changed')
    cpp_inputs = [h for name, h in inputs.items() if Path(name).name == 'scalar_conditions.cpp']
    need(len(cpp_inputs) == 1 and cpp_inputs[0] == file_hash(HERE / 'scalar_conditions.cpp', budget), 'CEW_PROVENANCE', 'actual source input identity')
    need(str(Path(d['compiler']['path']).resolve()) in paths and file_hash(d['compiler']['path'], budget) == COMPILER, 'CEW_PROVENANCE', 'actual compiler input')
    binary = file_hash(p, budget)
    need(binary == d.get('binary', {}).get('sha256'), 'CEW_PROVENANCE', 'oracle binary')
    bound = M.json_bound(inputs, budget)
    budget.charge(work=2 * bound, copied_bytes=2 * bound)
    encoded = canonical(inputs)
    need(len(encoded) <= bound, 'CEW_RESOURCE', 'native input encoding bound')
    return (d, raw, binary, digest(encoded))

def observe_conditions(source, condition_oracle, *, witness, budget):
    ledger(budget)
    require(type(witness) is A.ObservationWitness, 'SCALAR_ORIGINAL_AST')
    report = A.ObservationWitness.report(witness, budget=budget)
    doc, schema_raw = schema(budget)
    source_raw = read(source, 1 << 20, budget)
    require(digest(source_raw) == report['source_sha256'], 'SCALAR_CONDITION_SOURCE')
    build, receipt_raw, binary, inputs = native_identity(condition_oracle, budget)
    with tempfile.TemporaryDirectory(prefix='scalar-condition-', dir=os.environ.get('SCALAR_SCRATCH')) as tmp:
        path = Path(tmp) / 'input.cpp'
        budget.charge(work=len(source_raw), copied_bytes=len(source_raw))
        path.write_bytes(source_raw)
        raw = A.run_native(condition_oracle, path, budget)
    A.R.shape(doc['$defs']['conditionRaw'], raw, doc['$defs'], budget)
    budget.charge(work=32 + 16 * len(raw['functions']), edges=len(raw['functions']), copied_bytes=512 * (len(raw['functions']) + 1))
    base = dict(raw)
    base.pop('warning_count')
    base.pop('cplusplus23')
    base.pop('signed_overflow_behavior')
    base['format'] = 'clang-semantic-observation-raw'
    base['functions'] = []
    conditions = []
    for function in raw['functions']:
        budget.charge(work=8 * len(function), edges=len(function), copied_bytes=128 * (len(function) + 1))
        view = dict(function)
        value = view.pop('conditions')
        base['functions'].append(view)
        conditions.append(dict(declaration=function['declaration'], conditions=value))
    require(A.plain_equal(base, report['raw'], budget), 'SCALAR_CONDITION_ORIGINAL_NAMESPACE')
    out = dict(format='scalar-source-conditions-reference', revision=1, binding='unbound', runtime_authority=False, source_fact_authority=False, executable=False, semantic_admission=False, source_sha256=report['source_sha256'], source_config_sha256=report['config_sha256'], oracle_sha256=binary, build_input_identity=inputs, cplusplus23=raw['cplusplus23'], signed_overflow_behavior=raw['signed_overflow_behavior'], warning_count=raw['warning_count'], functions=conditions)
    A.R.shape(doc['$defs']['conditionReport'], out, doc['$defs'], budget)
    require(read(source, 1 << 20, budget) == source_raw, 'SCALAR_CONDITION_SOURCE_CHANGED')
    require(read(SCHEMA, 1 << 20, budget) == schema_raw, 'SCALAR_SCHEMA_CHANGED')
    after, after_raw, after_binary, after_inputs = native_identity(condition_oracle, budget)
    require(after_raw == receipt_raw and after_binary == binary and (after_inputs == inputs), 'SCALAR_CONDITION_NATIVE_CHANGED')
    A.ObservationWitness.report(witness, budget=budget)
    A.precharge_copy(out, budget)
    value = ConditionWitness(A.R.freeze(out), witness, budget)
    budget.charge(work=8 * (len(_ISSUED) + 1) ** 2, edges=2, copied_bytes=128)
    _ISSUED[value] = (value.data, witness, budget)
    return value
