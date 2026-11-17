"""Original-v3 compiler context reference; never execution admission."""
from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import importlib.util
import sys
import weakref
from common import require

ROOT = Path(__file__).resolve().parents[4]
_BUDGETS = weakref.WeakKeyDictionary()


def _package(name, directory):
    loaded = sys.modules.get(name)
    expected = (directory / '__init__.py').resolve()
    if loaded is not None:
        require(getattr(loaded, '__file__', None) is not None and
                Path(loaded.__file__).resolve() == expected, 'V3_IMPORT_CONTEXT')
        return loaded
    spec = importlib.util.spec_from_file_location(name, expected,
                                                submodule_search_locations=[str(directory)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def codec():
    return _package('_rax_smir_root3_context_carrier',
                    ROOT / 'tools/smir-runtime-contract/source_carrier')


def source_contracts():
    return _package('source_contracts', ROOT / 'tools/smir-runtime-contract/source_contracts')


def module_digest(payloads):
    from .context import ROOT_NAMES
    require(len(payloads[2]) >= 36, 'V3_MANIFEST')
    normalized = payloads[2][:4] + bytes(32) + payloads[2][36:]
    digest = hashlib.sha256(b'SMIR0.2\0' + (2).to_bytes(4, 'little'))
    for section in ROOT_NAMES:
        raw = normalized if section == 2 else payloads[section]
        digest.update(section.to_bytes(2, 'little'))
        digest.update(len(raw).to_bytes(8, 'little'))
        digest.update(raw)
    return digest.hexdigest()


def canonical_budget(budget):
    from .source_data_projection import source_api
    require(type(budget) is source_api().SourceQueryBudget, 'V3_BUDGET_CLASS')
    return budget


def bind(owner, budget):
    _BUDGETS[owner] = canonical_budget(budget)


def owner_budget(owner, budget=None):
    original = _BUDGETS.get(owner)
    require(original is not None and (budget is None or budget is original),
            'V3_CONSTRUCTION_BUDGET')
    return original


def record_name(context, section):
    from .context import ROOT_NAMES
    if section == 3:
        revision = context.sections[3]['payload_revision']
        require(type(revision) is int and revision in (2, 3), 'V3_REVISION')
        if revision == 3:
            return 'execution_functions_v3'
    return ROOT_NAMES[section]


def root_hashes(roots, budget):
    from .context import ROOT_NAMES
    canonical_budget(budget)
    require(type(roots) is dict and set(roots) == set(ROOT_NAMES), 'V3_ROOTS')
    ordered = codec().OrderedCodec(budget, codec().Limits(
        max_bytes=1024 * 1024, max_nodes=1000000, max_list=256,
        max_string=256, max_depth=64))
    payloads, nodes = {}, 0
    for section, name in ROOT_NAMES.items():
        selected = 'execution_functions_v3' if section == 3 else name
        payloads[section] = ordered.encode(selected, roots[section])
        nodes += ordered.nodes
    size = sum(map(len, payloads.values()))
    from .root3_profile import metrics
    metrics(roots, size, budget)
    budget.charge(work=8 * size + 8 * nodes, copied_bytes=8 * size + 128 * nodes)
    codec().raw_contract(roots[3]['source_contract'], budget=budget)
    from . import factory_meter as M
    M.json_bound(roots[3], budget)
    require(codec().decode_root3(payloads[3], budget=budget) == roots[3], 'V3_ROOT3_ROUNDTRIP')
    require(roots[2]['manifest']['identity'] == module_digest(payloads),
            'V3_IDENTITY')
    return {section: hashlib.sha256(raw).digest() for section, raw in payloads.items()}


def schema(base_frozen, base_digest, budget):
    from . import source_data_projection as P
    ordered = codec().OrderedCodec(budget)
    P._audit_schema(ordered.records, budget)
    frozen = P._freeze_json(ordered.records, P._hash(budget), budget)
    for name, record in base_frozen.items():
        require(name in frozen and P._schema_equal(record, frozen[name], budget),
                'V3_BASE_SCHEMA_CHANGED')
    raw = ROOT / 'docs/specifications/smir/portable/schema/runtime/source_carrier_records.json'
    size = raw.stat().st_size
    budget.charge(work=4 * (size + 1), copied_bytes=4 * (size + 1))
    with raw.open('rb') as stream:
        data = stream.read(size + 1)
    require(len(data) == size, 'V3_SCHEMA_CHANGED')
    digest = hashlib.sha256(data).digest()
    require(digest.hex() == 'c64512a81e9716f1870e77c266d9de8aebf2b6ee7779f5dd44fb33a9aa8f9cb0',
            'V3_SCHEMA_IDENTITY')
    return frozen, hashlib.sha256(b'SMIR_SOURCE_ROOT3_V3\0' + base_digest + digest).digest()


def no_observer(functions_root, budget):
    for function in functions_root['functions']:
        budget.charge(work=4 * len(function['blocks']))
        for block in function['blocks']:
            budget.charge(work=4 * len(block['ops']))
            require(all(op['op'] != 'source_journal_observe' for op in block['ops']),
                    'V3_OBSERVER_SEMANTICS_UNAVAILABLE')


@dataclass(frozen=True)
class V3BodyChecks:
    owner: object
    stamp: object
    verified: object
    deferred: tuple
    observers: tuple = ()
    binding: str = field(default='original_v3_body_only', init=False)
    executable: bool = field(default=False, init=False)
    semantic_admission: bool = field(default=False, init=False)
    active_v3_verified: bool = field(default=False, init=False)


def require_abi(owner):
    from .context import source_registry_api
    receipt = source_registry_api()._receipt(owner)
    graph = getattr(owner, 'abi_graph', None)
    require(owner.abi_checked is True and receipt['abi'] is not None and
            receipt['abi']() is graph, 'V3_GENUINE_ABI_REQUIRED')


def reserve_factory(owner, budget):
    """Recheck finite profile before actual factories on the original ledger."""
    owner_budget(owner, budget)
    from .root3_profile import metrics
    ordered = codec().OrderedCodec(budget, codec().Limits(
        max_bytes=1024 * 1024, max_nodes=1000000, max_list=256,
        max_string=256, max_depth=64))
    size = 0
    for section in sorted(owner.sections):
        size += len(ordered.encode(record_name(owner, section), owner.sections[section]))
    summary = metrics(owner.sections, size, budget)
    return summary
