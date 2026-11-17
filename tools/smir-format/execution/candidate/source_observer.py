"""Closed original-v3 observer typing and coordinates; no Journal issuer."""
from dataclasses import dataclass
from common import require
from . import factory_meter as M
from .type_system import Types


@dataclass(frozen=True)
class V3ObserverSite:
    function: int
    block: int
    index: int
    result: int
    result_type: int
    scope_value: int
    adoption: int


def _u32(value, *, source=False):
    return type(value) is int and 0 <= value <= (0xfffffffe if source else 0xffffffff)


def _shape(operation, budget):
    M.check(budget)
    require(budget is not None, 'V3_OBSERVER_TYPE_CONTEXT')
    require(type(operation) is dict, 'V3_OBSERVER_SHAPE')
    M.body_node(operation, budget)
    require(set(operation) ==
            {'op','results','operands','scope_value','adoption'} and
            operation['op'] == 'source_journal_observe', 'V3_OBSERVER_SHAPE')
    require(type(operation['operands']) is list and not operation['operands'] and
            type(operation['results']) is list and len(operation['results']) == 1,
            'V3_OBSERVER_ARITY')
    declaration = operation['results'][0]
    require(type(declaration) is dict and set(declaration) == {'id','type'} and
            _u32(declaration['id']), 'V3_OBSERVER_RESULT')
    reference = declaration['type']
    require(type(reference) is dict and set(reference) == {'module','id'} and
            type(reference['module']) is dict and reference['module'] == {'kind':'self'} and
            _u32(reference['id']), 'V3_OBSERVER_RESULT_TYPE')
    require(_u32(operation['scope_value'], source=True) and
            _u32(operation['adoption'], source=True), 'V3_OBSERVER_SOURCE_ID')
    return declaration, reference


def check(operation, types, *, budget):
    """Actual Types predicate; source namespaces/lineage belong to pass2."""
    declaration, reference = _shape(operation, budget)
    require(type(types) is Types and types._factory_budget is budget,
            'V3_OBSERVER_TYPE_CONTEXT')
    require(types.get(reference)['kind'] == 'journal', 'V3_OBSERVER_RESULT_TYPE')


def collect(functions_root, *, budget):
    """Coordinates from the complete actually verified v3 root, encoded order."""
    M.check(budget)
    require(budget is not None and type(functions_root) is dict and
            set(functions_root) == {'payload_revision','functions','source_contract'} and
            type(functions_root.get('payload_revision')) is int and
            functions_root['payload_revision'] == 3 and
            type(functions_root['functions']) is list and
            type(functions_root['source_contract']) is dict, 'V3_OBSERVER_TYPE_CONTEXT')
    M.json_bound(functions_root, budget)
    result = []
    for function in M.iter_rows(budget, functions_root['functions']):
        require(_u32(function['id'], source=True), 'V3_OBSERVER_FUNCTION')
        for block in M.iter_rows(budget, function['blocks']):
            require(_u32(block['id']), 'V3_OBSERVER_BLOCK')
            for index, operation in M.iter_rows(budget, enumerate(block['ops'])):
                if operation['op'] != 'source_journal_observe':
                    continue
                declaration, reference = _shape(operation, budget)
                M.charge(budget, work=64, edges=7, copied_bytes=256)
                result.append(V3ObserverSite(function['id'], block['id'], index,
                    declaration['id'], reference['id'], operation['scope_value'], operation['adoption']))
    M.charge(budget, work=len(result)+1, copied_bytes=64+8*len(result))
    return tuple(result)
