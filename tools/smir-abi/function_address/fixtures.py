"""Source-authored ABI3 declarations; only real verifiers can admit these data."""

from copy import deepcopy
import json
from pathlib import Path

from nominal import NominalGraph, ZERO, ref, some


ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'docs/specifications/smir/portable/conformance/execution/candidate/portable-identity.json'


def layout(identifier, size, align, fields=()):
    return dict(id=identifier, type=ref(identifier), size=size, align=align, data_size=size,
                nonvirtual_size=size, nonvirtual_align=align, fields=list(fields), bases=[], vptrs=[])


def source(identifier, kind, *, elements=(), extent=None, bits=0, execution=None,
           layout_id=None, representation='none', flags=(), entity=None):
    return dict(id=identifier, domain=0,
        identity=dict(language='cpp23', linkage='external' if kind == 'record' else 'builtin',
                      entity=entity or kind, definition=ZERO, library=None, unit=None),
        kind=kind, qualifiers=[], bits=bits, signed=False, elements=[ref(i) for i in elements],
        extent=None if extent is None else some(extent), representation=representation,
        execution=None if execution is None else some(ref(execution)),
        layout=None if layout_id is None else some(layout_id), flags=sorted(flags), methods=[],
        enumerators=[], record_input=None)


def seal(roots):
    expectations = {}
    for dependency in roots[2]['manifest']['dependencies']:
        for declaration in dependency['declarations']:
            if declaration['kind'] == 'nominal' and declaration['nominal'] is not None:
                expectations[dependency['slot'], declaration['id']] = declaration['nominal']['some']['id']
    graph = NominalGraph(roots[10], 'authored', nominal_expectations={'authored': expectations})
    for typ in roots[10]['types']:
        typ['identity']['definition'] = graph.fingerprint(ref(typ['id'])) if 'complete' in typ['flags'] else ZERO
    for table in ('types', 'layouts', 'signatures', 'storage_bindings'):
        roots[10][table].sort(key=lambda row: row['id'])
    roots[1]['types'].sort(key=lambda row: row['id'])
    return roots


def ordinary(*, complete_record=False, count=3, noexcept=False, nested_noexcept=False):
    roots = {int(k): v for k, v in json.loads(BASE.read_text())['sections'].items()}
    # Explicit source-author whole-module roots, never decoder-inserted fields.
    for key, value in {5: dict(payload_revision=2, relocations=[], constant_initializers=[]),
                       7: dict(payload_revision=1, segments=[]),
                       9: dict(payload_revision=1, capabilities=[], requirements=[], limits=[])}.items():
        roots.setdefault(key, value)
    roots[1]['types'] += [dict(id=1000, kind='code_address'), dict(id=1001, kind='function',
        cc='portable', variadic=False, params=[ref(1000)], results=[ref(1000)],
        param_noundef=[True], result_noundef=[True])]
    complete = ['complete', 'trivial_copy', 'trivial_destroy']
    prototype_flags = ['complete'] + (['noexcept'] if nested_noexcept else [])
    roots[10]['types'] += [
        source(100, 'record', entity='example.R'),
        source(101, 'array', elements=[100], extent=count),
        source(102, 'pointer', elements=[101], bits=64, execution=1002,
               layout_id=102, representation='value', flags=complete),
        source(103, 'function', elements=[102, 102], extent=1, flags=prototype_flags),
        source(104, 'pointer', elements=[103], bits=64, execution=1000,
               layout_id=104, representation='code_address', flags=complete + ['code']),
        source(105, 'function', elements=[104, 104], extent=1, execution=1001,
               representation='signature', flags=['complete'] + (['noexcept'] if noexcept else [])),
        source(106, 'function', elements=[100, 100], extent=1, flags=['complete']),
        source(107, 'pointer', elements=[106], bits=64, execution=1000,
               layout_id=107, representation='code_address', flags=complete + ['code']),
    ]
    roots[1]['types'].append(dict(id=1002, kind='data_ptr', space='guest_data'))
    roots[10]['layouts'] += [layout(i, 8, 8) for i in (102, 104, 107)]
    roots[10]['signatures'].append(dict(id=201, function_type=ref(105), params=[ref(104)],
        result=some(ref(104)), this_type=None, vtt=False, variadic=False, noexcept=noexcept,
        lowered_params=[dict(source_index=some(0), role='parameter', source_type=ref(104),
            value_type=ref(104), mode='direct', align=8, bytes=8, noundef=True,
            copy=None, move=None, destroy=None)], lowered_results=[ref(104)], varargs=None,
        return_noundef=True, execution=ref(1001)))
    if complete_record:
        record = next(t for t in roots[10]['types'] if t['id'] == 100)
        record.update(flags=complete, layout=some(100), execution=some(ref(1010)), representation='storage',
            record_input=some(dict(revision=1, kind='struct', explicit_align=None, pod03=True,
                trivial=True, standard_layout=True, polymorphic=False, dynamic=False, empty=False,
                fields=[dict(name=some('value'), type=ref(1), bit_width=None, explicit_align=None,
                             no_unique_address=False, anonymous=False, access='public')], bases=[])))
        array = next(t for t in roots[10]['types'] if t['id'] == 101)
        array.update(flags=complete, layout=some(101), execution=some(ref(1011)), representation='value')
        roots[1]['types'] += [dict(id=1010, kind='raw', bits=32),
                             dict(id=1011, kind='array', element=ref(1010), count=count)]
        roots[10]['layouts'] += [layout(100, 4, 4, [dict(declaration_index=0, name='value', type=ref(1),
                                                       offset_bits=0, width_bits=32, flags=[])]),
                                 layout(101, 4 * count, 4)]
    return seal(roots)


def dependency_plan(roots):
    roots = deepcopy(roots)
    roots[2]['manifest']['dependencies'] = [dict(slot=7,
        key=dict(namespace='example', name='provider', abi_major=1, abi_minor=0),
        minimum_minor=0, maximum_minor=None, site=roots[10]['identity'], declarations=[dict(
            id=201, kind='function', symbol_kind='none', source_linkage='none', namespace='example',
            name='expected', execution=some(ref(1001)), nominal=None, abi_signature=some(ref(201)), weak=False)])]
    return roots, ref(201, 7)


def source_only():
    """Only existing scalar call plus reachable noncall address declarations."""
    roots = ordinary()
    roots[10]['types'] = [t for t in roots[10]['types'] if t['id'] != 105]
    roots[10]['signatures'] = [s for s in roots[10]['signatures'] if s['id'] != 201]
    roots[1]['types'] = [t for t in roots[1]['types'] if t['id'] != 1001]
    for key, value in {5: dict(payload_revision=2, relocations=[], constant_initializers=[]),
                       7: dict(payload_revision=1, segments=[]),
                       9: dict(payload_revision=1, capabilities=[], requirements=[], limits=[])}.items():
        roots.setdefault(key, value)
    return seal(roots)


def variadic():
    """Authored closed execution plan plus canonical source va_state storage."""
    from source_roles.builder import build_builtin_states, SOURCE_KEYS, EXECUTION_KEYS
    roots = ordinary()
    parts = build_builtin_states(source_ids=dict(zip(SOURCE_KEYS, range(501, 507))),
        execution_ids=dict(zip(EXECUTION_KEYS, range(5001, 5006))), domain_id=0)
    roots[10]['types'] += parts['types']
    roots[10]['layouts'] += parts['layouts']
    roots[1]['types'] += parts['execution_graph']
    roots[10]['types'] += [source(110, 'void'), source(111, 'pointer', elements=[110],
        bits=64, execution=1002, layout_id=111, representation='value',
        flags=['complete', 'trivial_copy', 'trivial_destroy'])]
    roots[10]['layouts'].append(layout(111, 8, 8))
    next(t for t in roots[10]['types'] if t['id'] == 105)['flags'].append('variadic')
    signature = next(p for p in roots[10]['signatures'] if p['id'] == 201)
    signature.update(variadic=True, varargs=some(dict(state_layout=503, header_bytes=32,
        cookie_scope='thread_activation', table_module=dict(kind='self'),
        type_reference='nominal_declaration_u32')))
    for role, identifier in (('varargs_arena', 111), ('varargs_bytes', 502)):
        signature['lowered_params'].append(dict(source_index=None, role=role,
            source_type=ref(identifier), value_type=ref(identifier), mode='direct',
            align=8, bytes=8, noundef=True, copy=None, move=None, destroy=None))
    execution = next(t for t in roots[1]['types'] if t['id'] == 1001)
    execution.update(params=[ref(1000), ref(1002), ref(5002)], param_noundef=[True] * 3)
    return seal(roots)


def cases():
    before, after = ordinary(), ordinary(complete_record=True)
    return {
        'ordinary': [dict(name='ordinary-self', actual=before, expected=deepcopy(before),
                          actual_plan=ref(201), expected_plan=ref(201), compatible=True),
                     dict(name='pointee-definition-independent', actual=after, expected=before,
                          actual_plan=ref(201), expected_plan=ref(201), compatible=True),
                     dict(name='root-noexcept-weakening', actual=ordinary(noexcept=True), expected=before,
                          actual_plan=ref(201), expected_plan=ref(201), compatible=True)],
        'source-only': [dict(name='incomplete-R-byvalue-prototype-address', roots=source_only(),
                             function=ref(106), pointer=ref(107), has_call_plan=False)],
        'rejections': [dict(name='array-bound-mismatch', actual=ordinary(count=4), expected=before,
                            actual_plan=ref(201), expected_plan=ref(201), compatible=False),
                       dict(name='reverse-noexcept', actual=before, expected=ordinary(noexcept=True),
                            actual_plan=ref(201), expected_plan=ref(201), compatible=False),
                       dict(name='nested-noexcept-exact', actual=ordinary(nested_noexcept=True), expected=before,
                            actual_plan=ref(201), expected_plan=ref(201), compatible=False)],
        'expression-identity': [dict(name='source-definition-completion', before=before, after=after,
                                    equal_nominal_hashes=[102, 103, 104, 105, 106, 107],
                                    different_nominal_hashes=[100, 101])],
    }
