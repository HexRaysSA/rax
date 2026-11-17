"""Independent declared source graphs for accepted INT032/ABI030REV6.

This is a fixture producer, not source AST recovery or an admission certificate.
It writes no files when imported. All IDs are private to these witnesses.
"""
from copy import deepcopy
from pathlib import Path
import sys

EXECUTION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXECUTION))
from candidate_fixtures import declared_abi_source, seal_declared_abi
from candidate.type_system import ref
from test_candidate_context import roots

FLAGS = ['complete', 'trivial_copy', 'trivial_destroy']
STATE, WRAPPER, UINT, ULONG = 3000, 3001, 3002, 3003
STATE_EXEC, WRAPPER_EXEC = 4000, 4001


def base():
    sections = roots()
    sections[5] = dict(payload_revision=1, relocations=[], constant_initializers=[])
    sections[7] = dict(payload_revision=1, segments=[])
    sections[9] = dict(payload_revision=1, capabilities=[], requirements=[], limits=[])
    return sections


def geometry(identifier, size, align, fields=()):
    return dict(id=identifier, type=ref(identifier), size=size, align=align,
                data_size=size, nonvirtual_size=size, nonvirtual_align=align,
                fields=list(fields), bases=[], vptrs=[])


def nominal(identifier, kind, entity, execution, *, bits=0, elements=(), extent=None,
            representation='value', language='c23', flags=FLAGS):
    return dict(id=identifier, domain=0,
                identity=dict(language=language, linkage='builtin', entity=entity,
                              definition='0' * 64, library=None, unit=None),
                kind=kind, qualifiers=[], bits=bits, signed=False,
                elements=list(elements), extent=extent, representation=representation,
                execution={'some': ref(execution)}, layout={'some': identifier},
                flags=list(flags), methods=[], enumerators=[], record_input=None)


def append_nominals(sections, types, layouts):
    if ({t['id'] for t in sections[10]['types']} & {t['id'] for t in types}
            or {t['id'] for t in sections[10]['layouts']} & {t['id'] for t in layouts}):
        raise ValueError('SEM_SOURCE_FIXTURE_ID_COLLISION')
    sections[10]['types'] += types
    sections[10]['layouts'] += layouts
    sections[10]['types'].sort(key=lambda t: t['id'])
    sections[10]['layouts'].sort(key=lambda t: t['id'])
    sections[10] = seal_declared_abi(sections[10])


def builtin_state(sections, family):
    """Return canonical array-one source va_list/jmp_buf nominal qref.

    Uses exact compiler-reserved c23 normalization, not native libc storage or
    ordinary C++ record trait rewriting. Execution storage is Array32<Raw8>.
    """
    if family not in {'va', 'jmp'}:
        raise ValueError('SEM_SOURCE_FIXTURE_FAMILY')
    if {STATE_EXEC, WRAPPER_EXEC} & {t['id'] for t in sections[1]['types']}:
        raise ValueError('SEM_SOURCE_FIXTURE_ID_COLLISION')
    sections[1]['types'] += [dict(id=STATE_EXEC, kind='array', element=ref(9), count=32),
                            dict(id=WRAPPER_EXEC, kind='array', element=ref(STATE_EXEC), count=1)]
    sections[1]['types'].sort(key=lambda t: t['id'])
    uint = nominal(UINT, 'scalar', 'unsigned int', 1, bits=32)
    ulong = nominal(ULONG, 'scalar', 'unsigned long', 5, bits=64)
    declarations = [('area', ULONG, 0, 64), ('cursor', ULONG, 64, 64),
                    ('limit', ULONG, 128, 64), ('cookie', ULONG, 192, 64)] if family == 'va' else [
                    ('revision', UINT, 0, 32), ('reserved', UINT, 32, 32),
                    ('process', ULONG, 64, 64), ('checkpoint', ULONG, 128, 64),
                    ('generation', ULONG, 192, 64)]
    state = nominal(STATE, 'record', 'rax.' + family + '_state', STATE_EXEC,
                    representation='storage')
    state['record_input'] = {'some': dict(revision=1, kind='struct', explicit_align=None,
        pod03=False, trivial=False, standard_layout=False, polymorphic=False,
        dynamic=False, empty=False, bases=[], fields=[
            dict(name={'some': name}, type=ref(typ), bit_width=None,
                 explicit_align=None, no_unique_address=False, anonymous=False,
                 access='public') for name, typ, _, _ in declarations])}
    fields = [dict(declaration_index=i, name=name, type=ref(typ), offset_bits=offset,
                   width_bits=width, flags=[]) for i, (name, typ, offset, width) in enumerate(declarations)]
    wrapper = nominal(WRAPPER, 'array', 'array', WRAPPER_EXEC, elements=[ref(STATE)], extent={'some': 1})
    append_nominals(sections, [state, wrapper, uint, ulong],
                    [geometry(STATE, 32, 8, fields), geometry(WRAPPER, 32, 8),
                     geometry(UINT, 4, 4), geometry(ULONG, 8, 8)])
    return ref(WRAPPER)


def atomic_flag(sections):
    document, _ = declared_abi_source()
    flag = deepcopy(next(t for t in document['types'] if t['kind'] == 'atomic_flag'))
    layout = deepcopy(next(l for l in document['layouts'] if l['id'] == flag['layout']['some']))
    append_nominals(sections, [flag], [layout])
    return ref(flag['id'])


def reference_cell(sections, *, incomplete=False):
    """Explicit portable reference CELL, distinct from sizeof its referent."""
    identifier = 3010
    referent = ref(1)
    extra_types, extra_layouts = [], []
    if incomplete:
        referent = ref(3011)
        item = nominal(3011, 'record', 'example.Incomplete', 3, representation='none', language='cpp23', flags=[])
        item['identity'].update(linkage='external')
        item.update(execution=None, layout=None)
        extra_types.append(item)
    item = nominal(identifier, 'reference', 'reference', 4, bits=64, elements=[referent],
                   flags=sorted(FLAGS + ['lvalue_ref']))
    append_nominals(sections, extra_types + [item], extra_layouts + [geometry(identifier, 8, 8)])
    return ref(identifier)
