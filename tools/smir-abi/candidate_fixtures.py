"""Reproducible full ABI candidate, independent execution/symbol evidence fixtures."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from candidate import Context
from execution_shapes import ExecutionShapes
from nominal import NominalGraph, ZERO, ref, some
from site_config import identity, site_record


def field(name, typ, offset, width, flags=(), declaration_index=0):
    return {'declaration_index': declaration_index, 'name': name, 'type': ref(typ),
            'offset_bits': offset, 'width_bits': width, 'flags': list(flags)}


def declared_field(name, typ, *, bit_width=None, explicit_align=None,
                   no_unique_address=False, anonymous=False, access='public'):
    return {'name': None if name is None else some(name), 'type': ref(typ),
            'bit_width': None if bit_width is None else some(bit_width),
            'explicit_align': None if explicit_align is None else some(explicit_align),
            'no_unique_address': no_unique_address, 'anonymous': anonymous, 'access': access}


def plain_cpp_record(fields, *, explicit_align=None):
    """Known fixture declarations: plain public POD C++ records, no inferred AST."""
    return {'revision': 1, 'kind': 'struct',
            'explicit_align': None if explicit_align is None else some(explicit_align),
            'pod03': True, 'trivial': True, 'standard_layout': True,
            'polymorphic': False, 'dynamic': False, 'empty': not fields,
            'fields': fields, 'bases': []}


def step(identifier, action, inputs, outputs=(), normal=None, **kw):
    result = {'id': identifier, 'action': action, 'inputs': inputs,
              'outputs': [{'id': value, 'type': ref(typ)} for value, typ in outputs],
              'source_type': None, 'target_type': None, 'callee': None, 'adjustment': None,
              'extent': 0, 'align': 1, 'journal_slot': None, 'ticket': identifier,
              'normal': None if normal is None else some(normal), 'unwind': None, 'exception': None}
    result.update(kw)
    return result


def slot(identifier, typ, *, parent=None, count=1, count_source=None, offset=0,
         extent=8, stride=8, role='root', covers=(), destructor=None):
    return {'id': identifier, 'type': ref(typ), 'offset': offset, 'extent': extent,
            'align': min(stride, 8), 'parent': None if parent is None else some(parent),
            'role': role, 'count': count, 'stride': stride,
            'count_source': None if count_source is None else some(count_source),
            'constructor': None, 'destructor': None if destructor is None else some(destructor),
            'destructor_kind': 'none' if destructor is None else 'complete' if covers else 'leaf',
            'covers': list(covers), 'owner': 0, 'dependencies': [], 'child_program': None}


def build(*, all_kinds=False):
    doc = {'payload_revision': 3, 'identity': identity(), 'site': site_record(),
           'types': [], 'layouts': [], 'storage_bindings': [], 'signatures': [], 'domains': [
               {'id': 0, 'isa': 'portable', 'personality': 'portable', 'abi': 'portable',
                'compiler': '1' * 64, 'runtime': '2' * 64, 'build': '3' * 64,
                'library': '4' * 64, 'abi_identity': identity()},
               {'id': 1, 'isa': 'x86_64', 'personality': 'linux', 'abi': 'itanium',
                'compiler': '5' * 64, 'runtime': '6' * 64, 'build': '7' * 64,
                'library': '8' * 64, 'abi_identity': '9' * 64}],
           'recipes': [], 'personalities': [], 'unwind': [], 'catches': [], 'bridges': [], 'journals': []}
    shapes = {}

    def add(name, kind, bits=0, signed=False, elements=(), size=None, align=None,
            fields=(), flags=('complete', 'trivial_copy', 'trivial_destroy'), shape=None,
            representation='value', extent=None, domain=0, record_input=None):
        identifier = len(doc['types'])
        aliases={'size_t':'unsigned long','ptrdiff_t':'long','wint_t':'unsigned int'}
        entity=aliases.get(name,name) if kind=='scalar' else kind if kind in {
            'function','pointer','reference','member_pointer','array','vector','complex','atomic','bitint'} else name
        language='c23' if kind in {'void','pointer','array','vector','complex','atomic','bitint'} or (
            kind=='scalar' and name not in {'wchar_t','char8_t','char16_t','char32_t'}) else 'cpp23'
        record = {'id': identifier, 'domain': domain,
                  'identity': {'language': language, 'linkage': 'builtin' if kind != 'record' else 'external',
                               'entity': entity,
                               'definition': ZERO, 'library': None, 'unit': None},
                  'kind': kind, 'qualifiers': [], 'bits': bits, 'signed': signed,
                  'elements': [ref(child) for child in elements],
                  'extent': None if extent is None else some(extent),
                  'representation': representation, 'execution': None if shape is None else some(ref(identifier)),
                  'layout': None if size is None else some(identifier), 'flags': sorted(flags),
                  'methods': [], 'enumerators': [],
                  'record_input': None if record_input is None else some(record_input)}
        doc['types'].append(record)
        if size is not None:
            doc['layouts'].append({'id': identifier, 'type': ref(identifier), 'size': size, 'align': align,
                                   'data_size': size, 'nonvirtual_size': size, 'nonvirtual_align': align,
                                   'fields': [dict(item, declaration_index=index)
                                              for index, item in enumerate(fields)],
                                   'bases': [], 'vptrs': []})
        if shape is not None:
            shapes[identifier] = dict(shape)
        return identifier

    void = add('void', 'void', representation='none')
    integer = add('int', 'scalar', 32, True, size=4, align=4, shape={'kind': 'int', 'bits': 32})
    char = add('char', 'scalar', 8, True, size=1, align=1, shape={'kind': 'int', 'bits': 8})
    value = add('example.Value', 'record', size=8, align=4,
                fields=[field('a', char, 0, 8), field('b', integer, 32, 32)],
                record_input=plain_cpp_record([declared_field('a', char), declared_field('b', integer)]),
                shape={'kind': 'raw', 'bits': 64}, representation='storage')
    ptr = add('example.Value*', 'pointer', 64, elements=[value], size=8, align=8,
              shape={'kind': 'data_ptr', 'space': 'guest_data'})
    unsigned = add('unsigned long', 'scalar', 64, size=8, align=8, shape={'kind': 'int', 'bits': 64})
    opaque = add('void*', 'pointer', 64, elements=[void], size=8, align=8,
                 shape={'kind': 'data_ptr', 'space': 'guest_data'})
    lease = add('rax.exception_lease', 'handle', 64, size=8, align=8, shape={'kind': 'exception'})
    va = add('rax.va_state', 'record', size=32, align=8,
             fields=[field(name, unsigned, offset * 64, 64) for offset, name in enumerate(['area', 'cursor', 'limit', 'cookie'])],
             record_input=plain_cpp_record([declared_field(name, unsigned)
                                           for name in ['area', 'cursor', 'limit', 'cookie']]),
             shape={'kind': 'raw', 'bits': 256}, representation='storage')
    flag = add('atomic_flag', 'atomic_flag', 1, size=1, align=1,
               shape={'kind': 'raw', 'bits': 8}, representation='storage')
    bitint = add('_BitInt(65)', 'bitint', 65, True, size=16, align=8, shape={'kind': 'int', 'bits': 65})
    atom = add('_Atomic(example.Value)', 'atomic', elements=[value], size=8, align=8,
               shape={'kind': 'raw', 'bits': 64}, representation='storage')

    # Identity assigned independently from source numeric IDs.
    for shape in shapes.values():
        shape['identity'] = hashlib.sha256(json.dumps(shape, sort_keys=True).encode()).hexdigest()

    def function(name, params, result, lowered, *, variadic=False, this=None, vtt=False):
        flags = ['complete'] + (['variadic'] if variadic else [])
        identifier = add(name, 'function', elements=params + [result], flags=flags,
                         shape={'kind': 'function'}, representation='signature', extent=len(params))
        results = [] if result in (void, value) else [result]
        signatures = {'params': [shapes[t]['identity'] for t in lowered], 'cc': 'portable', 'variadic': False,
                      'results': [shapes[t]['identity'] for t in results],
                      'param_noundef': [True] * len(lowered), 'result_noundef': [True] * len(results)}
        shapes[identifier] = {'kind': 'function', **signatures,
                              'identity': hashlib.sha256(json.dumps(signatures, sort_keys=True).encode()).hexdigest()}
        signature = {'id': len(doc['signatures']), 'function_type': ref(identifier),
                     'params': [ref(t) for t in params], 'result': None if result == void else some(ref(result)),
                     'this_type': None if this is None else some(ref(this)), 'vtt': vtt,
                     'variadic': variadic, 'noexcept': False, 'lowered_params': [],
                     'lowered_results': [ref(t) for t in results],
                     'varargs': None if not variadic else some({'state_layout': va, 'header_bytes': 32,
                        'cookie_scope': 'thread_activation', 'table_module': {'kind': 'self'},
                        'type_reference': 'nominal_declaration_u32'}), 'return_noundef': True,
                     'execution': ref(identifier)}
        if this is not None:
            doc['types'][identifier].update(execution=None, representation='none')
        doc['signatures'].append(signature)
        return signature

    def parameter(source, target, role='parameter', index=None, mode='direct'):
        layout = next(layout for layout in doc['layouts'] if layout['id'] == source)
        return {'source_index': None if index is None else some(index), 'role': role,
                'source_type': ref(source), 'value_type': ref(target), 'mode': mode,
                'align': layout['align'], 'bytes': layout['size'], 'noundef': True,
                'copy': None, 'move': None, 'destroy': None}

    simple = function('example.add', [integer], integer, [integer])
    simple['lowered_params'] = [parameter(integer, integer, index=0)]
    aggregate = function('example.copy', [value], value, [ptr, ptr])
    aggregate['lowered_params'] = [parameter(value, ptr, 'sret', mode='sret'),
                                  parameter(value, ptr, index=0, mode='indirect_copy')]
    method = function('example.method', [integer], integer, [ptr, opaque, integer, opaque, unsigned],
                      variadic=True, this=ptr, vtt=True)
    method['lowered_params'] = [parameter(ptr, ptr, 'this'), parameter(opaque, opaque, 'vtt'),
                               parameter(integer, integer, index=0), parameter(opaque, opaque, 'varargs_arena'),
                               parameter(unsigned, unsigned, 'varargs_bytes')]
    recipe = {'id': 0, 'domain': 0, 'params': [{'id': 0, 'type': ref(integer)}],
              'results': [ref(integer)], 'entry': 0, 'steps': [step(0, 'return', [0])]}
    doc['recipes'].append(recipe)
    doc['journals'].append({'id': 0, 'signature': 0, 'params': [], 'slots': [slot(0, value)],
                             'normal_order': [0], 'exception_order': [0]})
    doc['catches'].append({'id': 0, 'thrown': some(ref(integer)), 'caught': some(ref(integer)),
                           'native_caught': None, 'kind': 'exact', 'base_path': [], 'qualification': [],
                           'adjustment': None, 'copy': None, 'destroy': None, 'mode': 'value', 'foreign_adapter': None})
    # Fixed native bridge/personality declarations live in trusted symbol evidence;
    # raw metadata is synthetic here, separately compiler-produced witnesses test source ABI.
    metadata = b'ABI\0normalized-cfi-and-actions'
    native_void = add('void', 'void', domain=1, representation='none')
    native_int = add('int', 'scalar', 32, True, size=4, align=4,
                     domain=1, shape={'kind': 'int', 'bits': 32})
    native_flags = add('unsigned int', 'scalar', 32, False, size=4, align=4,
                       domain=1, shape={'kind': 'int', 'bits': 32})
    native_u64 = add('unsigned long long', 'scalar', 64, False, size=8, align=8,
                     domain=1, shape={'kind': 'int', 'bits': 64})
    native_ptr = add('void*', 'pointer', 64, elements=[native_void], size=8, align=8,
                     domain=1, shape={'kind': 'data_ptr', 'space': 'guest_data'})
    packet = add('rax.BridgeFrame', 'record', size=80, align=16, domain=1,
                 fields=[field(name, native_flags if width == 32 else native_u64, offset, width)
                         for name, offset, width in [
                             ('revision',0,32),('flags',32,32),('signature_ref',64,64),
                             ('arguments_address',128,64),('arguments_bytes',192,64),
                             ('result_address',256,64),('result_bytes',320,64),
                             ('transition_id',384,64),('exception_lease',448,64),
                             ('status',512,32),('reserved_zero',544,32),('continuation_generation',576,64)]],
                 shape={'kind': 'raw', 'bits': 640}, representation='storage')
    frame_ptr = add('rax.BridgeFrame*', 'pointer', 64, elements=[packet], size=8, align=8,
                    domain=1, shape={'kind': 'data_ptr', 'space': 'guest_data'})
    native_bridge = add('bridge_entry', 'function', elements=[frame_ptr, native_void],
                        domain=1, flags=['complete', 'native'], extent=1,
                        representation='none')
    personality_type = add('personality_entry', 'function',
                           elements=[native_int, native_flags, native_u64, native_ptr, native_ptr, native_int],
                           domain=1, flags=['complete', 'native'], extent=5,
                           representation='none')
    symbols = {100: {'kind': 'function', 'signature': ref(native_bridge),
                      'domain': 1, 'code_size': 16, 'native_cc':'sysv_amd64', 'bridge_abi': 'sysv64_frame'},
               101: {'kind': 'function', 'signature': ref(personality_type), 'domain': 1,
                     'native_cc':'sysv_amd64','bridge_abi':'none','code_size': 16}}
    doc['personalities'].append({'id': 0, 'domain': 1, 'flavor': 'guest_itanium_dwarf', 'entry': ref(101),
                                 'signature': symbols[101]['signature'],
                                 'flags': ['search_readonly', 'cleanup_calls', 'forced_unwind','cross_domain_translation']})
    doc['unwind'].append({'id': 0, 'function': ref(100), 'domain': 1, 'code_size': 16,
                          'source_format': 'dwarf_cfi_lsda', 'metadata': [
                              {'symbol': ref(103), 'offset': 0, 'bytes': len(metadata),
                               'digest': hashlib.sha256(metadata).hexdigest(), 'encoding': 'fixture_normalized'}],
                          'personality': 0, 'rows': [{'start': 0, 'end': 16,
                              'cfa': {'base': 'sp', 'reg': 0, 'offset': 8},
                              'return_rule': {'kind': 'cfa_offset', 'offset': -8, 'width': 8}, 'registers': []}],
                          'actions': [{'id': 0, 'kind': 'catch', 'recipe': None, 'catch': some(0), 'next': None}],
                          'regions': [{'start': 0, 'end': 16, 'landing_pad': None, 'landing_offset': 8, 'actions': [0], 'scope': 0}]})
    doc['bridges'].append({'id': 0, 'source': 0, 'target': 1, 'signature': 0, 'entry': ref(100),
                           'personality': 0, 'unwind': 0, 'arguments': 0, 'result': some(0),
                           'construction': 0, 'callbacks': 'owner_thread', 'exceptions': 'mapped',
                           'ownership': 'borrowed', 'identity': 'proxy', 'aliases': 'exclusive'})
    memory_layouts = {}
    def memory_layout(identifier, typ, size, alignment, access, fields=()):
        memory_layouts[str(identifier)] = {'id': identifier, 'type': ref(typ), 'size': size,
            'alignment': alignment, 'access_bytes': access, 'fields': list(fields), 'element': None, 'stride': 0}
    memory_layout(0, integer, 4, 4, 4)
    memory_layout(1, value, 8, 4, 8)
    memory_layout(2, bitint, 16, 8, 9)
    memory_layout(3, 200, 8, 4, 8, fields=[
        {'value_index':0,'bit_offset':0,'bit_width':8,'layout':ref(4)},
        {'value_index':1,'bit_offset':32,'bit_width':32,'layout':ref(0)}])
    memory_layout(4, char, 1, 1, 1)
    def fragment(path, src, dst, width, role='value'):
        return {'source_path':path,'source_offset_bits':src,'execution_offset_bits':dst,
                'width_bits':width,'role':role}
    record_fragments=[fragment(['a'],0,0,8),fragment([],8,8,24,'padding'),fragment(['b'],32,32,32)]
    for identifier, nominal, physical, size, align, access, kind, fragments in [
        (0,integer,0,32,4,4,'object_bytes',[fragment([],0,0,32)]),
        (1,value,1,64,4,8,'object_bytes',record_fragments),
        (2,bitint,2,128,8,9,'object_bytes',[fragment([],0,0,65),fragment([],65,65,63,'padding')]),
        (3,value,3,64,4,8,'fieldwise',record_fragments)]:
        doc['storage_bindings'].append({'id':identifier,'nominal':ref(nominal),
            'execution_layout':ref(physical),'kind':kind,'view_offset_bits':0,'view_width_bits':size,
            'required_alignment':align,'access_bytes':access,'fragments':deepcopy(fragments)})
    if all_kinds:
        from layout import SCALARS, INTEGER_NAMES
        signed_names={'char','signed char','short','int','wchar_t','long','long long','ptrdiff_t','__int128'}
        for name,(size,align) in SCALARS.items():
            if name not in INTEGER_NAMES | {'float','double','long double'}:
                continue
            bits=1 if name=='bool' else size*8
            shape={'kind':'float','format':{4:'binary32',8:'binary64',16:'binary128'}[size]} if name in {
                'float','double','long double'} else {'kind':'int','bits':bits}
            add(name,'scalar',bits,name in signed_names,size=size,align=align,shape=shape)
        fp=add('double','scalar',64,size=8,align=8,shape={'kind':'float','format':'binary64'})
        add('example.array','array',elements=[integer],extent=3,size=12,align=4,
            shape={'kind':'array','count':3,'element':ref(integer)})
        add('example.vector3','vector',elements=[integer],extent=3,size=16,align=16,
            shape={'kind':'vector','count':3,'element':ref(integer)})
        add('example.complex','complex',elements=[fp],size=16,align=8,
            shape={'kind':'struct','fields':[ref(fp),ref(fp)]})
        enum=add('example.Enum','enum',32,True,elements=[integer],size=4,align=4,
            shape={'kind':'int','bits':32})
        doc['types'][enum]['enumerators']=[{'name':'minus_one','value':'ffffffff'},{'name':'zero','value':'00000000'}]
        add('example.EmptyEnum','enum',32,True,elements=[integer],size=4,align=4,
            shape={'kind':'int','bits':32})
        add('example.Value::*','member_pointer',64,False,elements=[value,integer],size=8,align=8,
            shape={'kind':'int','bits':64})
        add('example.Value::method*','member_pointer',128,False,elements=[value,12],size=16,align=8,
            shape={'kind':'struct','fields':[ref(unsigned),ref(unsigned)]})
        add('example.Value&','reference',64,elements=[value],size=8,align=8,
            flags=['complete','trivial_copy','trivial_destroy','lvalue_ref'],
            shape={'kind':'data_ptr','space':'guest_data'})
        add('example.function*','pointer',64,elements=[12],size=8,align=8,
            flags=['complete','trivial_copy','trivial_destroy','code'],
            shape={'kind':'code_address'}, representation='code_address')
        add('rax.fenv_snapshot','snapshot',256,size=32,align=8,shape={'kind':'fenv'})
        add('rax.construction_journal','handle',64,size=8,align=8,shape={'kind':'journal'})
        add('rax.stack_checkpoint','handle',64,size=8,align=8,shape={'kind':'stack_mark'})
    seal(doc)
    for shape in shapes.values():
        if 'identity' not in shape:
            shape['identity'] = hashlib.sha256(json.dumps(shape, sort_keys=True).encode()).hexdigest()
    inverse = {shape['identity']: key for key, shape in shapes.items()}
    execution_graph=[]
    for identifier, shape in shapes.items():
        raw={name:deepcopy(value) for name,value in shape.items() if name!='identity'}
        if raw['kind']=='function':
            raw['params']=[ref(inverse[value]) for value in raw['params']]
            raw['results']=[ref(inverse[value]) for value in raw['results']]
        execution_graph.append({'id':identifier,**raw})
    execution_graph.append({'id':200,'kind':'struct','fields':[ref(char),ref(integer)]})
    normalized=ExecutionShapes(execution_graph)
    evidence = {'execution': {str(item['id']): normalized.describe(ref(item['id'])) for item in execution_graph},
                'execution_graph':execution_graph, 'memory_layouts':memory_layouts,
                'symbols': {str(key): value for key, value in symbols.items()},
                'metadata': {'103': metadata.hex()},
                'native_types': {str(t['id']): deepcopy(t) for t in doc['types'] if t['domain'] == 1},
                'native_domains':{str(d['id']):deepcopy(d) for d in doc['domains'] if d['isa']!='portable'},
                'native_personalities':{str(p['id']):deepcopy(p) for p in doc['personalities']},
                'native_layouts':{str(t['id']):deepcopy(next(l for l in doc['layouts'] if l['id']==t['layout']['some']))
                                  for t in doc['types'] if t['domain']==1 and t['layout'] is not None},
                'native_unwind': {'100': deepcopy(doc['unwind'][0])}}
    return doc, evidence


def seal(document):
    graph = NominalGraph(document, 'main')
    for typ in document['types']:
        typ['identity']['definition'] = graph.fingerprint(ref(typ['id'])) if 'complete' in typ['flags'] else ZERO
    return document


def portable_identity_abi():
    """ABI2 scalar identity fixture, generated from declared source facts.

    This returns source metadata only. Numeric fixture IDs are not admission
    policy; execution/runtime roots and real same-context verification remain
    mandatory. No missing ABI1 input is inferred from selected output geometry.
    """
    document, _ = build()
    document['types'] = [item for item in document['types'] if item['id'] in (1, 12)]
    document['layouts'] = [item for item in document['layouts'] if item['id'] == 1]
    document['signatures'] = [item for item in document['signatures'] if item['id'] == 0]
    document['domains'] = [item for item in document['domains'] if item['isa'] == 'portable']
    for table in ('storage_bindings', 'recipes', 'personalities', 'unwind',
                  'catches', 'bridges', 'journals'):
        document[table] = []
    return seal(document)


def native_profile(isa='x86_64', personality='windows', abi='itanium'):
    """Synthetic profile facts; not certification of a native compiler/image."""
    document, evidence = build()
    domain = document['domains'][1]
    domain.update(isa=isa, personality=personality, abi=abi)
    cc = 'win64' if isa == 'x86_64' else 'aapcs64_windows'
    for symbol in evidence['symbols'].values():
        if symbol['domain'] == 1:
            symbol['native_cc'] = cc
            if symbol['bridge_abi'] != 'none':
                symbol['bridge_abi'] = 'win64_frame' if isa == 'x86_64' else 'aapcs64_frame'
    binding = document['personalities'][0]
    binding['flavor'] = 'guest_itanium_seh' if abi == 'itanium' else 'guest_msvc_seh4'
    signature = next(item for item in document['types'] if item['id'] == binding['signature']['id'])
    pointer = signature['elements'][-2]
    signature.update(elements=[deepcopy(pointer) for _ in range(4)] + [signature['elements'][-1]], extent=some(4))
    document['unwind'][0]['source_format'] = 'windows_x64_unwind' if isa == 'x86_64' else 'windows_arm64_unwind'
    seal(document)
    evidence['native_domains'] = {'1': deepcopy(domain)}
    evidence['native_types'] = {str(item['id']): deepcopy(item) for item in document['types'] if item['domain'] == 1}
    evidence['native_personalities'] = {'0': deepcopy(binding)}
    evidence['native_unwind'] = {'100': deepcopy(document['unwind'][0])}
    return document, evidence


def context(document, evidence, *, modules=None, bindings=None, module='main'):
    shapes=ExecutionShapes(evidence['execution_graph'])
    def get(table, reference):
        require_self = reference['module']['kind'] == 'self'
        if not require_self:
            raise ValueError('fixture context external execution/symbol requires admitted importer adapter')
        return deepcopy(evidence[table][str(reference['id'])])
    return Context(module, lambda reference: shapes.describe(reference),
                   lambda reference: get('symbols', reference),
                   lambda reference: bytes.fromhex(get('metadata', reference)),
                   modules or {}, bindings or {}, lambda reference: get('native_types', reference),
                   lambda reference: get('native_unwind', reference), {module: ('example', 'main', 1)},
                   lambda reference: get('memory_layouts', reference),
                   native_domains={int(key):value for key,value in evidence['native_domains'].items()},
                   native_layout=lambda reference:get('native_layouts',reference),
                   native_personality=lambda reference:get('native_personalities',reference))


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2] / 'docs/specifications/smir/portable/conformance/abi/candidate'
    root.mkdir(parents=True, exist_ok=True)
    doc, evidence = build()
    (root / 'complete.json').write_text(json.dumps(doc, indent=2) + '\n')
    (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
