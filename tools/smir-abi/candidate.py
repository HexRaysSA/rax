"""Semantic ABI section verifier, with explicit cross-section resolution hooks."""

from dataclasses import dataclass
from copy import deepcopy
import hashlib
import importlib.util
import importlib
from pathlib import Path
import sys

from candidate_codec import decode, encode
from construction import verify_program
from layout import ABIError, INTEGER_NAMES, MAX_OBJECT, SCALARS, align_up, alignment, require
from nominal import NominalGraph, ZERO, classify, option, unique
import factory_meter as M
from site_config import identity as site_identity, site_record

KINDS = {'void', 'scalar', 'bitint', 'enum', 'pointer', 'reference', 'member_pointer',
         'array', 'vector', 'complex', 'record', 'atomic', 'function', 'handle', 'atomic_flag', 'snapshot'}
FLAGS = {'complete', 'union', 'class', 'trivial_copy', 'trivial_destroy', 'polymorphic',
         'noexcept', 'variadic', 'nonnull', 'code', 'signed_char', 'flexible', 'native', 'scoped', 'fixed_base',
         'c_linkage', 'c_compatible', 'lvalue_ref', 'rvalue_ref'}
HANDLES = {'rax.exception_lease': 'exception', 'rax.construction_journal': 'journal',
           'rax.stack_checkpoint': 'stack_mark'}


@dataclass
class Context:
    """Resolvers run after cross-section graph/dependency declarations are admitted.

    execution(ref)->{kind,bits?,format?,space?,fields?}; symbol(ref)->{kind,
    signature,domain,...}; metadata(ref)->immutable bytes. Each ref is interpreted
    in this module's self/dependency declaration namespace. No defaults or host
    pointer fallback. Foreign metadata digest/ranges are checked against bytes.
    """
    module: str
    execution: object
    symbol: object
    metadata: object
    modules: dict
    bindings: dict
    native_type: object
    native_unwind: object
    families: dict
    memory_layout: object
    native_domains: dict = None
    native_layout: object = None
    native_personality: object = None
    # S-PROD014REV2: explicit prepared source context; no eager/default ledger.
    # Keep this callback outside the legacy bytes/dict resolver wrappers so its
    # exact SourceDataError kind/code and actual immutable views pass unchanged.
    source_data: object = None
    source_stamp: object = None
    source_budget: object = None
    # Actual consumer declaration expectations, separate from provider selection.
    nominal_expectations: object = None
    factory_budget: object = None

    def __post_init__(self):
        M.check_budget(self.factory_budget)
        if self.factory_budget is not None:
            require(not self.modules and not self.bindings and not self.native_domains,'ABI_FACTORY_COST_UNAVAILABLE')
        M.copy_cost(self.native_domains or {},self.factory_budget)
        self.native_domains=deepcopy(self.native_domains or {})
        for name in ('execution', 'symbol', 'metadata', 'native_type', 'native_unwind', 'memory_layout', 'native_layout',
                     'native_personality'):
            callback = getattr(self, name)

            def checked(reference, callback=callback, name=name):
                M.copy_cost(reference,self.factory_budget)
                try:
                    value = callback(reference)
                except (KeyError, IndexError, TypeError, OSError) as error:
                    raise ABIError('ABI_CC_' + name.upper() + '_EVIDENCE') from error
                if self.factory_budget is not None and isinstance(value,bytes if name=='metadata'else dict):
                    if name=='metadata':M.charge(self.factory_budget,work=len(value),copied_bytes=len(value))
                    else:M.copy_cost(value,self.factory_budget)
                require(isinstance(value, bytes if name == 'metadata' else dict),
                        'ABI_CC_' + name.upper() + '_EVIDENCE')
                if name == 'symbol':
                    require({'kind', 'signature', 'domain'} <= value.keys(), 'ABI_CC_SYMBOL_EVIDENCE')
                if name == 'execution':
                    require('kind' in value and isinstance(value.get('identity'), str) and
                            len(value['identity']) == 64 and all(c in '0123456789abcdef' for c in value['identity']),
                            'ABI_CC_EXECUTION_EVIDENCE')
                return value
            setattr(self, name, checked)


def _owner_package(name, directory, child):
    """Unique tool namespace: ABI/R/LLVM source_roles names must not collide."""
    path = Path(__file__).resolve().parent / directory
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path / '__init__.py',
                                                      submodule_search_locations=[str(path)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    require(Path(sys.modules[name].__file__).resolve() == (path / '__init__.py').resolve(),
            'ABI_CC_REFERENCE_MODULE_SCOPE')
    return importlib.import_module(name + '.' + child)


def verify(document, context):
    M.copy_cost(document,context.factory_budget)
    M.flat_profile(document,context.factory_budget)
    # Canonical shape enforcement also excludes implicit options/unknown keys.
    M.copy_cost(document,context.factory_budget)
    encoded_contract=encode('abi_contract',document)
    M.charge(context.factory_budget,work=len(encoded_contract),copied_bytes=len(encoded_contract))
    M.copy_cost(document,context.factory_budget)
    require(decode('abi_contract',encoded_contract)==document,'ABI_CC_CANONICAL')
    require(document['payload_revision'] == 3, 'ABI_CC_REVISION')
    from site_config import original_profile
    source_revision = original_profile(document, budget=context.factory_budget)
    if source_revision == 2:
        from record_layout.materialization import _api
        M.charge(context.factory_budget,work=1,copied_bytes=128)
        raise _api().SourceDataError('unavailable', 'ABI_CC_SOURCE_BYTE_EVIDENCE_UNAVAILABLE', 'genuine original source-category evidence not issued')
    graph = NominalGraph(document, context.module, context.modules, context.bindings, context.families,
                         nominal_expectations=context.nominal_expectations,budget=context.factory_budget)
    types = graph.tables[context.module]
    layouts = graph.layouts[context.module]
    tables = {name: unique(document[name], name.upper()) for name in
              ('signatures', 'domains', 'recipes', 'personalities', 'unwind', 'catches', 'bridges', 'journals')}

    def local(reference):
        module, item = graph.resolve(reference)
        require(module == context.module, 'ABI_CC_LOCAL_TYPE')
        return item

    for item in types.values():
        M.row(item,context.factory_budget)
        require(item['domain'] in tables['domains'], 'ABI_CC_TYPE_DOMAIN')
        require(item['kind'] in KINDS and set(item['flags']) <= FLAGS and
                len(item['flags']) == len(set(item['flags'])), 'ABI_CC_TYPE_KIND')
        reference_flags = set(item['flags']) & {'lvalue_ref', 'rvalue_ref'}
        require(len(reference_flags) == 1 if item['kind'] == 'reference' else
                len(reference_flags) <= 1 if item['kind'] == 'function' else not reference_flags,
                'ABI_CC_REFERENCE_CATEGORY')
        require(item['qualifiers'] == sorted(set(item['qualifiers'])) and
                set(item['qualifiers']) <= {'const', 'volatile', 'restrict'}, 'ABI_CC_QUALIFIER')
        source = item['identity']
        require(source['language'] in ('c23', 'cpp23') and
                source['linkage'] in ('builtin', 'external', 'internal', 'local', 'odr_local') and source['entity'],
                'ABI_CC_NOMINAL_IDENTITY')
        if item['kind'] in {'function','pointer','reference','member_pointer','array','vector','complex','atomic','bitint'}:
            require(source['entity']==item['kind'] and source['linkage']=='builtin' and source['unit'] is None,
                    'ABI_CC_CANONICAL_CONSTRUCTOR')
        if 'c_linkage' in item['flags']:
            require(item['kind']=='function' and not reference_flags,'ABI_CC_C_LINKAGE_KIND')
        if 'c_compatible' in item['flags']:
            require(item['kind'] in ('record','enum'),'ABI_CC_C_MIRROR_KIND')
        require((source['unit'] is not None) == (source['linkage'] in ('internal', 'local')),
                'ABI_CC_NOMINAL_UNIT')
        for child in item['elements']:
            graph.resolve(child)
        flag_kinds = {'union': {'record'}, 'class': {'record'}, 'polymorphic': {'record'},
                      'variadic': {'function'}, 'noexcept': {'function'},
                      'code': {'pointer', 'reference'}, 'flexible': {'array'},
                      'scoped': {'enum'}, 'fixed_base': {'enum'}, 'signed_char': {'scalar'}}
        require(all(flag not in item['flags'] or item['kind'] in allowed
                    for flag, allowed in flag_kinds.items()), 'ABI_CC_TYPE_KIND')
        if item['kind'] == 'function':
            children = [graph.resolve(child)[1] for child in item['elements']]
            count = option(item['extent'])
            require(count is not None and len(children) == count + 1 and
                    item['bits'] == 0 and not item['signed'] and
                    all(child['kind'] not in ('void', 'function', 'array') for child in children[:-1]) and
                    children[-1]['kind'] not in ('function', 'array') and
                    not item['enumerators'] and not item['methods'], 'ABI_CC_SOURCE_SIGNATURE')
        if item['kind'] in ('pointer', 'reference'):
            require(len(item['elements']) == 1, 'ABI_CC_TYPE_BINDING')
            pointed = graph.resolve(item['elements'][0])[1]
            require(('code' in item['flags']) == (pointed['kind'] == 'function'),
                    'ABI_CC_CODE_SIGNATURE')
            if pointed['kind'] == 'function':
                require(not pointed['qualifiers'] and not
                        (set(pointed['flags']) & {'lvalue_ref', 'rvalue_ref'}), 'ABI_CC_REF_QUALIFIED_THIS')
        for method in item['methods']:
            _, signature = graph.resolve(method['signature'])
            require(signature['kind'] == 'function', 'ABI_CC_METHOD_SIGNATURE')
        complete = 'complete' in item['flags']
        if item['kind'] in ('void','function'):
            require(item['layout'] is None,'ABI_CC_NONOBJECT_LAYOUT')
        if item['kind'] in ('record','array') and not complete:
            require(item['layout'] is None and item['record_input'] is None and
                    item['execution'] is None and item['representation']=='none','ABI_CC_INCOMPLETE_LAYOUT')
        if item['kind']=='array':
            require(len(item['elements'])==1,'ABI_CC_ELEMENT_TYPE')
            count=option(item['extent'])
            require(count is None or count>0,'ABI_CC_ARRAY_COUNT')
            _, element=graph.resolve(item['elements'][0])
            known=count is not None and 'complete' in element['flags'] and element['layout'] is not None
            require(complete==known and (not known or item['layout'] is not None),'ABI_CC_ARRAY_COMPLETENESS')
        require(not complete or item['kind'] in ('void','function') or item['layout'] is not None,
                'ABI_CC_MISSING_OBJECT_LAYOUT')
        if complete:
            require(source['definition'] == graph.fingerprint({'module': {'kind': 'self'}, 'id': item['id']}),
                    'ABI_CC_DEFINITION_HASH')
        else:
            require(source['definition'] == ZERO and item['kind'] in ('void', 'record', 'array', 'function'),
                    'ABI_CC_INCOMPLETE_DECLARATION')
        execution = option(item['execution'])
        foreign = tables['domains'][item['domain']]['isa'] != 'portable'
        require(item['representation'] in ('none', 'value', 'storage', 'signature', 'code_address'),
                'ABI_CC_TYPE_BINDING')
        require(item['representation'] != 'code_address' or
                item['kind'] in ('pointer', 'reference') and 'code' in item['flags'], 'ABI_CC_TYPE_BINDING')
        if item['kind'] == 'function':
            require(not foreign or execution is None, 'ABI_CC_FUNCTION_DEFAULT')
            require(execution is None or item['representation'] == 'signature', 'ABI_CC_TYPE_BINDING')
        require(item['record_input'] is None if item['kind'] != 'record' or not complete else
                foreign or item['record_input'] is not None, 'ABI_CC_RECORD_INPUT')
        if foreign:
            require(context.native_type({'module': {'kind': 'self'}, 'id': item['id']}) == item,
                    'ABI_CC_NATIVE_TYPE_EVIDENCE')
            if item['layout'] is not None:
                require(context.native_layout({'module':{'kind':'self'},'id':item['id']})==
                        graph.layout({'module':{'kind':'self'},'id':item['id']}),'ABI_CC_NATIVE_LAYOUT_EVIDENCE')
        if item['representation'] == 'none':
            require(execution is None and (not complete or item['kind'] in ('void', 'function') or foreign),
                    'ABI_CC_TYPE_BINDING')
            continue
        require(execution is not None, 'ABI_CC_TYPE_BINDING')
        shape = context.execution(execution)
        require(isinstance(shape, dict) and 'kind' in shape, 'ABI_CC_EXECUTION_REFERENCE')
        kind = item['kind']
        require(not item['enumerators'] or kind == 'enum', 'ABI_CC_ENUM_DECLARATION')
        if kind in ('pointer', 'reference'):
            expected = 'code_address' if 'code' in item['flags'] else 'data_ptr'
            require(shape['kind'] == expected and item['bits'] == 64 and len(item['elements']) == 1,
                    'ABI_CC_TYPE_BINDING')
            require(item['representation'] == ('code_address' if expected == 'code_address' else 'value'),
                    'ABI_CC_TYPE_BINDING')
        elif kind == 'handle':
            require(item['bits'] == 64 and shape['kind'] == HANDLES.get(source['entity']), 'ABI_CC_HANDLE_BINDING')
        elif kind == 'snapshot':
            require(source['entity'] == 'rax.fenv_snapshot' and shape['kind'] == 'fenv', 'ABI_CC_SNAPSHOT_BINDING')
        elif kind == 'member_pointer':
            require(len(item['elements']) == 2 and graph.resolve(item['elements'][0])[1]['kind'] == 'record',
                    'ABI_CC_MEMBER_POINTER')
            target = graph.resolve(item['elements'][1])[1]
            method = target['kind'] == 'function'
            if method:
                from execution_shapes import ExecutionShapes
                integer64 = ExecutionShapes([{'id':0,'kind':'int','bits':64}],budget=context.factory_budget).digest({'module':{'kind':'self'},'id':0})
                require(item['bits'] == 128 and shape['kind'] == 'struct' and
                        shape.get('fields') == [integer64,integer64], 'ABI_CC_MEMBER_POINTER')
            else:
                require(item['bits'] == 64 and shape['kind'] == 'int' and shape.get('bits') == 64,
                        'ABI_CC_MEMBER_POINTER')
        elif kind == 'scalar' and source['entity'] == 'nullptr_t':
            require(shape['kind'] == 'data_ptr' and item['bits'] == 64 and not item['signed'],
                    'ABI_CC_TYPE_BINDING')
        elif kind in ('bitint', 'enum') or kind == 'scalar' and shape['kind'] != 'float':
            require(shape['kind'] in ('int', 'raw') and shape.get('bits') == item['bits'], 'ABI_CC_TYPE_BINDING')
        elif kind == 'scalar':
            require(shape['kind'] == 'float' and shape.get('format') in
                    {32: {'binary32'}, 64: {'binary64'}, 128: {'binary128'}}.get(item['bits'], set()),
                    'ABI_CC_TYPE_BINDING')
        elif kind == 'record' and item['representation'] == 'storage':
            layout = graph.layout({'module': {'kind': 'self'}, 'id': item['id']})
            if shape['kind'] == 'raw':
                require(shape.get('bits') == layout['size'] * 8, 'ABI_CC_STORAGE_BINDING')
            else:
                from execution_shapes import ExecutionShapes
                raw8=ExecutionShapes([{'id':0,'kind':'raw','bits':8}],budget=context.factory_budget).digest({'module':{'kind':'self'},'id':0})
                require(shape['kind']=='array' and shape.get('count')==layout['size'] and
                        shape.get('element_identity')==raw8, 'ABI_CC_STORAGE_BINDING')
        elif kind == 'atomic_flag':
            require(shape['kind'] == 'raw' and shape.get('bits') == 8, 'ABI_CC_FLAG_BINDING')
        elif kind == 'atomic':
            require(len(item['elements']) == 1 and shape['kind'] in ('int', 'float', 'raw', 'data_ptr', 'code_address'),
                    'ABI_CC_ATOMIC_BINDING')
            base=graph.resolve(item['elements'][0])[1]
            require(base['execution'] is not None and
                    shape['identity']==context.execution(option(base['execution']))['identity'], 'ABI_CC_ATOMIC_BINDING')
        else:
            expected = {'complex': 'struct', 'vector': 'vector', 'array': 'array', 'function': 'function'}
            require(kind in expected and shape['kind'] == expected[kind], 'ABI_CC_TYPE_BINDING')
            if kind in ('array','vector','complex'):
                require(len(item['elements'])==1,'ABI_CC_ELEMENT_TYPE')
                element=graph.resolve(item['elements'][0])[1]
                require(element['execution'] is not None,'ABI_CC_ELEMENT_TYPE')
                child=context.execution(option(element['execution']))['identity']
                if kind=='complex':
                    require(shape.get('fields')==[child,child],'ABI_CC_COMPLEX_BINDING')
                else:
                    require(shape.get('element_identity')==child and shape.get('count')==option(item['extent']),
                            'ABI_CC_ELEMENT_BINDING')
    # By-value cycles are impossible source objects. Pointer/signature recursion
    # is legal and intentionally excluded from storage edges.
    M.collection(context.factory_budget,len(types))
    active, done = set(), set()

    def storage_visit(reference, owner):
        module, typ = graph.resolve(reference, owner)
        key = module, typ['id']
        if key in done:
            return
        require(key not in active, 'ABI_CC_VALUE_CYCLE')
        active.add(key)
        children = typ['elements'] if typ['kind'] in ('atomic', 'array', 'vector', 'complex', 'enum') else []
        if typ['kind'] == 'record' and typ['layout'] is not None:
            layout = graph.layout(reference, owner)
            children = [entry['type'] for entry in layout['fields'] + layout['bases']]
        M.charge(context.factory_budget,work=len(children),edges=len(children),copied_bytes=128*len(children))
        for child in children:
            storage_visit(child, module)
        active.remove(key)
        done.add(key)

    for identifier in types:
        storage_visit({'module': {'kind': 'self'}, 'id': identifier}, context.module)
    for layout in layouts.values():
        M.row(layout,context.factory_budget)
        item = local(layout['type'])
        require(option(item['layout']) == layout['id'], 'ABI_CC_LAYOUT_BINDING')
        alignment(layout['align'])
        alignment(layout['nonvirtual_align'])
        require(0 < layout['size'] <= MAX_OBJECT and layout['size'] % layout['align'] == 0 and
                0 <= layout['data_size'] <= layout['size'] and
                0 <= layout['nonvirtual_size'] <= layout['size'], 'ABI_CC_LAYOUT_EXTENT')
        kind = item['kind']
        expected = None
        if tables['domains'][item['domain']]['isa']=='portable' and kind!='record':
            require(not layout['fields'] and not layout['bases'] and not layout['vptrs'],'ABI_CC_NONRECORD_LAYOUT')
        if tables['domains'][item['domain']]['isa'] != 'portable':
            continue  # Native certificate bound above; portable equations differ.
        if kind == 'scalar':
            require(item['identity']['entity'] in INTEGER_NAMES | {'float','double','long double','nullptr_t'},
                    'ABI_CC_SCALAR_NAME')
            expected = SCALARS[item['identity']['entity']]
            name=item['identity']['entity']
            precision=1 if name=='bool' else expected[0]*8
            require(item['bits']==precision,'ABI_CC_SCALAR_PRECISION')
            require(item['signed'] == (name in {'char','signed char','short','int','wchar_t',
                    'long','long long','ptrdiff_t','__int128'}), 'ABI_CC_SCALAR_SIGNEDNESS')
        elif kind == 'bitint':
            require((2 if item['signed'] else 1) <= item['bits'] <= 65535, 'ABI_CC_BITINT_WIDTH')
            count = (item['bits'] + 7) // 8
            align = min(8, 1 << (count - 1).bit_length())
            expected = align_up(count, align), align
        elif kind in ('pointer', 'reference', 'handle'):
            expected = 8, 8
        elif kind == 'atomic_flag':
            expected = 1, 1
        elif kind == 'member_pointer':
            expected = (16,8) if graph.resolve(item['elements'][1])[1]['kind']=='function' else (8,8)
        elif kind == 'enum':
            require(len(item['elements'])==1,'ABI_CC_ENUM_BASE')
            base=graph.resolve(item['elements'][0])[1]
            require(base['kind'] in ('scalar','bitint') and base['bits']==item['bits'] and
                    base['signed']==item['signed'] and
                    (base['kind']=='bitint' or base['identity']['entity'] in INTEGER_NAMES),'ABI_CC_ENUM_BASE')
            base_layout=graph.layout(item['elements'][0]);expected=base_layout['size'],base_layout['align']
            names=[entry['name'] for entry in item['enumerators']]
            require(len(names)==len(set(names)),'ABI_CC_ENUM_DECLARATION')
            values=[]
            for entry in item['enumerators']:
                data=bytes.fromhex(entry['value'])
                require(len(data)==(item['bits']+7)//8 and int.from_bytes(data,'little')<1<<item['bits'],
                        'ABI_CC_ENUM_VALUE')
                value=int.from_bytes(data,'little')
                if item['signed'] and value & (1 << (item['bits']-1)):
                    value-=1 << item['bits']
                values.append(value)
            fixed='fixed_base' in item['flags'] or 'scoped' in item['flags']
            if not fixed:
                selected=None
                for name,width,signed in [('int',32,True),('unsigned int',32,False),
                                          ('long',64,True),('unsigned long',64,False)]:
                    lo=-(1 << (width-1)) if signed else 0
                    hi=(1 << (width-1))-1 if signed else (1 << width)-1
                    if all(lo <= value <= hi for value in values):
                        selected=name
                        break
                require(selected is not None and base['identity']['entity']==selected,
                        'ABI_CC_ENUM_SELECTION')
        elif kind == 'snapshot':
            expected = 32, 8
        elif kind == 'atomic':
            base = graph.layout(item['elements'][0])
            _, element = graph.resolve(item['elements'][0])
            require(element['kind'] not in ('atomic', 'array'), 'ABI_CC_ATOMIC_TYPE')
            size = 1 << (base['size'] - 1).bit_length() if base['size'] <= 16 else base['size']
            expected = size, max(size, base['align']) if base['size'] <= 16 else base['align']
        elif kind in ('array', 'vector', 'complex'):
            require(len(item['elements']) == 1, 'ABI_CC_ELEMENT_TYPE')
            base = graph.layout(item['elements'][0])
            count = 2 if kind == 'complex' else option(item['extent'])
            require(count is not None and count > 0, 'ABI_CC_ARRAY_COUNT')
            size = base['size'] * count
            if kind == 'vector':
                element=graph.resolve(item['elements'][0])[1]
                require(element['kind']=='scalar' and element['identity']['entity'] in
                    {'char','signed char','unsigned char','short','unsigned short','int','unsigned int',
                     'long','unsigned long','long long','unsigned long long','float','double'}, 'ABI_CC_VECTOR_ELEMENT')
                size = 1 << (size - 1).bit_length()
                require(size <= 64, 'ABI_CC_VECTOR_SIZE')
                expected = size, size
            else:
                if kind=='complex':
                    require(graph.resolve(item['elements'][0])[1]['identity']['entity'] in
                            ('float','double','long double'),'ABI_CC_COMPLEX_ELEMENT')
                expected = size, base['align']
        if expected is not None:
            require((layout['size'], layout['align']) == expected, 'ABI_CC_LAYOUT_POLICY')
        names = set()
        for field in layout['fields']:
            require(field['name'] not in names and field['offset_bits'] + field['width_bits'] <= layout['size'] * 8,
                    'ABI_CC_FIELD_LAYOUT')
            names.add(field['name'])
            graph.resolve(field['type'])
        for base in layout['bases']:
            graph.resolve(base['type'])
            require(base['virtual'] == (base['adjustment']['kind'] == 'virtual'), 'ABI_CC_BASE_ADJUSTMENT')
        for vptr in layout['vptrs']:
            _owner_package('rax_abi_record_layout', 'record_layout', 'vtable').components(vptr)
            require(vptr['offset'] % 8 == 0 and vptr['offset'] + 8 <= layout['size'], 'ABI_CC_VTABLE_LAYOUT')
            for slot in vptr['slots']:
                require(context.symbol(slot)['kind'] == 'function', 'ABI_CC_VTABLE_SLOT')

    # Portable record outputs are recomputed from independent source declarations.
    # Native geometry remains bound to separately qualified native certificates.
    record_model = _owner_package('rax_abi_record_layout', 'record_layout', 'checked').CheckedRecords(graph,budget=None if context.factory_budget is None else M.ModelBudgetAdapter(context.factory_budget))
    for item in types.values():
        if item['kind'] == 'record' and 'complete' in item['flags'] and \
                tables['domains'][item['domain']]['isa'] == 'portable':
            record_model.verify({'module': {'kind': 'self'}, 'id': item['id']})

    # Reserved builtin declarations must be exact even when no helper uses them.
    role_model = _owner_package('rax_abi_source_roles', 'source_roles', 'model').SourceRoles(
        graph, lambda owner, reference: context.execution(reference) if owner == context.module else
        require(False, 'ABI_CC_SOURCE_OWNER_EXECUTION_UNAVAILABLE'))
    for item in types.values():
        if item['identity']['linkage'] == 'builtin' and item['identity']['entity'] in (
                'rax.va_state', 'rax.jmp_state'):
            role_model.state({'module': {'kind': 'self'}, 'id': item['id']}, context.module,
                             item['identity']['entity'],base_declaration=True)

    for signature in tables['signatures'].values():
        M.row(signature,context.factory_budget)
        _, function = graph.resolve(signature['function_type'])
        require(not (set(function['flags']) & {'lvalue_ref', 'rvalue_ref'}) or
                signature['this_type'] is not None, 'ABI_CC_REF_QUALIFIED_THIS')
        require(signature['this_type'] is not None or not function['qualifiers'], 'ABI_CC_REF_QUALIFIED_THIS')
        require(function['kind'] == 'function' and 'complete' in function['flags'] and
                option(function['extent']) == len(signature['params']) and
                len(function['elements']) == len(signature['params']) + 1 and
                all(graph.compatible(a, b) for a, b in zip(function['elements'][:-1], signature['params'])) and
                ('variadic' in function['flags']) == signature['variadic'] and
                ('noexcept' in function['flags']) == signature['noexcept'], 'ABI_CC_SOURCE_SIGNATURE')
        source_result = option(signature['result'])
        if source_result is None:
            require(graph.resolve(function['elements'][-1])[1]['kind'] == 'void', 'ABI_CC_SOURCE_SIGNATURE')
        else:
            require(graph.compatible(source_result, function['elements'][-1]), 'ABI_CC_SOURCE_SIGNATURE')
        expected, results = classify(graph, signature)
        require(len(expected) == len(signature['lowered_params']) and results == signature['lowered_results'],
                'ABI_CC_CALL_SHAPE')
        for wanted, actual in zip(expected, signature['lowered_params']):
            require(all(actual[key] == value for key, value in wanted.items()), 'ABI_CC_CALL_PARAMETER')
            _, value_type = graph.resolve(actual['value_type'])
            if actual['role'] == 'varargs_bytes':
                require(value_type['kind'] == 'scalar' and value_type['bits'] == 64 and not value_type['signed'],
                        'ABI_CC_VARARGS_LENGTH_TYPE')
            elif actual['mode'] in ('sret', 'indirect_copy') or actual['role'] in ('this', 'vtt', 'varargs_arena'):
                require(value_type['kind'] == 'pointer', 'ABI_CC_INDIRECT_TYPE')
                if actual['mode'] in ('sret', 'indirect_copy'):
                    require(len(value_type['elements']) == 1 and graph.compatible(
                        value_type['elements'][0], actual['source_type']), 'ABI_CC_INDIRECT_TYPE')
            else:
                require(graph.compatible(actual['value_type'], actual['source_type']), 'ABI_CC_DIRECT_TYPE')
            source_type = graph.resolve(actual['source_type'])[1]
            if source_type['kind'] == 'record' and 'trivial_destroy' not in source_type['flags']:
                require(actual['destroy'] is not None, 'ABI_CC_DESTROY_RECIPE')
            for name in ('copy', 'move', 'destroy'):
                recipe = option(actual[name])
                require(recipe is None or recipe in tables['recipes'], 'ABI_CC_ADAPTER_REFERENCE')
        binding = option(signature['varargs'])
        require((binding is not None) == signature['variadic'], 'ABI_CC_VARARGS_BINDING')
        if binding:
            require(binding['state_layout'] in layouts and
                    (layouts[binding['state_layout']]['size'], layouts[binding['state_layout']]['align']) == (32, 8) and
                    binding['header_bytes'] == 32 and binding['cookie_scope'] == 'thread_activation' and
                    binding['type_reference'] == 'nominal_declaration_u32', 'ABI_CC_VARARGS_BINDING')
        function_shape = context.execution(signature['execution'])
        require(function_shape['kind'] == 'function', 'ABI_CC_LOWERED_SIGNATURE')
        parameter_shapes = [context.execution(option(graph.resolve(param['value_type'])[1]['execution']))
                            for param in signature['lowered_params']]
        result_shapes = [context.execution(option(graph.resolve(result)[1]['execution']))
                         for result in signature['lowered_results']]
        require(function_shape.get('params') == [shape['identity'] for shape in parameter_shapes] and
                function_shape.get('results') == [shape['identity'] for shape in result_shapes] and
                function_shape.get('param_noundef') == [p['noundef'] for p in signature['lowered_params']] and
                function_shape.get('result_noundef') == [signature['return_noundef']] * len(result_shapes),
                'ABI_CC_LOWERED_SIGNATURE')
        require(function_shape.get('variadic') is False and function_shape.get('cc') == 'portable',
                'ABI_CC_OPEN_EXECUTION_VARIADIC')

    # A source prototype is independent of executable plans. An optional default
    # association is valid only after its own local ordinary plan was verified.
    for item in types.values():
        if item['kind'] != 'function':
            continue
        execution = option(item['execution'])
        foreign = tables['domains'][item['domain']]['isa'] != 'portable'
        require(not foreign or execution is None, 'ABI_CC_FUNCTION_DEFAULT')
        if execution is None:
            continue
        from call_interfaces import same_execution
        require(any(graph.resolve(plan['function_type']) == (context.module, item) and
                    plan['this_type'] is None and not plan['vtt'] and
                    same_execution(context, execution, plan['execution'],budget=context.factory_budget)
                    for plan in tables['signatures'].values()), 'ABI_CC_FUNCTION_DEFAULT')

    for program in tables['journals'].values():
        M.journal_cost(program,context.factory_budget)
        require(program['signature'] in tables['signatures'], 'ABI_CC_JOURNAL_SIGNATURE')
        formals=unique(program['params'],'JOURNAL_PARAMETER')
        for formal in formals.values():
            typ=graph.resolve(formal['type'])[1]
            require(typ['execution'] is not None,'ABI_CC_JOURNAL_PARAMETER_TYPE')
        for slot in verify_program(program).values():
            graph.resolve(slot['type'])
            require(slot['owner'] in tables['domains'], 'ABI_CC_SLOT_OWNER')
            count=option(slot['count_source'])
            if count is not None:
                require(count in formals,'ABI_CC_JOURNAL_COUNT_SOURCE')
                typ=graph.resolve(formals[count]['type'])[1]
                require(typ['kind']=='scalar' and typ['bits']==64 and not typ['signed'],
                        'ABI_CC_JOURNAL_COUNT_SOURCE')
            for field in ('constructor', 'destructor'):
                recipe = option(slot[field])
                require(recipe is None or recipe in tables['recipes'], 'ABI_CC_ADAPTER_REFERENCE')
    from storage_binding import verify_binding
    for binding in unique(document['storage_bindings'], 'STORAGE_BINDING').values():
        M.binding_cost(binding,graph,context.factory_budget)
        verify_binding(binding, graph, context.memory_layout)
    from native_contract import verify_native
    M.copy_cost(document['domains'],context.factory_budget)
    for _ in range(8):M.collection(context.factory_budget,len(document['domains']))
    verify_native(document, graph, tables, context)
    M.copy_cost(document,context.factory_budget)
    M.copy_cost(document,context.factory_budget)
    return {'types': len(types), 'signatures': len(tables['signatures']),
            'layouts': len(layouts), 'payload_sha256': hashlib.sha256(encode('abi_contract', document)).hexdigest(),
            'admitted_for_execution': False}
