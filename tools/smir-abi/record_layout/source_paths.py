"""Original-source canonical paths; static data, never executable adjustment/facts.

Draft ABI-CANONICAL-SOURCE-PATHS-02. Actual original roots and cumulative
SourceQueryBudget are required; no source cell is inferred from byte overlap.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re

from nominal import NominalGraph, option, ref
from layout import ABIError, SCALARS, INTEGER_NAMES, MAX_OBJECT, align_up
from .checked import CheckedRecords, field_name
from .materialization import _api, _LayoutBudget, _charge_tree
from .model import ModelError, RecordType
from .source_programs import ROOT, capture, ledger, check_source_associations_deferred

SCHEMA = ROOT / 'docs/specifications/smir/portable/schema/abi/source_paths.json'
SCHEMA_SHA256 = '0a2e104002b7d54b47787cc6e4ccac701cdc8f48f310868e230e5fe5d8d44cc4'
U64 = (1 << 64) - 1


def fail(code, detail='', kind='semantic'):
    raise _api().SourceDataError(kind, code, detail)


def need(value, code, detail=''):
    if not value:
        fail(code, detail)


class _Gap(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Axis:
    position: int
    array_declaration: tuple
    extent: int
    first: int
    count: int


@dataclass(frozen=True, slots=True)
class PathGap:
    code: str
    selector_label: str
    route_index: int
    step_index: int | None


@dataclass(frozen=True, slots=True)
class SourceCellPattern:
    label: str
    canonical_skeleton: tuple
    axes: tuple[Axis, ...]
    declared_leaf: tuple
    leaf_kind: str
    most_derived_skeleton: tuple
    offset_constant_bits: int
    offset_coefficients_bits: tuple[int, ...]
    width_bits: int
    addressable: bool
    covered: bool
    root_view: str
    leaf_view: str


@dataclass(frozen=True, slots=True)
class OriginalSourcePaths:
    owner: object
    stamp: object
    root_declaration: tuple
    root_class_key: tuple
    view: str
    patterns: tuple[SourceCellPattern, ...]
    deferred: tuple[PathGap, ...]
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class OriginalSourcePathRelation:
    owner: object
    stamp: object
    left: SourceCellPattern
    right: SourceCellPattern
    relation: str
    same_coverage_view: bool
    deferred: tuple
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class OriginalSourceCoverage:
    owner: object
    stamp: object
    paths: OriginalSourcePaths
    source_associations: object
    context_id: int
    cleanup_id: int
    program_key: tuple
    memberships: tuple
    declared_cleanup_slots: tuple
    deferred: tuple
    obligations: tuple
    binding: str = field(default='unbound', init=False)
    runtime_authority: bool = field(default=False, init=False)
    source_fact_authority: bool = field(default=False, init=False)


OBLIGATIONS = (
    'actual runtime sourceobject/allocation/lifetime identity and generation',
    'effective expression qualifiers/mutable/accessibility/source legality',
    'typed dynamic vbase-slot target/dispatch/VTT/RTTI and executable adjustments',
    'original source body/frontier/initialization/history/current and private issuers',
    'static shape equality is neither runtime alias equality nor a coverage view conversion')


def _schema(budget):
    size = SCHEMA.stat().st_size
    if not 0 < size <= 256 * 1024:
        fail('ABI_PATH_SCHEMA_RESOURCE',kind='resource')
    budget.charge(work=4 * size, copied_bytes=8 * size)
    with SCHEMA.open('rb') as stream:
        raw = stream.read(size + 1)
    need(len(raw) == size and hashlib.sha256(raw).hexdigest() == SCHEMA_SHA256,
         'ABI_PATH_SCHEMA_IDENTITY')
    return raw


def _shape(rule, value, definitions, budget, depth=0):
    budget.work(1)
    if depth > min(128, budget.max_depth):
        fail('SOURCE_DATA_RESOURCE', 'path shape depth', 'resource')
    if '$ref' in rule:
        return _shape(definitions[rule['$ref'].rsplit('/', 1)[1]], value, definitions, budget, depth)
    if 'oneOf' in rule:
        accepted = 0
        for branch in rule['oneOf']:
            try:
                _shape(branch, value, definitions, budget, depth)
                accepted += 1
            except _api().SourceDataError as error:
                if error.code != 'ABI_PATH_SHAPE':
                    raise
        need(accepted == 1, 'ABI_PATH_SHAPE')
    if 'const' in rule:
        need(type(value) is type(rule['const']) and value == rule['const'], 'ABI_PATH_SHAPE')
    if 'enum' in rule:
        need(any(type(value) is type(x) and value == x for x in rule['enum']), 'ABI_PATH_SHAPE')
    kind = rule.get('type')
    expected = {'object': dict, 'array': list, 'integer': int, 'boolean': bool, 'string': str}
    if kind:
        need(type(value) is expected[kind], 'ABI_PATH_SHAPE')
    if kind == 'object':
        need(set(value) == set(rule['required']), 'ABI_PATH_SHAPE')
        for name, child in value.items():
            _shape(rule['properties'][name], child, definitions, budget, depth + 1)
    elif kind == 'array':
        need(rule['minItems'] <= len(value) <= rule['maxItems'], 'ABI_PATH_SHAPE')
        for child in value:
            _shape(rule['items'], child, definitions, budget, depth + 1)
    elif kind == 'integer':
        need(rule['minimum'] <= value <= rule['maximum'], 'ABI_PATH_SHAPE')
    elif kind == 'string':
        need(rule['minLength'] <= len(value) <= rule['maxLength'] and
             re.fullmatch(rule['pattern'], value) is not None, 'ABI_PATH_SHAPE')


def _document(document, budget):
    ledger(budget)
    # Bounded traversal before capture. Detect cycles without dereferencing them.
    pending = [(document, 0, False)]; active = set(); count = 0
    while pending:
        value, depth, leave = pending.pop()
        if leave:
            active.remove(id(value)); continue
        budget.charge(work=1, edges=1, copied_bytes=48); count += 1
        if count > 200000 or depth > min(128, budget.max_depth):
            fail('SOURCE_DATA_RESOURCE', 'path input bound', 'resource')
        if type(value) in (dict, list):
            need(id(value) not in active, 'ABI_PATH_CYCLE'); active.add(id(value))
            budget.reserve_bytes(64 * (len(value) + 1))
            pending.append((value, depth, True))
            pending.extend((x, depth + 1, False) for x in
                           (value.values() if type(value) is dict else value))
    copied, _ = capture(document, budget)
    raw = _schema(budget); schema = json.loads(raw)
    _shape(schema, copied, schema['$defs'], budget)
    need(len({x['label'] for x in copied['selectors']}) == len(copied['selectors']), 'ABI_PATH_LABEL_DUPLICATE')
    return copied, raw


def _qkey(reference):
    module = reference['module']
    return (module['kind'], module.get('slot'), reference['id'])


def _owner(owner, budget):
    from candidate.context import RootContext
    ledger(budget); need(type(owner) is RootContext, 'ABI_PATH_ORIGINAL_CONTEXT')
    return RootContext.prepare_source_data(owner, budget=budget)


def _after(owner, stamp, schema, budget):
    need(_owner(owner, budget) is stamp, 'ABI_PATH_ORIGINAL_CONTEXT')
    need(_schema(budget) == schema, 'ABI_PATH_SCHEMA_IDENTITY')


class _Records(CheckedRecords):
    def canonical_class(self,owner,item):
        identity=item['identity'];unit=option(identity['unit']);library=option(identity['library'])
        private=identity['linkage'] in ('internal','local')
        need((unit is not None)==private,'ABI_PATH_SOURCE_UNIT')
        if unit is not None:need(type(unit)is str and re.fullmatch('[0-9a-f]{64}',unit)is not None,'ABI_PATH_SOURCE_UNIT')
        domain=next((d for d in self.graph.modules[owner]['domains'] if d['id']==item['domain']),None)
        need(domain is not None,'ABI_PATH_DOMAIN')
        return (domain['abi_identity'],identity['language'],identity['linkage'],identity['entity'],library,unit,
                self.graph.families[owner] if private else None)


class _Source:
    def __init__(self, owner, budget):
        self.owner, self.b = owner, budget
        contract = owner.sections[10]; manifest = owner.sections[2]['manifest']; family = manifest['key']
        identity = tuple(family[k] for k in ('namespace', 'name', 'abi_major'))
        module = identity[0] + ':' + identity[1] + ':' + str(identity[2]); aliases = {}
        need(all(len(contract[k])<=4096 for k in ('types','layouts','domains')),'ABI_PATH_GRAPH_BOUND')
        self.bound = _charge_tree(contract, budget); n = sum(len(contract[k]) for k in ('types','layouts','domains'))
        budget.charge(work=n, edges=n, copied_bytes=256 * n)
        for dependency in manifest['dependencies']:
            budget.work(1)
            for declaration in dependency['declarations']:
                budget.work(1)
                if declaration['kind'] == 'nominal' and declaration['nominal'] is not None:
                    target = declaration['nominal']['some']
                    need(target['module'] == {'kind':'self'}, 'ABI_PATH_DECLARATION')
                    budget.reserve_bytes(96); aliases[dependency['slot'], declaration['id']] = target['id']
        self.graph = NominalGraph(contract, module, families={module:identity}, nominal_expectations={module:aliases})
        self.table = self.graph.tables[module]; self.layouts = self.graph.layouts[module]
        self.domains = {d['id']:d for d in contract['domains']}
        self.checked = _Records(self.graph, _LayoutBudget(budget))
        self.fingerprints = {}; self.done = set(); self.active = set(); self.classes = {};self.class_aliases={}
        for node in self.table.values():
            budget.work(1)
            if node['kind']=='record' and 'complete' in node['flags']:
                budget.reserve_bytes(128);self.class_aliases.setdefault(self.klass(node),[]).append(node)
        self.graph.compatible = self.same

    def get(self, reference):
        self.b.work(8)
        try:
            return self.graph.resolve(reference)[1]
        except ABIError as error:
            fail('ABI_PATH_ORIGINAL_REFERENCE', str(error))

    def klass(self, item):
        need(item['domain'] in self.domains, 'ABI_PATH_DOMAIN')
        return self.checked.canonical_class(self.graph.module_id, item)

    def fingerprint(self, item, ignore_top_cv=False):
        key = item['id'], ignore_top_cv
        if key not in self.fingerprints:
            n = 2 * len(self.table) + 1
            self.b.charge(work=32*n*n*(n.bit_length()+1)*(self.bound+1),
                          copied_bytes=8*n*(self.bound+1))
            self.fingerprints[key] = self.graph.fingerprint(ref(item['id']), ignore_top_cv=ignore_top_cv)
        return self.fingerprints[key]

    def same(self, left, right, left_owner=None, right_owner=None, ignore_top_cv=False):
        a,b = self.get(left),self.get(right)
        if a['id'] == b['id']:
            return True
        if a['kind'] != b['kind']:
            return False
        aq = [q for q in a['qualifiers'] if not(ignore_top_cv and q in ('const','volatile'))]
        bq = [q for q in b['qualifiers'] if not(ignore_top_cv and q in ('const','volatile'))]
        if aq != bq:
            return False
        if a['kind'] in ('record','enum'):
            if self.klass(a) != self.klass(b):
                return False
            if 'complete' not in a['flags'] or 'complete' not in b['flags']:
                return True
        return self.fingerprint(a,ignore_top_cv) == self.fingerprint(b,ignore_top_cv)

    def key(self, item):
        return ('class',self.klass(item)) if item['kind']=='record' else ('type',self.fingerprint(item))

    def selected(self, item):
        identifier = option(item['layout'])
        if identifier is None:
            raise _Gap('ABI_PATH_SOURCE_INPUT_UNAVAILABLE')
        need(identifier in self.layouts, 'ABI_PATH_LAYOUT_REFERENCE')
        selected=self.layouts[identifier];back=self.get(selected['type'])
        need(option(back['layout'])==identifier and self.same(ref(item['id']),selected['type']), 'ABI_PATH_LAYOUT_BINDING')
        return selected

    def ensure(self, item):
        identifier = item['id']; self.b.work(16)
        if identifier in self.done:
            return
        need(identifier not in self.active, 'ABI_PATH_VALUE_CYCLE')
        if len(self.active) >= min(128,self.b.max_depth):
            fail('SOURCE_DATA_RESOURCE','source path graph depth','resource')
        need(item['domain'] in self.domains, 'ABI_PATH_DOMAIN')
        if self.domains[item['domain']]['isa'] != 'portable':
            raise _Gap('ABI_PATH_FOREIGN_SOURCE_UNAVAILABLE')
        kind=item['kind']
        need(kind not in ('void','function'), 'ABI_PATH_OBJECT_TYPE')
        if 'complete' not in item['flags']:
            raise _Gap('ABI_PATH_ARRAY_EXTENT_UNAVAILABLE' if kind=='array' else 'ABI_PATH_SOURCE_INPUT_UNAVAILABLE')
        selected=self.selected(item); self.active.add(identifier)
        try:
            if kind=='record':
                source=option(item['record_input'])
                if source is None:
                    raise _Gap('ABI_PATH_SOURCE_INPUT_UNAVAILABLE')
                for child in source['fields']+source['bases']:
                    self.b.charge(work=1,edges=1,copied_bytes=32); self.ensure(self.get(child['type']))
                key=self.klass(item)
                for alias in self.class_aliases.get(key,()):
                    self.b.work(1)
                    need(self.same(ref(alias['id']),ref(identifier),ignore_top_cv=True),'ABI_PATH_CLASS_CONFLICT')
                if key in self.classes:
                    need(self.same(ref(self.classes[key]),ref(identifier),ignore_top_cv=True), 'ABI_PATH_CLASS_CONFLICT')
                else:
                    self.classes[key]=identifier;self.b.reserve_bytes(128)
                bound=self.checked.bind(ref(identifier)); expected=self.checked.model.layout(bound.key)
                need(tuple(selected[k] for k in ('size','align','data_size','nonvirtual_size','nonvirtual_align')) ==
                     (expected.size,expected.align,expected.data_size,expected.nvsize,expected.nvalign), 'ABI_PATH_LAYOUT_GEOMETRY')
                self._record(item,selected,expected)
            else:
                need(not selected['fields'] and not selected['bases'] and not selected['vptrs'], 'ABI_PATH_NONRECORD_LAYOUT')
                size,align=self._primitive(item)
                need(tuple(selected[k] for k in ('size','align','data_size','nonvirtual_size','nonvirtual_align')) ==
                     (size,align,size,size,align),'ABI_PATH_LAYOUT_GEOMETRY')
            self.b.charge(work=1,copied_bytes=64); self.done.add(identifier)
        except (ABIError,ModelError) as error:
            fail('ABI_PATH_SOURCE_LAYOUT',str(error))
        finally:
            self.active.remove(identifier)

    def _primitive(self,item):
        kind=item['kind']; children=item['elements']
        if kind=='scalar':
            name=item['identity']['entity'];need(name in INTEGER_NAMES|{'float','double','long double','nullptr_t'},'ABI_PATH_SCALAR_NAME')
            expected=SCALARS[name];need(item['bits']==(1 if name=='bool' else expected[0]*8),'ABI_PATH_SCALAR_PRECISION')
            need(item['signed']==(name in {'char','signed char','short','int','wchar_t','long','long long','ptrdiff_t','__int128'}),'ABI_PATH_SCALAR_SIGNEDNESS')
            return expected
        if kind=='bitint':
            need((2 if item['signed'] else 1)<=item['bits']<=65535,'ABI_PATH_BITINT_WIDTH')
            n=(item['bits']+7)//8;a=min(8,1<<(n-1).bit_length());return align_up(n,a),a
        if kind in ('pointer','reference','handle'):
            need(item['bits']==64 and (kind=='handle' or len(children)==1),'ABI_PATH_POINTER_TYPE')
            if kind!='handle':self.get(children[0])
            return 8,8
        if kind=='atomic_flag':return 1,1
        if kind=='snapshot':return 32,8
        if kind=='member_pointer':
            need(len(children)==2 and self.get(children[0])['kind']=='record','ABI_PATH_MEMBER_POINTER')
            return (16,8) if self.get(children[1])['kind']=='function' else (8,8)
        need(kind in ('enum','atomic','array','vector','complex') and len(children)==1,'ABI_PATH_ELEMENT_TYPE')
        base=self.get(children[0]);self.ensure(base);layout=self.selected(base);size,align=layout['size'],layout['align']
        if kind=='enum':
            need(base['kind'] in ('scalar','bitint') and base['bits']==item['bits'] and base['signed']==item['signed'],'ABI_PATH_ENUM_BASE')
            need(base['kind']=='bitint' or base['identity']['entity'] in INTEGER_NAMES,'ABI_PATH_ENUM_BASE')
            seen=set();values=[]
            for entry in item['enumerators']:
                self.b.charge(work=1+len(entry['value']),copied_bytes=len(entry['value'])+32)
                need(entry['name'] not in seen,'ABI_PATH_ENUM_DECLARATION');seen.add(entry['name'])
                value=int.from_bytes(bytes.fromhex(entry['value']),'little')
                need(len(entry['value'])==2*((item['bits']+7)//8) and value<1<<item['bits'],'ABI_PATH_ENUM_VALUE')
                if item['signed'] and value&(1<<(item['bits']-1)):value-=1<<item['bits']
                values.append(value)
            if not({'fixed_base','scoped'} & set(item['flags'])):
                chosen=None
                for name,width,signed in [('int',32,True),('unsigned int',32,False),('long',64,True),('unsigned long',64,False)]:
                    lo=-(1<<(width-1)) if signed else 0;hi=(1<<(width-1))-1 if signed else (1<<width)-1
                    self.b.work(len(values))
                    if all(lo<=v<=hi for v in values):chosen=name;break
                need(base['identity']['entity']==chosen,'ABI_PATH_ENUM_SELECTION')
            return size,align
        if kind=='atomic':
            need(base['kind'] not in ('array','atomic'),'ABI_PATH_ATOMIC_TYPE')
            n=1<<(size-1).bit_length() if size<=16 else size;return n,max(n,align) if size<=16 else align
        count=2 if kind=='complex' else option(item['extent'])
        if count is None:raise _Gap('ABI_PATH_ARRAY_EXTENT_UNAVAILABLE')
        need(count>0 and size<=MAX_OBJECT//count,'ABI_PATH_ARRAY_EXTENT')
        if kind=='complex':need(base['kind']=='scalar' and base['identity']['entity'] in ('float','double','long double'),'ABI_PATH_COMPLEX_ELEMENT')
        if kind=='vector':
            need(base['kind']=='scalar' and base['identity']['entity'] in {'char','signed char','unsigned char','short','unsigned short','int','unsigned int','long','unsigned long','long long','unsigned long long','float','double'},'ABI_PATH_VECTOR_ELEMENT')
            n=1<<(size*count-1).bit_length();need(n<=64,'ABI_PATH_VECTOR_SIZE');return n,n
        return size*count,align

    def _record(self,item,selected,expected):
        source=option(item['record_input']);key=self.klass(item)
        need(len(source['fields'])==len(selected['fields']),'ABI_PATH_FIELD_COUNT')
        for index,(field,actual,offset) in enumerate(zip(source['fields'],selected['fields'],expected.fields)):
            self.b.work(16); width=option(field['bit_width'])
            if width is None:
                width=self.checked.model.type_layout(self.checked.records[key]['fields'][index]['type']).size*8
            flags=[]
            if field['bit_width'] is not None:
                flags.append('bitfield')
                if field['name'] is None:flags.append('unnamed')
            if field['anonymous']:flags.append('anonymous')
            if field['no_unique_address']:flags.append('no_unique_address')
            if field['access']!='public':flags.append(field['access'])
            if self.get(field['type'])['kind']=='array' and self.get(field['type'])['extent'] is None:flags.append('flexible')
            need(actual['declaration_index']==index and actual['name']==field_name(field,index) and
                 self.same(actual['type'],field['type']) and actual['offset_bits']==offset and
                 actual['width_bits']==width and actual['flags']==sorted(flags),'ABI_PATH_FIELD_GEOMETRY')
        bases=[(i,b['type'].key,expected.bases[i],False,[i]) for i,b in enumerate(self.checked.records[key]['bases']) if not b['virtual']]
        origins=self.checked.paths(key)
        bases.extend((None,k,v,True,origins[k]) for k,v in expected.vbases.items())
        need(len(bases)==len(selected['bases']),'ABI_PATH_BASE_COUNT')
        for actual,(index,target,offset,virtual,path) in zip(selected['bases'],bases):
            self.b.work(16);node=self.get(actual['type'])
            need(node['kind']=='record' and self.klass(node)==target and actual['offset']==offset and
                 actual['virtual']==virtual and actual['declaration_index']==(None if index is None else {'some':index}) and
                 actual['origin_path']==path,'ABI_PATH_BASE_GEOMETRY')
            rule=actual['adjustment'];need(rule['kind']==('virtual' if virtual else 'fixed'),'ABI_PATH_BASE_ADJUSTMENT')
            if not virtual:need(rule['offset']==offset,'ABI_PATH_BASE_ADJUSTMENT')
            else:
                need(rule['vptr_offset'] in self.checked.vptr_offsets(key) and rule['slot_bytes']<0 and rule['slot_bytes']%8==0,'ABI_PATH_BASE_ADJUSTMENT')
                from .vtable import components
                ptr=next((p for p in selected['vptrs'] if p['offset']==rule['vptr_offset']),None)
                need(ptr is not None,'ABI_PATH_BASE_ADJUSTMENT')
                entry=components(ptr,_LayoutBudget(self.b)).get(rule['slot_bytes'])
                need(entry is not None and entry[0]=='vbase' and ptr['offset']+entry[1]+rule['addend']==offset,'ABI_PATH_BASE_ADJUSTMENT')
                # This checks numeric placement only; no source-target identity
                # for the runtime vbase slot or executable adjustment is issued.
        offsets=self.checked.vptr_offsets(key)
        need(len(selected['vptrs'])==len(offsets) and {p['offset'] for p in selected['vptrs']}==offsets and
             all(p['offset_top']==-p['offset'] for p in selected['vptrs']),'ABI_PATH_VPTR_GEOMETRY')


def _route(source,root,steps,view,label,route_index,gaps):
    b=source.b;item=root;key=();md=();mdtype=root;constant=0;coeff=[];mdconstant=0;mdcoeff=[]
    axes=[];known=view=='complete';complete=True;addressable=True;leafview=view;width_override=None;visited={}
    def gap(code,index):
        nonlocal complete
        b.charge(work=1,copied_bytes=128);gaps.append(PathGap(code,label,route_index,index));complete=False
    def layout(node,index):
        visited[node['id']]=node
        try:return source.selected(node)
        except _Gap as error:gap(str(error),index);return None
    current_layout=layout(root,None)
    if view=='nonvirtual':need(root['kind']=='record','ABI_PATH_ROOT_VIEW')
    for index,step in enumerate(steps):
        b.charge(work=32,edges=1,copied_bytes=256)
        if item is None:continue
        kind=step['kind'];current_layout=layout(item,index)
        if kind=='element':
            need(item['kind']=='array' and len(item['elements'])==1,'ABI_PATH_ELEMENT_TYPE')
            extent=option(item['extent']);selection=step['selection'];first,count=selection['first'],selection['count']
            child=source.get(item['elements'][0]);child_layout=layout(child,index)
            if extent is None:
                gap('ABI_PATH_ARRAY_EXTENT_UNAVAILABLE',index)
            else:need(0<count and first<=extent and count<=extent-first,'ABI_PATH_ARRAY_BOUNDS')
            if len(axes)>=16:fail('SOURCE_DATA_RESOURCE','source path array dimensions','resource')
            axis=len(axes);b.reserve_bytes(192);axes.append(Axis(axis,source.key(item),extent or 0,first,count))
            coeff.append(0 if child_layout is None else child_layout['size']*8)
            key=key+(('element',axis),);item=child;leafview='complete';width_override=None
            if item['kind']=='record':
                md=key;mdtype=item;mdconstant=constant;mdcoeff=coeff.copy();known=complete
            continue
        need(item['kind']=='record','ABI_PATH_RECORD_TYPE')
        declarations=option(item['record_input'])
        if declarations is None:
            gap('ABI_PATH_SOURCE_INPUT_UNAVAILABLE',index);item=None;continue
        declaration=step['declaration_index'];rows=declarations['fields' if kind=='member' else 'bases']
        need(declaration<len(rows),'ABI_PATH_DECLARATION_INDEX');edge=rows[declaration];child=source.get(edge['type'])
        if kind=='member':
            need(width_override is None,'ABI_PATH_NONOBJECT_MEMBER')
            if edge['bit_width'] is not None:
                need(edge['name'] is not None and option(edge['bit_width'])>0,'ABI_PATH_NONOBJECT_MEMBER')
                addressable=False;width_override=option(edge['bit_width'])
            else:width_override=None
            key=key+(('member',source.klass(item),declaration),)
            if current_layout is not None:
                fields=[x for x in current_layout['fields'] if x['declaration_index']==declaration]
                b.work(len(current_layout['fields']));need(len(fields)==1 and source.same(fields[0]['type'],edge['type']),'ABI_PATH_FIELD_GEOMETRY')
                constant+=fields[0]['offset_bits']
            item=child;leafview='complete'
            if item['kind']=='record':
                md=key;mdtype=item;mdconstant=constant;mdcoeff=coeff.copy();known=complete
        else:
            need(width_override is None and edge['virtual']==step['virtual'] and child['kind']=='record','ABI_PATH_BASE_DECLARATION')
            if edge['virtual']:
                if not known:
                    gap('ABI_PATH_NV_MOST_DERIVED_UNAVAILABLE',index)
                else:
                    owner_layout=layout(mdtype,index)
                    if owner_layout is not None:
                        bases=[x for x in owner_layout['bases'] if x['virtual'] and source.klass(source.get(x['type']))==source.klass(child)]
                        b.work(len(owner_layout['bases']));need(len(bases)==1,'ABI_PATH_BASE_GEOMETRY')
                        constant=mdconstant+8*bases[0]['offset'];coeff=mdcoeff.copy()
                    key=md+(('virtual_base',source.klass(child)),)
            else:
                key=key+(('nonvirtual_base',source.klass(item),declaration),)
                if current_layout is not None:
                    bases=[x for x in current_layout['bases'] if not x['virtual'] and x['declaration_index']=={'some':declaration}]
                    b.work(len(current_layout['bases']));need(len(bases)==1,'ABI_PATH_BASE_GEOMETRY');constant+=8*bases[0]['offset']
            item=child;leafview='nonvirtual'
    if item is not None:
        selected=layout(item,len(steps))
        width=width_override if width_override is not None else 0 if selected is None else 8*selected['nonvirtual_size' if item['kind']=='record' and leafview=='nonvirtual' else 'size']
    else:width=0
    # Check all represented route semantics before final independent numeric
    # layout derivation; a missing earlier input never skips later selectors.
    for node in visited.values():
        try:source.ensure(node)
        except _Gap as error:gap(str(error),None)
    if item is None:return None,None
    need(width_override is None or not steps or steps[-1]['kind']=='member','ABI_PATH_NONOBJECT_MEMBER')
    if not complete:return item,None
    count=1;low=high=constant
    for axis,stride in zip(axes,coeff):
        b.work(8);need(count<=U64//axis.count,'ABI_PATH_PATTERN_EXTENT');count*=axis.count
        low+=stride*axis.first;high+=stride*(axis.first+axis.count-1)
    need(len(coeff)==len(axes) and 0<=low<=high<=U64 and width<=U64-high,'ABI_PATH_AFFINE_EXTENT')
    selected_root=source.selected(root)
    root_extent=8*selected_root['size']  # NUA member sizeof may extend into base tail padding.
    need(high+width<=root_extent,'ABI_PATH_COVERAGE_EXTENT')
    return item,SourceCellPattern(label,key,tuple(axes),(source.graph.module_id,item['id']),item['kind'],md,
                                  constant,tuple(coeff),width,addressable,True,view,leafview)


def _gap_key(gap):
    return gap.selector_label,gap.route_index,-1 if gap.step_index is None else gap.step_index,gap.code


def _same_pattern(source,left,right):
    return (left.canonical_skeleton,left.axes,left.leaf_kind,left.most_derived_skeleton,
            left.offset_constant_bits,left.offset_coefficients_bits,left.width_bits,left.addressable,
            left.covered,left.root_view,left.leaf_view)==(
            right.canonical_skeleton,right.axes,right.leaf_kind,right.most_derived_skeleton,
            right.offset_constant_bits,right.offset_coefficients_bits,right.width_bits,right.addressable,
            right.covered,right.root_view,right.leaf_view) and source.same(ref(left.declared_leaf[1]),ref(right.declared_leaf[1]))


def resolve_source_paths(owner,document,*,budget):
    copied,schema=_document(document,budget);stamp=_owner(owner,budget);source=_Source(owner,budget)
    root=source.get(copied['root']);need(root['kind'] not in ('void','function'),'ABI_PATH_OBJECT_TYPE')
    if copied['view']=='nonvirtual':need(root['kind']=='record','ABI_PATH_ROOT_VIEW')
    patterns=[];gaps=[]
    for selector in copied['selectors']:
        expected=source.get(selector['declared_leaf']);need(expected['kind'] not in ('void','function'),'ABI_PATH_OBJECT_TYPE')
        seen=set();alternatives=[];start=len(gaps)
        for route_index,steps in enumerate(selector['routes']):
            signature=tuple((x['kind'],x.get('declaration_index'),x.get('virtual'),
                             None if x['kind']!='element' else (x['selection']['first'],x['selection']['count'])) for x in steps)
            budget.charge(work=len(steps),copied_bytes=96*len(steps)+64)
            need(signature not in seen,'ABI_PATH_ROUTE_DUPLICATE');seen.add(signature)
            leaf,pattern=_route(source,root,steps,copied['view'],selector['label'],route_index,gaps)
            if leaf is not None:need(source.same(ref(leaf['id']),ref(expected['id'])),'ABI_PATH_DECLARED_LEAF')
            if pattern is not None:alternatives.append(pattern)
        if len(gaps)==start:
            need(len(alternatives)==len(selector['routes']),'ABI_PATH_SOURCE_INPUT_UNAVAILABLE')
            budget.work(len(alternatives));need(all(_same_pattern(source,alternatives[0],x) for x in alternatives[1:]),'ABI_PATH_ALTERNATIVE_CELL')
            patterns.append(alternatives[0]);budget.reserve_bytes(256)
    n=len(gaps);budget.charge(work=n*(n.bit_length()+1),copied_bytes=256*n+256)
    unique=tuple(sorted(set(gaps),key=_gap_key))
    key=source.key(root);_after(owner,stamp,schema,budget)
    return OriginalSourcePaths(owner,stamp,_qkey(copied['root']),key,copied['view'],tuple(patterns),unique,OBLIGATIONS)


def _cell_relation(left,right,budget):
    budget.work(8+len(left.axes)+len(right.axes))
    if left.canonical_skeleton!=right.canonical_skeleton or len(left.axes)!=len(right.axes):return 'disjoint'
    equal=True
    for a,b in zip(left.axes,right.axes):
        if (a.position,a.array_declaration,a.extent)!=(b.position,b.array_declaration,b.extent):return 'disjoint'
        if max(a.first,b.first)>=min(a.first+a.count,b.first+b.count):return 'disjoint'
        equal=equal and (a.first,a.count)==(b.first,b.count)
    return 'equal' if equal else 'overlap'


def _selected(report,label):
    need(type(label) is str,'ABI_PATH_LABEL')
    matches=[p for p in report.patterns if p.label==label]
    if not matches:
        deferred=[x for x in report.deferred if x.selector_label==label]
        if deferred:fail(deferred[0].code,kind='unavailable')
        fail('ABI_PATH_LABEL')
    need(len(matches)==1,'ABI_PATH_LABEL_DUPLICATE');return matches[0]


def compare_source_paths(owner,left_document,left_label,right_document,right_label,*,budget):
    stamp=_owner(owner,budget)
    left=resolve_source_paths(owner,left_document,budget=budget)
    right=resolve_source_paths(owner,right_document,budget=budget)
    a,b=_selected(left,left_label),_selected(right,right_label)
    relation='disjoint' if left.root_class_key!=right.root_class_key else _cell_relation(a,b,budget)
    same_view=(a.root_view,a.leaf_view,a.covered)==(b.root_view,b.leaf_view,b.covered)
    budget.reserve_bytes(256);need(_owner(owner,budget) is stamp,'ABI_PATH_ORIGINAL_CONTEXT')
    return OriginalSourcePathRelation(owner,stamp,a,b,relation,same_view,(),OBLIGATIONS)


def check_source_coverage(source_program_document,path_document,owner,context_id,cleanup_id,*,budget):
    from .source_programs import Checker
    stamp=_owner(owner,budget)
    associations=check_source_associations_deferred(source_program_document,owner,context_id,budget=budget)
    checker=Checker(source_program_document,budget,deferred=True);checker.run()
    need(type(cleanup_id) is int and cleanup_id in checker.cleanups,'ABI_PATH_CLEANUP_REFERENCE')
    cleanup=checker.cleanups[cleanup_id];record=checker.records[cleanup['record']]
    need(record['source']['context']==context_id,'ABI_PATH_COVERAGE_CONTEXT')
    paths=resolve_source_paths(owner,path_document,budget=budget);source=_Source(owner,budget)
    root=source.get(path_document['root']);original=source.get(record['source']['nominal'])
    need(root['kind']=='record' and source.same(ref(root['id']),ref(original['id']),ignore_top_cv=True),'ABI_PATH_COVERAGE_CLASS')
    need(paths.view==cleanup['view'],'ABI_PATH_COVERAGE_VIEW')
    principals={};deferred=list(associations.deferred)+list(paths.deferred)
    for slot_id in cleanup['slots']:
        slot=checker.slots[record['id']][slot_id];routes=[]
        for route in slot['paths']:
            steps=[dict(kind=x['kind'],declaration_index=x['declaration_index'],**({} if x['kind']=='member' else dict(virtual=x['virtual']))) for x in route]
            # SourcePrograms slot describes the entire field array, not a fake
            # one-dimensional final leaf. Its original declared source is kept.
            routes.append(steps)
        selector=dict(label='slot'+str(slot_id),declared_leaf=slot['source']['nominal'],routes=routes)
        doc=dict(format='original-source-paths',revision=1,binding='unbound',runtime_authority=False,source_fact_authority=False,
                 root=record['source']['nominal'],view=cleanup['view'],selectors=[selector])
        result=resolve_source_paths(owner,doc,budget=budget)
        if result.deferred:deferred.extend(result.deferred);continue
        cell=result.patterns[0];need(cell.canonical_skeleton,'ABI_PATH_SLOT_IDENTITY')
        token=cell.canonical_skeleton[0]
        need(len(cell.canonical_skeleton)==1 and slot['kind']==('virtual_base' if token[0]=='virtual_base' else 'nonvirtual_base' if token[0]=='nonvirtual_base' else 'member'),'ABI_PATH_SLOT_IDENTITY')
        need(token not in principals,'ABI_PATH_SLOT_DUPLICATE');principals[token]=slot_id
    memberships=[]
    for pattern in paths.patterns:
        token=None if not pattern.canonical_skeleton else pattern.canonical_skeleton[0]
        if token is None:memberships.append((pattern.label,'root',None));continue
        if token not in principals:
            if not associations.deferred:fail('ABI_PATH_COVERAGE_VIEW')
            continue
        memberships.append((pattern.label,token[0],principals[token]));budget.reserve_bytes(128)
    for i,left in enumerate(paths.patterns):
        for right in paths.patterns[i+1:]:
            budget.work(1);need(_cell_relation(left,right,budget)=='disjoint','ABI_PATH_COVERAGE_DUPLICATE')
    program_key=(stamp.context_anchor,_qkey(cleanup['journal_program']),cleanup['view'])
    budget.reserve_bytes(512);need(_owner(owner,budget) is stamp,'ABI_PATH_ORIGINAL_CONTEXT')
    return OriginalSourceCoverage(owner,stamp,paths,associations,context_id,cleanup_id,program_key,
                                  tuple(memberships),tuple(cleanup['slots']),tuple(deferred),OBLIGATIONS)
