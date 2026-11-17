"""Cross-module source call plans; compiled bodies and local IDs are not ABI."""
from nominal import option
import factory_meter as M
from namespaces import Entities
from layout import require


def same_execution(context, left, right, *, budget=None):
    """Same-context component predicate using actual raw execution descriptors.

    These callbacks remain reference inputs, not API6 source-view/private facts.
    Missing raw metadata is an explicit error, never digest-only compatibility.
    """
    M.check_budget(budget)
    M.charge(budget,work=1,copied_bytes=256)
    pending, seen = [(left, right)], set()
    excluded = {'id', 'fields', 'params', 'results', 'element', 'signature'}
    while pending:
        M.collection(budget,len(seen)+1)
        ar, br = pending.pop()
        a, b = context.execution(ar).get('record'), context.execution(br).get('record')
        require(isinstance(a, dict) and isinstance(b, dict), 'ABI_CC_EXECUTION_EVIDENCE')
        M.copy_cost(a,budget);M.copy_cost(b,budget)
        pair = a['id'], b['id']
        if pair in seen:
            continue
        require(len(seen) < 4096, 'ABI_CC_GRAPH_LIMIT')
        seen.add(pair)
        labels = [{k: v for k, v in value.items() if k not in excluded} for value in (a, b)]
        if labels[0] != labels[1]:
            return False
        from execution_shapes import ExecutionShapes
        ac, bc = ExecutionShapes.children(a), ExecutionShapes.children(b)
        if len(ac) != len(bc) or a['kind'] == 'function' and len(a['params']) != len(b['params']):
            return False
        M.charge(budget,work=4*len(ac),edges=len(ac),copied_bytes=128*len(ac))
        pending.extend(zip(ac, bc))
    return True


def compatible(graph,left,right,left_owner=None,right_owner=None):
    left_owner=left_owner or graph.module_id
    right_owner=right_owner or graph.module_id
    entities=Entities(graph.module_id,graph.modules[graph.module_id],
        {name:doc for name,doc in graph.modules.items() if name!=graph.module_id},graph.bindings)
    try:
        ae=entities.resolve('signature',left,left_owner);be=entities.resolve('signature',right,right_owner)
        a,b=ae.record,be.record;ao,bo=ae.module,be.module
        if not graph.boundary_compatible(a['function_type'],b['function_type'],ao,bo):
            return False
        af=graph.resolve(a['function_type'],ao)[1];bf=graph.resolve(b['function_type'],bo)[1]
        c_linkage='c_linkage' in af['flags'] and 'c_linkage' in bf['flags']
        def typ(x,y):
            return graph.data_boundary_compatible(x,y,ao,bo) if c_linkage else graph.boundary_compatible(x,y,ao,bo)
        def optional_type(x,y):
            return (x is None and y is None) or (x is not None and y is not None and typ(option(x),option(y)))
        for name in ('vtt','variadic','noexcept','return_noundef'):
            if a[name]!=b[name]:return False
        if not optional_type(a['this_type'],b['this_type']) or not optional_type(a['result'],b['result']):return False
        for name in ('params','lowered_results'):
            if len(a[name])!=len(b[name]) or not all(typ(x,y) for x,y in zip(a[name],b[name])):return False
        def recipe(identifier,owner):
            if identifier is None:return None
            return entities.resolve('recipe',{'module':{'kind':'self'},'id':option(identifier)},owner)
        def recipe_interface(x,y):
            if x is None or y is None:return x is y
            xd=next(d for d in graph.modules[x.module]['domains'] if d['id']==x.record['domain'])
            yd=next(d for d in graph.modules[y.module]['domains'] if d['id']==y.record['domain'])
            if any(xd[k]!=yd[k] for k in ('isa','personality','abi','abi_identity')):return False
            xp=[v['type'] for v in x.record['params']];yp=[v['type'] for v in y.record['params']]
            for xs,ys in ((xp,yp),(x.record['results'],y.record['results'])):
                if len(xs)!=len(ys) or not all(graph.boundary_compatible(u,v,x.module,y.module) for u,v in zip(xs,ys)):return False
            return True
        if len(a['lowered_params'])!=len(b['lowered_params']):return False
        for x,y in zip(a['lowered_params'],b['lowered_params']):
            if any(x[k]!=y[k] for k in ('source_index','role','mode','align','bytes','noundef')):return False
            if not typ(x['source_type'],y['source_type']) or not typ(x['value_type'],y['value_type']):return False
            for role in ('copy','move','destroy'):
                if not recipe_interface(recipe(x[role],ao),recipe(y[role],bo)):return False
        av,bv=option(a['varargs']),option(b['varargs'])
        if av is None or bv is None:return av is bv
        if any(av[k]!=bv[k] for k in ('header_bytes','cookie_scope','type_reference')):return False
        al=graph.layouts[ao][av['state_layout']];bl=graph.layouts[bo][bv['state_layout']]
        # table_module is caller-local registration authority, not provider ID
        # equality. Its exact binding is checked by each admitted arena context.
        return (al['size'],al['align'])==(bl['size'],bl['align'])==(32,8)
    except (KeyError,IndexError,ValueError,StopIteration):
        return False
