"""Canonical live SSA environment before a precise execution frontier."""
from .errors import option, require, unique


def targets(term):
    op=term['op']
    if op=='jump':return [term['target']]
    if op=='cbranch':return [term['true'],term['false']]
    if op=='switch':return [term['default']]+[item['target'] for item in term['cases']]
    if op=='invoke':return [term['normal']['target'],term['unwind']['target']]
    if op=='indirect_branch':return term['targets']
    return []


def uses(node):
    values=set(node.get('operands',[]))
    field={'cbranch':'condition','switch':'index','indirect_branch':'address'}.get(node['op'])
    if field is not None:values.add(node[field])
    if node['op']=='return':values.update(node['values'])
    if 'exception' in node:
        value=node['exception']
        if type(value) is int:values.add(value)
        elif value is not None:values.add(option(value))
    for name in ['target','helper']:
        value=node.get(name)
        if type(value) is dict and value['kind']=='indirect':values.add(value['value'])
    return values


class Flow:
    """Least fixed-point liveness: O(V*E*L+operations*L), O(V*L).

    V blocks, E CFG edges, L SSA values. Roots MUST already pass full execution
    type/CFG/dominance verification. This does not admit arbitrary code.
    """
    def __init__(self,function,exception_data=None):
        self.function=function
        self.blocks=unique(function['blocks'],'id')
        self.definitions={item['id']:item['type'] for item in function['params']}
        self.phis={b:{p['result']['id'] for p in block['phis']} for b,block in self.blocks.items()}
        self.edge_defs={}
        self.predecessors={b:set() for b in self.blocks}
        self.extra={b:set() for b in self.blocks}
        exception_data=exception_data or {'actions':[],'regions':[]}
        actions=unique(exception_data['actions'],'id')
        regions=unique(exception_data['regions'],'id')
        for block_id,block in self.blocks.items():
            for phi in block['phis']:self.definitions[phi['result']['id']]=phi['result']['type']
            for operation in block['ops']:
                self.definitions.update({r['id']:r['type'] for r in operation['results']})
            for target in targets(block['term']):self.predecessors[target].add(block_id)
            term=block['term']
            if term['op']=='invoke':
                region=term['region']
                while region is not None:
                    current=regions[region]
                    selected=list(current['exit_actions'])
                    for handler in current['handlers']:
                        selected+=handler['cleanup_actions']
                        if handler['catch_copy'] is not None:selected.append(option(handler['catch_copy']))
                    for action in selected:
                        for capture in actions[action]['captures']:
                            if capture['source']['kind']=='value':self.extra[block_id].add(capture['source']['value'])
                    region=option(current['parent'])
                for edge,declarations in [(term['normal'],term['normal']['results']),
                                           (term['unwind'],[term['unwind']['exception']])]:
                    self.edge_defs[edge['target']]={d['id'] for d in declarations}
                    self.definitions.update({d['id']:d['type'] for d in declarations})
        self.before={b:set() for b in self.blocks}
        self.after={b:set() for b in self.blocks}
        changed=True
        while changed:
            changed=False
            for block_id,block in reversed(list(self.blocks.items())):
                after=set()
                for target in targets(block['term']):
                    needed=self.before[target]
                    after.update(needed-self.phis[target]-self.edge_defs.get(target,set()))
                    for phi in self.blocks[target]['phis']:
                        if phi['result']['id'] in needed:
                            after.update(pair['value'] for pair in phi['incoming'] if pair['block']==block_id)
                needed=after|uses(block['term'])|self.extra[block_id]
                for operation in reversed(block['ops']):
                    needed.difference_update(d['id'] for d in operation['results'])
                    needed.update(uses(operation))
                if after!=self.after[block_id] or needed!=self.before[block_id]:changed=True
                self.after[block_id],self.before[block_id]=after,needed

    def frontier(self,position):
        block_id=position['block']
        require(block_id in self.blocks,'RT_FRONTIER_BLOCK')
        block=self.blocks[block_id]
        index=position['operation']
        require(0<=index<=len(block['ops']),'RT_FRONTIER_OPERATION')
        predecessor=option(position['predecessor'])
        require((block_id==self.function['entry'] and predecessor is None) or
                predecessor in self.predecessors[block_id],'RT_FRONTIER_PREDECESSOR')
        needed=self.after[block_id]|uses(block['term'])|self.extra[block_id]
        for operation in reversed(block['ops'][index:]):
            needed.difference_update(d['id'] for d in operation['results'])
            needed.update(uses(operation))
        return {identity:self.definitions[identity] for identity in needed}

    def operation(self,position):
        self.frontier(position)
        block=self.blocks[position['block']]
        return block['term'] if position['operation']==len(block['ops']) else block['ops'][position['operation']]
