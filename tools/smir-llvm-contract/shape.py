"""Independent bounded bisimulation oracle for S-028 execution-type identity.

Uses pair elimination, distinct from SEMANTICS partition refinement. This is a
reference on resolved labeled graphs, not a producer-supplied identity verifier.
"""
from collections import deque
import hashlib
import json

from canonical import require, uint


def shape_digest(graph, root, max_nodes=128, domain=b'SMIR-TYPE-SHAPE-V1\0'):
    require(type(domain) is bytes and domain.endswith(b'\0'),'SHAPE_DOMAIN')
    require(type(graph) is dict and root in graph, 'SHAPE_ROOT')
    pending, reachable = [root], set()
    while pending:
        node = pending.pop()
        uint(node)
        require(node in graph, 'SHAPE_REFERENCE')
        if node in reachable:
            continue
        reachable.add(node)
        require(len(reachable) <= max_nodes, 'SHAPE_ORACLE_LIMIT')
        record = graph[node]
        require(type(record) is dict and record.keys() == {'label','children'}, 'SHAPE_RECORD')
        require(type(record['label']) is dict and type(record['children']) is list, 'SHAPE_RECORD')
        pending.extend(record['children'])
    ordered = sorted(reachable)
    labels = {node: json.dumps(graph[node]['label'], sort_keys=True, ensure_ascii=True,
                              separators=(',', ':'), allow_nan=False) for node in ordered}
    relation = {(left,right) for left in ordered for right in ordered
                if labels[left] == labels[right] and
                len(graph[left]['children']) == len(graph[right]['children'])}
    while True:
        removed = {(left,right) for left,right in relation
                   if any((a,b) not in relation for a,b in zip(graph[left]['children'], graph[right]['children']))}
        if not removed:
            break
        relation -= removed
    equivalence = {}
    for node in ordered:
        if node in equivalence:
            continue
        representative = node
        for peer in ordered:
            if (node,peer) in relation:
                equivalence[peer] = representative
    indices = {equivalence[root]:0}
    queue = deque([equivalence[root]])
    output = []
    while queue:
        representative = queue.popleft()
        children = []
        for child in graph[representative]['children']:
            group = equivalence[child]
            if group not in indices:
                indices[group] = len(indices)
                queue.append(group)
            children.append(indices[group])
        output.append({'label':json.loads(labels[representative]), 'children':children})
    encoded = json.dumps(output, sort_keys=True, ensure_ascii=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii')
    return hashlib.sha256(domain + encoded).hexdigest()


def execution_view(records):
    """Project resolved local execution records to S-028 labels/ordered edges."""
    result = {}
    child_fields = {'id','fields','params','results','element','signature'}
    for record in records:
        identifier = uint(record['id'])
        require(identifier not in result, 'SHAPE_DUPLICATE')
        kind = record['kind']
        label = {k:v for k,v in record.items() if k not in child_fields}
        if kind == 'function':
            refs = record['params'] + record['results']
            label['parameter_count'], label['result_count'] = len(record['params']), len(record['results'])
        elif kind == 'code_ptr':
            refs = [record['signature']]
        elif kind in ('array','vector'):
            refs = [record['element']]
        elif kind == 'struct':
            refs = record['fields']
        else:
            refs = []
        require(all(ref['module'] == {'kind':'self'} for ref in refs), 'SHAPE_UNRESOLVED_DEPENDENCY')
        result[identifier] = {'label':label, 'children':[ref['id'] for ref in refs]}
    return result
