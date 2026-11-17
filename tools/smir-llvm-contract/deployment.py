"""Independent declaration/deployment binder, no guest execution or authority."""
import hashlib

from canonical import digest, json_bytes, keys, require, text, uint


def symbol_identity(module_key, declaration):
    # Deployment family pins lookup; public ODR identity crosses those families.
    text(module_key)
    keys(declaration, 'id namespace name kind source_linkage signature nominal abi_signature')
    uint(declaration['id'])
    require(declaration['kind'] in ('function', 'data', 'tls'), 'LINK_KIND')
    require(declaration['source_linkage'] in ('none','c','cpp'),'LINK_SOURCE_LINKAGE')
    call_plan = declaration['abi_signature']
    source_function = declaration['kind'] == 'function' and declaration['source_linkage'] != 'none'
    require(source_function == (call_plan is not None), 'LINK_CALL_PLAN_PRESENCE')
    if call_plan is not None:
        digest(call_plan)
    return hashlib.sha256(json_bytes({
        'namespace': text(declaration['namespace']),
        'name': text(declaration['name']), 'kind': declaration['kind'],
        'source_linkage': declaration['source_linkage'],
        'signature': digest(declaration['signature']), 'nominal': digest(declaration['nominal']),
        'abi_signature': call_plan,
    })).hexdigest()


def bind_deployment(modules, deployment):
    """Validate whole SCC deployment before returning any declaration bindings.

    artifact digest inputs must already be verified against canonical module bytes
    by the integrator. This does not trust an artifact's self-declared digest as
    authority. Deployment generations come from runtime admission, not the file.
    O(V+E+declarations) time/space excluding string sorting for stable output.
    """
    require(type(modules) is list and type(deployment) is dict, 'LINK_INPUT')
    by_key = {}
    exports = {}
    for module in modules:
        keys(module, 'key artifact abi version exports dependencies')
        key = text(module['key'])
        require(key and key not in by_key, 'LINK_DUPLICATE_MODULE')
        digest(module['artifact'])
        digest(module['abi'])
        uint(module['version'])
        require(type(module['exports']) is list and type(module['dependencies']) is list, 'LINK_SEQUENCE')
        by_key[key] = module
        table = {}
        export_ids = set()
        for exported in module['exports']:
            symbol_identity(key, exported)
            identity = (exported['namespace'], exported['name'], exported['kind'])
            require(identity not in table and exported['id'] not in export_ids, 'LINK_DUPLICATE_EXPORT')
            export_ids.add(exported['id'])
            table[identity] = exported
        exports[key] = table
    require(deployment.keys() == by_key.keys(), 'LINK_DEPLOYMENT_SET')
    generations = {}
    for key, admission in deployment.items():
        keys(admission, 'artifact abi generation')
        digest(admission['artifact'])
        digest(admission['abi'])
        uint(admission['generation'], 64)
        require(admission['generation'] != 0, 'LINK_GENERATION')
        module = by_key[key]
        require(admission['artifact'] == module['artifact'], 'LINK_ARTIFACT')
        require(admission['abi'] == module['abi'], 'LINK_MODULE_ABI')
        generations[key] = admission['generation']
    bindings = {}
    graph = {key: [] for key in by_key}
    for key, module in by_key.items():
        slots = set()
        for dependency in module['dependencies']:
            keys(dependency, 'slot key abi minimum_version maximum_version declarations')
            slot = uint(dependency['slot'])
            require(slot not in slots, 'LINK_DUPLICATE_SLOT')
            slots.add(slot)
            target_key = text(dependency['key'])
            require(target_key in by_key, 'LINK_MISSING_MODULE')
            target = by_key[target_key]
            require(digest(dependency['abi']) == target['abi'], 'LINK_DEPENDENCY_ABI')
            minimum, maximum = uint(dependency['minimum_version']), uint(dependency['maximum_version'])
            require(minimum <= target['version'] <= maximum, 'LINK_VERSION')
            require(type(dependency['declarations']) is list, 'LINK_SEQUENCE')
            graph[key].append(target_key)
            declared_ids = set()
            for declaration in dependency['declarations']:
                symbol_identity(target_key, declaration)
                identifier = declaration['id']
                require(identifier not in declared_ids, 'LINK_DUPLICATE_DECLARATION')
                declared_ids.add(identifier)
                identity = (declaration['namespace'], declaration['name'], declaration['kind'])
                require(identity in exports[target_key], 'LINK_MISSING_EXPORT')
                exported = exports[target_key][identity]
                require(declaration['source_linkage']==exported['source_linkage'],'LINK_SOURCE_LINKAGE')
                require(declaration['signature'] == exported['signature'], 'LINK_EXECUTION_SIGNATURE')
                require(declaration['nominal'] == exported['nominal'], 'LINK_NOMINAL_SIGNATURE')
                require(declaration['abi_signature'] == exported['abi_signature'], 'LINK_SOURCE_CALL_PLAN')
                bindings[key, slot, identifier] = (target_key, exported['id'], generations[target_key])
    # Iterative Kosaraju: no recursion depth depends on the import graph.
    reverse = {key: [] for key in graph}
    for source, targets in graph.items():
        for target in targets:
            reverse[target].append(source)
    visited, finished = set(), []
    for start in sorted(graph):
        if start in visited:
            continue
        pending = [(start, False)]
        while pending:
            key, exit_node = pending.pop()
            if exit_node:
                finished.append(key)
            elif key not in visited:
                visited.add(key)
                pending.append((key, True))
                pending.extend((target, False) for target in sorted(graph[key], reverse=True) if target not in visited)
    components, visited = [], set()
    for start in reversed(finished):
        if start in visited:
            continue
        component, pending = [], [start]
        visited.add(start)
        while pending:
            key = pending.pop()
            component.append(key)
            for target in reverse[key]:
                if target not in visited:
                    visited.add(target)
                    pending.append(target)
        components.append(sorted(component))
    # Publication is this return, after every artifact/declaration passes. There
    # is deliberately no callback/constructor/token creation API in this model.
    return {'bindings': bindings, 'components': components}
