"""Optional actual-factory logical accounting; None preserves legacy behavior."""
from common import require


def check(budget):
    if budget is not None:
        from .source_data_projection import source_api
        require(type(budget) is source_api().SourceQueryBudget, 'V3_FACTORY_BUDGET')
    return budget


def charge(budget, *, work=0, edges=0, copied_bytes=0):
    if budget is not None:
        budget.charge(work=work, edges=edges, copied_bytes=copied_bytes)


def lookup(budget, entries, width=16):
    charge(budget, work=8 * (entries + 1) * (width + 1), edges=1)


def collection(budget, entries, width=16):
    charge(budget, work=16 * (entries + 1)**2 * (width + 1),
           edges=entries, copied_bytes=128 * (entries + 1))


def json_bound(value, budget):
    """Bound sorted compact ensure_ascii JSON before serializer allocation."""
    if budget is None:
        return 0
    pending = [(value, 0)]
    size = nodes = 0
    while pending:
        item, depth = pending.pop()
        charge(budget, work=4, edges=1)
        nodes += 1
        require(nodes <= 1000000 and depth <= min(128, budget.max_depth),
                'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        if item is None or type(item) is bool:
            size += 5
        elif type(item) is int:
            require(item.bit_length() <= 128, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            charge(budget, work=128, copied_bytes=64)
            size += 42
        elif type(item) is str:
            charge(budget, work=4 * len(item))
            size += 12 * len(item) + 2
        elif type(item) in (list, tuple):
            charge(budget, work=4 * len(item), edges=len(item), copied_bytes=32 * len(item))
            size += 2 + len(item)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is dict:
            charge(budget, work=4 * len(item), edges=len(item))
            collection(budget, len(item), max((len(k) for k in item if type(k) is str), default=0) + 1)
            require(all(type(k) is str for k in item), 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
            size += 2 + 2 * len(item)
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        else:
            require(False, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    charge(budget, work=8 * (size + 1), copied_bytes=4 * (size + 1))
    return size


def graph(budget, vertices, edges, label_bytes):
    if budget is not None:
        require(0 <= vertices <= 4096 and 0 <= edges <= 65536 and
                0 <= label_bytes <= 16 * 1024 * 1024,
                'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        charge(budget, work=64 * (vertices + 1)**3 * (vertices + edges + label_bytes + 1),
               edges=64 * (vertices + 1)**3 * (vertices + edges + 1),
               copied_bytes=128 * (vertices + 1)**2 * (vertices + edges + label_bytes + 1))


def step(budget):
    # Fixed loop bookkeeping; variable primitive payloads have their own guards.
    charge(budget, work=64, edges=1, copied_bytes=128)
    return True


def iter_rows(budget, source):
    if budget is None:
        return source
    def observed():
        iterator = iter(source)
        while True:
            step(budget)
            try:
                value = next(iterator)
            except StopIteration:
                return
            yield value
    return observed()


def snapshot_bound(value, budget):
    if budget is None:
        return
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        charge(budget, work=8, edges=1, copied_bytes=128)
        require(depth <= min(128, budget.max_depth), 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        if type(item) in (str, bytes):
            charge(budget, work=4 * len(item), copied_bytes=4 * len(item))
        elif item is None or type(item) in (bool, int):
            pass
        elif type(item) in (list, tuple, set, frozenset):
            collection(budget, len(item))
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is dict:
            collection(budget, len(item))
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        else:
            require(False, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')


def body_node(node, budget):
    """Before targets/uses/operation shell allocations on this actual node.

    json_bound covers scalar payloads. collection covers immediate argument,
    result, flag, index, mask, case and target list copies/scans/sets/sorts.
    Recursive type/equality/layout operations charge through actual Types/Layout.
    """
    if budget is None:
        return
    json_bound(node, budget)
    entries = sum(len(value) for value in node.values() if type(value) in (list, dict))
    collection(budget, entries + len(node))


def internal_helper(binding, dependencies, budget):
    """Precharge original bindings.validate plus its actual runtime helpers.

    Restricted to the three initial Journal helpers: no source-role/service/
    foreign/native callback is entered. Runtime JSON reads: candidate x3
    (documents and validate_shape encode/decode), helpers-v1 x5 (documents,
    two helper lookups, instantiate lookup and digest). Preparse bounds precede
    our oracle parse; repeated json_bound charges each delegated parse/copy/
    canonical digest and catalog scan. Actual type resolution charges itself.
    """
    if budget is None:
        return
    require(binding['kind'] == 'internal' and binding['name'] in
            ('journal_begin', 'journal_advance', 'journal_publish_object'),
            'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
    from pathlib import Path
    import json
    root = Path(__file__).resolve().parents[4]
    for name, calls in (('candidate.json', 3), ('helpers-v1.json', 5)):
        path = root / 'docs/specifications/smir/portable/schema/runtime' / name
        size = path.stat().st_size
        require(size <= 1024 * 1024, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        charge(budget, work=8 * (size + 1), copied_bytes=16 * (size + 1))
        with path.open('rb') as stream:
            raw = stream.read(size + 1)
        require(len(raw) == size, 'V3_ORIGINAL_FACTORY_COST_UNAVAILABLE')
        document = json.loads(raw)
        for _ in range(calls):
            json_bound(document, budget)
    body_node(binding, budget)
    # resolve() makes shallow dict views of exact namespace rows. The finite
    # initial profile limits Journal params to16; charge every actual possible
    # row and formal before original capture expansion and shape comparisons.
    for table in (dependencies.cleanup_programs, dependencies.nominals,
                  dependencies.abi_signatures, dependencies.layouts):
        collection(budget, len(table))
        for row in table.values():
            snapshot_bound(row, budget)


def operation_shell(node, dependencies, budget):
    if budget is None:
        return
    body_node(node, budget)
    # dependencies.target is called once by call/invoke/tailcall. A helper
    # operation calls target itself and once again through call_types.
    for field, repeats in (('target', 1), ('helper', 2)):
        target = node.get(field)
        if type(target) is dict and target.get('kind') == 'import':
            from .type_system import key
            identity = key(target['import'])
            require(identity in dependencies.imports, 'call_import_reference')
            for _ in range(repeats):
                internal_helper(dependencies.imports[identity], dependencies, budget)
