"""Ordinary C++ Switch coroutine pipeline and portable frame header geometry."""
from canonical import require


EARLY, SPLIT, CLEANUP = 'CoroEarlyPass', 'CoroSplitPass', 'CoroCleanupPass'


def normalize_policy(operands):
    """Decoded MDTuples after full-LTO/import; semantic dedup, O(N) time.

    Every input module is checked before linking/import, not just the merged
    destination. APInt i32 and MDString/i1 are decoded without integer/bool alias.
    Missing/unknown/conflicting policy fails before optimizer or code movement.
    """
    require(type(operands) is list and len(operands) >= 1, 'E-CORO-ALLOCATION-POLICY')
    require(len(operands) <= 65536, 'E-CORO-POLICY-RESOURCE')
    for item in operands:
        require(type(item) is list and len(item) == 3 and type(item[0]) is int and
                item[0] == 1 and item[1] == 'switch' and type(item[2]) is bool and item[2],
                'E-CORO-ALLOCATION-POLICY')
    return [[1, 'switch', True]]


def import_policy(destination, source):
    """Validate BOTH original modules before import and restore destination MD."""
    normalize_policy(destination)
    normalize_policy(source)
    return [[1, 'switch', True]]


def required_passes(level, phase):
    """Relevant pass subsequence, not a replacement for the pinned pipeline.

    level0/1/2/3; phases none/full-pre/thin-pre/full-post/thin-post.
    O(1) time/space. Optimizers may visit CGSCC/function passes repeatedly.
    """
    require(type(level) is int and level in (0, 1, 2, 3), 'E-CORO-PIPELINE')
    require(phase in ('none', 'full-pre', 'thin-pre', 'full-post', 'thin-post'), 'E-CORO-PIPELINE')
    if level == 0 or phase == 'full-post' and level == 1:
        return [EARLY, SPLIT, CLEANUP]
    if phase == 'thin-pre':
        return [EARLY]  # CoroElide can run, but frame split/cleanup is deferred.
    return ([] if phase == 'thin-post' else [EARLY]) + [SPLIT, 'CoroAnnotationElidePass', CLEANUP]


def promise_offset(alignment):
    """Two 8 B code tokens, followed by source-aligned promise; O(1)."""
    require(type(alignment) is int and 1 <= alignment <= 2**32 and
            alignment & (alignment - 1) == 0, 'E-CORO-PROMISE-ALIGN')
    return (16 + alignment - 1) & -alignment


def opaque_suspend_check(blocks, opaque_values):
    """SSA block-split liveness witness; opaque includes recursively containing E.

    Input blocks have exact id/defs/uses/edges/suspend fields. Edges each carry
    target and uses (phi incoming SSA operands on THAT edge). defs includes phi
    results, uses excludes those incoming operands. A suspend ends its block.
    This input is compiler-internal verified SSA, not an executable wire schema.
    O(B*(B+E)*max(1,V)) conservative set-operation time, O(B*V+E) retained space;
    B blocks, E edges+edge uses, V distinct SSA values. B<=512,V<=65536 resource
    profile, before quadratic state allocation. No opaque zero/serialization.
    """
    require(type(blocks) is list and len(blocks) <= 512, 'E-CORO-LIVENESS-RESOURCE')
    require(type(opaque_values) is set, 'E-CORO-LIVENESS-SHAPE')
    by_id = {}
    values = set()
    for block in blocks:
        require(type(block) is dict and set(block) == {'id','defs','uses','edges','suspend'},
                'E-CORO-LIVENESS-SHAPE')
        identifier = block['id']
        require(type(identifier) is int and identifier not in by_id and type(block['suspend']) is bool,
                'E-CORO-LIVENESS-SHAPE')
        require(all(type(block[k]) is list for k in ('defs','uses','edges')), 'E-CORO-LIVENESS-SHAPE')
        values.update(block['defs']); values.update(block['uses'])
        for edge in block['edges']:
            require(type(edge) is dict and set(edge) == {'target','uses'} and type(edge['uses']) is list,
                    'E-CORO-LIVENESS-SHAPE')
            values.update(edge['uses'])
        require(len(values) <= 65536, 'E-CORO-LIVENESS-RESOURCE')
        by_id[identifier] = block
    require(opaque_values <= values, 'E-CORO-LIVENESS-SHAPE')
    for block in blocks:
        require(all(edge['target'] in by_id for edge in block['edges']), 'E-CORO-LIVENESS-SHAPE')
    incoming = {identifier:set() for identifier in by_id}
    changed = True
    while changed:
        changed = False
        for block in reversed(blocks):
            outgoing = set()
            for edge in block['edges']:
                outgoing.update(incoming[edge['target']]); outgoing.update(edge['uses'])
            live = set(block['uses']) | (outgoing - set(block['defs']))
            if live != incoming[block['id']]:
                incoming[block['id']] = live
                changed = True
    for block in blocks:
        if block['suspend']:
            outgoing = set()
            for edge in block['edges']:
                outgoing.update(incoming[edge['target']]); outgoing.update(edge['uses'])
            require(not outgoing & opaque_values, 'E-CORO-OPAQUE-SPILL')
    return incoming
