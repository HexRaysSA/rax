"""Explicit source-object/LLVM memory correspondence, independent of value shape."""

from layout import alignment, require
import math


def verify_binding(binding, graph, memory_layout):
    source = graph.layout(binding['nominal'])
    physical = memory_layout(binding['execution_layout'])
    require(binding['kind'] in ('allocation','object_bytes', 'fieldwise', 'bit_container'), 'ABI_CC_STORAGE_VIEW')
    alignment(binding['required_alignment'])
    require(binding['required_alignment'] <= source['align'] and
            binding['access_bytes'] == physical['access_bytes'] <= physical['size'], 'ABI_CC_STORAGE_ACCESS')
    start, width = binding['view_offset_bits'], binding['view_width_bits']
    require(width > 0 and start + width <= source['size'] * 8, 'ABI_CC_STORAGE_VIEW_EXTENT')
    require(start % 8 == 0 and binding['required_alignment'] <= math.gcd(source['align'], start // 8),
            'ABI_CC_STORAGE_VIEW_ALIGNMENT')
    if binding['kind']=='allocation':
        require(start==0 and width==source['size']*8 and physical['size']==source['size'],
                'ABI_CC_STORAGE_ALLOCATION')
        require(binding['fragments']==[{'source_path':[],'source_offset_bits':0,
            'execution_offset_bits':0,'width_bits':width,'role':'object_representation'}],
            'ABI_CC_STORAGE_ALLOCATION_FRAGMENT')
        return True
    if binding['kind'] == 'object_bytes':
        require(start == 0 and width == source['size'] * 8 and physical['size'] == source['size'],
                'ABI_CC_STORAGE_ALLOCATION')
    value_bits = 0
    occupied = 0
    require(source['size'] <= 1024 * 1024, 'ABI_CC_STORAGE_REFERENCE_RESOURCE')
    source_mask = int.from_bytes(graph.value_mask(binding['nominal']), 'little')
    effect_start=start
    effect_end=start+physical['access_bytes']*8
    require(effect_end<=source['size']*8,'ABI_CC_STORAGE_EFFECT_RANGE')
    effect_mask=((1 << (effect_end-effect_start))-1) << effect_start
    view_mask = ((1 << width) - 1) << start
    require(source_mask & effect_mask & ~view_mask == 0,'ABI_CC_STORAGE_EFFECT_VALUE_CLOBBER')
    for fragment in binding['fragments']:
        require(fragment['role'] in ('value', 'padding', 'base', 'vptr'), 'ABI_CC_STORAGE_FRAGMENT_ROLE')
        src, dst, count = fragment['source_offset_bits'], fragment['execution_offset_bits'], fragment['width_bits']
        require(count > 0 and start <= src and src + count <= start + width and
                dst + count <= physical['size'] * 8, 'ABI_CC_STORAGE_FRAGMENT_EXTENT')
        require(dst == src - start, 'ABI_CC_STORAGE_POSITION')
        bits = ((1 << count) - 1) << src
        require(occupied & bits == 0, 'ABI_CC_STORAGE_FRAGMENT_OVERLAP')
        occupied |= bits
        if fragment['role'] != 'padding':
            require(dst + count <= physical['access_bytes'] * 8, 'ABI_CC_STORAGE_EFFECT_EXTENT')
            value_bits |= bits
        else:
            require(source_mask & bits == 0, 'ABI_CC_STORAGE_VALUE_AS_PADDING')
        if fragment['source_path']:
            current, owner, offset, bound = binding['nominal'], graph.module_id, 0, source['size'] * 8
            for name in fragment['source_path']:
                layout = graph.layout(current, owner)
                matches = [field for field in layout['fields'] if field['name'] == name]
                require(len(matches) == 1, 'ABI_CC_STORAGE_SOURCE_PATH')
                selected = matches[0]
                offset += selected['offset_bits']
                bound = selected['width_bits']
                owner, _ = graph.resolve(current, owner)
                current = selected['type']
            require(offset <= src and src + count <= offset + bound, 'ABI_CC_STORAGE_SOURCE_PATH')
    require(value_bits == source_mask & view_mask, 'ABI_CC_STORAGE_VALUE_COVERAGE')
    return True
