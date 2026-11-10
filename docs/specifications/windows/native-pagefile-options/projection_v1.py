"""Project original native rows without consulting emulator code."""
import re

def require(condition, message):
    if not condition:
        raise ValueError(message)

def fields(line):
    return dict(re.findall('([\\w-]+)=([^\\s]+)', line))

def projection(raw):
    cases, regions, unmaps = ([], {}, {})
    kernel = alias = done = None
    for line in raw.decode('ascii').splitlines():
        row = fields(line)
        if line.startswith('KERNEL '):
            require(kernel is None, 'native projection boundary')
            kernel = row
            require([int(row[k]) for k in ('major', 'minor', 'build')] == [10, 0, 29704], 'native projection boundary')
        elif line.startswith('CREATE '):
            require(row['status'] == '00000000' and row['maximum'] == '65536', 'native projection boundary')
            require(row['protect'] == '00000004' and row['attributes'] == '08000000', 'native projection boundary')
        elif line.startswith('CASE '):
            require(int(row['ordinal']) == len(cases), 'native projection boundary')
            numeric = {k: int(v, 16 if k in {'flags', 'zero', 'offset-in', 'base-in', 'protect', 'status', 'base-out', 'offset-out'} else 10) for k, v in row.items()}
            numeric['base_unchanged'] = numeric['base-in'] == numeric['base-out']
            numeric['base_nonzero'] = numeric['base-out'] != 0
            numeric['base_aligned'] = numeric['base-out'] % 65536 == 0
            cases.append(numeric)
        elif line.startswith('REGION '):
            ordinal = int(row.pop('ordinal'))
            require(ordinal not in regions, 'native projection boundary')
            regions[ordinal] = row
        elif line.startswith('UNMAP '):
            ordinal = int(row['ordinal'])
            require(ordinal not in unmaps and row['status'] == '00000000', 'native projection boundary')
            unmaps[ordinal] = row['status']
        elif line.startswith('ALIAS '):
            require(alias is None, 'native projection boundary')
            alias = row
            require(all((row[k] == '00000000' for k in ('write-status', 'read-status', 'write-unmap', 'close', 'read-unmap'))), 'native projection boundary')
            require(row['write-size'] == row['read-size'] == '65536', 'native projection boundary')
            require(row['coherent'] == row['retained-after-close'] == '1', 'native projection boundary')
            require(int(row['write-base'], 16) > int(row['read-base'], 16) > 0, 'native projection boundary')
        elif line.startswith('DONE '):
            require(done is None, 'native projection boundary')
            done = row
    require(kernel and alias and done and (len(cases) == 138), 'native projection boundary')
    require(done['cases'] == done['expected'] == '138' and done['failures'] == '0', 'native projection boundary')
    require(done['handles-before'] == done['handles-after'], 'native projection boundary')
    success = {row['ordinal'] for row in cases if row['status'] < 2147483648}
    require(len(success) == 64 and set(regions) == set(unmaps) == success, 'native projection boundary')
    require(done['mapped'] == done['released'] == '66', 'native projection boundary')
    for row in cases:
        require(row['inherit'] == 2 and row['protect'] == 4, 'native projection boundary')
        if row['ordinal'] in success:
            require(row['base_nonzero'] and row['base_aligned'], 'native projection boundary')
            require(0 < row['size-out'] <= 65536 and row['size-out'] % 4096 == 0, 'native projection boundary')
            region = regions[row['ordinal']]
            require(int(region['queried']) in (28, 48), 'native projection boundary')
            require(region['state'] == '00001000' and region['type'] == '00040000', 'native projection boundary')
            require(region['protect'] == region['allocation-protect'] == '00000004', 'native projection boundary')
            require(int(region['region-bytes']) >= row['size-out'], 'native projection boundary')
        else:
            require(row['base_unchanged'] and row['size-out'] == row['size-in'], 'native projection boundary')
        require(row['offset-out'] == row['offset-in'], 'native projection boundary')
        del row['base-in'], row['base-out']
    alias_projection = {k: v for k, v in alias.items() if k not in ('write-base', 'read-base')}
    alias_projection['top_view_above_ordinary_view'] = True
    return dict(kernel=kernel, cases=cases, alias=alias_projection, lifetime=done)
