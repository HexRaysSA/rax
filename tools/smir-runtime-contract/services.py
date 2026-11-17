"""Pure argument/result policy witnesses for the portable import catalog.

No host service is invoked and no numeric status code is allocated. Real memory,
handle, capability, signature and registered-adapter checks remain mandatory.
"""
from catalog import BY_NAME
from link import admit_code_token
from schema import alignment, require


def validate_request(name, arguments, input_buffers=None):
    require(name in BY_NAME, 'UNKNOWN_PORTABLE_IMPORT')
    entry = BY_NAME[name]
    require(type(arguments) is list and len(arguments) == len(entry['params']), 'SERVICE_ARITY')
    for value, kind in zip(arguments, entry['params']):
        require(type(value) is int, 'SERVICE_TYPE')
        if kind == 'i32':
            valid = -2**31 <= value < 2**31
        elif kind == 'u32':
            valid = 0 <= value < 2**32
        else:
            valid = 0 <= value < 2**64
        require(valid, 'SERVICE_RANGE')
        if kind == 'handle':
            require(value != 0, 'SERVICE_HANDLE')
        elif kind == 'code':
            admit_code_token(value)
    for buffer in entry['buffers']:
        address = arguments[buffer['pointer_param']]
        length = arguments[buffer['length_param']]
        if name in {'file.read', 'file.write'}:
            length = min(length, 65536)
        if length:
            require(address != 0 and address + length <= 2**64, 'SERVICE_BUFFER_RANGE')
    if name in {'memory.map', 'memory.protect'}:
        permissions = arguments[2]
        require(permissions & ~3 == 0, 'SERVICE_PERMISSIONS')
    if name == 'memory.map':
        require(arguments[0] > 0 and alignment(arguments[1]), 'SERVICE_MAPPING')
    elif name in {'memory.unmap', 'memory.protect'}:
        require(arguments[0] > 0 and arguments[1] > 0 and
                arguments[0] + arguments[1] <= 2**64, 'SERVICE_MAPPING')
    elif name == 'file.open':
        flags, mode = arguments[2:]
        require(flags & ~31 == 0 and flags & 3 != 0, 'SERVICE_OPEN_FLAGS')
        require(flags & 24 == 0 or flags & 2 != 0, 'SERVICE_OPEN_FLAGS')
        require(mode & ~0o777 == 0, 'SERVICE_OPEN_MODE')
    elif name == 'clock.now':
        require(arguments[0] in {0, 1}, 'SERVICE_CLOCK')
    elif name == 'entropy.fill':
        require(arguments[1] <= 1048576, 'SERVICE_BUFFER_LIMIT')
    elif name == 'thread.spawn':
        size = arguments[2]
        require(size == 0 or (16384 <= size <= 1073741824 and size % 16 == 0),
                'SERVICE_STACK_SIZE')
    elif name in {'sync.wait32', 'sync.wake32'}:
        require(arguments[0] != 0 and arguments[0] % 4 == 0 and
                arguments[0] + 4 <= 2**64, 'SERVICE_WAIT_ADDRESS')
    if name in {'file.open', 'module.open', 'module.symbol'}:
        index = 1 if name == 'module.symbol' else 0
        length_index = index + 1
        require(0 < arguments[length_index] <= 4096, 'SERVICE_NAME_LENGTH')
        require(input_buffers is not None and index in input_buffers, 'SERVICE_INPUT_REQUIRED')
        data = input_buffers[index]
        require(type(data) is bytes and len(data) == arguments[length_index] and b'\0' not in data,
                'SERVICE_INPUT_BYTES')
        try:
            data.decode('utf-8')
        except UnicodeError:
            require(False, 'SERVICE_INPUT_UTF8')
        if name == 'module.open':
            require(len(data) == 64 and all(c in b'0123456789abcdef' for c in data),
                    'SERVICE_MODULE_IDENTITY')
    return True


def to_nanoseconds(seconds, nanoseconds):
    require(type(seconds) is int and seconds >= 0 and type(nanoseconds) is int and
            0 <= nanoseconds < 1000000000, 'CLOCK_REPRESENTATION')
    value = seconds * 1000000000 + nanoseconds
    require(value < 2**64, 'CLOCK_OVERFLOW')
    return value
