"""Canonical reference comparison exception; no runtime admission authority."""

if __name__ != '_rax_smir_call_comparison_errors_v1':
    raise ImportError('comparison errors require the canonical exact-path loader')


class CallComparisonError(Exception):
    """Exact API6 error category/code/detail, immutable after construction."""

    __slots__ = ('_kind', '_code', '_detail')

    def __init__(self, kind, code, detail):
        if hasattr(self, '_kind'):
            raise AttributeError('comparison error is already initialized')
        if type(kind) is not str or kind not in ('semantic', 'unavailable', 'resource'):
            raise ValueError('invalid comparison error kind')
        if type(code) is not str or not code or type(detail) is not str:
            raise ValueError('invalid comparison error code/detail')
        object.__setattr__(self, '_kind', kind)
        object.__setattr__(self, '_code', code)
        object.__setattr__(self, '_detail', detail)
        super().__init__(code + (': ' + detail if detail else ''))

    def __setattr__(self, name, value):
        if name in ('kind', 'code', 'detail', '_kind', '_code', '_detail'):
            raise AttributeError('comparison error fields are immutable')
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name in ('kind', 'code', 'detail', '_kind', '_code', '_detail'):
            raise AttributeError('comparison error fields are immutable')
        super().__delattr__(name)

    @property
    def kind(self):
        return self._kind

    @property
    def code(self):
        return self._code

    @property
    def detail(self):
        return self._detail


_CANONICAL_INITIALIZED = True
