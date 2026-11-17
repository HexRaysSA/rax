"""Inspection-only source constraints; no execution or source-fact authority."""


class ContractToolError(ValueError):
    def __init__(self, kind, code, detail=''):
        self.kind, self.code, self.detail = kind, code, detail
        super().__init__(code + (': ' + detail if detail else ''))


def verify(owner, document, *, budget):
    from .api import verify as implementation
    return implementation(owner, document, budget=budget)


def compare(left_owner, left_document, right_owner, right_document, function, *, budget):
    from .api import compare as implementation
    return implementation(left_owner, left_document, right_owner, right_document,
                          function, budget=budget)


def __getattr__(name):
    if name in ('StaticConstraints', 'StaticComparison'):
        from . import api
        return getattr(api, name)
    raise AttributeError(name)


__all__ = ['verify', 'compare', 'StaticConstraints', 'StaticComparison', 'ContractToolError']


def load_tests(loader, tests, pattern):
    """Run this package in a fresh interpreter, preserving legacy parent imports."""
    from .discovery import isolated_suite
    return isolated_suite(loader, pattern)
