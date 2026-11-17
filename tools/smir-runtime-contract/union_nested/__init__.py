"""Inert bounded nested reference package; no candidate imported in parent."""
def load_tests(loader,tests,pattern):
    from .discovery import isolated_suite
    return isolated_suite(loader,pattern)
