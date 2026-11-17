"""Unbound union reference package; importing it never imports either candidate."""

def load_tests(loader,tests,pattern):
    from .discovery import isolated_suite
    return isolated_suite(pattern)
