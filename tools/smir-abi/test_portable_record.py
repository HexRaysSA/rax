"""Stdlib-only registration for the real isolated portable frontend test suite."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest


class NativeTypeProfile(unittest.TestCase):
    def test_actual_native_profile(self):
        native = os.environ.get('PORTABLE_RECORD_NATIVE')
        if not native:
            self.skipTest('PORTABLE_RECORD_NATIVE_PROFILE_UNAVAILABLE: explicit native tool required')
        # Foundation selection remains in the real child. A draft without its
        # explicit foundation is unavailable, not an implicit workspace search.
        installed = Path(__file__).resolve().parents[2]
        if (not os.environ.get('SMIR_RECORD_FRONTEND_FOUNDATION') and
                not (installed / 'tools/smir-abi/nominal.py').is_file()):
            self.skipTest('PORTABLE_RECORD_FOUNDATION_UNAVAILABLE: explicit draft foundation required')
        before_path = tuple(sys.path)
        before_modules = dict(sys.modules)
        with tempfile.TemporaryDirectory(prefix='portable-record-child-') as temporary:
            configured = os.environ.get('PORTABLE_RECORD_QUALIFICATION')
            output = Path(configured) if configured else Path(temporary) / 'results'
            output.mkdir(parents=True, exist_ok=True)
            inherited = sys.pycache_prefix
            cache = inherited if inherited and not Path(inherited).exists() else str(Path(temporary) / 'absent-cache')
            body = Path(__file__).with_name('_portable_record_cases.py').resolve()
            command = [sys.executable, '-B']
            if sys.flags.optimize:
                command.append('-' + 'O' * sys.flags.optimize)
            command += ['-X', 'pycache_prefix=' + cache, str(body)]
            environment = dict(os.environ, PORTABLE_RECORD_QUALIFICATION=str(output),
                               PYTHONOPTIMIZE=str(sys.flags.optimize), PYTHONDONTWRITEBYTECODE='1',
                               PYTHONPYCACHEPREFIX=cache)
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=environment)
            try:
                stdout, stderr = child.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise
            (output / 'native-child.stdout.log').write_text(stdout)
            (output / 'native-child.stderr.log').write_text(stderr)
            self.assertEqual(child.returncode, 0, stdout + stderr)
            result = json.loads((output / 'results.json').read_text())
            self.assertEqual(result['pid'], child.pid, 'stale child result')
            self.assertEqual(result['source'], str(body))
            self.assertEqual(result['tests'], 67)
            self.assertEqual((result['failures'], result['errors'], result['skipped']), (0, 0, 0))
            self.assertEqual(result['optimize'], sys.flags.optimize)
            self.assertTrue(result['dont_write_bytecode'])
            self.assertEqual(result['cache_prefix'], cache)
            self.assertIs(result['cache_before'], False)
            self.assertIs(result['cache_after'], False)
            self.assertFalse(Path(cache).exists())
            self.assertEqual(tuple(sys.path), before_path)
            self.assertTrue(all(sys.modules.get(name) is module for name, module in before_modules.items()),
                            'parent module identity replaced or removed')
            audit = dict(format='portable-record-parent-child-audit-r1', parent_pid=os.getpid(),
                         child_pid=child.pid, command=command, child_source_sha256=hashlib.sha256(body.read_bytes()).hexdigest(),
                         parent_optimize=sys.flags.optimize, parent_dont_write_bytecode=bool(sys.flags.dont_write_bytecode),
                         parent_cache_prefix=sys.pycache_prefix, child_cache_prefix=cache,
                         inherited_absent_cache=bool(inherited and cache == inherited),
                         parent_path_unchanged=True, preexisting_parent_modules_unchanged=True,
                         child_tests=result['tests'], child_failures=0, child_errors=0, child_skips=0)
            (output / 'parent-child-audit.json').write_text(json.dumps(audit, indent=2) + '\n')


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromTestCase(NativeTypeProfile)


if __name__ == '__main__':
    unittest.main(verbosity=2)
