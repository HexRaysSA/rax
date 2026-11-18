"""Build `smir-run` for the tests and say where it is.

The runner is built for the host unless the environment variable
SMIR_RUN_TARGET names another Rust target that this machine can run, such as
`x86_64-apple-darwin` on Apple silicon, where Rosetta runs it. The tests then
exercise that target's native code as well as its interpreter.
"""
import os
from pathlib import Path
import subprocess

CRATE = Path(__file__).resolve().parents[2] / 'crates/smir-portable'


def build():
    """Build the runner and return its path."""
    target = os.environ.get('SMIR_RUN_TARGET')
    chosen = ['--target', target] if target else []
    cargo = subprocess.run(['cargo', 'build', '--offline', '--locked', '--manifest-path',
                            str(CRATE / 'Cargo.toml'), '--bin', 'smir-run', *chosen],
                           capture_output=True, text=True)
    if cargo.returncode != 0:
        raise RuntimeError('cannot build smir-run:\n' + cargo.stderr[-4000:])
    # Under the crate, unless the environment says where cargo builds.
    return Path(os.environ.get('CARGO_TARGET_DIR') or CRATE / 'target') / (target or '') / 'debug/smir-run'
