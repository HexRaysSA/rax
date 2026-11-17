"""Controlled native-host reentrant coroutine source oracle; no guest runtime."""
import hashlib
from pathlib import Path
import shlex
import subprocess
import tempfile

OBSERVATIONS = []


def observe(compiler, source):
    compiler, source = Path(compiler), Path(source)
    sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    sdk = subprocess.check_output(['/usr/bin/xcrun','--show-sdk-path'],text=True).strip()
    options = [str(compiler),'-std=c++23','-nostdinc++','-isysroot',sdk,'-fcoro-aligned-allocation']
    compiler_hash = sha(compiler)
    with tempfile.TemporaryDirectory(prefix='smir-coro-host-') as temporary:
        directory = Path(temporary)
        depfile = directory/'dependencies.d'
        subprocess.run([*options,'-M','-MT','coroutine_probe','-MF',str(depfile),str(source)],
                       capture_output=True,text=True,check=True)
        paths = sorted(set(shlex.split(depfile.read_text().split(':',1)[1].replace('\\\n',''))))
        before = [dict(path=p,sha256=sha(p)) for p in paths]
        cases = []
        for level in ('-O0','-O2'):
            binary = directory / level[1:]
            argv = [*options,level,str(source),'-o',str(binary)]
            subprocess.run(argv,capture_output=True,text=True,check=True)
            result = subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
            if result.returncode or result.stdout or result.stderr:
                raise AssertionError(('native coroutine source ordering',level,result))
            cases.append(dict(compile_command=argv,binary_sha256=sha(binary),returncode=0,
                observations='inline-resume order1234; one Guard destruction; final-suspended done; explicit frame destroy',
                linked_images=subprocess.check_output(['/usr/bin/otool','-L',str(binary)],text=True)))
        after = [dict(path=p,sha256=sha(p)) for p in paths]
    if before != after or sha(compiler) != compiler_hash:
        raise AssertionError('Native coroutine oracle input drift')
    report = dict(scope='native Darwin arm64 host source oracle',compiler_sha256=compiler_hash,
        sdk=sdk,sources_before=before,sources_after=after,inputs_stable=True,cases=cases,
        limits='Same-host-thread inline reentry, not a peer-thread or portable-SMIR execution proof. System C++ runtime binary identity unknown; no pinned-library/foreign-JIT qualification.')
    OBSERVATIONS.append(report)
    return report
