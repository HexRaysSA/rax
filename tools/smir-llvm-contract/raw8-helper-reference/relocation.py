"""Actual relocation from current dirty portable foundation; no HEAD-only copy."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def capture(project, output):
    project, output = project.resolve(), output.resolve()
    output.mkdir(exist_ok=False)
    hashes = {}
    for relative in ('tools/smir-format', 'tools/smir-runtime-contract', 'tools/smir-abi',
                     'docs/specifications/smir/portable'):
        source = project / relative
        for path in sorted(source.rglob('*')):
            if not path.is_file() or any(part in ('__pycache__', 'target', '.git') for part in path.relative_to(source).parts):
                continue
            rel = path.relative_to(project)
            destination = output / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes()
            hashes[str(rel)] = hashlib.sha256(data).hexdigest()
            destination.write_bytes(data)
    package = output / 'tools/smir-llvm-contract/raw8-helper-reference'
    package.mkdir(parents=True)
    for name in ('raw8_reference.cpp', 'build.py', 'reference.py', 'oracle.py', 'cli.py', 'schema.json',
                 'fixtures.json', 'helper-image.json'):
        shutil.copyfile(HERE / name, package / name)
    drift = [rel for rel, digest in hashes.items() if hashlib.sha256((project / rel).read_bytes()).hexdigest() != digest]
    if drift:
        raise RuntimeError('Foundation changed during capture: '+repr(drift))
    (output / 'capture.json').write_text(json.dumps({'source':str(project),'files':hashes,'drift':drift},indent=2)+'\n')
    return package


def qualify(project, llvm, destination):
    destination.mkdir(exist_ok=False)
    relocated = destination / 'relocated foundation with spaces'
    package = capture(project, relocated)
    native = destination / 'actual native with spaces'
    env = dict(os.environ)
    env.pop('SMIR_RAW8_REFERENCE_PROJECT', None)
    env['PYTHONPYCACHEPREFIX'] = str(destination / 'fresh-build-cache')
    build = [sys.executable,'-B',str(package/'build.py'),'--llvm',str(llvm),'--output',str(native)]
    result = subprocess.run(build,env=env,capture_output=True,text=True,timeout=180)
    (destination/'build.stdout').write_text(result.stdout);(destination/'build.stderr').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError('Actual relocated native build failed: '+result.stderr)
    rows=[]
    for optimize in (0,1):
        env['PYTHONOPTIMIZE']=str(optimize)
        env['PYTHONPYCACHEPREFIX']=str(destination/('fresh-relocated-'+str(optimize)))
        command=[sys.executable]+(['-O']if optimize else[])+['-B',str(package/'cli.py'),'--profile','relay',
            '--binary',str(native/'raw8-reference'),'--receipt',str(native/'build-receipt.json')]
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=120)
        (destination/('run'+str(optimize)+'.stdout')).write_text(result.stdout)
        (destination/('run'+str(optimize)+'.stderr')).write_text(result.stderr)
        if result.returncode:raise RuntimeError('Relocated actual witness failed: '+result.stderr)
        row=json.loads(result.stdout)
        if (row['return_value'],row['permits'],row['entries'],row['optimize'])!=(42,1,1,optimize):
            raise RuntimeError('Relocated real bind/call/mode mismatch')
        rows.append({'command':command,'exit':result.returncode,'witness':row})
    receipt={'scope':'Actual copied current dirty foundation+installed-layout source in pathspaces, fresh native build from THAT source, no draftoverride/fallback; normal/O actual bind42. No sourceABI2/backend/nativeguest proof.',
             'rows':rows,'build_receipt':str(native/'build-receipt.json'),'source':str(package),'status':'PASS'}
    (destination/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--llvm',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(qualify(args.project,args.llvm,args.output),sort_keys=True))
