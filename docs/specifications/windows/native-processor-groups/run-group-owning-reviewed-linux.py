from pathlib import Path
import subprocess
root='/tmp/assist-native-allocate-ex-root-final';logs='/tmp/assist-native-root-cpp-linux';base=['docker','run','--rm','--platform','linux/amd64','-v',root+':/work:ro','-v','/Users/int/hexrays/kvasir/vendor/rax:/work/vendor/rax:ro','-v',logs+':/validation','-v','rax-cargo-registry:/usr/local/cargo/registry','-v','rax-cargo-git:/usr/local/cargo/git','-e','CARGO_TARGET_DIR=/target','-e','RUSTUP_TOOLCHAIN=1.95.0-x86_64-unknown-linux-gnu']
steps=[('full',base+['-v','rax-user-target:/target','-w','/work/vendor/rax','rust:1.95-bullseye','cargo','test','--locked','--no-default-features','--lib','--','--nocapture']),('capi',base+['-v','rax-user-target:/target','-w','/work/vendor/rax','rust:1.95-bullseye','cargo','test','--locked','--no-default-features','-p','rax-capi','--','--nocapture']),('shipping',base+['-v','assist-native-linux-root-target:/target','-w','/work/rust/assist-rs','rust:1.95-bullseye','cargo','build','--locked','--offline','--features','rax']),('cpp',base+['-v','assist-native-linux-root-target:/target:ro','-v','/tmp/assist-native-process-root-macos/generated/static-text:/generated:ro','-v','/tmp/assist-native-process-root-macos/_deps/monocypher-src/src:/monocypher:ro','-v','/tmp/assist-native-process-root-macos/_deps/json-src/single_include:/json:ro','rust:1.95-bullseye','python3','/validation/build.py'])]
for name,args in steps:
 if name not in {'shipping','cpp'}:continue
 with Path('/tmp/assist-native-windows-29683/topology-evidence/linux-group-owning-reviewed-'+name+'.log').open('w') as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 print(name,r.returncode,flush=True)
 if r.returncode and name!='full':raise SystemExit(r.returncode)
