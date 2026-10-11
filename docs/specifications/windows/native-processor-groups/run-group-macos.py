from pathlib import Path
import subprocess
steps=[('targeted', ['test', '--lib', 'native_group_topology']), ('full', ['test', '--lib']), ('capi', ['test', '-p', 'rax-capi']), ('all-targets', ['build', '--all-targets']), ('integration', ['test', '--test', 'user_windows', '--test', 'user_windows_memory'])]
for name,args in steps:
 args=["cargo",args[0],"--locked","--offline","--no-default-features"]+args[1:]+([] if name=="all-targets" else ["--","--nocapture"])
 with Path("/tmp/assist-native-windows-29683/topology-evidence/macos-group-final-"+name+"-macos.log").open("w") as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,cwd="/Users/int/hexrays/kvasir/vendor/rax")
 print(name,r.returncode,flush=True)
 if r.returncode and name!="full":raise SystemExit(r.returncode)
