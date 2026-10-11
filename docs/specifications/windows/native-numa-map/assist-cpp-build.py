from pathlib import Path
import subprocess
root=Path('C:/Windows/Temp/assist-native-rax-20261010/assist');out=root/'native-cpp';out.mkdir(exist_ok=True)
gen=root/'generated';mono=root/'monocypher';archive=Path('C:/Windows/Temp/assist-native-rax-20261010/target/debug/assist_rs.lib')
def run(args):
 print('run',args[0],args[-1],flush=True);subprocess.run([str(a) for a in args],check=True,cwd=out)
run(['cl.exe','/nologo','/c','/MT','/O1',mono/'monocypher.c','/I'+str(mono),'/Fo'+str(out/'monocypher.obj')])
includes=['/I'+str(root/'include'),'/I'+str(root/'vendor/rax/capi/include'),'/I'+str(root/'rust/assist-rs/include'),'/I'+str(gen),'/I'+str(mono),'/I'+str(root/'json')]
flags=['/nologo','/std:c++20','/O1','/MT','/EHsc','/utf-8','/DNOMINMAX','/DASSIST_STATIC_TEXT_HAS_CODEC=1','/DASSIST_RAX_PROCESS_FIXTURES="C:/Windows/Temp/assist-native-rax-20261010/src/tests/fixtures/user/windows"']
factory=root/'src/tools/builtin/emulation/sessions/process_tool.cpp';adapter=root/'src/emulation/rax/rax_process.cpp';loader=root/'src/emulation/rax/librax_loader.cpp'
text=[root/'src/crypto/static_text.cpp',gen/'metadata.cpp',gen/'metadata_keys.cpp',out/'monocypher.obj']
libs=['ws2_32.lib','userenv.lib','ntdll.lib','bcrypt.lib','advapi32.lib']
for name,sources,rax in [
 ('process_tool',[root/'test/process_tool_tests.cpp',factory,adapter,loader,*text],True),
 ('process_tool_unavailable',[root/'test/process_tool_unavailable_tests.cpp',factory,*text],False),
 ('rax_process',[root/'test/rax_process_tests.cpp',adapter],True),
 ('rax_abi_drift',[root/'test/e14_rax_abi_drift_tests.cpp'],True),
 ('rust_archive_link',[root/'test/rust_archive_link_tests.cpp'],True),
]:
 run(['cl.exe',*flags,*includes,*( ['/DASSIST_HAS_RAX=1'] if rax else []),*sources,archive,*libs,'/Fe:'+str(out/(name+'.exe'))])
 run([out/(name+'.exe')])
