from pathlib import Path
import ctypes as c,hashlib,json,msvcrt,sys
assert sys.getwindowsversion().build == 29695 and c.sizeof(c.c_void_p)==8
class Io(c.Structure):
 _fields_=[('status',c.c_size_t),('information',c.c_size_t)]
n=c.WinDLL('ntdll');n.NtQueryVolumeInformationFile.argtypes=[c.c_void_p,c.POINTER(Io),c.c_void_p,c.c_uint32,c.c_uint32];n.NtQueryVolumeInformationFile.restype=c.c_int32
p=Path('C:/Windows/Temp/assist-native-rax-20261010/src-display-candidate1/target/native-wow64-csr-model-gates-v1/tmp/native-volume-control-v1.bin')
with p.open('x+b') as f:
 f.write(b'volume-query');f.flush();f.seek(7);io=Io(0x103,0);out=(c.c_uint32*2)();status=n.NtQueryVolumeInformationFile(msvcrt.get_osfhandle(f.fileno()),c.byref(io),c.byref(out),8,4);assert status==0 and io.status==0 and io.information==8
 result={'kernel':list(sys.getwindowsversion()),'status':status,'information':io.information,'device':out[0],'characteristics':out[1],'position':f.tell(),'path':str(p),'ntdll_sha256':hashlib.sha256(Path('C:/Windows/System32/ntdll.dll').read_bytes()).hexdigest()}
p.unlink();print(json.dumps(result))
