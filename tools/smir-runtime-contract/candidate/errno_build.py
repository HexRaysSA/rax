#!/usr/bin/env python3
"""Extract pinned errno/status numbers from local primary headers, never host SDK."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT/'docs/specifications/smir/portable/schema/runtime/errno-v1.json'
SOURCES = {
 'linux_base':'docs/specifications/linux/uapi-6.19/any-linux-any/asm-generic/errno-base.h',
 'linux_ext':'docs/specifications/linux/uapi-6.19/any-linux-any/asm-generic/errno.h',
 'darwin':'docs/specifications/darwin/xnu-12377.121.6/bsd/sys/errno.h',
 'win32':'docs/specifications/windows/mingw-w64-headers/winerror.h',
 'ntstatus':'docs/specifications/windows/mingw-w64-headers/ntstatus.h',
}


def macros(path):
    result, aliases = {}, {}
    for name, text in re.findall(r'^#define\s+([A-Z][A-Z0-9_]*)\s+([^\n]+)', path.read_text(), re.M):
        raw = text.split('/*')[0].strip()
        match = re.fullmatch(r'(0x[0-9a-fA-F]+|[0-9]+)[uUlL]*', raw)
        match = match or re.fullmatch(r'__MSABI_LONG\((0x[0-9a-fA-F]+|[0-9]+)\)', raw)
        match = match or re.fullmatch(r'\(\(NTSTATUS\)(0x[0-9a-fA-F]+)\)', raw)
        if match:
            result[name] = int(match[1],0)
        elif re.fullmatch(r'[A-Z][A-Z0-9_]*',raw):
            aliases[name]=raw
    while aliases:
        ready={name:result[target] for name,target in aliases.items() if target in result}
        if not ready:
            break
        result.update(ready)
        aliases={name:target for name,target in aliases.items() if name not in ready}
    return result


# Canonical representative for outbound conversion. Inbound aliases are separately
# listed. Lossy conversions are explicit; original native status remains diagnostic.
WIN32 = {
 'EPERM':'ERROR_ACCESS_DENIED','ENOENT':'ERROR_FILE_NOT_FOUND','ESRCH':'ERROR_INVALID_THREAD_ID',
 'EINTR':'ERROR_OPERATION_ABORTED','EIO':'ERROR_GEN_FAILURE','ENOEXEC':'ERROR_BAD_EXE_FORMAT',
 'EBADF':'ERROR_INVALID_HANDLE','EAGAIN':'ERROR_NO_SYSTEM_RESOURCES','ENOMEM':'ERROR_NOT_ENOUGH_MEMORY',
 'EACCES':'ERROR_ACCESS_DENIED','EFAULT':'ERROR_NOACCESS','EBUSY':'ERROR_BUSY','EEXIST':'ERROR_ALREADY_EXISTS',
 'EXDEV':'ERROR_NOT_SAME_DEVICE','ENODEV':'ERROR_INVALID_DRIVE','ENOTDIR':'ERROR_DIRECTORY',
 'EISDIR':'ERROR_ACCESS_DENIED','EINVAL':'ERROR_INVALID_PARAMETER','ENFILE':'ERROR_TOO_MANY_OPEN_FILES',
 'EMFILE':'ERROR_TOO_MANY_OPEN_FILES','EFBIG':'ERROR_FILE_TOO_LARGE','ENOSPC':'ERROR_DISK_FULL',
 'ESPIPE':'ERROR_SEEK','EROFS':'ERROR_WRITE_PROTECT','EPIPE':'ERROR_BROKEN_PIPE',
 'EDOM':'ERROR_INVALID_DATA','ERANGE':'ERROR_INSUFFICIENT_BUFFER','EDEADLK':'ERROR_POSSIBLE_DEADLOCK',
 'ENAMETOOLONG':'ERROR_FILENAME_EXCED_RANGE','ENOSYS':'ERROR_CALL_NOT_IMPLEMENTED',
 'ENOTEMPTY':'ERROR_DIR_NOT_EMPTY','EOVERFLOW':'ERROR_ARITHMETIC_OVERFLOW',
 'EILSEQ':'ERROR_NO_UNICODE_TRANSLATION','EOPNOTSUPP':'ERROR_NOT_SUPPORTED',
 'ETIMEDOUT':'ERROR_TIMEOUT','ECANCELED':'ERROR_OPERATION_ABORTED',
 'EOWNERDEAD':'ERROR_ABANDONED_WAIT_0','ENOTRECOVERABLE':'ERROR_GEN_FAILURE',
}
NTSTATUS = {
 'EPERM':'STATUS_ACCESS_DENIED','ENOENT':'STATUS_OBJECT_NAME_NOT_FOUND','ESRCH':'STATUS_INVALID_CID',
 'EINTR':'STATUS_ALERTED','EIO':'STATUS_UNSUCCESSFUL','ENOEXEC':'STATUS_INVALID_IMAGE_FORMAT',
 'EBADF':'STATUS_INVALID_HANDLE','EAGAIN':'STATUS_INSUFFICIENT_RESOURCES','ENOMEM':'STATUS_NO_MEMORY',
 'EACCES':'STATUS_ACCESS_DENIED','EFAULT':'STATUS_ACCESS_VIOLATION','EBUSY':'STATUS_SHARING_VIOLATION',
 'EEXIST':'STATUS_OBJECT_NAME_COLLISION','EXDEV':'STATUS_NOT_SAME_DEVICE',
 'ENOTDIR':'STATUS_NOT_A_DIRECTORY','EISDIR':'STATUS_FILE_IS_A_DIRECTORY',
 'EINVAL':'STATUS_INVALID_PARAMETER','EMFILE':'STATUS_TOO_MANY_OPENED_FILES',
 'ENOSPC':'STATUS_DISK_FULL','EROFS':'STATUS_MEDIA_WRITE_PROTECTED','EPIPE':'STATUS_PIPE_BROKEN',
 'ERANGE':'STATUS_BUFFER_TOO_SMALL','ENAMETOOLONG':'STATUS_NAME_TOO_LONG',
 'ENOSYS':'STATUS_NOT_IMPLEMENTED','ENOTEMPTY':'STATUS_DIRECTORY_NOT_EMPTY',
 'EOVERFLOW':'STATUS_INTEGER_OVERFLOW','EILSEQ':'STATUS_ILLEGAL_CHARACTER',
 'EOPNOTSUPP':'STATUS_NOT_SUPPORTED','ETIMEDOUT':'STATUS_TIMEOUT','ECANCELED':'STATUS_CANCELLED',
}


def document():
    tables={name:macros(ROOT/path) for name,path in SOURCES.items()}
    linux={name:value for table in [tables['linux_base'],tables['linux_ext']]
           for name,value in table.items() if name.startswith('E')}
    if not (linux['EAGAIN']==11 and linux['EOVERFLOW']==75 and linux['ECANCELED']==125):
        raise ValueError('Pinned Linux errno baseline changed')
    # Alias spellings are not separate numeric statuses.
    aliases={'EWOULDBLOCK':'EAGAIN','EDEADLOCK':'EDEADLK','ENOTSUP':'EOPNOTSUPP'}
    linux['ENOTSUP']=linux['EOPNOTSUPP']
    canonical={name:value for name,value in linux.items() if name not in aliases}
    outbound={domain:{} for domain in ['linux','darwin','win32','ntstatus']}
    for name,value in sorted(canonical.items(),key=lambda item:item[1]):
        outbound['linux'][str(value)]={'name':name,'value':value,'exact':True}
        for domain,mapping in [('darwin',None),('win32',WIN32),('ntstatus',NTSTATUS)]:
            selected=name if mapping is None else mapping.get(name)
            fallback='EIO' if domain=='darwin' else 'ERROR_GEN_FAILURE' if domain=='win32' else 'STATUS_UNSUCCESSFUL'
            exact=selected is not None and selected in tables[domain]
            selected=selected if exact else fallback
            outbound[domain][str(value)]={'name':selected,'value':tables[domain][selected],
                                          'exact_name_match':exact}
    # Inbound map explicitly resolves many-to-one native ambiguities. Otherwise
    # deterministic smallest portable value is documented, not an identity cast.
    inbound={domain:{} for domain in outbound}
    for domain,rows in outbound.items():
        for portable,row in rows.items():
            if row.get('exact',row.get('exact_name_match',False)):
                inbound[domain].setdefault(str(row['value']),int(portable))
    for name,value in tables['darwin'].items():
        if name in linux:
            inbound['darwin'][str(value)]=linux[name]
    for name,portable in [('ERROR_ACCESS_DENIED','EACCES'),('ERROR_OPERATION_ABORTED','ECANCELED'),
                          ('ERROR_FILE_EXISTS','EEXIST'),('ERROR_PATH_NOT_FOUND','ENOENT'),
                          ('ERROR_OUTOFMEMORY','ENOMEM'),('ERROR_HANDLE_EOF','SUCCESS')]:
        inbound['win32'][str(tables['win32'][name])]=0 if portable=='SUCCESS' else linux[portable]
    for name,portable in [('STATUS_ACCESS_DENIED','EACCES'),('STATUS_OBJECT_PATH_NOT_FOUND','ENOENT'),
                          ('STATUS_NO_SUCH_FILE','ENOENT'),('STATUS_END_OF_FILE','SUCCESS')]:
        inbound['ntstatus'][str(tables['ntstatus'][name])]=0 if portable=='SUCCESS' else linux[portable]
    for rows in inbound.values():
        rows['0']=0
    return {'format':'portable_errno_linux_pinned_v1','status':'candidate_contract',
            'success':0,'portable':canonical,'aliases':aliases,'to_personality':outbound,
            'from_personality':inbound,'unknown_native_fallback':linux['EIO'],
            'unknown_portable':'reject_not_host_identity',
            'native_original':'retain domain+raw32 in runtime cause; lossy numeric conversion is explicit',
            'sources':[{'path':path,'sha256':hashlib.sha256((ROOT/path).read_bytes()).hexdigest()}
                       for path in SOURCES.values()]}


if __name__=='__main__':
    OUTPUT.write_text(json.dumps(document(),indent=2)+'\n')
