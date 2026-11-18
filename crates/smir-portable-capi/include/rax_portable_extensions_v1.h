#ifndef RAX_PORTABLE_EXTENSIONS_V1_H
#define RAX_PORTABLE_EXTENSIONS_V1_H
/* What this runtime offers a host beyond rax_portable_contract_v1.h. These
 * are not part of that contract and may change with the runtime.
 */
#include "rax_portable_contract_v1.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Give the processes of a context files: those under the directory `path`
 * names, a path of this machine, in UTF-8. The directory is the root of every
 * path a program uses and where its relative paths start. Processes made
 * before the call are not affected. The context must also grant `file`.
 * ENOENT or ENOTDIR if there is no such directory.
 */
RaxPortableStatusV1 rax_portable_x1_context_files(
    RaxPortableHandleV1 context, RaxPortableBytesV1 path)
#ifdef __cplusplus
    noexcept
#endif
    ;

#ifdef __cplusplus
}
#endif
#endif
