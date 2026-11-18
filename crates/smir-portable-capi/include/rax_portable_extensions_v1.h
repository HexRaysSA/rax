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

/* Link `count` verified modules of a context into one program. `modules[0]`
 * is the program: the linked module has its exported functions and its
 * types. The others are the modules it and they depend on, in any order.
 * `linked` is a module of the context like any other, to make a process of
 * and to release; the modules given stay what they were. A module that calls
 * functions of others is verified like any module, and no process is made
 * of it (ENOEXEC) until it is linked.
 * EINVAL for no modules; EBADF for a handle that is no module of the
 * context; ENOEXEC if the modules do not link: a dependency that none or
 * more than one of them answers, a function that is missing or of another
 * type, modules that need one another in a circle, or one nobody needs.
 */
RaxPortableStatusV1 rax_portable_x1_module_link(
    RaxPortableHandleV1 context, const RaxPortableHandleV1 *modules,
    uint64_t count, RaxPortableHandleV1 *linked)
#ifdef __cplusplus
    noexcept
#endif
    ;

#ifdef __cplusplus
}
#endif
#endif
