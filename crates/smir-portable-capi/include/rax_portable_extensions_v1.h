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

/* The version of the host interface these headers declare. The major
 * version is that of the contract's functions. Minor version 0 is those
 * functions alone; 1 adds the extensions declared here. A program built
 * against these headers runs with a runtime of the same major version and of
 * this minor version or a later one.
 */
#define RAX_PORTABLE_ABI_MAJOR 1
#define RAX_PORTABLE_ABI_MINOR 1
/* The executable profile of the objects a runtime of this interface runs. */
#define RAX_PORTABLE_PROFILE 2

/* A runtime, as it describes itself to a launcher that has found it
 * installed and decides whether it is the one its program needs.
 */
typedef struct RaxPortableRuntimeX1 {
  uint32_t size, version; /* sizeof and 1, set by the caller */
  uint32_t abi_major, abi_minor;
  uint32_t revision; /* of the implementation; later is more */
  uint32_t profile;
  /* What tells the implementation from another: SHA-256 of what it was
   * built of, which two builds of one version for one machine share. */
  uint8_t implementation[32];
  uint8_t helpers[32]; /* the identity of the catalog of helpers */
  /* How many catalogs of services, and their identities, the first catalog
   * first; zeros in the rest. */
  uint32_t service_catalogs, reserved0;
  uint8_t services[4][32];
} RaxPortableRuntimeX1;

/* Describe this runtime. EINVAL for a size or version that is not the
 * structure's; nothing else of it is then read or written.
 */
RaxPortableStatusV1 rax_portable_x1_runtime(RaxPortableRuntimeX1 *runtime)
#ifdef __cplusplus
    noexcept
#endif
    ;

#ifdef __cplusplus
}
#endif
#endif
