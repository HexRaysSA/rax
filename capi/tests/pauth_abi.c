/* ABI 1.15: exact config layout and non-reused AArch64 register identifiers. */
#include <stddef.h>
#include "rax.h"

_Static_assert(RAX_API_MAJOR == 1u && RAX_API_MINOR >= 15u, "PAuth API version");
_Static_assert(sizeof(rax_arm64_pauth_config) == 32, "PAuth config size");
_Static_assert(offsetof(rax_arm64_pauth_config, features) == 4, "features offset");
_Static_assert(offsetof(rax_arm64_pauth_config, algorithm) == 8, "algorithm offset");
_Static_assert(offsetof(rax_arm64_pauth_config, profile) == 12, "profile offset");
_Static_assert(offsetof(rax_arm64_pauth_config, reserved) == 16, "reserved offset");
_Static_assert(RAX_ARM64_REG_CNTV_CVAL_EL0 == 0x0412, "legacy ID unchanged");
_Static_assert(RAX_ARM64_REG_APIAKEYLO_EL1 == 0x0413, "first appended ID");
_Static_assert(RAX_ARM64_REG_SPSR_EL3 == 0x0433, "last appended ID");

rax_status (*rax_pauth_set_signature)(rax_engine *, const rax_arm64_pauth_config *) = rax_arm64_pauth_configure;
rax_status (*rax_pauth_get_signature)(const rax_engine *, rax_arm64_pauth_config *) = rax_arm64_pauth_get_config;
