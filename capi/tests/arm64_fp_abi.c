/* ABI 1.16: additive optional FP/SIMD configuration prefix and signatures. */
#include <stddef.h>
#include "rax.h"

_Static_assert(RAX_API_MAJOR == 1u && RAX_API_MINOR >= 16u, "FP profile API version");
_Static_assert(sizeof(rax_arm64_fp_config) == 32, "FP profile prefix size");
_Static_assert(_Alignof(rax_arm64_fp_config) == 4, "FP profile alignment");
_Static_assert(offsetof(rax_arm64_fp_config, size) == 0, "size offset");
_Static_assert(offsetof(rax_arm64_fp_config, features) == 4, "features offset");
_Static_assert(offsetof(rax_arm64_fp_config, reserved) == 8, "reserved offset");
_Static_assert(RAX_ARM64_FEATURE_FP16 == 1u && RAX_ARM64_FEATURE_FHM == 2u, "half flags");
_Static_assert(RAX_ARM64_FEATURE_JSCVT == 4u && RAX_ARM64_FEATURE_FCMA == 8u, "conversion/complex flags");
_Static_assert(RAX_ARM64_FEATURE_FRINTTS == 16u && RAX_ARM64_FEATURE_BF16 == 32u, "rounding/BF16 flags");
_Static_assert(RAX_ARM64_FEATURE_I8MM == 64u && RAX_ARM64_FEATURE_DOTPROD == 128u, "matrix/dot flags");
_Static_assert((RAX_ARM64_FEATURE_FP16 | RAX_ARM64_FEATURE_FHM |
                RAX_ARM64_FEATURE_JSCVT | RAX_ARM64_FEATURE_FCMA |
                RAX_ARM64_FEATURE_FRINTTS | RAX_ARM64_FEATURE_BF16 |
                RAX_ARM64_FEATURE_I8MM | RAX_ARM64_FEATURE_DOTPROD) == 0xffu,
               "complete non-overlapping feature flags");
_Static_assert(RAX_ARM64_FP_FEATURES_SUPPORTED == 0xffu, "supported flag mask");
_Static_assert(RAX_ARM64_REG_PC == 0x0011, "legacy register identifier");

rax_status (*rax_fp_set_signature)(rax_engine *, const rax_arm64_fp_config *) = rax_arm64_fp_configure;
rax_status (*rax_fp_get_signature)(const rax_engine *, rax_arm64_fp_config *) = rax_arm64_fp_get_config;
