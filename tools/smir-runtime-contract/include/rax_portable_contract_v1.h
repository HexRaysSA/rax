#ifndef RAX_PORTABLE_CONTRACT_V1_H
#define RAX_PORTABLE_CONTRACT_V1_H
/* Candidate contract declarations only. No implementation is linked by this file.
 * Host C ABI uses fixed integers/pointers; guest ABI never equals host ABI by default.
 * Status: 0 success, otherwise positive portable errno from errno-v1.json.
 */
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
#define RAXP_NOEXCEPT noexcept
extern "C" {
#else
#define RAXP_NOEXCEPT
#endif

typedef uint32_t RaxPortableStatusV1;
typedef struct RaxPortableHandleV1 {
    uint64_t instance;
    uint64_t slot;
    uint64_t generation;
} RaxPortableHandleV1;
typedef struct RaxPortableBytesV1 {
    const uint8_t *data;
    uint64_t length;
} RaxPortableBytesV1;
typedef struct RaxPortableBufferV1 {
    uint8_t *data;
    uint64_t capacity;
    uint64_t written;
} RaxPortableBufferV1;
typedef struct RaxPortablePollV1 {
    uint32_t size;
    uint32_t version;
    RaxPortableBytesV1 state; /* exact token: pending, returned, raised, exited, failed */
    RaxPortableHandleV1 result; /* retained result-vector/exception/exit record */
    RaxPortableStatusV1 error;
    uint32_t reserved0;
} RaxPortablePollV1;
typedef RaxPortableStatusV1 (*RaxPortableHostCallV1)(
    void *user, RaxPortableHandleV1 call,
    const RaxPortableHandleV1 *arguments, uint64_t count,
    RaxPortablePollV1 *result) RAXP_NOEXCEPT;
typedef void (*RaxPortableHostReleaseV1)(void *user) RAXP_NOEXCEPT;
typedef struct RaxPortableHostImportV1 {
    uint32_t size;
    uint32_t version;
    RaxPortableBytesV1 name;
    RaxPortableBytesV1 admitted_descriptor;
    RaxPortableHostCallV1 call;
    RaxPortableHostReleaseV1 release;
    void *user;
} RaxPortableHostImportV1;
typedef struct RaxPortableConfigV1 {
    uint32_t size;
    uint32_t version;
    uint64_t workers;
    uint64_t memory_bytes;
    uint64_t stack_bytes;
    uint64_t atomic_bytes;
    uint64_t code_bytes;
    RaxPortableBytesV1 profile;
    RaxPortableBytesV1 personality;
    const RaxPortableBytesV1 *capabilities;
    uint64_t capability_count;
    const RaxPortableHostImportV1 *imports;
    uint64_t import_count;
} RaxPortableConfigV1;

RaxPortableStatusV1 rax_portable_v1_context_create(
    const RaxPortableConfigV1 *, RaxPortableHandleV1 *) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_module_verify(
    RaxPortableHandleV1 context, RaxPortableBytesV1 immutable_copy,
    RaxPortableHandleV1 *module) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_process_create(
    RaxPortableHandleV1 context, RaxPortableHandleV1 module,
    RaxPortableBytesV1 canonical_spawn_spec, RaxPortableHandleV1 *process) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_process_run(
    RaxPortableHandleV1 process, RaxPortableHandleV1 *request) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_symbol(
    RaxPortableHandleV1 module, RaxPortableBytesV1 name_space,
    RaxPortableBytesV1 name, RaxPortableHandleV1 *code_value) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_value_bits(
    RaxPortableHandleV1 module, uint32_t execution_type, uint32_t reserved0,
    RaxPortableBytesV1 bits, RaxPortableHandleV1 *value) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_value_aggregate(
    RaxPortableHandleV1 module, uint32_t execution_type, uint32_t reserved0,
    const RaxPortableHandleV1 *elements, uint64_t count,
    RaxPortableHandleV1 *value) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_value_pointer(
    RaxPortableHandleV1 pointer_value, uint64_t offset, RaxPortableHandleV1 *value) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_start(
    RaxPortableHandleV1 process, RaxPortableHandleV1 code,
    const RaxPortableHandleV1 *arguments, uint64_t count,
    RaxPortableHandleV1 *request) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_poll(
    RaxPortableHandleV1 request, RaxPortablePollV1 *result) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_cancel(
    RaxPortableHandleV1 request, uint32_t *won_before_effect) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_call_result_bits(
    RaxPortableHandleV1 call, uint64_t result_index, RaxPortableBytesV1 bits,
    RaxPortableHandleV1 *value) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_call_return(
    RaxPortableHandleV1 call, const RaxPortableHandleV1 *values, uint64_t count,
    RaxPortablePollV1 *completion) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_host_complete(
    RaxPortableHandleV1 call, const RaxPortablePollV1 *result) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_result_count(
    RaxPortableHandleV1 result, uint64_t *count) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_result_at(
    RaxPortableHandleV1 result, uint64_t index, RaxPortableHandleV1 *value) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_value_read_bits(
    RaxPortableHandleV1 value, RaxPortableBufferV1 *buffer) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_process_join(
    RaxPortableHandleV1 process, RaxPortablePollV1 *result) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_record_read(
    RaxPortableHandleV1 record, RaxPortableBufferV1 *buffer) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_retain(RaxPortableHandleV1 handle) RAXP_NOEXCEPT;
RaxPortableStatusV1 rax_portable_v1_release(RaxPortableHandleV1 handle) RAXP_NOEXCEPT;

#ifdef __cplusplus
}
#define RAXP_ASSERT static_assert
#else
#define RAXP_ASSERT _Static_assert
#endif
RAXP_ASSERT(sizeof(void *) == 8, "portable runtime host requires64-bit pointers");
RAXP_ASSERT(sizeof(RaxPortableHandleV1) == 24, "handle24");
RAXP_ASSERT(sizeof(RaxPortableBytesV1) == 16, "bytes16");
RAXP_ASSERT(sizeof(RaxPortableBufferV1) == 24, "buffer24");
RAXP_ASSERT(sizeof(RaxPortablePollV1) == 56, "poll56");
RAXP_ASSERT(offsetof(RaxPortablePollV1,result) == 24, "poll result offset24");
RAXP_ASSERT(sizeof(RaxPortableHostImportV1) == 64, "host import64");
RAXP_ASSERT(sizeof(RaxPortableConfigV1) == 112, "config112");
#undef RAXP_ASSERT
#undef RAXP_NOEXCEPT
#endif
