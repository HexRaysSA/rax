/* Compile-time downstream C11 contract for the process ABI. */
#include "rax.h"
#include <stddef.h>

_Static_assert(RAX_API_MAJOR == 1u && RAX_API_MINOR >= 10u, "process ABI version");
_Static_assert(RAX_PROCESS_RESULT_VERSION == 1u, "result version");
_Static_assert(sizeof(rax_process_result) == 32u, "process result size");
_Static_assert(offsetof(rax_process_result, reason) == 8u, "process reason offset");
_Static_assert(offsetof(rax_process_result, exit_code) == 12u, "process exit offset");
_Static_assert(offsetof(rax_process_result, turns_started) == 16u, "process turns offset");
_Static_assert(offsetof(rax_process_result, elapsed_us) == 24u, "process time offset");
_Static_assert(sizeof(rax_process_image) == 2u * sizeof(void *) + 2u * sizeof(size_t),
               "image record size");
_Static_assert(RAX_PROCESS_BUDGET == 1u && RAX_PROCESS_BLOCKED == 2u &&
                   RAX_PROCESS_CANCELLED == 3u && RAX_PROCESS_EXITED == 4u &&
                   RAX_PROCESS_FAILED == 5u && RAX_PROCESS_TIMEOUT == 6u,
               "process reasons");

void rax_process_abi_signatures(void) {
    rax_status (*open_fn)(const uint8_t *, size_t, const char *, size_t, const rax_process_image *,
                          size_t, rax_process **) = rax_process_open_image;
    rax_status (*run_fn)(const rax_process *, uint64_t, uint64_t, rax_process_result *) =
        rax_process_run;
    rax_status (*close_fn)(rax_process *) = rax_process_close;
    rax_status (*cancel_fn)(const rax_process *, int) = rax_process_set_cancelled;
    (void)open_fn;
    (void)run_fn;
    (void)close_fn;
    (void)cancel_fn;
}
