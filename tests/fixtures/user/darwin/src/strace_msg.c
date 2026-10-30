/* Mach messages for the `--strace-mach-msg` tests: a complex message to a
 * port of the task's own, received back, then a kernel call whose request
 * and reply are messages. The message's inline marker and out-of-line
 * pattern are 16 bytes at 16-byte offsets, so a dump of 16 bytes a line
 * shows each whole. Port names and addresses are never printed. */
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

/* "RA". */
#define MESSAGE_ID 0x5241

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool;
    uint32_t pad; /* the marker at offset 48 */
    char marker[16];
} message_t;

typedef struct {
    message_t message;
    mach_msg_trailer_t trailer;
} received_t;

static char ool[64];

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_port_t task = mach_task_self();
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr) {
        printf("allocate %#x\n", kr);
        return 1;
    }
    for (int i = 0; i < 4; i++) {
        memcpy(ool + 16 * i, "RAX-OOL-PATTERN!", 16);
    }

    message_t m;
    memset(&m, 0, sizeof m);
    m.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    m.header.msgh_size = sizeof m;
    m.header.msgh_remote_port = port;
    m.header.msgh_id = MESSAGE_ID;
    m.body.msgh_descriptor_count = 1;
    m.ool.address = ool;
    m.ool.size = sizeof ool;
    m.ool.deallocate = 0;
    m.ool.copy = MACH_MSG_PHYSICAL_COPY;
    m.ool.type = MACH_MSG_OOL_DESCRIPTOR;
    memcpy(m.marker, "RAX-INLINE-MARK!", 16);
    printf("message size %zu\n", sizeof m);
    kr = mach_msg(&m.header, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
    printf("send %#x\n", kr);

    received_t r;
    memset(&r, 0, sizeof r);
    kr = mach_msg(&r.message.header, MACH_RCV_MSG, 0, sizeof r, port, MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
    printf("receive %#x id %#x size %u\n", kr, r.message.header.msgh_id,
           r.message.header.msgh_size);
    int same = r.message.ool.size == sizeof ool
               && memcmp(r.message.ool.address, ool, sizeof ool) == 0
               && memcmp(r.message.marker, "RAX-INLINE-MARK!", 16) == 0;
    printf("contents %s\n", same ? "match" : "differ");
    vm_deallocate(task, (vm_address_t)r.message.ool.address, r.message.ool.size);

    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    kr = task_info(task, MACH_TASK_BASIC_INFO, (task_info_t)&info, &count);
    printf("task_info %#x count %u\n", kr, count);
    return 0;
}
