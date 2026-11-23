#include <errno.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int csops(pid_t, unsigned int, void *, size_t);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);

#define STATUS 0
#define XML_ENTITLEMENTS 7
#define DER_ENTITLEMENTS 16

int main(void)
{
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) ||
        count != TASK_AUDIT_TOKEN_COUNT) return 1;
    pid_t pid = getpid();
    unsigned int flags = 0;
    if (csops_audittoken(pid, STATUS, &flags, sizeof(flags), &token) || !flags) return 2;

    const unsigned int operations[] = {XML_ENTITLEMENTS, DER_ENTITLEMENTS};
    const unsigned char guard[] = {1, 2, 3, 4, 5, 6, 7, 8};
    for (unsigned int index = 0; index < 2; ++index) {
        unsigned int operation = operations[index];
        unsigned char buffer[sizeof(guard)];
        memcpy(buffer, guard, sizeof(buffer));
        if (csops(0, operation, buffer, sizeof(buffer)) ||
            csops_audittoken(pid, operation, buffer, sizeof(buffer), &token) ||
            memcmp(buffer, guard, sizeof(guard)) ||
            csops_audittoken(0, operation, NULL, 0, &token)) return 3;
        if (csops_audittoken(pid, operation, buffer, sizeof(buffer), NULL) != -1 ||
            errno != EINVAL) return 4;
        if (csops_audittoken(pid, operation, buffer, sizeof(buffer),
                (audit_token_t *)1) != -1 || errno != EFAULT) return 5;
        audit_token_t stale = token;
        stale.val[7] ^= 1;
        if (csops_audittoken(pid, operation, buffer, sizeof(buffer), &stale) != -1 ||
            errno != ESRCH) return 6;
    }
    puts("self entitlement queries leave empty replies untouched");
    return 0;
}
