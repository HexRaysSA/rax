// The audit calls: the process's audit identity (getauid, getaudit_addr,
// and auditon's session queries), the copy rules (short lengths, null and
// read-only buffers), and the privileged calls, which an unprivileged
// process is refused after or before their own checks.
#include <bsm/audit.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// The audit interfaces are deprecated, not gone.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static void show(const char *what, int r) { printf("%s: %d errno=%d\n", what, r, r ? errno : 0); }

int main(void) {
    au_id_t au = 12345;
    int r = getauid(&au);
    printf("getauid: %d errno=%d is_uid=%d unset=%d\n", r, r ? errno : 0, au == getuid(), au == AU_DEFAUDITID);
    show("getauid(NULL)", getauid(NULL));

    // The credential's audit information: a length shorter than the
    // structure gets that much, a longer one the structure.
    auditinfo_addr_t ai;
    memset(&ai, 0xa5, sizeof ai);
    r = getaudit_addr(&ai, sizeof ai);
    printf("getaudit_addr: %d errno=%d auid_matches=%d mask=%#x/%#x type=%u asid_set=%d flags=%#llx\n", r,
           r ? errno : 0, ai.ai_auid == au, ai.ai_mask.am_success, ai.ai_mask.am_failure, ai.ai_termid.at_type,
           ai.ai_asid > 0, (unsigned long long)ai.ai_flags);
    auditinfo_addr_t full = ai;
    unsigned lens[] = {0, 4, 8, 28, 47, 48, 56, 1000};
    for (unsigned k = 0; k < sizeof lens / sizeof *lens; k++) {
        unsigned len = lens[k];
        unsigned char b[1024];
        memset(b, 0xa5, sizeof b);
        r = getaudit_addr((auditinfo_addr_t *)b, (int)len);
        unsigned changed = 0, prefix = 1;
        for (unsigned i = 0; i < sizeof b; i++) changed += b[i] != 0xa5;
        for (unsigned i = 0; i < len && i < sizeof ai; i++) prefix &= b[i] == ((unsigned char *)&full)[i];
        printf("getaudit_addr length %u: %d errno=%d changed=%u prefix=%d\n", len, r, r ? errno : 0, changed, prefix);
    }
    show("getaudit_addr(NULL, 48)", getaudit_addr(NULL, sizeof ai));
    show("getaudit_addr(NULL, 0)", getaudit_addr(NULL, 0));

    // auditon: the session queries that need no privilege.
    au_asflgs_t flags = 0;
    r = auditon(A_GETSFLAGS, &flags, sizeof flags);
    printf("A_GETSFLAGS: %d errno=%d flags_match=%d\n", r, r ? errno : 0, flags == full.ai_flags);
    show("A_GETSFLAGS short", auditon(A_GETSFLAGS, &flags, 4));
    show("A_GETSFLAGS NULL", auditon(A_GETSFLAGS, NULL, sizeof flags));
    auditinfo_addr_t si;
    memset(&si, 0, sizeof si);
    si.ai_asid = full.ai_asid;
    r = auditon(A_GETSINFO_ADDR, &si, sizeof si);
    printf("A_GETSINFO_ADDR: %d errno=%d same=%d mask=%#x/%#x\n", r, r ? errno : 0,
           si.ai_auid == full.ai_auid && si.ai_asid == full.ai_asid && si.ai_flags == full.ai_flags,
           si.ai_mask.am_success, si.ai_mask.am_failure);
    si.ai_asid = 0x7ffffff0;
    show("A_GETSINFO_ADDR no session", auditon(A_GETSINFO_ADDR, &si, sizeof si));
    show("A_GETSINFO_ADDR short", auditon(A_GETSINFO_ADDR, &si, 8));
    // A query whose result cannot be written back fails ENOSYS.
    au_asflgs_t *ro = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    *ro = 0;
    mprotect(ro, 16384, PROT_READ);
    show("A_GETSFLAGS into read-only", auditon(A_GETSFLAGS, ro, sizeof *ro));
    show("auditon length 0", auditon(A_GETSFLAGS, &flags, 0));
    show("auditon length 65536", auditon(A_GETSFLAGS, &flags, 65536));
    show("auditon bad command", auditon(9999, &flags, sizeof flags));

    // The privileged ones.
    int cond = 0;
    show("A_GETCOND", auditon(A_GETCOND, &cond, sizeof cond));
    show("A_GETPOLICY NULL", auditon(A_GETPOLICY, NULL, sizeof cond));
    au_id_t id = au;
    show("setauid", setauid(&id));
    show("setauid(NULL)", setauid(NULL));
    auditinfo_addr_t set = full;
    show("setaudit_addr", setaudit_addr(&set, sizeof set));
    set.ai_termid.at_type = 7;
    show("setaudit_addr bad type", setaudit_addr(&set, sizeof set));
    set = full;
    set.ai_asid = 0x7ffffff0;
    show("setaudit_addr bad asid", setaudit_addr(&set, sizeof set));
    show("setaudit_addr short", setaudit_addr(&set, 8));
    show("setaudit_addr(NULL)", setaudit_addr(NULL, sizeof set));
    char rec[16] = {0};
    show("audit", audit(rec, sizeof rec));
    show("audit(NULL)", audit(NULL, 16));
    show("audit length 0", audit(rec, 0));
    show("auditctl", auditctl("/nonexistent/trail"));
    show("auditctl(NULL)", auditctl(NULL));
    show("auditctl(bad)", auditctl((const char *)8));
    return 0;
}
