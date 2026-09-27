// Dumps a macOS kernel's sysctl subtrees as the sysctl metadata calls
// report them, one node per line, tab-separated: the name ({0,1}), the
// OID, the kind and format ({0,4}), and the description ({0,5}); interior
// nodes first, then every leaf {0,2} visits under the subtree.
//
//   xcrun clang -O1 -o sysctl_dump tools/darwin/sysctl_dump.c
//   ./sysctl_dump hw machdep > hw-machdep-arm64.tsv
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

static int name2oid(const char *n, int *oid) {
    int q[2] = {0, 3};
    size_t len = CTL_MAXNAME * sizeof(int);
    if (sysctl(q, 2, oid, &len, (void *)n, strlen(n))) return -1;
    return (int)(len / sizeof(int));
}

static void field(const char *s) {
    for (; *s; s++) {
        if (*s == '\t' || *s == '\n' || *s == '\\')
            printf("\\%c", *s == '\t' ? 't' : *s == '\n' ? 'n' : '\\');
        else
            putchar(*s);
    }
}

static void show(const int *oid, int n) {
    int q[CTL_MAXNAME + 2] = {0, 1};
    char buf[1024];
    size_t len = sizeof buf;
    memcpy(q + 2, oid, n * sizeof(int));
    if (sysctl(q, n + 2, buf, &len, 0, 0)) snprintf(buf, sizeof buf, "?%d", errno);
    field(buf);
    printf("\t");
    for (int i = 0; i < n; i++) printf(i ? ",%d" : "%d", oid[i]);
    q[1] = 4;
    char f[256];
    len = sizeof f;
    if (sysctl(q, n + 2, f, &len, 0, 0) == 0) {
        unsigned kind;
        memcpy(&kind, f, 4);
        printf("\t%#x\t", kind);
        field(f + 4);
    } else {
        printf("\t-\t-");
    }
    q[1] = 5;
    char d[1024];
    len = sizeof d;
    printf("\t");
    if (sysctl(q, n + 2, d, &len, 0, 0) == 0) field(d); else printf("-");
    printf("\n");
}

int main(int argc, char **argv) {
    for (int a = 1; a < argc; a++) {
        int oid[CTL_MAXNAME];
        int n = name2oid(argv[a], oid);
        if (n < 0) continue;
        show(oid, n);
        int cur[CTL_MAXNAME], cn = n;
        memcpy(cur, oid, n * sizeof(int));
        for (;;) {
            int q[CTL_MAXNAME + 2] = {0, 2};
            memcpy(q + 2, cur, cn * sizeof(int));
            int nx[CTL_MAXNAME];
            size_t len = sizeof nx;
            if (sysctl(q, cn + 2, nx, &len, 0, 0)) break;
            int nn = (int)(len / sizeof(int));
            if (nn < n || memcmp(nx, oid, n * sizeof(int))) break;
            // The interior nodes on the way to this leaf.
            for (int d = n + 1; d < nn; d++)
                if (d > cn || memcmp(cur, nx, d * sizeof(int))) show(nx, d);
            show(nx, nn);
            memcpy(cur, nx, nn * sizeof(int));
            cn = nn;
        }
    }
    return 0;
}
