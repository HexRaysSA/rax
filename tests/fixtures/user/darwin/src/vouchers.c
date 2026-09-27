/* Mach vouchers and activity IDs: creation, deduplication, extraction,
 * attribute commands, voucher ports, vouchers in messages, thread
 * vouchers, and activity-ID allocation. Port names, pids, and absolute
 * activity IDs are never printed, only relations between them; strings
 * that embed the pid are compared with a locally formatted expectation.
 * Uref counts of the BANK_CREATE voucher are printed only as deltas
 * (under Rosetta the runtime already holds one reference to it). */
#include <mach/mach.h>
#include <mach/mach_voucher.h>
#include <mach/mach_traps.h>
#include <bank/bank_types.h>
#include <atm/atm_types.h>
#include <mach_debug/mach_debug.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PTHPRIORITY_CREATE 710
extern int __bsdthread_ctl(uintptr_t cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

static mach_port_t task;
static int pid;
static uint8_t rb[6144];

static size_t put(uint8_t *b, size_t off, uint32_t key, uint32_t cmd, mach_port_name_t prev,
                  const void *c, uint32_t cs) {
    mach_voucher_attr_recipe_data_t r = { key, cmd, prev, cs };
    memcpy(b + off, &r, sizeof r);
    if (cs) memcpy(b + off + sizeof r, c, cs);
    return off + sizeof r + cs;
}

static kern_return_t mk(size_t n, mach_port_name_t *v) {
    *v = 0x5eed;
    return host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)rb,
                                    (mach_msg_type_number_t)n, v);
}

static kern_return_t mk1(uint32_t key, uint32_t cmd, mach_port_name_t prev, const void *c,
                         uint32_t cs, mach_port_name_t *v) {
    return mk(put(rb, 0, key, cmd, prev, c, cs), v);
}

static int urefs(mach_port_name_t n) {
    mach_port_urefs_t r = 0;
    kern_return_t kr = mach_port_get_refs(task, n, MACH_PORT_RIGHT_SEND, &r);
    return kr ? -(int)kr : (int)r;
}

static void expect_text(const char *label, const uint8_t *p, uint32_t n, const char *fmt) {
    char want[128];
    int len = snprintf(want, sizeof want, fmt, pid);
    printf("%s size=%u matches=%d\n", label, n, (uint32_t)len + 1 == n && memcmp(p, want, n) == 0);
}

static void extract(const char *label, mach_port_name_t v, uint32_t key, uint32_t in) {
    uint8_t b[6144];
    memset(b, 0xAA, sizeof b);
    mach_msg_type_number_t sz = in;
    kern_return_t kr = mach_voucher_extract_attr_recipe_trap(v, key, b, &sz);
    printf("%s key=%u in=%u: kr=%#x size=%u", label, key, in, kr, sz);
    if (kr == 0 && sz >= 16) {
        mach_voucher_attr_recipe_data_t *r = (void *)b;
        printf(" key=%u cmd=%u prev=%u csize=%u", r->key, r->command, r->previous_voucher,
               r->content_size);
    }
    printf("\n");
}

static void *other_thread(void *arg) {
    mach_port_name_t v = 1;
    kern_return_t kr = thread_get_mach_voucher(mach_thread_self(), 0, &v);
    printf("thread: new pthread voucher kr=%#x null=%d\n", kr, v == 0);
    return arg;
}

static volatile int spin = 1;
static void *spinner(void *arg) {
    while (spin) usleep(1000);
    return arg;
}

typedef struct { mach_msg_header_t h; uint8_t pad[256]; } msg_t;

static void roundtrip(const char *label, mach_port_name_t rp, mach_port_name_t v,
                      mach_msg_type_name_t vdisp, mach_msg_option_t rcv, mach_port_name_t expect) {
    msg_t m;
    memset(&m, 0, sizeof m);
    m.h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, vdisp, 0);
    m.h.msgh_remote_port = rp;
    m.h.msgh_voucher_port = v;
    m.h.msgh_size = sizeof(mach_msg_header_t);
    int u0 = v && v != 0x1234 ? urefs(v) : 0;
    kern_return_t s = mach_msg(&m.h, MACH_SEND_MSG, m.h.msgh_size, 0, 0, 0, 0);
    int u1 = v && v != 0x1234 ? urefs(v) : 0;
    memset(&m, 0, sizeof m);
    kern_return_t r = mach_msg(&m.h, MACH_RCV_MSG | rcv, 0, sizeof m, rp, 0, 0);
    int u2 = v && v != 0x1234 ? urefs(v) : 0;
    printf("%s: send=%#x rcv=%#x voucher_bits=%u received=%s urefs %+d/%+d\n", label, s, r,
           MACH_MSGH_BITS_VOUCHER(m.h.msgh_bits),
           m.h.msgh_voucher_port == 0 ? "null"
           : m.h.msgh_voucher_port == expect ? "expected"
           : m.h.msgh_voucher_port == 0x1234 ? "0x1234" : "other",
           u1 - u0, u2 - u1);
}

int main(void) {
    task = mach_task_self();
    pid = getpid();
    kern_return_t kr;
    mach_port_name_t bank, bank2, empty, ud, v;

    /* 1. Creation basics. */
    kr = mk(0, &v);
    printf("create: empty array kr=%#x null=%d\n", kr, v == 0);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_BANK_CREATE, 0, NULL, 0, &bank);
    int bu = urefs(bank);
    printf("create: bank kr=%#x null=%d\n", kr, bank == 0);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_BANK_CREATE, 0, NULL, 0, &bank2);
    printf("create: bank again kr=%#x same=%d urefs %+d\n", kr, bank2 == bank, urefs(bank) - bu);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_ALL, MACH_VOUCHER_ATTR_COPY, 0, NULL, 0, &empty);
    printf("create: copy(all, no prev) kr=%#x null=%d urefs=%d\n", kr, empty == 0, urefs(empty));
    kr = mk1(MACH_VOUCHER_ATTR_KEY_USER_DATA, MACH_VOUCHER_ATTR_USER_DATA_STORE, 0, NULL, 0, &v);
    printf("create: user data of size 0 kr=%#x is_empty=%d\n", kr, v == empty);
    uint32_t pp0 = 0;
    kr = mk1(MACH_VOUCHER_ATTR_KEY_PTHPRIORITY, PTHPRIORITY_CREATE, 0, &pp0, 4, &v);
    printf("create: pthpriority 0 kr=%#x is_empty=%d\n", kr, v == empty);
    uint32_t ppx = 0x15;
    kr = mk1(MACH_VOUCHER_ATTR_KEY_PTHPRIORITY, PTHPRIORITY_CREATE, 0, &ppx, 4, &v);
    printf("create: pthpriority 0x15 (no QoS) kr=%#x is_empty=%d\n", kr, v == empty);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_USER_DATA, MACH_VOUCHER_ATTR_USER_DATA_STORE, 0, "fixture", 8, &ud);
    int uu = urefs(ud);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_USER_DATA, MACH_VOUCHER_ATTR_USER_DATA_STORE, 0, "fixture", 8, &v);
    printf("create: user data twice kr=%#x same=%d urefs %d->%d\n", kr, v == ud, uu, urefs(ud));
    size_t n = put(rb, 0, MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_BANK_CREATE, 0, NULL, 0);
    n = put(rb, n, MACH_VOUCHER_ATTR_KEY_USER_DATA, MACH_VOUCHER_ATTR_USER_DATA_STORE, 0, "fixture", 8);
    mach_port_name_t both, both2;
    kr = mk(n, &both);
    n = put(rb, 0, MACH_VOUCHER_ATTR_KEY_USER_DATA, MACH_VOUCHER_ATTR_USER_DATA_STORE, 0, "fixture", 8);
    n = put(rb, n, MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_BANK_CREATE, 0, NULL, 0);
    kern_return_t kr2 = mk(n, &both2);
    printf("create: bank+udata kr=%#x/%#x order_independent=%d distinct=%d\n", kr, kr2,
           both == both2, both != bank && both != ud);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_ALL, MACH_VOUCHER_ATTR_COPY, bank, NULL, 0, &v);
    printf("create: copy(all, prev=bank) kr=%#x is_bank=%d\n", kr, v == bank);
    n = put(rb, 0, MACH_VOUCHER_ATTR_KEY_ALL, MACH_VOUCHER_ATTR_COPY, both, NULL, 0);
    n = put(rb, n, MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_REMOVE, 0, NULL, 0);
    kr = mk(n, &v);
    printf("create: copy(all, prev=bank+udata)+remove(bank) kr=%#x is_udata=%d\n", kr, v == ud);
    n = put(rb, 0, MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_BANK_CREATE, 0, NULL, 0);
    n = put(rb, n, MACH_VOUCHER_ATTR_KEY_ALL, MACH_VOUCHER_ATTR_REMOVE, bank, NULL, 0);
    kr = mk(n, &v);
    printf("create: bank+remove(all, prev=bank) kr=%#x is_empty=%d\n", kr, v == empty);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_REDEEM, bank, NULL, 0, &v);
    printf("create: redeem(bank, prev=bank) kr=%#x is_bank=%d\n", kr, v == bank);
    n = put(rb, 0, MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_BANK_CREATE, 0, NULL, 0);
    n = put(rb, n, MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_SEND_PREPROCESS, 0, NULL, 0);
    mach_port_name_t pre;
    kr = mk(n, &pre);
    printf("create: bank+send_preprocess kr=%#x distinct=%d\n", kr, pre != bank && pre != empty);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_AUTO_REDEEM, pre, NULL, 0, &v);
    printf("create: auto_redeem(prev=preprocessed) kr=%#x is_bank=%d\n", kr, v == bank);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_AUTO_REDEEM, bank, NULL, 0, &v);
    printf("create: auto_redeem(prev=bank) kr=%#x is_empty=%d\n", kr, v == empty);
    kr = mk1(MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_REDEEM, pre, NULL, 0, &v);
    printf("create: redeem(prev=preprocessed) kr=%#x is_bank=%d\n", kr, v == bank);
    mach_port_name_t imp;
    kr = mk1(MACH_VOUCHER_ATTR_KEY_IMPORTANCE, MACH_VOUCHER_ATTR_IMPORTANCE_SELF, 0, NULL, 0, &imp);
    printf("create: importance self kr=%#x distinct=%d\n", kr, imp != empty);
    uint32_t ppq = 0x21000;
    mach_port_name_t pq;
    kr = mk1(MACH_VOUCHER_ATTR_KEY_PTHPRIORITY, PTHPRIORITY_CREATE, 0, &ppq, 4, &pq);
    printf("create: pthpriority 0x21000 kr=%#x distinct=%d\n", kr, pq != empty);
    kr = mk1(9, MACH_VOUCHER_ATTR_COPY, 0, NULL, 0, &v);
    printf("create: copy(key 9, no prev) kr=%#x is_empty=%d\n", kr, v == empty);
    kr = mk1(1, MACH_VOUCHER_ATTR_COPY, bank, NULL, 0, &v);
    printf("create: copy(key 1, prev=bank) kr=%#x is_empty=%d\n", kr, v == empty);

    /* 2. Creation errors. */
    struct { const char *what; uint32_t key, cmd; mach_port_name_t prev; const char *c; uint32_t cs; int trunc; } bad[] = {
        { "truncated header", 3, 610, 0, NULL, 0, 8 },
        { "content overruns", 7, 211, 0, "abc", 4, -1 },
        { "bank unknown command", 3, 9999, 0, NULL, 0, 0 },
        { "bank noop", 3, 0, 0, NULL, 0, 0 },
        { "atm create", 1, 510, 0, NULL, 0, 0 },
        { "key 5", 5, 1000, 0, NULL, 0, 0 },
        { "key 0", 0, 1000, 0, NULL, 0, 0 },
        { "key all + bank create", 0xffffffffu, 610, 0, NULL, 0, 0 },
        { "copy with content", 3, 1, 0, "x", 1, 0 },
        { "remove with content", 3, 2, 0, "y", 1, 0 },
        { "remove key 9", 9, 2, 0, NULL, 0, 0 },
        { "prev = task port", 3, 1, 1, NULL, 0, 0 },
        { "prev = bogus name", 3, 1, 0x12345, NULL, 0, 0 },
        { "prev = dead name", 3, 1, 0xffffffffu, NULL, 0, 0 },
        { "set value handle", 3, 3, 0, "\1\0\0\0\0\0\0\0", 8, 0 },
        { "redeem(all)", 0xffffffffu, 10, 2, NULL, 0, 0 },
        { "importance self with content", 2, 200, 0, "z", 1, 0 },
        { "pthpriority size 3", 4, 710, 0, "\x15\0\0", 3, 0 },
        { "user data noop", 7, 0, 0, NULL, 0, 0 },
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        mach_port_name_t prev = bad[i].prev == 1 ? task : bad[i].prev == 2 ? bank : bad[i].prev;
        n = put(rb, 0, bad[i].key, bad[i].cmd, prev, bad[i].c, bad[i].cs);
        if (bad[i].trunc > 0) n = (size_t)bad[i].trunc;
        if (bad[i].trunc < 0) n -= 1;
        kr = mk(n, &v);
        printf("create error: %s kr=%#x name_untouched=%d\n", bad[i].what, kr, v == 0x5eed);
    }
    n = put(rb, 0, 3, 610, 0, NULL, 0);
    kr = host_create_mach_voucher_trap(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)rb, -1, &v);
    printf("create error: trap size -1 kr=%#x\n", kr);
    kr = host_create_mach_voucher_trap(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)rb, 5121, &v);
    printf("create error: trap size 5121 kr=%#x\n", kr);
    kr = host_create_mach_voucher_trap(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)8, 16, &v);
    printf("create error: trap unreadable recipes kr=%#x\n", kr);
    kr = host_create_mach_voucher_trap(MACH_PORT_NULL, (mach_voucher_attr_raw_recipe_array_t)rb, 16, &v);
    printf("create error: trap host 0 kr=%#x\n", kr);
    kr = host_create_mach_voucher_trap(task, (mach_voucher_attr_raw_recipe_array_t)rb, 16, &v);
    printf("create error: trap host = task port kr=%#x\n", kr);
    kr = host_create_mach_voucher(task, (mach_voucher_attr_raw_recipe_array_t)rb, 16, &v);
    printf("create error: library host = task port kr=%#x\n", kr);
    bu = urefs(bank);
    kr = host_create_mach_voucher_trap(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)rb, 16,
                                       (mach_port_name_t *)8);
    printf("create error: trap unwritable result kr=%#x bank urefs %+d\n", kr, urefs(bank) - bu);
    static uint8_t big[5104];
    memset(big, 'u', sizeof big);
    put(rb, 0, 7, 211, 0, big, sizeof big);
    kr = mk(5120, &v);
    printf("create: user data of 5104 bytes kr=%#x\n", kr);

    /* 3. Extraction. */
    uint32_t keys[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xffffffffu };
    for (unsigned i = 0; i < sizeof keys / sizeof keys[0]; i++) extract("extract bank voucher", bank, keys[i], 1024);
    uint32_t sizes[] = { 0, 15, 16, 17, 515, 516, 5120, 5121 };
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) extract("extract bank size", bank, 3, sizes[i]);
    {
        uint8_t b[1024]; mach_msg_type_number_t sz = sizeof b;
        kr = mach_voucher_extract_attr_recipe_trap(bank, 3, b, &sz);
        expect_text("extract bank text", b + 16, sz - 16, " Bank Context for a pid %d\n");
        sz = sizeof b;
        kr = mach_voucher_extract_attr_recipe_trap(pre, 3, b, &sz);
        printf("extract preprocessed kr=%#x cmd=%u\n", kr, ((mach_voucher_attr_recipe_data_t *)b)->command);
        expect_text("extract preprocessed text", b + 16, sz - 16, " Bank Context for a pid %d\n");
        sz = sizeof b;
        kr = mach_voucher_extract_attr_recipe_trap(imp, 2, b, &sz);
        printf("extract importance kr=%#x cmd=%u\n", kr, ((mach_voucher_attr_recipe_data_t *)b)->command);
        expect_text("extract importance text", b + 16, sz - 16, "Importance for pid %d");
        sz = 21;
        kr = mach_voucher_extract_attr_recipe_trap(imp, 2, b, &sz);
        printf("extract importance in=21 kr=%#x size=%u text=%.4s nul=%d\n", kr, sz, (char *)b + 16, b[20] == 0);
        extract("extract importance", imp, 2, 16);
        extract("extract pthpriority", pq, 4, 1024);
        sz = sizeof b;
        mach_voucher_extract_attr_recipe_trap(pq, 4, b, &sz);
        uint32_t val; memcpy(&val, b + 16, 4);
        printf("extract pthpriority value=%#x\n", val);
        extract("extract pthpriority", pq, 4, 19);
        extract("extract user data", ud, 7, 1024);
        extract("extract user data", ud, 7, 16);
        extract("extract user data", ud, 7, 23);
        sz = sizeof b;
        mach_voucher_extract_attr_recipe_trap(ud, 7, b, &sz);
        printf("extract user data content=%s\n", (char *)b + 16);
        extract("extract empty", empty, 3, 1024);
    }
    {
        uint8_t b[64]; mach_msg_type_number_t sz = sizeof b;
        kr = mach_voucher_extract_attr_recipe_trap(MACH_PORT_NULL, 3, b, &sz);
        printf("extract error: trap name 0 kr=%#x\n", kr);
        sz = sizeof b;
        kr = mach_voucher_extract_attr_recipe_trap(task, 3, b, &sz);
        printf("extract error: trap task port kr=%#x\n", kr);
        sz = sizeof b;
        kr = mach_voucher_extract_attr_recipe(task, 3, b, &sz);
        printf("extract error: library task port kr=%#x\n", kr);
        kr = mach_voucher_extract_attr_recipe_trap(bank, 3, b, (mach_msg_type_number_t *)8);
        printf("extract error: unreadable size kr=%#x\n", kr);
        sz = 64;
        kr = mach_voucher_extract_attr_recipe_trap(ud, 3, (uint8_t *)8, &sz);
        printf("extract error: unreadable buffer (no value) kr=%#x size=%u\n", kr, sz);
    }
    {
        uint8_t c[1024]; mach_msg_type_number_t cs = sizeof c;
        kr = mach_voucher_extract_attr_content(bank, 3, c, &cs);
        expect_text("content bank", c, cs, " Bank Context for a pid %d\n");
        cs = 499;
        kr = mach_voucher_extract_attr_content(bank, 3, c, &cs);
        printf("content bank size 499 kr=%#x\n", kr);
        cs = 0;
        kr = mach_voucher_extract_attr_content(bank, 3, c, &cs);
        printf("content bank size 0 kr=%#x size=%u\n", kr, cs);
        cs = sizeof c;
        kr = mach_voucher_extract_attr_content(ud, 7, c, &cs);
        printf("content user data kr=%#x size=%u content=%s\n", kr, cs, (char *)c);
        cs = sizeof c;
        kr = mach_voucher_extract_attr_content(task, 3, c, &cs);
        printf("content on task port kr=%#x\n", kr);
    }
    {
        uint8_t a[5120]; mach_msg_type_number_t as = sizeof a;
        memset(a, 0xAA, sizeof a);
        kr = mach_voucher_extract_all_attr_recipes(both, a, &as);
        printf("extract all bank+udata kr=%#x size=%u\n", kr, as);
        for (uint32_t off = 0; kr == 0 && off + 16 <= as;) {
            mach_voucher_attr_recipe_data_t *r = (void *)(a + off);
            printf("  recipe key=%u cmd=%u prev=%u csize=%u\n", r->key, r->command, r->previous_voucher, r->content_size);
            off += 16 + r->content_size;
        }
        as = 16;
        kr = mach_voucher_extract_all_attr_recipes(bank, a, &as);
        printf("extract all bank size 16 kr=%#x size=%u cmd=%u\n", kr, as, ((mach_voucher_attr_recipe_data_t *)a)->command);
        as = 15;
        kr = mach_voucher_extract_all_attr_recipes(bank, a, &as);
        printf("extract all bank size 15 kr=%#x\n", kr);
        as = sizeof a;
        kr = mach_voucher_extract_all_attr_recipes(empty, a, &as);
        printf("extract all empty kr=%#x size=%u\n", kr, as);
        as = sizeof a;
        kr = mach_voucher_debug_info(task, bank, a, &as);
        printf("debug info kr=%#x\n", kr);
    }

    /* 4. Attribute commands. */
    {
        uint32_t cmds[] = { BANK_ORIGINATOR_PID, BANK_PERSONA_TOKEN, BANK_PERSONA_ID, BANK_PERSONA_ADOPT_ANY,
                            BANK_ORIGINATOR_PROXIMATE_PID, 0, 6 };
        mach_port_name_t on[] = { bank, empty };
        for (int w = 0; w < 2; w++)
            for (unsigned i = 0; i < sizeof cmds / sizeof cmds[0]; i++) {
                int32_t out[32]; mach_msg_type_number_t os = sizeof out;
                memset(out, 0xAA, sizeof out);
                kr = mach_voucher_attr_command(on[w], 3, cmds[i], NULL, 0, (uint8_t *)out, &os);
                printf("command %s bank cmd=%u: kr=%#x", w ? "empty" : "bank", cmds[i], kr);
                if (!kr) {
                    printf(" size=%u", os);
                    for (unsigned j = 0; j < os / 4; j++)
                        printf(out[j] == pid ? " pid" : " %d", out[j]);
                }
                printf("\n");
                os = 0;
                kr = mach_voucher_attr_command(on[w], 3, cmds[i], NULL, 0, (uint8_t *)out, &os);
                printf("command %s bank cmd=%u out 0: kr=%#x\n", w ? "empty" : "bank", cmds[i], kr);
            }
        uint8_t o[16]; mach_msg_type_number_t os = sizeof o; uint32_t one = 1;
        kr = mach_voucher_attr_command(ud, 7, 1, NULL, 0, o, &os);
        printf("command user data kr=%#x\n", kr);
        os = sizeof o;
        kr = mach_voucher_attr_command(pq, 4, 1, NULL, 0, o, &os);
        printf("command pthpriority kr=%#x\n", kr);
        os = sizeof o;
        kr = mach_voucher_attr_command(bank, 1, 1, NULL, 0, o, &os);
        printf("command atm kr=%#x\n", kr);
        os = 0;
        kr = mach_voucher_attr_command(imp, 2, MACH_VOUCHER_IMPORTANCE_ATTR_DROP_EXTERNAL, (uint8_t *)&one, 4, o, &os);
        printf("command importance drop kr=%#x\n", kr);
        os = 0;
        kr = mach_voucher_attr_command(imp, 2, MACH_VOUCHER_IMPORTANCE_ATTR_ADD_EXTERNAL, (uint8_t *)&one, 4, o, &os);
        printf("command importance add kr=%#x\n", kr);
        os = 0;
        kr = mach_voucher_attr_command(imp, 2, MACH_VOUCHER_IMPORTANCE_ATTR_DROP_EXTERNAL, NULL, 0, o, &os);
        printf("command importance no input kr=%#x\n", kr);
    }

    /* 5. Voucher ports. */
    {
        mach_port_type_t t = 0;
        kr = mach_port_type(task, bank, &t);
        printf("port: type kr=%#x type=%#x\n", kr, t);
        natural_t kt = 0; mach_vm_address_t ka = 1;
        kr = mach_port_kobject(task, bank, &kt, &ka);
        printf("port: kobject kr=%#x type=%u addr=%#llx\n", kr, kt, (unsigned long long)ka);
        mach_port_name_t d;
        kr = mk1(7, 211, 0, "dealloc", 8, &d);
        kr = mach_port_deallocate(task, d);
        printf("port: deallocate last ref kr=%#x refs=%d\n", kr, urefs(d));
        mach_port_name_t d2;
        kr = mk1(7, 211, 0, "dealloc", 8, &d2);
        printf("port: recreate kr=%#x same_name=%d\n", kr, d2 == d);
        kr = mach_port_mod_refs(task, d2, MACH_PORT_RIGHT_SEND, 2);
        printf("port: mod_refs +2 kr=%#x refs=%d\n", kr, urefs(d2));
        kr = mach_port_insert_right(task, d2, d2, MACH_MSG_TYPE_MAKE_SEND);
        printf("port: insert make-send kr=%#x\n", kr);
        mach_port_status_t st; mach_msg_type_number_t cnt = MACH_PORT_RECEIVE_STATUS_COUNT;
        kr = mach_port_get_attributes(task, d2, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&st, &cnt);
        printf("port: receive status kr=%#x\n", kr);
    }

    /* 6. Vouchers in messages. */
    {
        mach_port_name_t rp;
        mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &rp);
        mach_port_insert_right(task, rp, rp, MACH_MSG_TYPE_MAKE_SEND);
        roundtrip("msg: udata copy-send, no rcv-voucher", rp, ud, MACH_MSG_TYPE_COPY_SEND, 0, ud);
        roundtrip("msg: udata copy-send, rcv-voucher", rp, ud, MACH_MSG_TYPE_COPY_SEND, MACH_RCV_VOUCHER, ud);
        roundtrip("msg: udata move-send, rcv-voucher", rp, ud, MACH_MSG_TYPE_MOVE_SEND, MACH_RCV_VOUCHER, ud);
        roundtrip("msg: bank copy-send, rcv-voucher", rp, bank, MACH_MSG_TYPE_COPY_SEND, MACH_RCV_VOUCHER, bank);
        roundtrip("msg: preprocessed copy-send, rcv-voucher", rp, pre, MACH_MSG_TYPE_COPY_SEND, MACH_RCV_VOUCHER, bank);
        roundtrip("msg: bank+udata copy-send, rcv-voucher", rp, both, MACH_MSG_TYPE_COPY_SEND, MACH_RCV_VOUCHER, both);
        roundtrip("msg: importance copy-send, rcv-voucher", rp, imp, MACH_MSG_TYPE_COPY_SEND, MACH_RCV_VOUCHER, empty);
        roundtrip("msg: pthpriority copy-send, rcv-voucher", rp, pq, MACH_MSG_TYPE_COPY_SEND, MACH_RCV_VOUCHER, pq);
        roundtrip("msg: no voucher bits, field 0x1234", rp, 0x1234, 0, MACH_RCV_VOUCHER, 0);
        roundtrip("msg: copy-send of name 0, no rcv-voucher", rp, 0, MACH_MSG_TYPE_COPY_SEND, 0, 0);
        roundtrip("msg: copy-send of name 0, rcv-voucher", rp, 0, MACH_MSG_TYPE_COPY_SEND, MACH_RCV_VOUCHER, 0);
        msg_t m;
        memset(&m, 0, sizeof m);
        m.h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, MACH_MSG_TYPE_MAKE_SEND, 0);
        m.h.msgh_remote_port = rp; m.h.msgh_voucher_port = ud; m.h.msgh_size = sizeof(mach_msg_header_t);
        printf("msg error: make-send voucher kr=%#x\n", mach_msg(&m.h, MACH_SEND_MSG, m.h.msgh_size, 0, 0, 0, 0));
        m.h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, MACH_MSG_TYPE_COPY_SEND, 0);
        m.h.msgh_voucher_port = rp;
        printf("msg error: non-voucher voucher kr=%#x\n", mach_msg(&m.h, MACH_SEND_MSG, m.h.msgh_size, 0, 0, 0, 0));
        m.h.msgh_voucher_port = MACH_PORT_DEAD;
        printf("msg error: dead voucher kr=%#x\n", mach_msg(&m.h, MACH_SEND_MSG, m.h.msgh_size, 0, 0, 0, 0));
        struct { mach_msg_header_t h; mach_msg_body_t b; mach_msg_port_descriptor_t d; uint8_t pad[64]; } cm;
        memset(&cm, 0, sizeof cm);
        cm.h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
        cm.h.msgh_remote_port = rp;
        cm.h.msgh_size = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + sizeof(mach_msg_port_descriptor_t);
        cm.b.msgh_descriptor_count = 1;
        cm.d.name = ud; cm.d.disposition = MACH_MSG_TYPE_COPY_SEND; cm.d.type = MACH_MSG_PORT_DESCRIPTOR;
        int u0 = urefs(ud);
        kr = mach_msg(&cm.h, MACH_SEND_MSG, cm.h.msgh_size, 0, 0, 0, 0);
        memset(&cm, 0, sizeof cm);
        kr2 = mach_msg(&cm.h, MACH_RCV_MSG, 0, sizeof cm, rp, 0, 0);
        printf("msg: voucher in a port descriptor send=%#x rcv=%#x same=%d urefs %+d\n", kr, kr2, cm.d.name == ud, urefs(ud) - u0);
    }

    /* 7. Thread and task vouchers. */
    {
        mach_port_name_t tv = 1;
        mach_port_t self = mach_thread_self();
        kr = thread_get_mach_voucher(self, 0, &tv);
        printf("thread: initial kr=%#x null=%d\n", kr, tv == 0);
        int u0 = urefs(ud);
        kr = thread_set_mach_voucher(self, ud);
        printf("thread: set kr=%#x urefs %+d\n", kr, urefs(ud) - u0);
        kr = thread_get_mach_voucher(self, 0, &tv);
        printf("thread: get kr=%#x same=%d urefs %+d\n", kr, tv == ud, urefs(ud) - u0);
        kr = thread_get_mach_voucher(self, 1, &tv);
        printf("thread: get effective kr=%#x same=%d\n", kr, tv == ud);
        mach_port_name_t old = ud;
        kr = thread_swap_mach_voucher(self, bank, &old);
        printf("thread: swap kr=%#x old_unchanged=%d\n", kr, old == ud);
        kr = thread_set_mach_voucher(self, task);
        kr2 = thread_get_mach_voucher(self, 0, &tv);
        printf("thread: set to task port kr=%#x then get null=%d\n", kr, tv == 0);
        kr = thread_get_mach_voucher(task, 0, &tv);
        printf("thread: get on task port kr=%#x\n", kr);
        pthread_t th;
        pthread_create(&th, NULL, other_thread, NULL);
        pthread_join(th, NULL);
        pthread_create(&th, NULL, spinner, NULL);
        usleep(20000);
        kr = thread_set_mach_voucher(pthread_mach_thread_np(th), ud);
        printf("thread: set on another running thread kr=%#x\n", kr);
        spin = 0;
        pthread_join(th, NULL);
        errno = 0;
        int r = __bsdthread_ctl(0x100, 0, ud, 0x02);
        printf("set_self: user data voucher r=%d errno=%d\n", r, errno);
        kr = thread_get_mach_voucher(self, 0, &tv);
        printf("set_self: then get same=%d\n", tv == ud);
        errno = 0; r = __bsdthread_ctl(0x100, 0, task, 0x02);
        printf("set_self: task port r=%d errno=%d\n", r, errno);
        errno = 0; r = __bsdthread_ctl(0x100, 0, 0xffffffffu, 0x02);
        printf("set_self: dead name r=%d errno=%d\n", r, errno);
        errno = 0; r = __bsdthread_ctl(0x100, 0x12345678, 0x7777, 0x03);
        printf("set_self: bad qos and bad voucher r=%d errno=%d\n", r, errno);
        errno = 0; r = __bsdthread_ctl(0x100, 0, 0, 0x02);
        kr = thread_get_mach_voucher(self, 0, &tv);
        printf("set_self: null r=%d then get null=%d\n", r, tv == 0);
        mach_port_name_t hold;
        kr = mk1(7, 211, 0, "held by thread", 15, &hold);
        kr = thread_set_mach_voucher(self, hold);
        int hu = urefs(hold);
        for (int i = 0; i < hu; i++) mach_port_deallocate(task, hold);
        kr = thread_get_mach_voucher(self, 0, &tv);
        uint8_t b[64]; mach_msg_type_number_t sz = sizeof b;
        kr2 = mach_voucher_extract_attr_recipe_trap(tv, 7, b, &sz);
        printf("thread: voucher outlives its names kr=%#x extract=%#x content=%s\n", kr, kr2, (char *)b + 16);
        thread_set_mach_voucher(self, MACH_PORT_NULL);
        kr = task_get_mach_voucher(task, 0, &tv);
        printf("task: get kr=%#x null=%d\n", kr, tv == 0);
        kr = task_set_mach_voucher(task, ud);
        printf("task: set kr=%#x\n", kr);
        old = ud;
        kr = task_swap_mach_voucher(task, ud, &old);
        printf("task: swap kr=%#x\n", kr);
    }

    /* 8. Activity IDs. */
    {
        uint64_t a = 0, b = 0, c = 0, d = 0;
        kern_return_t k1 = mach_generate_activity_id(task, 1, &a);
        kern_return_t k2 = mach_generate_activity_id(task, 1, &b);
        kern_return_t k3 = mach_generate_activity_id(task, 16, &c);
        kern_return_t k4 = mach_generate_activity_id(task, 1, &d);
        printf("activity: kr=%#x,%#x,%#x,%#x nonzero=%d below_2^52=%d increasing=%d step1=%d step16=%d\n", k1, k2, k3, k4,
               a != 0, a < (1ull << 52), a < b && b < c && c < d, b - a >= 1 && b - a < 1000000,
               d - c >= 16 && d - c < 1000000);
        printf("activity: count 0 kr=%#x\n", mach_generate_activity_id(task, 0, &a));
        printf("activity: count 17 kr=%#x\n", mach_generate_activity_id(task, 17, &a));
        printf("activity: count -1 kr=%#x\n", mach_generate_activity_id(task, -1, &a));
        printf("activity: target 0 kr=%#x\n", mach_generate_activity_id(MACH_PORT_NULL, 1, &a));
        printf("activity: unwritable kr=%#x\n", mach_generate_activity_id(task, 1, (uint64_t *)8));
    }
    return 0;
}
