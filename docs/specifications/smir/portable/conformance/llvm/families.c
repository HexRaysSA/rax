/* Header-free existing-target witnesses; not a portable frontend/sysroot. */
typedef unsigned long size_t;
struct Record { int a; double b; };
struct Big { unsigned char bytes[32]; };
extern void *memcpy(void *, const void *, size_t);
extern void *memmove(void *, const void *, size_t);
_Thread_local int logical_tls;
volatile int volatile_cell;
_Atomic(unsigned long) scalar_atomic;
_Atomic(struct Big) wide_atomic;
struct Record aggregate_copy(struct Record x) { return x; }
int tls_volatile(int x) {
    logical_tls += x;
    volatile_cell = logical_tls;
    return volatile_cell;
}
unsigned long compare_exchange(unsigned long expected, unsigned long desired) {
    __c11_atomic_compare_exchange_strong(&scalar_atomic, &expected, desired, 5, 2);
    return expected;
}
struct Big large_atomic_load(void) { return __c11_atomic_load(&wide_atomic, 5); }
void move_bytes(void *dst, const void *src, size_t n) { memmove(dst, src, n); }
int promoted_varargs(int n, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, n);
    int value = __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    return value;
}
long double fp_convert(long long value, long double x) {
    return (long double)value / x + (long double)(unsigned long long)value;
}
typedef int Vec4 __attribute__((vector_size(16)));
Vec4 fixed_vector(Vec4 x, Vec4 y) { Vec4 mask=x<y; return (mask&x)|(~mask&y); }
