// Large struct by-value parameters and returns (byval / sret in IR).
//
// These calls carry ABI parameter attributes (byval, sret).  Passes that route
// calls through forwarder proxies must preserve those attributes end-to-end or
// the caller and callee disagree on argument layout — a silent ABI miscompile
// the verifier does not catch.  Deterministic checksum output makes any such
// corruption observable by a clean-vs-obfuscated diff.

#include <cstdint>
#include <cstdio>

struct Big {
    long a[8];
};

__attribute__((noinline)) Big make(long base) {
    Big b;
    for (int i = 0; i < 8; ++i)
        b.a[i] = base + (long)i * i;
    return b; // sret
}

__attribute__((noinline)) long consume(Big x) { // byval
    long s = 0;
    for (int i = 0; i < 8; ++i)
        s += x.a[i] * (i + 1);
    return s;
}

__attribute__((noinline)) Big transform(Big x, long k) { // byval + sret
    Big r;
    for (int i = 0; i < 8; ++i)
        r.a[i] = x.a[i] ^ k;
    return r;
}

int main() {
    long total = 0;
    for (long i = 0; i < 2000; ++i) { /* rax: was 20000 */
        Big b = make(i);
        Big t = transform(b, i & 0x3f);
        total += consume(t);
    }
    std::printf("%ld\n", total);
    return 0;
}
