/* Freestanding frontend witnesses: compiled for an explicit existing ABI. */
static_assert(__CHAR_BIT__ == 8);
static_assert(sizeof(long) == 8);
static_assert(sizeof(void *) == 8);
static_assert(sizeof(long double) == 16);
static_assert(alignof(long double) == 16);
struct CharInt { char a; int b; };
struct CharBit65 { char a; _BitInt(65) b; };
static_assert(sizeof(struct CharInt) == 8);
static_assert(__builtin_offsetof(struct CharInt, b) == 4);
static_assert(sizeof(_BitInt(65)) == 16);
static_assert(alignof(_BitInt(65)) == 8);
static_assert(__builtin_offsetof(struct CharBit65, b) == 8);
static_assert(sizeof(struct CharBit65) == 24);
unsigned _BitInt(65) wide_add(unsigned _BitInt(65) a, unsigned _BitInt(65) b) {
    return a + b;
}
int c23_constant(void) {
    constexpr int answer = 23;
    auto copy = answer;
    return copy;
}

struct CharBit65 clang_storage;
_BitInt(65) load_bit65(void) {
    return clang_storage.b;
}
