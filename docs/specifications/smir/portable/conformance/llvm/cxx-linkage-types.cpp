// Records the pinned frontend's language-linkage TYPE equality behavior.
extern "C" { typedef int CFunction(int); }
extern "C++" { typedef int CxxFunction(int); }
static_assert(__is_same(CFunction, CxxFunction));
static_assert(!__is_same(wchar_t, int));
static_assert(!__is_same(char8_t, unsigned char));
static_assert(!__is_same(char16_t, unsigned short));
static_assert(!__is_same(char32_t, unsigned int));
