struct R;
using P = R(*)[3];
using CP = const R(*)[3];
using P4 = R(*)[4];
using F = P(P);
static_assert(sizeof(P) == 8 && alignof(P) == 8 && sizeof(F*) == 8);
static_assert(!__is_same(P, CP) && !__is_same(P, P4));
P before(P value) { return value; }
struct R { int value; };
P after(P value) { return value; }
static_assert(sizeof(R[3]) == 12);
static_assert(__is_same(decltype(&before), decltype(&after)));
F* before_address = &before;
F* after_address = &after;
