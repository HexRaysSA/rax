struct V { int v; };
struct B : virtual V { int b; };
struct D : B { char pad[64]; };
static_assert(sizeof(D) > sizeof(B));
B b; D d;
