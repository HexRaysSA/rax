struct A { virtual void f(); };
struct B: virtual A {};
struct C: B {};
struct D: virtual B, C {};
