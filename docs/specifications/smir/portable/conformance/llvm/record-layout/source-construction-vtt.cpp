struct V { int value; virtual void f(); };
struct A: virtual V { int a; void f() override; };
struct Pad { virtual void pad(); long extra; };
struct C: Pad, A { long c; void f() override; };
