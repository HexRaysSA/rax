struct V { virtual void f(); };
struct W { virtual void g(); };
struct A: virtual V { void f() override; virtual void h(); };
struct C: virtual A, virtual W {
    void f() override;
    void h() override;
    void g() override;
};
