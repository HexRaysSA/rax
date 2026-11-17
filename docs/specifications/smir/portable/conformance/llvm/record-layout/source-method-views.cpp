struct MethodViews {
    int value;
    int ordinary() { return value; }
    int lvalue() & { return value; }
    int rvalue() && { return value; }
    int explicit_object(this MethodViews &self) { return self.value; }
    static int static_like(MethodViews &self) { return self.value; }
    auto undecided();
    template<class T> auto unused(T x) { return x.nonexistent(x); }
};
static_assert(sizeof(MethodViews) == 4);
