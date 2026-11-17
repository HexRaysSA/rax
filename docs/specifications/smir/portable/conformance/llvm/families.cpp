/* Native existing-target IR families, with no standard-library headers. */
extern int risky(int);
struct Guard {
    Guard();
    ~Guard() noexcept;
};
struct Base { virtual ~Base(); };
struct Derived : Base { int n; };
int exception_flow(int n) {
    Guard outer;
    try {
        Guard inner;
        return risky(n);
    } catch (const Derived& e) {
        return e.n;
    } catch (...) {
        throw;
    }
}
struct Base* checked_cast(Base *p) { return dynamic_cast<Derived*>(p); }
extern "C" __attribute__((returns_twice)) int portable_checkpoint(void *);
int nonlocal_frame(void *mark) { int r=portable_checkpoint(mark); return r ? r : 7; }
