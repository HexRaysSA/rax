/* C++23 language probes; no host standard-library headers or ABI substitution. */
struct Object {
    int value;
    constexpr int get(this const Object& self) { return self.value; }
};
constexpr int language_probe() {
    if consteval {
        return Object{23}.get();
    } else {
        return 0;
    }
}
static_assert(language_probe() == 23);
static_assert(sizeof(long) == 8 && sizeof(void*) == 8);
struct Pair { char a; int b; };
static_assert(sizeof(Pair) == 8 && __builtin_offsetof(Pair, b) == 4);
int cxx23_constant() { return language_probe(); }
