/*
 * C++ RTTI and dynamic_cast
 *
 * Tests runtime type information and dynamic type checking.
 * Exercises typeid, type_info, and dynamic_cast.
 *
 * Features exercised:
 *   - typeid operator
 *   - dynamic_cast for pointers and references
 *   - Cross-cast in multiple inheritance
 *   - Type comparison
 */

#include <cstdint>
#include <cinttypes> /* rax: print the result so that runs can be compared */
#include <cstdio>
#include <typeinfo>

volatile int64_t sink;

/* Base hierarchy for RTTI tests */
class Base {
public:
    int base_value;
    explicit Base(int v) : base_value(v) {}
    virtual ~Base() = default;
    virtual int get_type_id() const { return 0; }
};

class DerivedA : public Base {
public:
    int a_value;
    explicit DerivedA(int v) : Base(v), a_value(v * 2) {}
    int get_type_id() const override { return 1; }
    int specific_a() const { return a_value * 3; }
};

class DerivedB : public Base {
public:
    int b_value;
    explicit DerivedB(int v) : Base(v), b_value(v * 3) {}
    int get_type_id() const override { return 2; }
    int specific_b() const { return b_value * 4; }
};

class DerivedAA : public DerivedA {
public:
    int aa_value;
    explicit DerivedAA(int v) : DerivedA(v), aa_value(v * 4) {}
    int get_type_id() const override { return 3; }
    int specific_aa() const { return aa_value * 5; }
};

class DerivedAB : public DerivedA {
public:
    int ab_value;
    explicit DerivedAB(int v) : DerivedA(v), ab_value(v * 5) {}
    int get_type_id() const override { return 4; }
    int specific_ab() const { return ab_value * 6; }
};

/* Multiple inheritance for cross-cast tests */
class Interface1 {
public:
    virtual ~Interface1() = default;
    virtual int interface1_method() const = 0;
};

class Interface2 {
public:
    virtual ~Interface2() = default;
    virtual int interface2_method() const = 0;
};

class MultiDerived : public Base, public Interface1, public Interface2 {
public:
    int multi_value;
    explicit MultiDerived(int v) : Base(v), multi_value(v * 6) {}
    int get_type_id() const override { return 5; }
    int interface1_method() const override { return multi_value; }
    int interface2_method() const override { return multi_value * 2; }
};

/* Diamond inheritance for complex RTTI */
class VirtualBase {
public:
    int vb_value;
    explicit VirtualBase(int v) : vb_value(v) {}
    virtual ~VirtualBase() = default;
    virtual int identify() const { return 100; }
};

class LeftDerived : virtual public VirtualBase {
public:
    int left_value;
    explicit LeftDerived(int v) : VirtualBase(v), left_value(v * 2) {}
    int identify() const override { return 101; }
};

class RightDerived : virtual public VirtualBase {
public:
    int right_value;
    explicit RightDerived(int v) : VirtualBase(v), right_value(v * 3) {}
    int identify() const override { return 102; }
};

class DiamondDerived : public LeftDerived, public RightDerived {
public:
    int diamond_value;
    explicit DiamondDerived(int v)
        : VirtualBase(v), LeftDerived(v), RightDerived(v), diamond_value(v * 4) {}
    int identify() const override { return 103; }
};

/* dynamic_cast for downcasting */
__attribute__((noinline))
int64_t downcast_test(Base* ptr) {
    int64_t result = 0;

    /* Try casting to each derived type */
    if (DerivedAA* daa = dynamic_cast<DerivedAA*>(ptr)) {
        result += daa->specific_aa();
    } else if (DerivedAB* dab = dynamic_cast<DerivedAB*>(ptr)) {
        result += dab->specific_ab();
    } else if (DerivedA* da = dynamic_cast<DerivedA*>(ptr)) {
        result += da->specific_a();
    } else if (DerivedB* db = dynamic_cast<DerivedB*>(ptr)) {
        result += db->specific_b();
    } else {
        result += ptr->base_value;
    }

    return result;
}

/* dynamic_cast for cross-casting */
__attribute__((noinline))
int64_t crosscast_test(Base* ptr) {
    int64_t result = 0;

    /* Try to cross-cast to interfaces */
    if (Interface1* i1 = dynamic_cast<Interface1*>(ptr)) {
        result += i1->interface1_method();
    }
    if (Interface2* i2 = dynamic_cast<Interface2*>(ptr)) {
        result += i2->interface2_method();
    }

    return result;
}

/* dynamic_cast for sidecasting in diamond */
__attribute__((noinline))
int64_t sidecast_test(LeftDerived* left) {
    int64_t result = 0;

    /* Try to sidecast to RightDerived */
    if (RightDerived* right = dynamic_cast<RightDerived*>(left)) {
        result += right->right_value;
    }

    /* Try to downcast to DiamondDerived */
    if (DiamondDerived* diamond = dynamic_cast<DiamondDerived*>(left)) {
        result += diamond->diamond_value;
    }

    return result + left->left_value;
}

/* typeid comparisons */
__attribute__((noinline))
int64_t typeid_test(Base* ptr) {
    int64_t result = 0;

    /* Compare types */
    if (typeid(*ptr) == typeid(Base)) {
        result += 1;
    } else if (typeid(*ptr) == typeid(DerivedA)) {
        result += 2;
    } else if (typeid(*ptr) == typeid(DerivedB)) {
        result += 3;
    } else if (typeid(*ptr) == typeid(DerivedAA)) {
        result += 4;
    } else if (typeid(*ptr) == typeid(DerivedAB)) {
        result += 5;
    } else if (typeid(*ptr) == typeid(MultiDerived)) {
        result += 6;
    }

    /* Use type_info hash_code */
    result += typeid(*ptr).hash_code() & 0xFF;

    return result;
}

/* Reference dynamic_cast (throws on failure) */
__attribute__((noinline))
int64_t reference_cast_test(Base& ref) {
    int64_t result = 0;

    try {
        DerivedA& da = dynamic_cast<DerivedA&>(ref);
        result += da.specific_a();
    } catch (const std::bad_cast&) {
        result += 1000;
    }

    return result;
}

/* Type comparison using type_info */
__attribute__((noinline))
bool same_type(const Base* a, const Base* b) {
    return typeid(*a) == typeid(*b);
}

__attribute__((noinline))
bool is_derived_a(const Base* ptr) {
    /* Check if ptr is DerivedA or any subclass */
    return dynamic_cast<const DerivedA*>(ptr) != nullptr;
}

int main() {
    int64_t result = 0;

    /* Create objects of various types */
    Base base(10);
    DerivedA da(20);
    DerivedB db(30);
    DerivedAA daa(40);
    DerivedAB dab(50);
    MultiDerived multi(60);

    /* Diamond hierarchy objects */
    LeftDerived left(70);
    RightDerived right(80);
    DiamondDerived diamond(90);

    /* Array of base pointers */
    Base* bases[6] = {&base, &da, &db, &daa, &dab, &multi};

    /* Array of left derived pointers */
    LeftDerived* lefts[2] = {&left, &diamond};

    for (int iter = 0; iter < 6; iter++) { /* rax: was 50000 */
        /* Downcast tests */
        result += downcast_test(bases[iter % 6]);

        /* Cross-cast tests */
        result += crosscast_test(bases[iter % 6]);

        /* Sidecast tests */
        result += sidecast_test(lefts[iter % 2]);

        /* typeid tests */
        result += typeid_test(bases[iter % 6]);

        /* Reference cast tests */
        result += reference_cast_test(*bases[iter % 6]);

        /* Type comparison tests */
        result += same_type(bases[iter % 6], bases[(iter + 1) % 6]) ? 1 : 0;
        result += is_derived_a(bases[iter % 6]) ? 10 : 0;

        /* Virtual base dynamic_cast */
        VirtualBase* vb = &diamond;
        if (DiamondDerived* dd = dynamic_cast<DiamondDerived*>(vb)) {
            result += dd->identify();
        }

        /* Null pointer dynamic_cast (should return null) */
        Base* null_ptr = nullptr;
        DerivedA* null_result = dynamic_cast<DerivedA*>(null_ptr);
        result += (null_result == nullptr) ? 1 : 0;
    }

    sink = result;
    std::printf("sink=%" PRId64 "\n", static_cast<int64_t>(sink)); /* rax: print the result so that runs can be compared */
    return 0;
}
