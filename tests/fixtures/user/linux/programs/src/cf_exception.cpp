/*
 * C++ Exception Handling
 *
 * Tests exception throw/catch mechanisms.
 * Exercises stack unwinding and cleanup.
 *
 * Features exercised:
 *   - Exception throwing and catching
 *   - Stack unwinding
 *   - RAII destructors during unwinding
 *   - Exception specifications
 *   - Multiple catch handlers
 */

#include <cstdint>
#include <cinttypes> /* rax: print the result so that runs can be compared */
#include <cstdio>

volatile int64_t sink;

/* Custom exception classes */
class BaseException {
public:
    int code;
    explicit BaseException(int c) : code(c) {}
    virtual ~BaseException() = default;
    virtual int get_code() const { return code; }
};

class DerivedException : public BaseException {
public:
    int extra;
    DerivedException(int c, int e) : BaseException(c), extra(e) {}
    int get_code() const override { return code + extra; }
};

class AnotherException {
public:
    const char *message;
    explicit AnotherException(const char *msg) : message(msg) {}
};

/* RAII class for testing destructor calls during unwinding */
class ResourceGuard {
    int64_t *counter;
    int value;
public:
    ResourceGuard(int64_t *c, int v) : counter(c), value(v) {
        *counter += value;
    }
    ~ResourceGuard() {
        *counter -= value;
    }
    int get_value() const { return value; }
};

/* Simple throw and catch */
__attribute__((noinline))
int simple_throw_catch(int x) {
    try {
        if (x < 0) {
            throw BaseException(x);
        }
        return x * 2;
    } catch (const BaseException &e) {
        return e.code * -1;
    }
}

/* Nested try-catch */
__attribute__((noinline))
int nested_try_catch(int x) {
    try {
        try {
            if (x < 0) {
                throw BaseException(-1);
            }
            if (x == 0) {
                throw DerivedException(0, 100);
            }
            return x;
        } catch (const DerivedException &e) {
            return e.get_code();
        }
    } catch (const BaseException &e) {
        return e.code;
    }
}

/* Rethrow */
__attribute__((noinline))
int rethrow_example(int x) {
    try {
        try {
            if (x < 10) {
                throw BaseException(x);
            }
            return x;
        } catch (const BaseException &) {
            throw; /* Rethrow */
        }
    } catch (const BaseException &e) {
        return e.code + 1000;
    }
}

/* Multiple catch handlers */
__attribute__((noinline))
int multi_catch(int selector, int value) {
    try {
        switch (selector % 4) {
            case 0:
                throw BaseException(value);
            case 1:
                throw DerivedException(value, 10);
            case 2:
                throw AnotherException("error");
            case 3:
                throw value;
        }
        return 0;
    } catch (const DerivedException &e) {
        return e.get_code() * 2;
    } catch (const BaseException &e) {
        return e.code * 3;
    } catch (const AnotherException &) {
        return 999;
    } catch (int v) {
        return v * 4;
    } catch (...) {
        return -1;
    }
}

/* Stack unwinding with RAII */
__attribute__((noinline))
int64_t unwind_with_raii(int depth, int64_t *counter) {
    ResourceGuard guard(counter, depth * 10);

    if (depth <= 0) {
        throw BaseException(depth);
    }

    return unwind_with_raii(depth - 1, counter) + guard.get_value();
}

__attribute__((noinline))
int64_t test_unwinding(int depth) {
    int64_t counter = 0;
    try {
        return unwind_with_raii(depth, &counter);
    } catch (const BaseException &e) {
        /* Counter should be 0 after all destructors ran */
        return counter + e.code;
    }
}

/* Exception in constructor */
class MayThrow {
    int value;
public:
    explicit MayThrow(int v) : value(v) {
        if (v < 0) {
            throw BaseException(v);
        }
    }
    int get() const { return value; }
};

__attribute__((noinline))
int construct_may_throw(int x) {
    try {
        MayThrow obj(x);
        return obj.get() * 2;
    } catch (const BaseException &e) {
        return e.code;
    }
}

/* Exception across function boundaries */
__attribute__((noinline))
void thrower(int x) {
    if (x % 3 == 0) throw BaseException(x);
    if (x % 3 == 1) throw DerivedException(x, 5);
    throw x;
}

__attribute__((noinline))
int intermediate(int x) {
    ResourceGuard guard(const_cast<int64_t*>(&sink), 1);
    thrower(x);
    return 0;
}

__attribute__((noinline))
int caller_catches(int x) {
    try {
        return intermediate(x);
    } catch (const DerivedException &e) {
        return e.get_code();
    } catch (const BaseException &e) {
        return e.code;
    } catch (int v) {
        return v * 2;
    }
}

/* noexcept and exception propagation */
__attribute__((noinline))
int noexcept_wrapper(int x) noexcept {
    /* This function promises not to throw */
    /* If it did throw, std::terminate would be called */
    return x * x;
}

__attribute__((noinline))
int exception_or_not(int x) {
    try {
        if (x > 100) {
            return noexcept_wrapper(x);
        }
        throw BaseException(x);
    } catch (const BaseException &e) {
        return e.code + noexcept_wrapper(10);
    }
}

/* Loop with exceptions */
__attribute__((noinline))
int64_t loop_with_exceptions(int iterations) {
    int64_t sum = 0;
    for (int i = 0; i < iterations; i++) {
        try {
            if (i % 7 == 0) {
                throw BaseException(i);
            }
            sum += i;
        } catch (const BaseException &e) {
            sum += e.code * 2;
        }
    }
    return sum;
}

/* Exception specification in derived class */
class Base {
public:
    virtual int process(int x) { return x; }
    virtual ~Base() = default;
};

class DerivedThrower : public Base {
public:
    int process(int x) override {
        if (x < 0) throw BaseException(x);
        return x * 2;
    }
};

__attribute__((noinline))
int polymorphic_throw(Base *obj, int x) {
    try {
        return obj->process(x);
    } catch (const BaseException &e) {
        return e.code;
    }
}

int main() {
    int64_t result = 0;

    Base base;
    DerivedThrower derived;
    Base *objects[2] = {&base, &derived};

    for (int i = 0; i < 4; i++) { /* rax: was 50000 */
        /* Simple throw/catch */
        result += simple_throw_catch(i % 20 - 10);

        /* Nested try/catch */
        result += nested_try_catch(i % 10 - 3);

        /* Rethrow */
        result += rethrow_example(i % 20);

        /* Multiple catch handlers */
        result += multi_catch(i, i % 100);

        /* Stack unwinding */
        if (i % 100 == 0) {
            result += test_unwinding(5);
        }

        /* Constructor throw */
        result += construct_may_throw(i % 20 - 5);

        /* Cross-function exceptions */
        result += caller_catches(i % 10);

        /* noexcept */
        result += exception_or_not(i % 200);

        /* Loop with exceptions */
        if (i % 500 == 0) {
            result += loop_with_exceptions(8); /* rax: was 100 */
        }

        /* Polymorphic throw */
        result += polymorphic_throw(objects[i % 2], i % 20 - 5);
    }

    sink = result;
    std::printf("sink=%" PRId64 "\n", static_cast<int64_t>(sink)); /* rax: print the result so that runs can be compared */
    return 0;
}
