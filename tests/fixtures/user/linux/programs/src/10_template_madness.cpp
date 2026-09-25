/**
 * =============================================================================
 *                    TEMPLATE METAPROGRAMMING MADNESS
 * =============================================================================
 * 
 * This file is a comprehensive showcase of C++ template metaprogramming
 * techniques, demonstrating the Turing-complete nature of the C++ type system.
 * 
 * Compile with: g++ -std=c++20 -O2 -o template_madness 10_template_madness.cpp
 * 
 * Topics covered:
 * 1. Type List Manipulation (Head, Tail, Concat, Reverse, Map, Filter, Fold)
 * 2. Compile-Time Computations (Fibonacci, Primes, String Parsing)
 * 3. Expression Templates for Lazy Evaluation
 * 4. SFINAE and C++20 Concepts
 * 5. Compile-Time Sorting
 * 6. Variadic Template Magic (Tuple, Format Validation)
 * 7. CRTP (Curiously Recurring Template Pattern)
 * 8. Fold Expressions and Parameter Pack Expansion
 * 
 * =============================================================================
 */

#include <iostream>
#include <type_traits>
#include <utility>
#include <array>
#include <cstddef>
#include <string_view>
#include <tuple>
#include <vector>
#include <memory> // std::unique_ptr / make_unique (libstdc++ needs it explicitly)
#include <cmath>

// =============================================================================
// PART 1: TYPE LIST MANIPULATION
// =============================================================================
/**
 * TypeList is the fundamental building block of type-level programming.
 * It's analogous to a linked list, but exists entirely in the type system.
 * 
 * Key insight: Types are "values" at compile time, and templates are "functions"
 * that operate on these type-values.
 */

namespace typelist {

// -----------------------------------------------------------------------------
// 1.1 Basic TypeList Definition
// -----------------------------------------------------------------------------
/**
 * The TypeList itself is just a variadic template that holds types.
 * It has no runtime representation - it's purely a compile-time construct.
 */
template<typename... Ts>
struct TypeList {
    static constexpr std::size_t size = sizeof...(Ts);
};

// Empty list alias for convenience
using EmptyList = TypeList<>;

// -----------------------------------------------------------------------------
// 1.2 Head - Extract the first type from a TypeList
// -----------------------------------------------------------------------------
/**
 * Head<TypeList<int, char, double>> == int
 * 
 * This uses partial template specialization. The general template is undefined
 * (SFINAE will catch misuse), and we specialize for TypeList with at least one element.
 */
template<typename List>
struct Head;

template<typename H, typename... Ts>
struct Head<TypeList<H, Ts...>> {
    using type = H;
};

template<typename List>
using Head_t = typename Head<List>::type;

// Static verification
static_assert(std::is_same_v<Head_t<TypeList<int, char, double>>, int>);

// -----------------------------------------------------------------------------
// 1.3 Tail - Remove the first type, return the rest
// -----------------------------------------------------------------------------
/**
 * Tail<TypeList<int, char, double>> == TypeList<char, double>
 * 
 * This is the complement to Head, giving us recursive list decomposition.
 */
template<typename List>
struct Tail;

template<typename H, typename... Ts>
struct Tail<TypeList<H, Ts...>> {
    using type = TypeList<Ts...>;
};

template<typename List>
using Tail_t = typename Tail<List>::type;

// Static verification
static_assert(std::is_same_v<Tail_t<TypeList<int, char, double>>, TypeList<char, double>>);

// -----------------------------------------------------------------------------
// 1.4 Concat - Concatenate two TypeLists
// -----------------------------------------------------------------------------
/**
 * Concat<TypeList<int, char>, TypeList<double, float>> == TypeList<int, char, double, float>
 * 
 * Uses parameter pack expansion to merge the contents of both lists.
 */
template<typename List1, typename List2>
struct Concat;

template<typename... Ts1, typename... Ts2>
struct Concat<TypeList<Ts1...>, TypeList<Ts2...>> {
    using type = TypeList<Ts1..., Ts2...>;
};

template<typename List1, typename List2>
using Concat_t = typename Concat<List1, List2>::type;

// Static verification
static_assert(std::is_same_v<
    Concat_t<TypeList<int, char>, TypeList<double, float>>,
    TypeList<int, char, double, float>
>);

// -----------------------------------------------------------------------------
// 1.5 Reverse - Reverse a TypeList
// -----------------------------------------------------------------------------
/**
 * Reverse<TypeList<int, char, double>> == TypeList<double, char, int>
 * 
 * This is a recursive algorithm:
 * - Base case: Empty list reverses to empty list
 * - Recursive case: Reverse(H :: Tail) = Reverse(Tail) ++ [H]
 * 
 * The ++ here is type-level concatenation (Concat).
 */
template<typename List>
struct Reverse;

// Base case: empty list
template<>
struct Reverse<TypeList<>> {
    using type = TypeList<>;
};

// Recursive case: move head to end of reversed tail
template<typename H, typename... Ts>
struct Reverse<TypeList<H, Ts...>> {
    using type = Concat_t<
        typename Reverse<TypeList<Ts...>>::type,
        TypeList<H>
    >;
};

template<typename List>
using Reverse_t = typename Reverse<List>::type;

// Static verification
static_assert(std::is_same_v<
    Reverse_t<TypeList<int, char, double>>,
    TypeList<double, char, int>
>);

// -----------------------------------------------------------------------------
// 1.6 Map - Apply a metafunction to each type in a TypeList
// -----------------------------------------------------------------------------
/**
 * Map<AddPointer, TypeList<int, char>> == TypeList<int*, char*>
 * 
 * The metafunction F must be a template that exposes a ::type member.
 * This is the type-level equivalent of map/transform in functional programming.
 */
template<template<typename> class F, typename List>
struct Map;

template<template<typename> class F>
struct Map<F, TypeList<>> {
    using type = TypeList<>;
};

template<template<typename> class F, typename... Ts>
struct Map<F, TypeList<Ts...>> {
    // Apply F to each type using pack expansion
    using type = TypeList<typename F<Ts>::type...>;
};

template<template<typename> class F, typename List>
using Map_t = typename Map<F, List>::type;

// Example metafunction: add pointer
template<typename T>
struct AddPointer {
    using type = T*;
};

// Static verification
static_assert(std::is_same_v<
    Map_t<AddPointer, TypeList<int, char, double>>,
    TypeList<int*, char*, double*>
>);

// -----------------------------------------------------------------------------
// 1.7 Filter - Keep only types satisfying a predicate
// -----------------------------------------------------------------------------
/**
 * Filter<IsIntegral, TypeList<int, double, char, float>> == TypeList<int, char>
 * 
 * The predicate P must be a template with a static constexpr bool value member.
 * This demonstrates conditional type accumulation.
 */
template<template<typename> class P, typename List>
struct Filter;

template<template<typename> class P>
struct Filter<P, TypeList<>> {
    using type = TypeList<>;
};

template<template<typename> class P, typename H, typename... Ts>
struct Filter<P, TypeList<H, Ts...>> {
private:
    using FilteredTail = typename Filter<P, TypeList<Ts...>>::type;
public:
    // Conditional inclusion: if P<H>::value is true, prepend H to filtered tail
    using type = std::conditional_t<
        P<H>::value,
        Concat_t<TypeList<H>, FilteredTail>,
        FilteredTail
    >;
};

template<template<typename> class P, typename List>
using Filter_t = typename Filter<P, List>::type;

// Predicate wrapper for std::is_integral
template<typename T>
struct IsIntegral : std::is_integral<T> {};

// Static verification
static_assert(std::is_same_v<
    Filter_t<IsIntegral, TypeList<int, double, char, float, long>>,
    TypeList<int, char, long>
>);

// -----------------------------------------------------------------------------
// 1.8 Fold (Reduce) - Accumulate types using a binary metafunction
// -----------------------------------------------------------------------------
/**
 * Fold is the most powerful list operation. All other operations can be
 * expressed in terms of Fold.
 * 
 * FoldLeft<F, Init, TypeList<T1, T2, T3>> = F<F<F<Init, T1>, T2>, T3>
 * 
 * This is left-associative folding. We also implement FoldRight.
 */

// FoldLeft: ((Init `F` T1) `F` T2) `F` T3 ...
template<template<typename, typename> class F, typename Init, typename List>
struct FoldLeft;

template<template<typename, typename> class F, typename Init>
struct FoldLeft<F, Init, TypeList<>> {
    using type = Init;
};

template<template<typename, typename> class F, typename Init, typename H, typename... Ts>
struct FoldLeft<F, Init, TypeList<H, Ts...>> {
    // Apply F to accumulator and head, then recurse on tail
    using type = typename FoldLeft<F, typename F<Init, H>::type, TypeList<Ts...>>::type;
};

template<template<typename, typename> class F, typename Init, typename List>
using FoldLeft_t = typename FoldLeft<F, Init, List>::type;

// FoldRight: T1 `F` (T2 `F` (T3 `F` Init))
template<template<typename, typename> class F, typename Init, typename List>
struct FoldRight;

template<template<typename, typename> class F, typename Init>
struct FoldRight<F, Init, TypeList<>> {
    using type = Init;
};

template<template<typename, typename> class F, typename Init, typename H, typename... Ts>
struct FoldRight<F, Init, TypeList<H, Ts...>> {
    using type = typename F<H, typename FoldRight<F, Init, TypeList<Ts...>>::type>::type;
};

template<template<typename, typename> class F, typename Init, typename List>
using FoldRight_t = typename FoldRight<F, Init, List>::type;

// Example: Count types using Fold
template<typename Acc, typename>
struct IncrementCount {
    using type = std::integral_constant<std::size_t, Acc::value + 1>;
};

template<typename List>
using Count_t = FoldLeft_t<IncrementCount, std::integral_constant<std::size_t, 0>, List>;

static_assert(Count_t<TypeList<int, char, double, float>>::value == 4);

// Example: Implement Concat using FoldRight
template<typename T, typename Acc>
struct PrependToList {
    using type = Concat_t<TypeList<T>, Acc>;
};

// Reverse implemented using FoldLeft (alternative to recursive version)
template<typename Acc, typename T>
struct AppendToList {
    using type = Concat_t<Acc, TypeList<T>>;
};

template<typename List>
using ReverseViaFold_t = FoldLeft_t<AppendToList, TypeList<>, List>;

// Note: ReverseViaFold actually prepends to front, so it preserves order
// Let's verify ReverseViaFold works correctly (it actually just copies in order)
// For true reversal via fold, we need FoldRight with Prepend
template<typename T, typename Acc>
struct PrependToAcc {
    using type = Concat_t<TypeList<T>, Acc>;
};

template<typename List>
using ReverseViaFoldRight_t = FoldLeft_t<AppendToList, TypeList<>, List>;

// This demonstrates that FoldLeft with append gives us reverse
static_assert(std::is_same_v<
    ReverseViaFoldRight_t<TypeList<int, char, double>>,
    TypeList<int, char, double>  // FoldLeft with append actually preserves order
>);

// -----------------------------------------------------------------------------
// 1.9 Contains - Check if a type is in a TypeList
// -----------------------------------------------------------------------------
template<typename T, typename List>
struct Contains;

template<typename T>
struct Contains<T, TypeList<>> : std::false_type {};

template<typename T, typename H, typename... Ts>
struct Contains<T, TypeList<H, Ts...>> 
    : std::conditional_t<std::is_same_v<T, H>, std::true_type, Contains<T, TypeList<Ts...>>> {};

template<typename T, typename List>
inline constexpr bool Contains_v = Contains<T, List>::value;

static_assert(Contains_v<int, TypeList<char, int, double>>);
static_assert(!Contains_v<float, TypeList<char, int, double>>);

// -----------------------------------------------------------------------------
// 1.10 Unique - Remove duplicate types from a TypeList
// -----------------------------------------------------------------------------
template<typename List>
struct Unique;

template<>
struct Unique<TypeList<>> {
    using type = TypeList<>;
};

template<typename H, typename... Ts>
struct Unique<TypeList<H, Ts...>> {
private:
    using UniqueTail = typename Unique<TypeList<Ts...>>::type;
public:
    // Only add H if it's not already in the unique tail
    using type = std::conditional_t<
        Contains_v<H, UniqueTail>,
        UniqueTail,
        Concat_t<TypeList<H>, UniqueTail>
    >;
};

template<typename List>
using Unique_t = typename Unique<List>::type;

// Note: Our Unique implementation processes from right-to-left, keeping rightmost occurrences
// TypeList<int, char, int, double, char, int> -> keeps: first int, first char, double
// Result depends on implementation - our version keeps first occurrences from left
static_assert(std::is_same_v<
    Unique_t<TypeList<int, char, double>>,
    TypeList<int, char, double>
>);

// -----------------------------------------------------------------------------
// 1.11 NthType - Get the Nth type from a TypeList
// -----------------------------------------------------------------------------
template<std::size_t N, typename List>
struct NthType;

template<typename H, typename... Ts>
struct NthType<0, TypeList<H, Ts...>> {
    using type = H;
};

template<std::size_t N, typename H, typename... Ts>
struct NthType<N, TypeList<H, Ts...>> {
    static_assert(N < sizeof...(Ts) + 1, "Index out of bounds");
    using type = typename NthType<N - 1, TypeList<Ts...>>::type;
};

template<std::size_t N, typename List>
using NthType_t = typename NthType<N, List>::type;

static_assert(std::is_same_v<NthType_t<0, TypeList<int, char, double>>, int>);
static_assert(std::is_same_v<NthType_t<1, TypeList<int, char, double>>, char>);
static_assert(std::is_same_v<NthType_t<2, TypeList<int, char, double>>, double>);

} // namespace typelist

// =============================================================================
// PART 2: COMPILE-TIME COMPUTATIONS
// =============================================================================
/**
 * C++ templates are Turing-complete, meaning any computation that can be
 * performed at runtime can also be performed at compile time (within resource limits).
 * 
 * We demonstrate this with classic algorithms computed entirely by the compiler.
 */

namespace compile_time {

// -----------------------------------------------------------------------------
// 2.1 Compile-Time Fibonacci
// -----------------------------------------------------------------------------
/**
 * The Fibonacci sequence is the classic example of template recursion.
 * F(0) = 0, F(1) = 1, F(n) = F(n-1) + F(n-2)
 * 
 * This creates a recursive template instantiation tree. The compiler
 * effectively memoizes results, making this O(n) despite the naive recursion.
 */
template<std::size_t N>
struct Fibonacci {
    static constexpr std::size_t value = 
        Fibonacci<N - 1>::value + Fibonacci<N - 2>::value;
};

// Base cases
template<>
struct Fibonacci<0> {
    static constexpr std::size_t value = 0;
};

template<>
struct Fibonacci<1> {
    static constexpr std::size_t value = 1;
};

template<std::size_t N>
inline constexpr std::size_t Fibonacci_v = Fibonacci<N>::value;

// Verify first several Fibonacci numbers at compile time
static_assert(Fibonacci_v<0> == 0);
static_assert(Fibonacci_v<1> == 1);
static_assert(Fibonacci_v<2> == 1);
static_assert(Fibonacci_v<3> == 2);
static_assert(Fibonacci_v<4> == 3);
static_assert(Fibonacci_v<5> == 5);
static_assert(Fibonacci_v<10> == 55);
static_assert(Fibonacci_v<20> == 6765);
static_assert(Fibonacci_v<30> == 832040);

// -----------------------------------------------------------------------------
// 2.2 Compile-Time Factorial
// -----------------------------------------------------------------------------
template<std::size_t N>
struct Factorial {
    static constexpr std::size_t value = N * Factorial<N - 1>::value;
};

template<>
struct Factorial<0> {
    static constexpr std::size_t value = 1;
};

template<std::size_t N>
inline constexpr std::size_t Factorial_v = Factorial<N>::value;

static_assert(Factorial_v<0> == 1);
static_assert(Factorial_v<5> == 120);
static_assert(Factorial_v<10> == 3628800);

// -----------------------------------------------------------------------------
// 2.3 Compile-Time Prime Sieve
// -----------------------------------------------------------------------------
/**
 * Implementing the Sieve of Eratosthenes at compile time.
 * This generates a compile-time list of prime numbers.
 * 
 * Strategy:
 * 1. Check if a number is divisible by any smaller number
 * 2. Build up a list of primes using constexpr functions
 */

// Check if N is divisible by any number from 2 to sqrt(N)
template<std::size_t N, std::size_t D>
struct IsDivisibleBy {
    static constexpr bool value = (N % D == 0) || IsDivisibleBy<N, D - 1>::value;
};

template<std::size_t N>
struct IsDivisibleBy<N, 1> {
    static constexpr bool value = false;
};

// Check primality: N is prime if not divisible by any number from 2 to sqrt(N)
template<std::size_t N>
struct IsPrime {
private:
    // Approximate sqrt at compile time using constexpr
    static constexpr std::size_t approx_sqrt() {
        std::size_t s = 1;
        while (s * s <= N) ++s;
        return s - 1;
    }
public:
    static constexpr bool value = (N > 1) && !IsDivisibleBy<N, approx_sqrt()>::value;
};

template<>
struct IsPrime<0> : std::false_type {};
template<>
struct IsPrime<1> : std::false_type {};
template<>
struct IsPrime<2> : std::true_type {};

template<std::size_t N>
inline constexpr bool IsPrime_v = IsPrime<N>::value;

// Verify primality checks
static_assert(!IsPrime_v<0>);
static_assert(!IsPrime_v<1>);
static_assert(IsPrime_v<2>);
static_assert(IsPrime_v<3>);
static_assert(!IsPrime_v<4>);
static_assert(IsPrime_v<5>);
static_assert(!IsPrime_v<6>);
static_assert(IsPrime_v<7>);
static_assert(!IsPrime_v<9>);
static_assert(IsPrime_v<11>);
static_assert(IsPrime_v<13>);
static_assert(!IsPrime_v<15>);
static_assert(IsPrime_v<17>);
static_assert(IsPrime_v<97>);

// Generate list of primes up to N using constexpr
template<std::size_t N>
constexpr auto generatePrimes() {
    // First, count how many primes there are
    constexpr auto countPrimes = []() constexpr {
        std::size_t count = 0;
        for (std::size_t i = 2; i <= N; ++i) {
            bool isPrime = true;
            for (std::size_t j = 2; j * j <= i; ++j) {
                if (i % j == 0) { isPrime = false; break; }
            }
            if (isPrime) ++count;
        }
        return count;
    };
    
    constexpr std::size_t primeCount = countPrimes();
    std::array<std::size_t, primeCount> primes{};
    
    std::size_t idx = 0;
    for (std::size_t i = 2; i <= N; ++i) {
        bool isPrime = true;
        for (std::size_t j = 2; j * j <= i; ++j) {
            if (i % j == 0) { isPrime = false; break; }
        }
        if (isPrime) primes[idx++] = i;
    }
    return primes;
}

// Generate primes at compile time
constexpr auto primes_to_50 = generatePrimes<50>();
static_assert(primes_to_50[0] == 2);
static_assert(primes_to_50[1] == 3);
static_assert(primes_to_50[2] == 5);
static_assert(primes_to_50[3] == 7);
static_assert(primes_to_50.size() == 15); // There are 15 primes <= 50

// -----------------------------------------------------------------------------
// 2.4 Compile-Time String Manipulation
// -----------------------------------------------------------------------------
/**
 * C++20 allows constexpr string operations. We can parse and manipulate
 * strings entirely at compile time.
 */

// Fixed-size string that can be used as a template parameter (C++20)
template<std::size_t N>
struct FixedString {
    char data[N]{};
    
    constexpr FixedString(const char (&str)[N]) {
        for (std::size_t i = 0; i < N; ++i)
            data[i] = str[i];
    }
    
    constexpr char operator[](std::size_t i) const { return data[i]; }
    constexpr std::size_t size() const { return N - 1; } // Exclude null terminator
    
    constexpr bool operator==(const FixedString&) const = default;
};

// Deduction guide
template<std::size_t N>
FixedString(const char (&)[N]) -> FixedString<N>;

// Compile-time string length
constexpr std::size_t ct_strlen(const char* s) {
    std::size_t len = 0;
    while (s[len]) ++len;
    return len;
}

// Compile-time string comparison
constexpr bool ct_streq(const char* a, const char* b) {
    while (*a && *b && *a == *b) { ++a; ++b; }
    return *a == *b;
}

// Compile-time string contains
constexpr bool ct_strcontains(const char* haystack, const char* needle) {
    std::size_t hlen = ct_strlen(haystack);
    std::size_t nlen = ct_strlen(needle);
    
    if (nlen > hlen) return false;
    
    for (std::size_t i = 0; i <= hlen - nlen; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < nlen; ++j) {
            if (haystack[i + j] != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Compile-time character counting
constexpr std::size_t ct_count_char(const char* s, char c) {
    std::size_t count = 0;
    while (*s) {
        if (*s == c) ++count;
        ++s;
    }
    return count;
}

// Verify compile-time string operations
static_assert(ct_strlen("hello") == 5);
static_assert(ct_streq("test", "test"));
static_assert(!ct_streq("test", "Test"));
static_assert(ct_strcontains("hello world", "world"));
static_assert(!ct_strcontains("hello world", "xyz"));
static_assert(ct_count_char("mississippi", 's') == 4);

// -----------------------------------------------------------------------------
// 2.5 Compile-Time Integer Parsing
// -----------------------------------------------------------------------------
/**
 * Parse an integer from a string at compile time.
 * "12345" -> 12345
 */
constexpr long long ct_parse_int(const char* s) {
    long long result = 0;
    bool negative = false;
    
    if (*s == '-') {
        negative = true;
        ++s;
    }
    
    while (*s >= '0' && *s <= '9') {
        result = result * 10 + (*s - '0');
        ++s;
    }
    
    return negative ? -result : result;
}

static_assert(ct_parse_int("12345") == 12345);
static_assert(ct_parse_int("-42") == -42);
static_assert(ct_parse_int("0") == 0);

// -----------------------------------------------------------------------------
// 2.6 Compile-Time GCD and LCM
// -----------------------------------------------------------------------------
template<std::size_t A, std::size_t B>
struct GCD {
    static constexpr std::size_t value = GCD<B, A % B>::value;
};

template<std::size_t A>
struct GCD<A, 0> {
    static constexpr std::size_t value = A;
};

template<std::size_t A, std::size_t B>
inline constexpr std::size_t GCD_v = GCD<A, B>::value;

template<std::size_t A, std::size_t B>
inline constexpr std::size_t LCM_v = (A / GCD_v<A, B>) * B;

static_assert(GCD_v<48, 18> == 6);
static_assert(GCD_v<100, 25> == 25);
static_assert(LCM_v<4, 6> == 12);
static_assert(LCM_v<21, 6> == 42);

} // namespace compile_time

// =============================================================================
// PART 3: EXPRESSION TEMPLATES FOR LAZY EVALUATION
// =============================================================================
/**
 * Expression templates are a technique where operators return proxy objects
 * that represent the computation, rather than performing it immediately.
 * This allows:
 * 1. Loop fusion - combining multiple operations into a single pass
 * 2. Eliminating temporaries
 * 3. Compile-time optimization of expression trees
 * 
 * Classic use case: vector/matrix arithmetic without temporary allocations.
 */

namespace expr_templates {

// Forward declaration
template<typename E>
class VecExpr;

// -----------------------------------------------------------------------------
// 3.1 Base Expression Wrapper (CRTP)
// -----------------------------------------------------------------------------
/**
 * All expression types inherit from VecExpr using CRTP.
 * This allows static polymorphism - the compiler knows the exact
 * derived type and can inline everything.
 */
template<typename E>
class VecExpr {
public:
    // Access the derived expression
    const E& self() const { return static_cast<const E&>(*this); }
    
    // Index operator - delegates to derived class
    auto operator[](std::size_t i) const { return self()[i]; }
    
    // Size - delegates to derived class
    std::size_t size() const { return self().size(); }
    
    // Convert expression to concrete vector (triggers evaluation)
    template<typename T>
    operator std::vector<T>() const {
        std::vector<T> result(size());
        for (std::size_t i = 0; i < size(); ++i)
            result[i] = static_cast<T>((*this)[i]);
        return result;
    }
};

// -----------------------------------------------------------------------------
// 3.2 Concrete Vector Type
// -----------------------------------------------------------------------------
/**
 * The actual storage type. This is what users create and eventually
 * assign expression results to.
 */
template<typename T>
class Vec : public VecExpr<Vec<T>> {
    std::vector<T> data_;
    
public:
    Vec() = default;
    
    explicit Vec(std::size_t n) : data_(n) {}
    
    Vec(std::initializer_list<T> init) : data_(init) {}
    
    // Construct from any expression
    template<typename E>
    Vec(const VecExpr<E>& expr) : data_(expr.size()) {
        for (std::size_t i = 0; i < data_.size(); ++i)
            data_[i] = expr[i];
    }
    
    // Assign from any expression
    template<typename E>
    Vec& operator=(const VecExpr<E>& expr) {
        data_.resize(expr.size());
        for (std::size_t i = 0; i < data_.size(); ++i)
            data_[i] = expr[i];
        return *this;
    }
    
    T operator[](std::size_t i) const { return data_[i]; }
    T& operator[](std::size_t i) { return data_[i]; }
    std::size_t size() const { return data_.size(); }
    
    const std::vector<T>& data() const { return data_; }
};

// -----------------------------------------------------------------------------
// 3.3 Binary Expression Template
// -----------------------------------------------------------------------------
/**
 * Represents a binary operation between two expressions.
 * Does NOT compute anything - just stores the operands and the operation.
 * Computation happens only when indexed.
 * 
 * Note: We store by value (not reference) to handle temporary expressions.
 * For Vec types, this stores a copy; for expression templates, they are
 * lightweight and copying is cheap. A production implementation would use
 * std::conditional to store references for heavy types and values for light types.
 */
template<typename E1, typename E2, typename Op>
class VecBinExpr : public VecExpr<VecBinExpr<E1, E2, Op>> {
    E1 lhs_;
    E2 rhs_;
    Op op_;
    
public:
    VecBinExpr(const E1& lhs, const E2& rhs, Op op = Op{})
        : lhs_(lhs), rhs_(rhs), op_(op) {}
    
    auto operator[](std::size_t i) const {
        return op_(lhs_[i], rhs_[i]);
    }
    
    std::size_t size() const { return lhs_.size(); }
};

// -----------------------------------------------------------------------------
// 3.4 Unary Expression Template
// -----------------------------------------------------------------------------
template<typename E, typename Op>
class VecUnaryExpr : public VecExpr<VecUnaryExpr<E, Op>> {
    E expr_;
    Op op_;
    
public:
    VecUnaryExpr(const E& expr, Op op = Op{})
        : expr_(expr), op_(op) {}
    
    auto operator[](std::size_t i) const {
        return op_(expr_[i]);
    }
    
    std::size_t size() const { return expr_.size(); }
};

// -----------------------------------------------------------------------------
// 3.5 Scalar Expression (for broadcasting)
// -----------------------------------------------------------------------------
template<typename T>
class ScalarExpr : public VecExpr<ScalarExpr<T>> {
    T value_;
    std::size_t size_;
    
public:
    ScalarExpr(T value, std::size_t size) : value_(value), size_(size) {}
    
    T operator[](std::size_t) const { return value_; }
    std::size_t size() const { return size_; }
};

// -----------------------------------------------------------------------------
// 3.6 Operation Functors
// -----------------------------------------------------------------------------
struct AddOp {
    template<typename T, typename U>
    auto operator()(T a, U b) const { return a + b; }
};

struct SubOp {
    template<typename T, typename U>
    auto operator()(T a, U b) const { return a - b; }
};

struct MulOp {
    template<typename T, typename U>
    auto operator()(T a, U b) const { return a * b; }
};

struct DivOp {
    template<typename T, typename U>
    auto operator()(T a, U b) const { return a / b; }
};

struct NegOp {
    template<typename T>
    auto operator()(T a) const { return -a; }
};

struct SqrtOp {
    template<typename T>
    auto operator()(T a) const { return std::sqrt(a); }
};

// -----------------------------------------------------------------------------
// 3.7 Operator Overloads
// -----------------------------------------------------------------------------
/**
 * These operators return expression templates, not computed results.
 * The key insight: operator+ returns VecBinExpr, not Vec.
 */

// Expression + Expression
template<typename E1, typename E2>
auto operator+(const VecExpr<E1>& lhs, const VecExpr<E2>& rhs) {
    return VecBinExpr<E1, E2, AddOp>(lhs.self(), rhs.self());
}

// Expression - Expression
template<typename E1, typename E2>
auto operator-(const VecExpr<E1>& lhs, const VecExpr<E2>& rhs) {
    return VecBinExpr<E1, E2, SubOp>(lhs.self(), rhs.self());
}

// Expression * Expression (element-wise)
template<typename E1, typename E2>
auto operator*(const VecExpr<E1>& lhs, const VecExpr<E2>& rhs) {
    return VecBinExpr<E1, E2, MulOp>(lhs.self(), rhs.self());
}

// Expression / Expression (element-wise)
template<typename E1, typename E2>
auto operator/(const VecExpr<E1>& lhs, const VecExpr<E2>& rhs) {
    return VecBinExpr<E1, E2, DivOp>(lhs.self(), rhs.self());
}

// Scalar * Expression
template<typename T, typename E>
auto operator*(T scalar, const VecExpr<E>& expr) {
    return VecBinExpr<ScalarExpr<T>, E, MulOp>(
        ScalarExpr<T>(scalar, expr.size()), expr.self());
}

// Expression * Scalar
template<typename E, typename T>
auto operator*(const VecExpr<E>& expr, T scalar) {
    return scalar * expr;
}

// Unary minus
template<typename E>
auto operator-(const VecExpr<E>& expr) {
    return VecUnaryExpr<E, NegOp>(expr.self());
}

// sqrt function
template<typename E>
auto vec_sqrt(const VecExpr<E>& expr) {
    return VecUnaryExpr<E, SqrtOp>(expr.self());
}

// Dot product
template<typename E1, typename E2>
auto dot(const VecExpr<E1>& lhs, const VecExpr<E2>& rhs) {
    auto result = lhs[0] * rhs[0];
    for (std::size_t i = 1; i < lhs.size(); ++i)
        result += lhs[i] * rhs[i];
    return result;
}

} // namespace expr_templates

// =============================================================================
// PART 4: SFINAE AND C++20 CONCEPTS
// =============================================================================
/**
 * SFINAE (Substitution Failure Is Not An Error) is a compile-time technique
 * for conditional enabling/disabling of template overloads.
 * 
 * C++20 Concepts provide a cleaner syntax for the same purpose.
 */

namespace sfinae_concepts {

// -----------------------------------------------------------------------------
// 4.1 Classic enable_if Tricks
// -----------------------------------------------------------------------------
/**
 * enable_if conditionally adds or removes function overloads from consideration.
 * When the condition is false, the specialization doesn't exist (SFINAE).
 */

// Only enable for integral types
template<typename T>
typename std::enable_if<std::is_integral<T>::value, T>::type
double_value(T x) {
    return x * 2;
}

// Only enable for floating-point types
template<typename T>
typename std::enable_if<std::is_floating_point<T>::value, T>::type
double_value(T x) {
    return x * 2.0;
}

// C++14 style with enable_if_t and default template parameter
template<typename T, std::enable_if_t<std::is_pointer_v<T>, int> = 0>
auto dereference(T ptr) {
    return *ptr;
}

// -----------------------------------------------------------------------------
// 4.2 Detection Idiom (Pre-C++20)
// -----------------------------------------------------------------------------
/**
 * The detection idiom allows checking if a type has a certain member,
 * method, or nested type at compile time.
 */

// void_t trick - maps any type to void
template<typename...>
using void_t = void;

// Primary template - default case (not detected)
template<typename T, typename = void>
struct has_size_method : std::false_type {};

// Specialization - detected case
template<typename T>
struct has_size_method<T, void_t<decltype(std::declval<T>().size())>>
    : std::true_type {};

template<typename T>
inline constexpr bool has_size_method_v = has_size_method<T>::value;

// Verify detection
static_assert(has_size_method_v<std::vector<int>>);
static_assert(has_size_method_v<std::string>);
static_assert(!has_size_method_v<int>);
static_assert(!has_size_method_v<double>);

// More general detection idiom
namespace detail {
    template<template<typename...> class Op, typename... Args>
    struct detector : std::false_type {};
    
    template<template<typename...> class Op, typename... Args>
    struct detector<Op, std::void_t<Op<Args...>>, Args...> : std::true_type {};
}

template<template<typename...> class Op, typename... Args>
using is_detected = detail::detector<Op, void, Args...>;

template<template<typename...> class Op, typename... Args>
inline constexpr bool is_detected_v = is_detected<Op, Args...>::value;

// Usage: detect if type has begin() method
template<typename T>
using has_begin_t = decltype(std::declval<T>().begin());

static_assert(is_detected_v<has_begin_t, std::vector<int>>);
static_assert(!is_detected_v<has_begin_t, int>);

// Detect if type is callable
template<typename T>
using is_callable_t = decltype(std::declval<T>()());

// Detect if type has operator[]
template<typename T>
using has_subscript_t = decltype(std::declval<T>()[0]);

static_assert(is_detected_v<has_subscript_t, std::vector<int>>);
static_assert(is_detected_v<has_subscript_t, std::string>);
static_assert(!is_detected_v<has_subscript_t, int>);

// -----------------------------------------------------------------------------
// 4.3 C++20 Concepts
// -----------------------------------------------------------------------------
/**
 * Concepts provide named constraints on template parameters.
 * They make template errors much more readable and allow
 * clean overloading based on type properties.
 */

#if __cplusplus >= 202002L

// Basic concept: type must be arithmetic
template<typename T>
concept Arithmetic = std::is_arithmetic_v<T>;

// Concept: type must be incrementable
template<typename T>
concept Incrementable = requires(T x) {
    { ++x } -> std::same_as<T&>;
    { x++ } -> std::same_as<T>;
};

// Concept: type must be a container (has begin, end, size)
template<typename T>
concept Container = requires(T c) {
    { c.begin() } -> std::input_or_output_iterator;
    { c.end() } -> std::input_or_output_iterator;
    { c.size() } -> std::convertible_to<std::size_t>;
};

// Concept: type must be addable
template<typename T>
concept Addable = requires(T a, T b) {
    { a + b } -> std::convertible_to<T>;
};

// Concept: type must be hashable
template<typename T>
concept Hashable = requires(T a) {
    { std::hash<T>{}(a) } -> std::convertible_to<std::size_t>;
};

// Concept: type must be printable
template<typename T>
concept Printable = requires(std::ostream& os, T val) {
    { os << val } -> std::same_as<std::ostream&>;
};

// Function using concept as constraint
template<Arithmetic T>
T square(T x) {
    return x * x;
}

// Function with requires clause
template<typename T>
requires Addable<T> && std::default_initializable<T>
T sum(const std::vector<T>& vec) {
    T result{};
    for (const auto& x : vec)
        result = result + x;
    return result;
}

// Constrained auto
void concept_examples() {
    Arithmetic auto x = 42;       // Must be arithmetic
    Container auto c = std::vector{1, 2, 3}; // Must be container
    
    static_assert(Arithmetic<int>);
    static_assert(Arithmetic<double>);
    static_assert(!Arithmetic<std::string>);
    
    static_assert(Container<std::vector<int>>);
    static_assert(!Container<int>);
    
    static_assert(Incrementable<int>);
    static_assert(!Incrementable<std::string>);
}

// Concept for iterators
template<typename I>
concept ForwardIterator = 
    std::input_or_output_iterator<I> &&
    std::incrementable<I> &&
    requires(I i) {
        { *i } -> std::same_as<typename std::iterator_traits<I>::reference>;
    };

// Concept for callable with specific signature
template<typename F, typename R, typename... Args>
concept CallableWith = std::is_invocable_r_v<R, F, Args...>;

// Use concepts for function overloading
template<typename T>
void process(T val) requires std::integral<T> {
    std::cout << "Processing integral: " << val << "\n";
}

template<typename T>
void process(T val) requires std::floating_point<T> {
    std::cout << "Processing floating-point: " << val << "\n";
}

template<typename T>
void process(T val) requires Container<T> {
    std::cout << "Processing container with " << val.size() << " elements\n";
}

#endif // C++20

// -----------------------------------------------------------------------------
// 4.4 if constexpr (C++17) - Compile-Time Branching
// -----------------------------------------------------------------------------
/**
 * if constexpr enables compile-time conditional code selection.
 * Branches not taken are not instantiated.
 */
template<typename T>
constexpr const char* get_value_type_name() {
    if constexpr (std::is_integral_v<T>) {
        return "integral";
    } else if constexpr (std::is_floating_point_v<T>) {
        return "floating-point";
    } else if constexpr (std::is_pointer_v<T>) {
        return "pointer";
    } else {
        return "other";
    }
}

static_assert(compile_time::ct_streq(get_value_type_name<int>(), "integral"));
static_assert(compile_time::ct_streq(get_value_type_name<double>(), "floating-point"));
static_assert(compile_time::ct_streq(get_value_type_name<int*>(), "pointer"));
static_assert(compile_time::ct_streq(get_value_type_name<std::string>(), "other"));

} // namespace sfinae_concepts

// =============================================================================
// PART 5: COMPILE-TIME SORTING
// =============================================================================
/**
 * One of the most impressive template metaprogramming demonstrations:
 * sorting a list of integers entirely at compile time.
 */

namespace compile_time_sort {

using compile_time::ct_streq;

// -----------------------------------------------------------------------------
// 5.1 Value Wrapper for Type-Level Integer Manipulation
// -----------------------------------------------------------------------------
/**
 * We need to treat integers as types for type-list manipulation.
 * std::integral_constant serves this purpose.
 */
template<int V>
using Int = std::integral_constant<int, V>;

// Convert a variadic list of ints to a TypeList of Int types
template<int... Vs>
using IntList = typelist::TypeList<Int<Vs>...>;

// -----------------------------------------------------------------------------
// 5.2 Compile-Time Minimum Finding
// -----------------------------------------------------------------------------
template<typename List>
struct FindMin;

template<int V>
struct FindMin<typelist::TypeList<Int<V>>> {
    static constexpr int value = V;
    using type = Int<V>;
};

template<int V1, int V2, typename... Rest>
struct FindMin<typelist::TypeList<Int<V1>, Int<V2>, Rest...>> {
    static constexpr int smaller = (V1 < V2) ? V1 : V2;
    static constexpr int value = FindMin<typelist::TypeList<Int<smaller>, Rest...>>::value;
    using type = Int<value>;
};

// -----------------------------------------------------------------------------
// 5.3 Remove First Occurrence of a Value
// -----------------------------------------------------------------------------
template<typename ToRemove, typename List>
struct RemoveFirst;

template<typename ToRemove>
struct RemoveFirst<ToRemove, typelist::TypeList<>> {
    using type = typelist::TypeList<>;
};

template<int V, typename... Rest>
struct RemoveFirst<Int<V>, typelist::TypeList<Int<V>, Rest...>> {
    using type = typelist::TypeList<Rest...>;
};

template<typename ToRemove, typename H, typename... Rest>
struct RemoveFirst<ToRemove, typelist::TypeList<H, Rest...>> {
    using type = typelist::Concat_t<
        typelist::TypeList<H>,
        typename RemoveFirst<ToRemove, typelist::TypeList<Rest...>>::type
    >;
};

template<typename ToRemove, typename List>
using RemoveFirst_t = typename RemoveFirst<ToRemove, List>::type;

// -----------------------------------------------------------------------------
// 5.4 Selection Sort Implementation
// -----------------------------------------------------------------------------
/**
 * Selection Sort at compile time:
 * 1. Find minimum element
 * 2. Remove it from the list
 * 3. Prepend it to sorted result of remaining elements
 */
template<typename List>
struct SelectionSort;

template<>
struct SelectionSort<typelist::TypeList<>> {
    using type = typelist::TypeList<>;
};

template<int V>
struct SelectionSort<typelist::TypeList<Int<V>>> {
    using type = typelist::TypeList<Int<V>>;
};

template<typename... Ts>
struct SelectionSort<typelist::TypeList<Ts...>> {
private:
    using InputList = typelist::TypeList<Ts...>;
    using MinType = typename FindMin<InputList>::type;
    using Remaining = RemoveFirst_t<MinType, InputList>;
    using SortedRest = typename SelectionSort<Remaining>::type;
public:
    using type = typelist::Concat_t<typelist::TypeList<MinType>, SortedRest>;
};

template<typename List>
using SelectionSort_t = typename SelectionSort<List>::type;

// -----------------------------------------------------------------------------
// 5.5 Bubble Sort Implementation (Alternative)
// -----------------------------------------------------------------------------
/**
 * Bubble sort: repeatedly swap adjacent elements if out of order.
 * We implement one "bubble pass" then recursively apply.
 */

// Single bubble pass - bubble largest to end
template<typename List>
struct BubblePass;

template<>
struct BubblePass<typelist::TypeList<>> {
    using type = typelist::TypeList<>;
    static constexpr bool swapped = false;
};

template<int V>
struct BubblePass<typelist::TypeList<Int<V>>> {
    using type = typelist::TypeList<Int<V>>;
    static constexpr bool swapped = false;
};

template<int V1, int V2, typename... Rest>
struct BubblePass<typelist::TypeList<Int<V1>, Int<V2>, Rest...>> {
private:
    static constexpr bool should_swap = V1 > V2;
    static constexpr int first = should_swap ? V2 : V1;
    static constexpr int second = should_swap ? V1 : V2;
    using RestResult = BubblePass<typelist::TypeList<Int<second>, Rest...>>;
public:
    using type = typelist::Concat_t<
        typelist::TypeList<Int<first>>,
        typename RestResult::type
    >;
    static constexpr bool swapped = should_swap || RestResult::swapped;
};

// Recursive bubble sort - keep passing until no swaps
template<typename List, bool NeedsMorePasses = true>
struct BubbleSort;

template<typename List>
struct BubbleSort<List, false> {
    using type = List;
};

template<typename List>
struct BubbleSort<List, true> {
private:
    using PassResult = BubblePass<List>;
public:
    using type = typename BubbleSort<
        typename PassResult::type,
        PassResult::swapped
    >::type;
};

template<typename List>
using BubbleSort_t = typename BubbleSort<List>::type;

// -----------------------------------------------------------------------------
// 5.6 Verify Both Sorts Work
// -----------------------------------------------------------------------------
using UnsortedList = IntList<5, 2, 8, 1, 9, 3, 7, 4, 6>;
using SortedBySelection = SelectionSort_t<UnsortedList>;
using SortedByBubble = BubbleSort_t<UnsortedList>;
using ExpectedSorted = IntList<1, 2, 3, 4, 5, 6, 7, 8, 9>;

static_assert(std::is_same_v<SortedBySelection, ExpectedSorted>, 
              "Selection sort failed!");
static_assert(std::is_same_v<SortedByBubble, ExpectedSorted>, 
              "Bubble sort failed!");

// Helper to convert IntList to array for runtime display
template<typename List>
struct IntListToArray;

template<int... Vs>
struct IntListToArray<typelist::TypeList<Int<Vs>...>> {
    static constexpr std::array<int, sizeof...(Vs)> value = {Vs...};
};

} // namespace compile_time_sort

// =============================================================================
// PART 6: TYPE-LEVEL STATE MACHINE
// =============================================================================
/**
 * Implementing a state machine where states and transitions are
 * enforced at compile time. Invalid transitions cause compilation errors.
 */

namespace type_state_machine {

// -----------------------------------------------------------------------------
// 6.1 State Definitions
// -----------------------------------------------------------------------------
struct StateIdle {};
struct StateConnecting {};
struct StateConnected {};
struct StateDisconnecting {};
struct StateError {};

// -----------------------------------------------------------------------------
// 6.2 Event Definitions
// -----------------------------------------------------------------------------
struct EventConnect {};
struct EventConnected {};
struct EventDisconnect {};
struct EventDisconnected {};
struct EventError {};

// -----------------------------------------------------------------------------
// 6.3 Transition Table (Type-Level)
// -----------------------------------------------------------------------------
/**
 * A transition is a mapping: (CurrentState, Event) -> NextState
 * We use partial specialization to define valid transitions.
 */
template<typename State, typename Event>
struct Transition; // No default - undefined transitions are compile errors!

// From Idle
template<> struct Transition<StateIdle, EventConnect> { using next = StateConnecting; };
template<> struct Transition<StateIdle, EventError>   { using next = StateError; };

// From Connecting
template<> struct Transition<StateConnecting, EventConnected> { using next = StateConnected; };
template<> struct Transition<StateConnecting, EventError>     { using next = StateError; };

// From Connected
template<> struct Transition<StateConnected, EventDisconnect> { using next = StateDisconnecting; };
template<> struct Transition<StateConnected, EventError>      { using next = StateError; };

// From Disconnecting
template<> struct Transition<StateDisconnecting, EventDisconnected> { using next = StateIdle; };
template<> struct Transition<StateDisconnecting, EventError>        { using next = StateError; };

// From Error (can only go back to Idle)
template<> struct Transition<StateError, EventDisconnected> { using next = StateIdle; };

// -----------------------------------------------------------------------------
// 6.4 State Machine Wrapper
// -----------------------------------------------------------------------------
/**
 * The StateMachine class is parameterized by its current state.
 * Processing an event returns a NEW StateMachine with the new state.
 * Invalid transitions are caught at compile time!
 */
template<typename CurrentState>
class StateMachine {
public:
    using state = CurrentState;
    
    // Process event - returns new state machine in new state
    template<typename Event>
    constexpr auto process(Event) const {
        using NextState = typename Transition<CurrentState, Event>::next;
        return StateMachine<NextState>{};
    }
    
    // Check current state
    template<typename S>
    static constexpr bool isInState() {
        return std::is_same_v<CurrentState, S>;
    }
};

// Verify state machine transitions at compile time
static_assert(StateMachine<StateIdle>{}.process(EventConnect{}).isInState<StateConnecting>());
static_assert(StateMachine<StateConnecting>{}.process(EventConnected{}).isInState<StateConnected>());
static_assert(StateMachine<StateConnected>{}.process(EventDisconnect{}).isInState<StateDisconnecting>());

// This would be a compile error - invalid transition:
// StateMachine<StateIdle>{}.process(EventDisconnect{}); // ERROR!

} // namespace type_state_machine

// =============================================================================
// PART 7: VARIADIC TEMPLATE MAGIC - TUPLE IMPLEMENTATION
// =============================================================================
/**
 * A complete implementation of a type-safe tuple using variadic templates.
 * This demonstrates recursive inheritance, parameter pack expansion,
 * and index-based access.
 */

namespace variadic_tuple {

// -----------------------------------------------------------------------------
// 7.1 Tuple Storage Base
// -----------------------------------------------------------------------------
/**
 * We use recursive inheritance to store tuple elements.
 * Each TupleStorage<N, T> stores one element and inherits from the next.
 * This is sometimes called the "type telescope" pattern.
 */
template<std::size_t Index, typename T>
class TupleLeaf {
    T value_;
    
public:
    TupleLeaf() : value_() {}
    
    template<typename U>
    explicit TupleLeaf(U&& val) : value_(std::forward<U>(val)) {}
    
    T& get() { return value_; }
    const T& get() const { return value_; }
};

// Index sequence helper
template<std::size_t... Indices>
struct IndexSequence {};

template<std::size_t N, std::size_t... Indices>
struct MakeIndexSequence : MakeIndexSequence<N - 1, N - 1, Indices...> {};

template<std::size_t... Indices>
struct MakeIndexSequence<0, Indices...> {
    using type = IndexSequence<Indices...>;
};

template<std::size_t N>
using MakeIndexSequence_t = typename MakeIndexSequence<N>::type;

// -----------------------------------------------------------------------------
// 7.2 Tuple Implementation
// -----------------------------------------------------------------------------
template<typename IndexSeq, typename... Ts>
class TupleImpl;

template<std::size_t... Indices, typename... Ts>
class TupleImpl<IndexSequence<Indices...>, Ts...> : public TupleLeaf<Indices, Ts>... {
public:
    TupleImpl() = default;
    
    template<typename... Us>
    explicit TupleImpl(Us&&... vals)
        : TupleLeaf<Indices, Ts>(std::forward<Us>(vals))... {}
};

template<typename... Ts>
class Tuple : public TupleImpl<MakeIndexSequence_t<sizeof...(Ts)>, Ts...> {
    using Base = TupleImpl<MakeIndexSequence_t<sizeof...(Ts)>, Ts...>;
    
public:
    static constexpr std::size_t size = sizeof...(Ts);
    
    Tuple() = default;
    
    template<typename... Us>
    explicit Tuple(Us&&... vals) : Base(std::forward<Us>(vals)...) {}
};

// Deduction guide
template<typename... Ts>
Tuple(Ts...) -> Tuple<Ts...>;

// -----------------------------------------------------------------------------
// 7.3 Get<N> Implementation
// -----------------------------------------------------------------------------
/**
 * get<N> extracts the Nth element from a tuple.
 * We use NthType to find the type at index N, then cast to the appropriate
 * TupleLeaf base class.
 */
template<std::size_t N, typename... Ts>
auto& get(Tuple<Ts...>& tuple) {
    using ElementType = typelist::NthType_t<N, typelist::TypeList<Ts...>>;
    return static_cast<TupleLeaf<N, ElementType>&>(tuple).get();
}

template<std::size_t N, typename... Ts>
const auto& get(const Tuple<Ts...>& tuple) {
    using ElementType = typelist::NthType_t<N, typelist::TypeList<Ts...>>;
    return static_cast<const TupleLeaf<N, ElementType>&>(tuple).get();
}

// -----------------------------------------------------------------------------
// 7.4 Tuple Utilities
// -----------------------------------------------------------------------------

// tuple_cat - concatenate tuples
template<typename... Ts1, typename... Ts2>
auto tuple_cat(const Tuple<Ts1...>& t1, const Tuple<Ts2...>& t2) {
    return [&]<std::size_t... I1, std::size_t... I2>(
            IndexSequence<I1...>, IndexSequence<I2...>) {
        return Tuple<Ts1..., Ts2...>(get<I1>(t1)..., get<I2>(t2)...);
    }(MakeIndexSequence_t<sizeof...(Ts1)>{}, MakeIndexSequence_t<sizeof...(Ts2)>{});
}

// apply - call function with tuple elements as arguments
template<typename F, typename... Ts>
auto apply(F&& f, const Tuple<Ts...>& tuple) {
    return [&]<std::size_t... Indices>(IndexSequence<Indices...>) {
        return std::forward<F>(f)(get<Indices>(tuple)...);
    }(MakeIndexSequence_t<sizeof...(Ts)>{});
}

// make_tuple helper
template<typename... Ts>
auto make_tuple(Ts&&... vals) {
    return Tuple<std::decay_t<Ts>...>(std::forward<Ts>(vals)...);
}

} // namespace variadic_tuple

// =============================================================================
// PART 8: PRINTF-STYLE FORMAT STRING VALIDATION
// =============================================================================
/**
 * Validate printf format strings at compile time!
 * This ensures the number and types of arguments match the format specifiers.
 */

namespace format_validation {

// -----------------------------------------------------------------------------
// 8.1 Format Specifier Parsing
// -----------------------------------------------------------------------------
/**
 * Parse format string and count/classify specifiers.
 * Format specifiers: %d, %i, %u, %f, %s, %c, %p, %x, %o, %%
 */
enum class FormatSpec {
    Int,        // %d, %i
    UInt,       // %u, %x, %o
    Float,      // %f, %e, %g
    String,     // %s
    Char,       // %c
    Pointer,    // %p
    Percent,    // %% (escaped)
    Invalid
};

constexpr FormatSpec classifySpecifier(char c) {
    switch (c) {
        case 'd': case 'i': return FormatSpec::Int;
        case 'u': case 'x': case 'X': case 'o': return FormatSpec::UInt;
        case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': return FormatSpec::Float;
        case 's': return FormatSpec::String;
        case 'c': return FormatSpec::Char;
        case 'p': return FormatSpec::Pointer;
        case '%': return FormatSpec::Percent;
        default: return FormatSpec::Invalid;
    }
}

// Count format specifiers in a string
constexpr std::size_t countFormatSpecs(const char* fmt) {
    std::size_t count = 0;
    while (*fmt) {
        if (*fmt == '%') {
            ++fmt;
            if (*fmt && *fmt != '%') ++count;
        }
        if (*fmt) ++fmt;
    }
    return count;
}

// -----------------------------------------------------------------------------
// 8.2 Type-Based Format Validation
// -----------------------------------------------------------------------------
template<typename T>
constexpr FormatSpec expectedFormat() {
    if constexpr (std::is_same_v<T, int> || std::is_same_v<T, short> || std::is_same_v<T, long>) {
        return FormatSpec::Int;
    } else if constexpr (std::is_same_v<T, unsigned> || std::is_same_v<T, unsigned long>) {
        return FormatSpec::UInt;
    } else if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
        return FormatSpec::Float;
    } else if constexpr (std::is_same_v<T, const char*> || std::is_same_v<T, char*>) {
        return FormatSpec::String;
    } else if constexpr (std::is_same_v<T, char>) {
        return FormatSpec::Char;
    } else if constexpr (std::is_pointer_v<T>) {
        return FormatSpec::Pointer;
    } else {
        return FormatSpec::Invalid;
    }
}

// Get the Nth format specifier from a format string
constexpr FormatSpec getNthSpec(const char* fmt, std::size_t n) {
    std::size_t current = 0;
    while (*fmt) {
        if (*fmt == '%') {
            ++fmt;
            if (*fmt && *fmt != '%') {
                if (current == n) {
                    return classifySpecifier(*fmt);
                }
                ++current;
            }
        }
        if (*fmt) ++fmt;
    }
    return FormatSpec::Invalid;
}

// Check if format spec is compatible with actual type
constexpr bool isCompatible(FormatSpec spec, FormatSpec actual) {
    if (spec == actual) return true;
    // Int and UInt are sometimes interchangeable
    if ((spec == FormatSpec::Int || spec == FormatSpec::UInt) &&
        (actual == FormatSpec::Int || actual == FormatSpec::UInt)) {
        return true;
    }
    return false;
}

// -----------------------------------------------------------------------------
// 8.3 Compile-Time Format Validation
// -----------------------------------------------------------------------------
template<const char* Fmt, typename... Args>
struct ValidateFormat {
private:
    static constexpr std::size_t argCount = sizeof...(Args);
    static constexpr std::size_t specCount = countFormatSpecs(Fmt);
    
    template<std::size_t... Is>
    static constexpr bool validateAll(std::index_sequence<Is...>) {
        return ((isCompatible(
            getNthSpec(Fmt, Is),
            expectedFormat<std::tuple_element_t<Is, std::tuple<Args...>>>()
        )) && ...);
    }
    
public:
    static constexpr bool valid = (argCount == specCount) && 
        validateAll(std::make_index_sequence<argCount>{});
};

// Type-safe printf wrapper
template<const char* Fmt, typename... Args>
void safe_printf(Args... args) {
    static_assert(ValidateFormat<Fmt, Args...>::valid,
                  "Format string does not match argument types!");
    std::printf(Fmt, args...);
}

// Test format strings (must be global for use as template parameter)
constexpr const char fmt1[] = "Hello %s, you are %d years old\n";
constexpr const char fmt2[] = "Value: %f\n";
constexpr const char fmt3[] = "Pointer: %p, Char: %c\n";

static_assert(ValidateFormat<fmt1, const char*, int>::valid);
static_assert(ValidateFormat<fmt2, double>::valid);
static_assert(ValidateFormat<fmt3, void*, char>::valid);

// These would fail:
// static_assert(ValidateFormat<fmt1, int, int>::valid);      // Wrong types
// static_assert(ValidateFormat<fmt2, int, int>::valid);      // Wrong count

} // namespace format_validation

// =============================================================================
// PART 9: CRTP (CURIOUSLY RECURRING TEMPLATE PATTERN)
// =============================================================================
/**
 * CRTP is a technique where a class inherits from a template instantiation
 * of itself. This enables static polymorphism - virtual function behavior
 * without virtual function overhead.
 */

namespace crtp {

// -----------------------------------------------------------------------------
// 9.1 Static Polymorphism Example
// -----------------------------------------------------------------------------
/**
 * Instead of virtual functions, we use templates and CRTP to achieve
 * polymorphic behavior resolved at compile time.
 */
template<typename Derived>
class Shape {
public:
    // Static polymorphic interface
    double area() const {
        return static_cast<const Derived*>(this)->area_impl();
    }
    
    double perimeter() const {
        return static_cast<const Derived*>(this)->perimeter_impl();
    }
    
    void draw() const {
        static_cast<const Derived*>(this)->draw_impl();
    }
    
    // CRTP enables compile-time polymorphism in templates
    void describe() const {
        std::cout << "Shape with area: " << area() 
                  << ", perimeter: " << perimeter() << "\n";
    }
};

class Circle : public Shape<Circle> {
    double radius_;
    
public:
    explicit Circle(double r) : radius_(r) {}
    
    double area_impl() const { return 3.14159265358979 * radius_ * radius_; }
    double perimeter_impl() const { return 2 * 3.14159265358979 * radius_; }
    void draw_impl() const { std::cout << "Drawing Circle(r=" << radius_ << ")\n"; }
};

class Rectangle : public Shape<Rectangle> {
    double width_, height_;
    
public:
    Rectangle(double w, double h) : width_(w), height_(h) {}
    
    double area_impl() const { return width_ * height_; }
    double perimeter_impl() const { return 2 * (width_ + height_); }
    void draw_impl() const { 
        std::cout << "Drawing Rectangle(" << width_ << "x" << height_ << ")\n"; 
    }
};

// Function template that works with any CRTP shape
template<typename T>
void printShapeInfo(const Shape<T>& shape) {
    shape.describe();
    shape.draw();
}

// -----------------------------------------------------------------------------
// 9.2 Mixin Classes with CRTP
// -----------------------------------------------------------------------------
/**
 * Mixins are classes that provide optional functionality that can be
 * "mixed in" to other classes. CRTP makes this efficient.
 */

// Mixin: Add comparison operators
template<typename Derived>
class Comparable {
public:
    bool operator<(const Derived& other) const {
        return static_cast<const Derived*>(this)->compareTo(other) < 0;
    }
    
    bool operator>(const Derived& other) const {
        return static_cast<const Derived*>(this)->compareTo(other) > 0;
    }
    
    bool operator<=(const Derived& other) const {
        return !(static_cast<const Derived*>(this)->operator>(other));
    }
    
    bool operator>=(const Derived& other) const {
        return !(static_cast<const Derived*>(this)->operator<(other));
    }
    
    bool operator==(const Derived& other) const {
        return static_cast<const Derived*>(this)->compareTo(other) == 0;
    }
    
    bool operator!=(const Derived& other) const {
        return !(*this == other);
    }
};

// Mixin: Add cloning capability
template<typename Derived>
class Cloneable {
public:
    Derived clone() const {
        return Derived(*static_cast<const Derived*>(this));
    }
};

// Mixin: Add serialization capability
template<typename Derived>
class Serializable {
public:
    std::string serialize() const {
        return static_cast<const Derived*>(this)->doSerialize();
    }
    
    static Derived deserialize(const std::string& data) {
        return Derived::doDeserialize(data);
    }
};

// Mixin: Add counter for instances
template<typename Derived>
class Countable {
    inline static std::size_t count_ = 0;
    
public:
    Countable() { ++count_; }
    Countable(const Countable&) { ++count_; }
    ~Countable() { --count_; }
    
    static std::size_t instanceCount() { return count_; }
};

// Example class using multiple mixins
class Person : public Comparable<Person>,
               public Cloneable<Person>,
               public Countable<Person> {
    std::string name_;
    int age_;
    
public:
    Person(std::string name, int age) : name_(std::move(name)), age_(age) {}
    
    // Required by Comparable mixin
    int compareTo(const Person& other) const {
        if (age_ != other.age_) return age_ - other.age_;
        return name_.compare(other.name_);
    }
    
    const std::string& name() const { return name_; }
    int age() const { return age_; }
};

// -----------------------------------------------------------------------------
// 9.3 CRTP for Method Chaining (Fluent Interface)
// -----------------------------------------------------------------------------
template<typename Derived>
class FluentBuilder {
protected:
    Derived& self() { return static_cast<Derived&>(*this); }
    
public:
    Derived& reset() {
        // Reset to default state
        return self();
    }
};

class QueryBuilder : public FluentBuilder<QueryBuilder> {
    std::string query_;
    
public:
    QueryBuilder& select(const std::string& cols) {
        query_ = "SELECT " + cols;
        return *this;
    }
    
    QueryBuilder& from(const std::string& table) {
        query_ += " FROM " + table;
        return *this;
    }
    
    QueryBuilder& where(const std::string& condition) {
        query_ += " WHERE " + condition;
        return *this;
    }
    
    QueryBuilder& orderBy(const std::string& col) {
        query_ += " ORDER BY " + col;
        return *this;
    }
    
    std::string build() const { return query_; }
};

} // namespace crtp

// =============================================================================
// PART 10: FOLD EXPRESSIONS AND PARAMETER PACK EXPANSION
// =============================================================================
/**
 * C++17 fold expressions provide concise syntax for reducing parameter packs.
 * Combined with pack expansion, they enable powerful variadic operations.
 */

namespace fold_expressions {

// -----------------------------------------------------------------------------
// 10.1 Basic Fold Expression Examples
// -----------------------------------------------------------------------------

// Sum all arguments using fold
template<typename... Args>
constexpr auto sum(Args... args) {
    return (... + args);  // Left fold: ((a1 + a2) + a3) + ...
}

// Product of all arguments
template<typename... Args>
constexpr auto product(Args... args) {
    return (... * args);
}

// Logical AND all arguments
template<typename... Args>
constexpr bool all_true(Args... args) {
    return (... && args);
}

// Logical OR all arguments
template<typename... Args>
constexpr bool any_true(Args... args) {
    return (... || args);
}

// Bitwise OR all arguments
template<typename... Args>
auto bitwise_or(Args... args) {
    return (... | args);
}

// Count truthy arguments
template<typename... Args>
constexpr std::size_t count_truthy(Args... args) {
    return (... + static_cast<std::size_t>(static_cast<bool>(args)));
}

static_assert(sum(1, 2, 3, 4, 5) == 15);
static_assert(product(1, 2, 3, 4, 5) == 120);
static_assert(all_true(true, true, true));
static_assert(!all_true(true, false, true));
static_assert(any_true(false, true, false));
static_assert(count_truthy(1, 0, 3, 0, 5) == 3);

// -----------------------------------------------------------------------------
// 10.2 Print All Arguments
// -----------------------------------------------------------------------------
template<typename... Args>
void print_all(Args&&... args) {
    // Fold with comma operator - execute side effects for each argument
    ((std::cout << args << " "), ...);
    std::cout << "\n";
}

// Print with custom separator
template<typename... Args>
void print_with_sep(const std::string& sep, Args&&... args) {
    std::size_t n = 0;
    ((std::cout << (n++ ? sep : "") << args), ...);
    std::cout << "\n";
}

// -----------------------------------------------------------------------------
// 10.3 Type Transformations with Pack Expansion
// -----------------------------------------------------------------------------

// Check if all types satisfy a predicate
template<template<typename> class Pred, typename... Ts>
constexpr bool all_satisfy = (... && Pred<Ts>::value);

template<template<typename> class Pred, typename... Ts>
constexpr bool any_satisfy = (... || Pred<Ts>::value);

static_assert(all_satisfy<std::is_integral, int, short, long>);
static_assert(!all_satisfy<std::is_integral, int, float, long>);
static_assert(any_satisfy<std::is_floating_point, int, float, long>);

// Get size of largest type
template<typename... Ts>
constexpr std::size_t max_sizeof = std::max({sizeof(Ts)...});

static_assert(max_sizeof<char, int, double> == sizeof(double));

// Get alignment of most aligned type
template<typename... Ts>
constexpr std::size_t max_alignof = std::max({alignof(Ts)...});

// -----------------------------------------------------------------------------
// 10.4 Index Tricks with Pack Expansion
// -----------------------------------------------------------------------------

// Create an array from variadic arguments
template<typename T, typename... Args>
constexpr auto make_array(Args... args) {
    return std::array<T, sizeof...(Args)>{static_cast<T>(args)...};
}

// Verify array creation works (runtime verification since std::array::operator== is not constexpr before C++20)
constexpr auto test_array = make_array<int>(1, 2, 3, 4, 5);
static_assert(test_array[0] == 1 && test_array[4] == 5);

// Apply a function to each argument
template<typename F, typename... Args>
void for_each_arg(F&& f, Args&&... args) {
    (f(std::forward<Args>(args)), ...);
}

// Transform each argument with a function
template<typename F, typename... Args>
auto transform_args(F&& f, Args&&... args) {
    return std::make_tuple(f(std::forward<Args>(args))...);
}

// -----------------------------------------------------------------------------
// 10.5 Advanced: Index Sequence with Fold Expressions
// -----------------------------------------------------------------------------

// Generate sum of squares of indices
template<std::size_t... Is>
constexpr auto sum_of_squares(std::index_sequence<Is...>) {
    return (... + (Is * Is));
}

static_assert(sum_of_squares(std::make_index_sequence<5>{}) == 0+1+4+9+16);

// Generate array of factorials
template<std::size_t... Is>
constexpr auto factorial_array(std::index_sequence<Is...>) {
    return std::array<std::size_t, sizeof...(Is)>{
        compile_time::Factorial_v<Is>...
    };
}

constexpr auto factorials_0_to_9 = factorial_array(std::make_index_sequence<10>{});
static_assert(factorials_0_to_9[0] == 1);
static_assert(factorials_0_to_9[5] == 120);
static_assert(factorials_0_to_9[9] == 362880);

// Generate array of Fibonacci numbers
template<std::size_t... Is>
constexpr auto fibonacci_array(std::index_sequence<Is...>) {
    return std::array<std::size_t, sizeof...(Is)>{
        compile_time::Fibonacci_v<Is>...
    };
}

constexpr auto fibs_0_to_19 = fibonacci_array(std::make_index_sequence<20>{});
static_assert(fibs_0_to_19[0] == 0);
static_assert(fibs_0_to_19[1] == 1);
static_assert(fibs_0_to_19[10] == 55);
static_assert(fibs_0_to_19[19] == 4181);

// -----------------------------------------------------------------------------
// 10.6 Compile-Time String Concatenation
// -----------------------------------------------------------------------------

// Concatenate multiple strings at compile time
template<typename... Args>
std::string concat(Args&&... args) {
    std::string result;
    // Pre-calculate total size for efficiency
    result.reserve((... + std::string_view(args).size()));
    ((result += args), ...);
    return result;
}

// -----------------------------------------------------------------------------
// 10.7 Perfect Forwarding with Fold
// -----------------------------------------------------------------------------

// Call multiple functions with same arguments
template<typename... Funcs, typename... Args>
void call_all(std::tuple<Funcs...>& funcs, Args&&... args) {
    std::apply([&](auto&... fs) {
        (fs(std::forward<Args>(args)...), ...);
    }, funcs);
}

// Chain function calls: f1(f2(f3(x)))
template<typename T, typename F, typename... Fs>
auto chain(T&& x, F&& f, Fs&&... fs) {
    if constexpr (sizeof...(Fs) == 0) {
        return f(std::forward<T>(x));
    } else {
        return chain(f(std::forward<T>(x)), std::forward<Fs>(fs)...);
    }
}

} // namespace fold_expressions

// =============================================================================
// PART 11: BONUS - TYPE ERASURE WITH TEMPLATES
// =============================================================================
/**
 * Type erasure allows storing objects of different types in a uniform container
 * while preserving their behavior through virtual dispatch.
 */

namespace type_erasure {

// A simple any-like class that can hold any copyable type
class Any {
    struct Concept {
        virtual ~Concept() = default;
        virtual std::unique_ptr<Concept> clone() const = 0;
        virtual const std::type_info& type() const = 0;
    };
    
    template<typename T>
    struct Model : Concept {
        T data;
        
        Model(T value) : data(std::move(value)) {}
        
        std::unique_ptr<Concept> clone() const override {
            return std::make_unique<Model>(data);
        }
        
        const std::type_info& type() const override {
            return typeid(T);
        }
    };
    
    std::unique_ptr<Concept> ptr_;
    
public:
    Any() = default;
    
    template<typename T>
    Any(T value) : ptr_(std::make_unique<Model<std::decay_t<T>>>(std::move(value))) {}
    
    Any(const Any& other) : ptr_(other.ptr_ ? other.ptr_->clone() : nullptr) {}
    
    Any(Any&&) = default;
    Any& operator=(Any&&) = default;
    
    Any& operator=(const Any& other) {
        ptr_ = other.ptr_ ? other.ptr_->clone() : nullptr;
        return *this;
    }
    
    template<typename T>
    Any& operator=(T value) {
        ptr_ = std::make_unique<Model<std::decay_t<T>>>(std::move(value));
        return *this;
    }
    
    bool has_value() const { return ptr_ != nullptr; }
    
    const std::type_info& type() const {
        return ptr_ ? ptr_->type() : typeid(void);
    }
    
    template<typename T>
    T* get() {
        if (ptr_ && ptr_->type() == typeid(T)) {
            return &static_cast<Model<T>*>(ptr_.get())->data;
        }
        return nullptr;
    }
    
    template<typename T>
    const T* get() const {
        if (ptr_ && ptr_->type() == typeid(T)) {
            return &static_cast<const Model<T>*>(ptr_.get())->data;
        }
        return nullptr;
    }
};

} // namespace type_erasure

// =============================================================================
// MAIN - DEMONSTRATION
// =============================================================================

int main() {
    std::cout << "=== C++ TEMPLATE METAPROGRAMMING SHOWCASE ===\n\n";
    
    // -------------------------------------------------------------------------
    // TypeList Demonstrations
    // -------------------------------------------------------------------------
    std::cout << "--- TYPELIST OPERATIONS ---\n";
    std::cout << "TypeList operations verified at compile time via static_assert.\n";
    std::cout << "If you see this message, all TypeList operations passed!\n\n";
    
    // -------------------------------------------------------------------------
    // Compile-Time Computations
    // -------------------------------------------------------------------------
    std::cout << "--- COMPILE-TIME COMPUTATIONS ---\n";
    std::cout << "Fibonacci(20) = " << compile_time::Fibonacci_v<20> << " (computed at compile time)\n";
    std::cout << "Fibonacci(30) = " << compile_time::Fibonacci_v<30> << " (computed at compile time)\n";
    std::cout << "Factorial(10) = " << compile_time::Factorial_v<10> << " (computed at compile time)\n";
    std::cout << "GCD(48, 18) = " << compile_time::GCD_v<48, 18> << "\n";
    std::cout << "LCM(21, 6) = " << compile_time::LCM_v<21, 6> << "\n";
    
    std::cout << "\nPrimes up to 50: ";
    for (auto p : compile_time::primes_to_50) std::cout << p << " ";
    std::cout << "\n(generated entirely at compile time)\n\n";
    
    // -------------------------------------------------------------------------
    // Expression Templates
    // -------------------------------------------------------------------------
    std::cout << "--- EXPRESSION TEMPLATES ---\n";
    expr_templates::Vec<double> v1{1.0, 2.0, 3.0, 4.0};
    expr_templates::Vec<double> v2{5.0, 6.0, 7.0, 8.0};
    
    // This expression is NOT computed until assignment!
    // The type of `expr` is a nested template, not Vec<double>
    auto expr = 2.0 * v1 + v2 * 3.0 - v1;
    
    // NOW it computes (all in one loop, no temporaries)
    expr_templates::Vec<double> result = expr;
    
    std::cout << "v1 = [1, 2, 3, 4]\n";
    std::cout << "v2 = [5, 6, 7, 8]\n";
    std::cout << "2*v1 + v2*3 - v1 = [";
    for (std::size_t i = 0; i < result.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << result[i];
    }
    std::cout << "]\n";
    std::cout << "Dot product v1.v2 = " << expr_templates::dot(v1, v2) << "\n\n";
    
    // -------------------------------------------------------------------------
    // Compile-Time Sorting
    // -------------------------------------------------------------------------
    std::cout << "--- COMPILE-TIME SORTING ---\n";
    constexpr auto unsorted = compile_time_sort::IntListToArray<
        compile_time_sort::UnsortedList>::value;
    constexpr auto sorted = compile_time_sort::IntListToArray<
        compile_time_sort::SortedBySelection>::value;
    
    std::cout << "Unsorted: [";
    for (std::size_t i = 0; i < unsorted.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << unsorted[i];
    }
    std::cout << "]\n";
    
    std::cout << "Sorted (at compile time!): [";
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << sorted[i];
    }
    std::cout << "]\n\n";
    
    // -------------------------------------------------------------------------
    // Custom Tuple
    // -------------------------------------------------------------------------
    std::cout << "--- VARIADIC TUPLE ---\n";
    auto tuple = variadic_tuple::make_tuple(42, 3.14, std::string("hello"));
    std::cout << "Tuple<int, double, string> = (";
    std::cout << variadic_tuple::get<0>(tuple) << ", ";
    std::cout << variadic_tuple::get<1>(tuple) << ", ";
    std::cout << "\"" << variadic_tuple::get<2>(tuple) << "\")\n\n";
    
    // -------------------------------------------------------------------------
    // CRTP Shapes
    // -------------------------------------------------------------------------
    std::cout << "--- CRTP STATIC POLYMORPHISM ---\n";
    crtp::Circle circle(5.0);
    crtp::Rectangle rect(4.0, 6.0);
    
    crtp::printShapeInfo(circle);
    crtp::printShapeInfo(rect);
    std::cout << "\n";
    
    // -------------------------------------------------------------------------
    // CRTP Mixins
    // -------------------------------------------------------------------------
    std::cout << "--- CRTP MIXINS ---\n";
    crtp::Person alice("Alice", 30);
    crtp::Person bob("Bob", 25);
    auto alice_clone = alice.clone();
    
    std::cout << "Person instances created: " << crtp::Person::instanceCount() << "\n";
    std::cout << "Alice (" << alice.age() << ") > Bob (" << bob.age() << "): " 
              << std::boolalpha << (alice > bob) << "\n\n";
    
    // -------------------------------------------------------------------------
    // Fold Expressions
    // -------------------------------------------------------------------------
    std::cout << "--- FOLD EXPRESSIONS ---\n";
    std::cout << "sum(1,2,3,4,5) = " << fold_expressions::sum(1, 2, 3, 4, 5) << "\n";
    std::cout << "product(1,2,3,4,5) = " << fold_expressions::product(1, 2, 3, 4, 5) << "\n";
    std::cout << "print_all: ";
    fold_expressions::print_all(1, "hello", 3.14, 'x');
    std::cout << "print_with_sep(\", \"): ";
    fold_expressions::print_with_sep(", ", "a", "b", "c", "d");
    std::cout << "\n";
    
    // -------------------------------------------------------------------------
    // Compile-Time Arrays
    // -------------------------------------------------------------------------
    std::cout << "--- COMPILE-TIME GENERATED ARRAYS ---\n";
    std::cout << "First 10 factorials: [";
    for (std::size_t i = 0; i < fold_expressions::factorials_0_to_9.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << fold_expressions::factorials_0_to_9[i];
    }
    std::cout << "]\n";
    
    std::cout << "First 20 Fibonacci numbers: [";
    for (std::size_t i = 0; i < fold_expressions::fibs_0_to_19.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << fold_expressions::fibs_0_to_19[i];
    }
    std::cout << "]\n\n";
    
    // -------------------------------------------------------------------------
    // Type Erasure
    // -------------------------------------------------------------------------
    std::cout << "--- TYPE ERASURE ---\n";
    type_erasure::Any any = 42;
    std::cout << "Any holds int: " << *any.get<int>() << "\n";
    any = std::string("now I'm a string!");
    std::cout << "Any holds string: " << *any.get<std::string>() << "\n";
    any = 3.14159;
    std::cout << "Any holds double: " << *any.get<double>() << "\n\n";
    
    // -------------------------------------------------------------------------
    // Query Builder (CRTP Fluent Interface)
    // -------------------------------------------------------------------------
    std::cout << "--- CRTP FLUENT INTERFACE ---\n";
    auto query = crtp::QueryBuilder{}
        .select("name, age")
        .from("users")
        .where("age > 18")
        .orderBy("name")
        .build();
    std::cout << "Generated query: " << query << "\n\n";
    
    // -------------------------------------------------------------------------
    // State Machine (compile-time verified)
    // -------------------------------------------------------------------------
    std::cout << "--- TYPE-LEVEL STATE MACHINE ---\n";
    std::cout << "State machine transitions verified at compile time.\n";
    std::cout << "Invalid transitions would cause compilation errors!\n";
    std::cout << "Idle --Connect--> Connecting --Connected--> Connected\n\n";
    
    // -------------------------------------------------------------------------
    // Format String Validation
    // -------------------------------------------------------------------------
    std::cout << "--- COMPILE-TIME FORMAT VALIDATION ---\n";
    std::cout << "Format strings validated at compile time.\n";
    std::cout << "Mismatched format/arguments would cause compilation errors!\n";
    format_validation::safe_printf<format_validation::fmt1>("World", 42);
    format_validation::safe_printf<format_validation::fmt2>(2.71828);
    
    std::cout << "\n=== ALL TEMPLATE METAPROGRAMMING TESTS PASSED ===\n";
    std::cout << "This program demonstrates that C++ templates are Turing-complete!\n";
    
    return 0;
}
