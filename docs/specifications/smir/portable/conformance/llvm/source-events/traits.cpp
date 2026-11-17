struct Aggregate { int value; };
struct NotImplicit { ~NotImplicit() {} };
struct ContainsNotImplicit { NotImplicit member; };
static_assert(__builtin_is_implicit_lifetime(Aggregate));
static_assert(!__builtin_is_implicit_lifetime(NotImplicit));
static_assert(__builtin_is_implicit_lifetime(NotImplicit[2]));
static_assert(__builtin_is_implicit_lifetime(ContainsNotImplicit));
static_assert(!__builtin_is_implicit_lifetime(NotImplicit));
void trait_boundary() { NotImplicit array[2]; ContainsNotImplicit aggregate; }
