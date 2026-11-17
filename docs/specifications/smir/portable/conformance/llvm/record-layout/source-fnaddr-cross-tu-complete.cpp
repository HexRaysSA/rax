// Same pointer/prototype source spelling after the record definition is known.
struct R { int value; };
using F = R(R);
using Other = void();
static_assert(sizeof(R) == 4 && sizeof(F*) == 8 && alignof(F*) == 8);
R function(R);
F* address = &function;
F* null_address = nullptr;
F* pass(F* value) { return value; }
Other* change_view(F* value) { return reinterpret_cast<Other*>(value); }
F* restore_view(Other* value) { return reinterpret_cast<F*>(value); }
bool equal(F* left, F* right) { return left == right; }
bool is_null(F* value) { return value == nullptr; }
