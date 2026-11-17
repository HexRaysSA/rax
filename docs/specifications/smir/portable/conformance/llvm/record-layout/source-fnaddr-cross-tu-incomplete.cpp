// Existing-target witness. Addressing this function does not supply its call ABI.
struct R;
using F = R(R);
using Other = void();
static_assert(sizeof(F*) == 8 && alignof(F*) == 8);
R function(R);
F* address = &function;
F* null_address = nullptr;
F* pass(F* value) { return value; }
Other* change_view(F* value) { return reinterpret_cast<Other*>(value); }
F* restore_view(Other* value) { return reinterpret_cast<F*>(value); }
bool equal(F* left, F* right) { return left == right; }
bool is_null(F* value) { return value == nullptr; }
#ifdef RAX_REJECT_INCOMPLETE_CALL
void rejected_call(R* value) { function(*value); }
#endif
#ifdef RAX_REJECT_FUNCTION_ARITHMETIC
F* rejected_arithmetic(F* value) { return value + 1; }
#endif
