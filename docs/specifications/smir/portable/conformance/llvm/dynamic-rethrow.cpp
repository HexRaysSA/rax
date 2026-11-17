/* A rethrow expression obtains the dynamically handled exception, not lexical SSA. */
[[noreturn]] void dynamic_rethrow() { throw; }
extern void raise_source();
void indirect_catch_rethrow() {
    try { raise_source(); }
    catch (...) { dynamic_rethrow(); }
}
