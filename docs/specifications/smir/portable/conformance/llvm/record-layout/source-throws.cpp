extern void target();
void normalized_payloads(const int &value, int (&array)[2]) {
    try { throw value; } catch (...) {}
    try { throw array; } catch (...) {}
    try { throw target; } catch (...) {}
    try { throw static_cast<const void *>(nullptr); } catch (...) {}
}
