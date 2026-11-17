// Compile-only transport witness. This is not an ISO or provenance proof.
using F = int(*)(int);
static_assert(sizeof(F) == 8 && __is_trivially_copyable(F));
int copy_call(F source, int value) {
    F copied = nullptr;
    const unsigned char* from = reinterpret_cast<const unsigned char*>(&source);
    unsigned char* to = reinterpret_cast<unsigned char*>(&copied);
    for (unsigned i = 0; i < sizeof(F); ++i) to[i] = from[i];
    return copied(value);
}
