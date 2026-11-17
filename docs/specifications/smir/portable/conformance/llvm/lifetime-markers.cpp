/* Source fixture for retained private IR notes; no marker is linked/executed. */
#include "coroutine-state.cpp"
#define LIFE_NAME(phase) "__smir_life_v1.1111111111111111111111111111111111111111111111111111111111111111.7." phase
extern "C" void life_begin(void *, unsigned, unsigned long, int) noexcept __asm__(LIFE_NAME("object.begin"));
extern "C" void life_commit(void *, unsigned, unsigned long) noexcept __asm__(LIFE_NAME("construct.commit"));
extern "C" void life_publish(void *, unsigned, unsigned long) noexcept __asm__(LIFE_NAME("publish"));
StateTask marked_lifetime(int captured) {
    int value = (life_begin(&value, 0, 0, captured), co_await IntPause{captured});
    life_commit(&value, 0, 0);
    life_publish(&value, 0, 0);
    co_return;
}
