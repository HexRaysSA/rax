// A module that needs no other: a counter of its own, and a value that is
// there once its constructor has run.
static long counter;
static long ready;

__attribute__((constructor)) static void prepare(void) { ready = 7; }

int scale(int x) { return 3 * x; }
long count(void) { return ++counter; }
long ready_value(void) { return ready; }
// For this module alone.
__attribute__((visibility("hidden"))) int inner(int x) { return x; }
