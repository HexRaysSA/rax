// A module that needs `base`.
int scale(int);
long count(void);
long ready_value(void);

// What `base` had ready when this module's constructor ran: its own
// constructor must have run by then.
static long stored;
__attribute__((constructor)) static void prepare(void) { stored = ready_value() + 1; }

int area(int w, int h) { return scale(w) * h; }
long ticks(void) {
  count();
  return count();
}
long stored_value(void) { return stored; }
