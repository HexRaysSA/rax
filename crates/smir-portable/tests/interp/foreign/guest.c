// Foreign code for the tests: functions as a native compiler makes them, and
// the bridge of each, the stub the runtime enters with one argument, the
// address of a frame (chapter 07 of the specification, "Generated bridges and
// fixed packet ABI").
//
// Built by build_guest.py for x86-64 and for AArch64 into the committed
// `guest-*.elf`: static, at fixed addresses, with no library and no entry of
// its own. A bridge reads its arguments out of the frame's arena, calls the
// function by the machine's own calling convention, writes the result where
// the frame says, and says that it returned.
typedef unsigned int u32;
typedef unsigned long long u64;

// The frame: 80 bytes, the same on every machine.
typedef struct {
  u32 revision, flags;
  u64 signature_ref;
  u64 arguments_address, arguments_bytes;
  u64 result_address, result_bytes;
  u64 transition_id, exception_lease;
  u32 status, reserved_zero;
  u64 continuation_generation;
} Frame;

// An argument in the arena: this header, then the argument's bytes at the
// next address that has its alignment. `next` is how far on the next header
// is.
typedef struct {
  u32 declaration, reserved;
  u64 size, alignment, next;
} Entry;

enum { ENTERED = 1, RETURNED = 3 };

// The address of the bytes of the argument at `index`.
static const void *argument(const Frame *frame, unsigned index) {
  const Entry *entry = (const Entry *)frame->arguments_address;
  while (index--)
    entry = (const Entry *)((const char *)entry + entry->next);
  u64 payload = (u64)entry + sizeof *entry;
  return (const void *)((payload + entry->alignment - 1) & ~(entry->alignment - 1));
}

// The functions themselves. What `count` keeps, it keeps in the image's own
// data, from one call to the next.
__attribute__((noinline)) int scale(int x) { return 3 * x + 1; }

static int counted = 100;
__attribute__((noinline)) int count(int by) {
  counted += by;
  return counted;
}

void bridge_scale(Frame *frame) {
  *(int *)frame->result_address = scale(*(const int *)argument(frame, 0));
  frame->status = RETURNED;
}

void bridge_count(Frame *frame) {
  *(int *)frame->result_address = count(*(const int *)argument(frame, 0));
  frame->status = RETURNED;
}

// The personality of this code, which catches nothing and has nothing to
// clean up: asked about an exception in either phase, it tells the unwinder
// to go on (8, `_URC_CONTINUE_UNWIND`).
int personality(int version, int actions, u64 exception_class, void *exception, void *context) {
  (void)version, (void)actions, (void)exception_class, (void)exception, (void)context;
  return 8;
}

// Bridges that go wrong, each in one way.

// Reads where nothing is.
void bridge_fault(Frame *frame) {
  *(int *)frame->result_address = *(volatile int *)16;
  frame->status = RETURNED;
}

// Returns without having said so.
void bridge_silent(Frame *frame) { *(int *)frame->result_address = 7; }

// Returns into another transition than the one it was entered for.
void bridge_stale(Frame *frame) {
  *(int *)frame->result_address = 7;
  frame->continuation_generation += 1;
  frame->status = RETURNED;
}

// Never returns.
void bridge_spin(Frame *frame) {
  for (volatile u64 forever = 1; forever;)
    frame->flags = 0;
}
