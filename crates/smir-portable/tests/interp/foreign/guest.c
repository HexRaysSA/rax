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

// The frame: 80 bytes at a multiple of 16, the same on every machine.
typedef struct {
  _Alignas(16) u32 revision;
  u32 flags;
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

// A function that needs its stack: `deep(n)` is 1 + 2 + ... + n, and every
// level has a block of its own that it writes before it goes down and reads
// when it is back.
__attribute__((noinline)) int deep(int n) {
  volatile char block[256];
  if (n <= 0)
    return 0;
  block[n & 255] = (char)n;
  int below = deep(n - 1);
  return below + n + (block[n & 255] != (char)n);
}

void bridge_deep(Frame *frame) {
  *(int *)frame->result_address = deep(*(const int *)argument(frame, 0));
  frame->status = RETURNED;
}

// Calls back into portable code.
//
// A portable function that this code calls has a wrapper here of the
// function's own type, which is what this code calls. The wrapper puts the
// argument into an arena and a frame of its own, on its stack, and goes with
// the frame to the entry of the callback: a function of this image in name
// only, which the runtime takes over. What is in it never runs. When the
// runtime comes back from there, the frame says that the portable function
// returned, and its result is where the frame said it should go.

// What the modules call their callbacks (the identifiers of the bridges in
// build_foreign.py), and how they declare `int`.
enum { TWICE = 100, STEP = 101, INT = 1 };

__attribute__((weak)) void callback_twice(Frame *frame) {
  (void)frame;
  __builtin_trap();
}

__attribute__((weak)) void callback_step(Frame *frame) {
  (void)frame;
  __builtin_trap();
}

// One call back, at `entry`, as the callback `bridge`, of `x`, which the
// arena says is of the type `declaration`.
static int called_back(void (*entry)(Frame *), u32 bridge, int x, u32 declaration) {
  struct {
    Entry entry;
    int value, zero;
  } arena = {{declaration, 0, sizeof(int), _Alignof(int), sizeof arena}, x, 0};
  int result = 0;
  Frame frame = {1, 0, bridge, (u64)&arena, sizeof arena, (u64)&result, sizeof result, 0, 0, ENTERED, 0, 0};
  entry(&frame);
  if (frame.status != RETURNED)
    __builtin_trap();
  return result;
}

// The wrappers: `twice(x)` is 2x, and `step(n)` is `down(n - 1)`, which
// portable code computes by calling `down` here.
__attribute__((noinline)) int twice(int x) { return called_back(callback_twice, TWICE, x, INT); }
__attribute__((noinline)) int step(int n) { return called_back(callback_step, STEP, n, INT); }

// Functions that call portable code: once, and as deep as their argument
// says, portable and foreign code by turns. `down(n)` is n.
__attribute__((noinline)) int apply(int x) { return twice(x) + 1; }
__attribute__((noinline)) int down(int n) { return n <= 0 ? 0 : step(n) + 1; }

void bridge_apply(Frame *frame) {
  *(int *)frame->result_address = apply(*(const int *)argument(frame, 0));
  frame->status = RETURNED;
}

void bridge_down(Frame *frame) {
  *(int *)frame->result_address = down(*(const int *)argument(frame, 0));
  frame->status = RETURNED;
}

// Callbacks that are none. The module says of this bridge's function that
// it does not call back, and it does.
void bridge_quiet(Frame *frame) {
  *(int *)frame->result_address = apply(*(const int *)argument(frame, 0));
  frame->status = RETURNED;
}

// At the entry of one callback with a frame that names another.
void bridge_other(Frame *frame) {
  *(int *)frame->result_address = called_back(callback_twice, STEP, *(const int *)argument(frame, 0), INT);
  frame->status = RETURNED;
}

// With an argument that is said to be of another type than the callback
// takes.
void bridge_crooked(Frame *frame) {
  *(int *)frame->result_address = called_back(callback_twice, TWICE, *(const int *)argument(frame, 0), INT + 1);
  frame->status = RETURNED;
}

#if defined(__x86_64__)
// The bridge of `scale` as code for Windows has it: entered with the frame
// in RCX, and with 32 bytes above its return address that are its own to
// write, which it does.
__attribute__((ms_abi)) void bridge_scale_ms(Frame *frame) {
  volatile u64 *home = (volatile u64 *)__builtin_frame_address(0) + 2;
  for (int index = 0; index < 4; index++)
    home[index] = (u64)frame;
  *(int *)frame->result_address = scale(*(const int *)argument(frame, 0));
  frame->status = RETURNED;
}
#endif

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
