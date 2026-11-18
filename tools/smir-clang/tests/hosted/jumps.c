// Non-local jumps: out of the function that asked for one, out of functions
// it called, through a function pointer and a library function, to one of
// several places, and again and again to the same one.
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Back to where it was asked from, in the same function.
static int in_place(int value) {
  jmp_buf here;
  volatile int passes = 0;
  int yielded = setjmp(here);
  passes = passes + 1;
  if (yielded == 0)
    longjmp(here, value);
  return yielded * 10 + passes;
}

// From several calls down, past activations that are left without
// returning.
static jmp_buf surface;

static void dive(int depth, int value) {
  char weight[32];
  memset(weight, depth, sizeof weight);
  if (depth == 0)
    longjmp(surface, value);
  dive(depth - 1, value + weight[0]);
  puts("not reached");
}

static int from_below(int depth) {
  int yielded = setjmp(surface);
  if (yielded != 0)
    return yielded;
  dive(depth, 100);
  return -1;
}

// What a volatile variable held when the jump was made is what it holds
// after; a jump with zero yields one.
static int kept(void) {
  jmp_buf here;
  volatile int steps = 0;
  int yielded = setjmp(here);
  if (steps < 3) {
    steps = steps + 1;
    longjmp(here, yielded == 0 ? 0 : yielded + 1);
  }
  return steps * 100 + yielded;
}

// The function that jumps is told so: nothing follows a call of it.
static jmp_buf failure;
static int cleanups;

_Noreturn static void fail(int code) {
  cleanups++;
  longjmp(failure, code);
}

static int checked_divide(int dividend, int divisor) {
  if (divisor == 0)
    fail(7);
  return dividend / divisor;
}

static int recover(int divisor) {
  int code = setjmp(failure);
  if (code != 0)
    return -code;
  return checked_divide(84, divisor);
}

// Through a library function that calls back: out of `qsort`.
static jmp_buf sorted_out;
static int comparisons;

static int compare(const void *left, const void *right) {
  if (++comparisons == 5)
    longjmp(sorted_out, comparisons);
  return *(const int *)left - *(const int *)right;
}

static int interrupted_sort(void) {
  int values[] = {9, 3, 7, 1, 8, 2, 6, 4, 5, 0};
  comparisons = 0;
  int yielded = setjmp(sorted_out);
  if (yielded == 0) {
    qsort(values, 10, sizeof values[0], compare);
    return -1;
  }
  return yielded;
}

// Several places in one function, each with its own buffer, and one of
// them in a structure.
struct machine {
  int state;
  jmp_buf places[3];
};

static void move(struct machine *machine, int place) { longjmp(machine->places[place], place + 1); }

static int travel(void) {
  struct machine machine = {0};
  volatile int trail = 0;
  if (setjmp(machine.places[0]) != 0)
    trail = trail * 10 + 1;
  if (setjmp(machine.places[1]) != 0)
    trail = trail * 10 + 2;
  if (setjmp(machine.places[2]) != 0)
    trail = trail * 10 + 3;
  // Each place is visited once, last first.
  if (trail == 0)
    move(&machine, 2);
  if (trail == 3)
    move(&machine, 1);
  if (trail == 323)
    move(&machine, 0);
  return trail;
}

// An inner function's buffer and an outer one's: the inner jump does not
// disturb the outer, and the outer is still good afterwards.
static jmp_buf outer_place;

static int inner(int value) {
  jmp_buf inner_place;
  int yielded = setjmp(inner_place);
  if (yielded == 0)
    longjmp(inner_place, value);
  if (yielded > 2)
    longjmp(outer_place, yielded * 2);
  return yielded;
}

static int nested(int value) {
  int yielded = setjmp(outer_place);
  if (yielded != 0)
    return 1000 + yielded;
  return inner(value);
}

// The other names for the same thing.
static int by_other_names(void) {
  sigjmp_buf here;
  int yielded = sigsetjmp(here, 1);
  if (yielded == 0)
    siglongjmp(here, 5);
  jmp_buf there;
  int again = _setjmp(there);
  if (again == 0)
    _longjmp(there, 6);
  return yielded * 10 + again;
}

int main(void) {
  printf("in place %d %d\n", in_place(4), in_place(9));
  printf("from below %d %d %d\n", from_below(0), from_below(3), from_below(40));
  printf("kept %d\n", kept());
  printf("recover %d %d, cleanups %d\n", recover(4), recover(0), cleanups);
  printf("sort %d\n", interrupted_sort());
  printf("travel %d\n", travel());
  printf("nested %d %d\n", nested(2), nested(3));
  printf("names %d\n", by_other_names());
  // And many times over, with nothing left behind.
  long total = 0;
  for (int round = 0; round < 2000; round++)
    total += from_below(round % 7) + recover(round % 3);
  printf("total %ld\n", total);
  return 0;
}
