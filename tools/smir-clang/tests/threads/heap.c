// Threads allocate, fill, resize and free blocks of the one heap at the same
// time, and format text, each checking that what it wrote is still there.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { THREADS = 6, ROUNDS = 400, HELD = 16 };

static void *churn(void *argument) {
  unsigned seed = (unsigned)(long)argument * 2654435761u + 1;
  unsigned char *blocks[HELD] = {0};
  size_t sizes[HELD] = {0};
  long damaged = 0;
  for (int round = 0; round < ROUNDS; ++round) {
    seed = seed * 1103515245u + 12345u;
    int slot = (seed >> 16) % HELD;
    size_t size = 1 + (seed >> 8) % 200;
    unsigned char mark = (unsigned char)((long)argument * 16 + slot);
    if (blocks[slot]) {
      for (size_t index = 0; index < sizes[slot]; ++index)
        damaged += blocks[slot][index] != mark;
      if (seed & 1) {
        free(blocks[slot]);
        blocks[slot] = NULL;
        continue;
      }
      blocks[slot] = realloc(blocks[slot], size);
      size_t kept = size < sizes[slot] ? size : sizes[slot];
      for (size_t index = 0; index < kept; ++index)
        damaged += blocks[slot][index] != mark;
    } else {
      blocks[slot] = malloc(size);
    }
    if (!blocks[slot])
      return (void *)-1;
    memset(blocks[slot], mark, size);
    sizes[slot] = size;
  }
  char text[64];
  snprintf(text, sizeof text, "%ld:%.3f:%s", (long)argument, (double)(long)argument / 8, "done");
  for (int slot = 0; slot < HELD; ++slot)
    free(blocks[slot]);
  char *copy = malloc(strlen(text) + 1);
  strcpy(copy, text);
  return damaged ? NULL : copy;
}

int main(void) {
  pthread_t threads[THREADS];
  for (long index = 0; index < THREADS; ++index)
    pthread_create(&threads[index], NULL, churn, (void *)index);
  int failed = 0;
  for (int index = 0; index < THREADS; ++index) {
    void *result;
    pthread_join(threads[index], &result);
    if (result == NULL || result == (void *)-1) {
      printf("thread %d: %s\n", index, result ? "out of memory" : "damaged");
      failed = 1;
    } else {
      printf("thread %s\n", (char *)result);
      free(result);
    }
  }
  // The heap is whole: one block of most of it can still be had.
  void *large = malloc(512 * 1024);
  printf("large block: %s\n", large ? "yes" : "no");
  free(large);
  return failed;
}
