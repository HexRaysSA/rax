// Two threads that each need the other to be running: one waits, without
// blocking, for a word the other writes, round after round. A runtime that
// ran one thread to its end before the next would never finish this.
// Then a sum computed by several threads over parts of one array.
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

enum { ROUNDS = 300 };
static atomic_int turn;

static void *play(void *argument) {
  int side = (int)(long)argument;
  for (int round = 0; round < ROUNDS; ++round) {
    while (atomic_load(&turn) % 2 != side)
      ;
    atomic_fetch_add(&turn, 1);
  }
  return NULL;
}

struct part {
  const unsigned *values;
  size_t count;
  unsigned long sum;
};

static void *sum(void *argument) {
  struct part *part = argument;
  unsigned long total = 0;
  for (int pass = 0; pass < 20; ++pass)
    for (size_t index = 0; index < part->count; ++index)
      total += part->values[index] * (unsigned long)(pass + 1) ^ (total >> 7);
  part->sum = total;
  return NULL;
}

int main(int argc, char **argv) {
  pthread_t players[2];
  for (long side = 0; side < 2; ++side)
    pthread_create(&players[side], NULL, play, (void *)side);
  for (int side = 0; side < 2; ++side)
    pthread_join(players[side], NULL);
  printf("turns %d\n", atomic_load(&turn));

  int threads = argc > 1 ? atoi(argv[1]) : 4;
  size_t count = argc > 2 ? (size_t)atol(argv[2]) : 20000;
  if (threads < 1 || threads > 16)
    return 2;
  unsigned *values = malloc(count * sizeof *values);
  if (!values)
    return 3;
  unsigned state = 12345;
  for (size_t index = 0; index < count; ++index)
    values[index] = state = state * 1664525u + 1013904223u;
  // Always sixteen parts, so that the result does not depend on how many
  // threads share them out.
  enum { PARTS = 16 };
  struct part parts[PARTS];
  pthread_t workers[PARTS];
  for (int part = 0; part < PARTS; ++part) {
    parts[part].values = values + count * part / PARTS;
    parts[part].count = count * (part + 1) / PARTS - count * part / PARTS;
  }
  for (int first = 0; first < PARTS; first += threads) {
    for (int part = first; part < first + threads && part < PARTS; ++part)
      pthread_create(&workers[part], NULL, sum, &parts[part]);
    for (int part = first; part < first + threads && part < PARTS; ++part)
      pthread_join(workers[part], NULL);
  }
  unsigned long total = 0;
  for (int part = 0; part < PARTS; ++part)
    total = total * 31 + parts[part].sum;
  printf("sum %lu\n", total);
  free(values);
  return 0;
}
