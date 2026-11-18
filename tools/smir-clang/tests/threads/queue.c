// Producers and consumers share a bounded queue guarded by one mutex and two
// condition variables. Every item is consumed exactly once.
#include <pthread.h>
#include <stdio.h>

enum { PRODUCERS = 3, CONSUMERS = 4, ITEMS = 2000, CAPACITY = 8 };

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t not_full = PTHREAD_COND_INITIALIZER;
static int queue[CAPACITY];
static int head, count, producing = PRODUCERS;
static unsigned char seen[PRODUCERS * ITEMS];

static void *produce(void *argument) {
  int producer = (int)(long)argument;
  for (int item = 0; item < ITEMS; ++item) {
    pthread_mutex_lock(&mutex);
    while (count == CAPACITY)
      pthread_cond_wait(&not_full, &mutex);
    queue[(head + count++) % CAPACITY] = producer * ITEMS + item;
    pthread_cond_signal(&not_empty);
    pthread_mutex_unlock(&mutex);
  }
  pthread_mutex_lock(&mutex);
  if (--producing == 0)
    pthread_cond_broadcast(&not_empty);
  pthread_mutex_unlock(&mutex);
  return NULL;
}

static void *consume(void *argument) {
  long taken = 0;
  (void)argument;
  for (;;) {
    pthread_mutex_lock(&mutex);
    while (count == 0 && producing != 0)
      pthread_cond_wait(&not_empty, &mutex);
    if (count == 0) {
      pthread_mutex_unlock(&mutex);
      return (void *)taken;
    }
    int value = queue[head];
    head = (head + 1) % CAPACITY;
    --count;
    ++seen[value];
    pthread_cond_signal(&not_full);
    pthread_mutex_unlock(&mutex);
    ++taken;
  }
}

int main(void) {
  pthread_t producers[PRODUCERS], consumers[CONSUMERS];
  for (long index = 0; index < CONSUMERS; ++index)
    pthread_create(&consumers[index], NULL, consume, NULL);
  for (long index = 0; index < PRODUCERS; ++index)
    pthread_create(&producers[index], NULL, produce, (void *)index);
  for (int index = 0; index < PRODUCERS; ++index)
    pthread_join(producers[index], NULL);
  long taken = 0;
  for (int index = 0; index < CONSUMERS; ++index) {
    void *result;
    pthread_join(consumers[index], &result);
    taken += (long)result;
  }
  int once = 0;
  for (int value = 0; value < PRODUCERS * ITEMS; ++value)
    once += seen[value] == 1;
  printf("taken %ld, consumed once %d of %d\n", taken, once, PRODUCERS * ITEMS);
  return taken == PRODUCERS * ITEMS && once == PRODUCERS * ITEMS ? 0 : 1;
}
