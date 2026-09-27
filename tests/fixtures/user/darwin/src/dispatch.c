// libdispatch: global concurrent queues, serial queues, groups, semaphores,
// dispatch_apply, dispatch_after, barriers, timer and read sources, and a
// signal source. Only totals and orderings that do not depend on
// scheduling are printed.
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static atomic_long sum;
static char order[11];
static char got[16];
static int pipefd[2];

int main(void) {
    dispatch_queue_t global = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);

    // A group of blocks on the global queue.
    dispatch_group_t g = dispatch_group_create();
    for (long i = 1; i <= 100; i++) {
        dispatch_group_async(g, global, ^{
            atomic_fetch_add(&sum, i);
        });
    }
    long r = dispatch_group_wait(g, DISPATCH_TIME_FOREVER);
    printf("group: r=%ld sum=%ld\n", r, atomic_load(&sum));

    // A serial queue keeps order.
    dispatch_queue_t serial = dispatch_queue_create("serial", DISPATCH_QUEUE_SERIAL);
    __block int n = 0;
    for (int i = 0; i < 10; i++) {
        dispatch_async(serial, ^{
            order[n++] = (char)('0' + i);
        });
    }
    dispatch_sync(serial, ^{});
    printf("serial: %s\n", order);

    // dispatch_apply.
    atomic_store(&sum, 0);
    dispatch_apply(64, global, ^(size_t i) {
        atomic_fetch_add(&sum, (long)i);
    });
    printf("apply: %ld\n", atomic_load(&sum));

    // A semaphore signalled from another queue.
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(global, ^{
        dispatch_semaphore_signal(sem);
    });
    printf("semaphore: %ld\n", dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER));
    printf("semaphore timeout: %s\n",
           dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_MSEC)) != 0
               ? "timed out"
               : "?");

    // Barriers on a concurrent queue.
    dispatch_queue_t conc = dispatch_queue_create("conc", DISPATCH_QUEUE_CONCURRENT);
    __block atomic_int before = 0, seen_at_barrier = -1;
    for (int i = 0; i < 8; i++) {
        dispatch_async(conc, ^{
            atomic_fetch_add(&before, 1);
        });
    }
    dispatch_barrier_async(conc, ^{
        atomic_store(&seen_at_barrier, atomic_load(&before));
    });
    dispatch_sync(conc, ^{});
    printf("barrier: saw %d\n", atomic_load(&seen_at_barrier));

    // dispatch_after.
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block int after_ran = 0;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC), global, ^{
        after_ran = 1;
        dispatch_semaphore_signal(done);
    });
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    printf("after: %d\n", after_ran);

    // A repeating timer source, cancelled after three fires.
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, serial);
    __block int fires = 0;
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_MSEC),
                              5 * NSEC_PER_MSEC, 0);
    dispatch_source_set_event_handler(timer, ^{
        if (++fires == 3) {
            dispatch_source_cancel(timer);
        }
    });
    dispatch_source_set_cancel_handler(timer, ^{
        dispatch_semaphore_signal(done);
    });
    dispatch_resume(timer);
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    printf("timer: fires=%d\n", fires);

    // A read source on a pipe.
    pipe(pipefd);
    dispatch_source_t rd =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)pipefd[0], 0, serial);
    dispatch_source_set_event_handler(rd, ^{
        size_t avail = dispatch_source_get_data(rd);
        ssize_t k = read(pipefd[0], got, avail < 15 ? avail : 15);
        (void)k;
        dispatch_source_cancel(rd);
    });
    dispatch_source_set_cancel_handler(rd, ^{
        dispatch_semaphore_signal(done);
    });
    dispatch_resume(rd);
    write(pipefd[1], "hello", 5);
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    printf("read source: %s\n", got);

    // A signal source.
    signal(SIGUSR1, SIG_IGN);
    dispatch_source_t sig = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, serial);
    __block unsigned long sigs = 0;
    dispatch_source_set_event_handler(sig, ^{
        sigs += dispatch_source_get_data(sig);
        dispatch_source_cancel(sig);
    });
    dispatch_source_set_cancel_handler(sig, ^{
        dispatch_semaphore_signal(done);
    });
    dispatch_resume(sig);
    kill(getpid(), SIGUSR1);
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    printf("signal source: %lu\n", sigs);
    return 0;
}
