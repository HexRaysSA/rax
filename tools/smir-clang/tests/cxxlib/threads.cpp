// The C++ library's threads: threads that are joined, a mutex and a
// condition variable handing work to them, atomics, and call_once.
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

int main() {
  std::mutex mutex;
  std::condition_variable ready;
  std::queue<int> work;
  bool closed = false;
  std::atomic<long> total{0};
  std::atomic<int> started{0};
  std::once_flag once;
  int initialized = 0;

  std::vector<std::thread> workers;
  for (int index = 0; index < 4; ++index) {
    workers.emplace_back([&] {
      std::call_once(once, [&] { ++initialized; });
      ++started;
      for (;;) {
        int item;
        {
          std::unique_lock<std::mutex> lock(mutex);
          ready.wait(lock, [&] { return closed || !work.empty(); });
          if (work.empty())
            return;
          item = work.front();
          work.pop();
        }
        total += static_cast<long>(item) * item;
      }
    });
  }
  for (int item = 1; item <= 1000; ++item) {
    {
      std::lock_guard<std::mutex> lock(mutex);
      work.push(item);
    }
    ready.notify_one();
  }
  {
    std::lock_guard<std::mutex> lock(mutex);
    closed = true;
  }
  ready.notify_all();
  for (std::thread &worker : workers)
    worker.join();

  std::printf("total %ld, started %d, initialized %d, threads %u\n", total.load(), started.load(), initialized,
              static_cast<unsigned>(workers.size()));
  return 0;
}
