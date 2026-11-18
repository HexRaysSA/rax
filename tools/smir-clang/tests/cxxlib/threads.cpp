// The C++ library's threads: threads that are joined, a mutex and a
// condition variable handing work to them, atomics, call_once, a promise
// fulfilled by another thread, and an exception carried from one thread to
// another by a future.
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <future>
#include <stdexcept>
#include <mutex>
#include <queue>
#include <string>
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

  std::promise<int> promise;
  std::future<int> future = promise.get_future();
  std::thread fulfiller([&promise] { promise.set_value(77); });
  int promised = future.get();
  fulfiller.join();

  std::promise<int> broken;
  std::future<int> failing = broken.get_future();
  std::thread thrower([&broken] {
    try {
      throw std::runtime_error("from another thread");
    } catch (...) {
      broken.set_exception(std::current_exception());
    }
  });
  thrower.join();
  const char *carried = "nothing";
  std::string message;
  try {
    failing.get();
  } catch (const std::runtime_error &error) {
    message = error.what();
    carried = message.c_str();
  }

  std::printf("total %ld, started %d, initialized %d, threads %u, promised %d, carried %s\n", total.load(),
              started.load(), initialized, static_cast<unsigned>(workers.size()), promised, carried);
  return 0;
}
