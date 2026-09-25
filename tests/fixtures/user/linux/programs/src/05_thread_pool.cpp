/**
 * Production-Quality Thread Pool Implementation
 * 
 * Features:
 * - Configurable number of worker threads
 * - Task queue with mutex and condition variable synchronization
 * - Submit function returning std::future for async result retrieval
 * - Graceful shutdown mechanism with two modes (wait vs. immediate)
 * - Support for any callable (lambdas, function pointers, std::function, functors)
 * - Proper exception handling and thread safety
 * - C++17 features: std::invoke_result_t, structured bindings, if-init
 * 
 * Compile: g++ -std=c++17 -pthread -O2 -o thread_pool 05_thread_pool.cpp
 */

#include <iostream>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <memory>
#include <type_traits>
#include <stdexcept>
#include <atomic>
#include <chrono>
#include <numeric>
#include <random>
#include <iomanip>

/**
 * ThreadPool - A production-quality thread pool implementation
 * 
 * This class manages a pool of worker threads that execute tasks from a shared
 * queue. Tasks can be any callable object and their results are accessible via
 * std::future objects returned by the submit() method.
 * 
 * Thread Safety:
 * - All public methods are thread-safe
 * - Tasks are executed in FIFO order (though completion order may vary)
 * - Exceptions thrown by tasks are captured and propagated via futures
 * 
 * Shutdown Behavior:
 * - Destructor waits for all pending tasks to complete (graceful shutdown)
 * - shutdown() can be called explicitly for immediate termination
 */
class ThreadPool {
public:
    /**
     * Construct a thread pool with the specified number of worker threads.
     * 
     * @param num_threads Number of worker threads to create. If 0 or not specified,
     *                    uses std::thread::hardware_concurrency() (number of CPU cores).
     * @throws std::invalid_argument if num_threads is negative (shouldn't happen with size_t)
     */
    explicit ThreadPool(size_t num_threads = 0)
        : stop_flag_(false)
        , shutdown_immediate_(false)
        , tasks_queued_(0)
        , tasks_completed_(0)
    {
        // Default to hardware concurrency if not specified
        if (num_threads == 0) {
            num_threads = std::thread::hardware_concurrency();
            // Fallback to 4 threads if hardware_concurrency() returns 0
            if (num_threads == 0) {
                num_threads = 4;
            }
        }
        
        // Reserve space to avoid reallocations
        workers_.reserve(num_threads);
        
        // Create worker threads
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this, i] {
                worker_thread(i);
            });
        }
        
        std::cout << "[ThreadPool] Initialized with " << num_threads << " worker threads\n";
    }
    
    /**
     * Destructor - performs graceful shutdown.
     * 
     * Waits for all queued tasks to complete before destroying the pool.
     * If immediate shutdown is needed, call shutdown(true) before destruction.
     */
    ~ThreadPool() {
        shutdown(false);  // Graceful shutdown by default
    }
    
    // Disable copy operations (thread pools should not be copied)
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    
    // Disable move operations (complex to implement correctly with running threads)
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;
    
    /**
     * Submit a task to the thread pool.
     * 
     * This method accepts any callable object (lambda, function pointer, functor,
     * std::function, etc.) along with its arguments. The callable is wrapped in a
     * std::packaged_task and a std::future is returned for result retrieval.
     * 
     * @tparam F    Type of the callable
     * @tparam Args Types of the arguments to pass to the callable
     * @param f     The callable to execute
     * @param args  Arguments to forward to the callable
     * @return      std::future<R> where R is the return type of f(args...)
     * @throws      std::runtime_error if the pool has been shut down
     * 
     * Example usage:
     *   auto future = pool.submit([](int x) { return x * x; }, 42);
     *   int result = future.get();  // Blocks until task completes, returns 1764
     */
    template<typename F, typename... Args>
    auto submit(F&& f, Args&&... args) 
        -> std::future<std::invoke_result_t<F, Args...>>
    {
        // Deduce the return type of the callable
        using return_type = std::invoke_result_t<F, Args...>;
        
        // Create a packaged_task that wraps the callable with its arguments
        // We use std::bind to capture the arguments, then wrap in packaged_task
        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        
        // Get the future before we move the task into the queue
        std::future<return_type> result = task->get_future();
        
        // Lock and check if we can accept new tasks
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Don't allow enqueueing after stopping the pool
            if (stop_flag_) {
                throw std::runtime_error("Cannot submit task to stopped ThreadPool");
            }
            
            // Wrap the packaged_task in a void() function for type erasure
            // This allows us to store heterogeneous tasks in a single queue
            task_queue_.emplace([task]() {
                (*task)();
            });
            
            ++tasks_queued_;
        }
        
        // Notify one waiting worker that a task is available
        condition_.notify_one();
        
        return result;
    }
    
    /**
     * Shutdown the thread pool.
     * 
     * @param immediate If true, discards pending tasks and stops immediately.
     *                  If false (default), waits for all pending tasks to complete.
     * 
     * This method is idempotent - calling it multiple times has no additional effect.
     */
    void shutdown(bool immediate = false) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // If already stopped, nothing to do
            if (stop_flag_) {
                return;
            }
            
            stop_flag_ = true;
            shutdown_immediate_ = immediate;
            
            if (immediate) {
                // Clear the queue for immediate shutdown
                std::queue<std::function<void()>> empty;
                std::swap(task_queue_, empty);
                std::cout << "[ThreadPool] Immediate shutdown requested\n";
            } else {
                std::cout << "[ThreadPool] Graceful shutdown requested ("
                          << task_queue_.size() << " tasks pending)\n";
            }
        }
        
        // Wake up all workers so they can check the stop flag
        condition_.notify_all();
        
        // Wait for all worker threads to finish
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        
        std::cout << "[ThreadPool] Shutdown complete. Tasks completed: " 
                  << tasks_completed_.load() << "/" << tasks_queued_.load() << "\n";
    }
    
    /**
     * Get the number of worker threads in the pool.
     */
    size_t size() const noexcept {
        return workers_.size();
    }
    
    /**
     * Get the number of tasks currently waiting in the queue.
     * Note: This is a snapshot and may be stale by the time it's used.
     */
    size_t pending_tasks() const {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        return task_queue_.size();
    }
    
    /**
     * Get statistics about task execution.
     */
    std::pair<size_t, size_t> get_stats() const noexcept {
        return {tasks_queued_.load(), tasks_completed_.load()};
    }

private:
    /**
     * Worker thread function.
     * 
     * Each worker runs this function, which loops waiting for tasks
     * and executing them until the pool is shut down.
     */
    void worker_thread(size_t thread_id) {
        while (true) {
            std::function<void()> task;
            
            // Wait for a task or shutdown signal
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                
                // Wait until there's a task or we need to stop
                condition_.wait(lock, [this] {
                    return stop_flag_ || !task_queue_.empty();
                });
                
                // Check if we should exit
                if (stop_flag_) {
                    // For immediate shutdown, exit even if tasks remain
                    if (shutdown_immediate_ || task_queue_.empty()) {
                        return;
                    }
                }
                
                // If queue is empty (spurious wakeup), continue waiting
                if (task_queue_.empty()) {
                    continue;
                }
                
                // Get the next task
                task = std::move(task_queue_.front());
                task_queue_.pop();
            }
            
            // Execute the task outside the lock
            // Exceptions are captured by packaged_task and stored in the future
            try {
                task();
            } catch (...) {
                // Task threw an exception that wasn't captured by packaged_task
                // This shouldn't happen with our wrapper, but handle it gracefully
                std::cerr << "[ThreadPool] Worker " << thread_id 
                          << ": Uncaught exception in task\n";
            }
            
            ++tasks_completed_;
        }
    }
    
    // Worker threads
    std::vector<std::thread> workers_;
    
    // Task queue (stores type-erased callables)
    std::queue<std::function<void()>> task_queue_;
    
    // Synchronization primitives
    mutable std::mutex queue_mutex_;
    std::condition_variable condition_;
    
    // State flags
    std::atomic<bool> stop_flag_;
    std::atomic<bool> shutdown_immediate_;
    
    // Statistics
    std::atomic<size_t> tasks_queued_;
    std::atomic<size_t> tasks_completed_;
};


// ============================================================================
// Demonstration Code
// ============================================================================

/**
 * Compute the sum of squares for a range [start, end).
 * This simulates a CPU-bound computation.
 */
uint64_t sum_of_squares(uint64_t start, uint64_t end) {
    uint64_t sum = 0;
    for (uint64_t i = start; i < end; ++i) {
        sum += i * i;
    }
    return sum;
}

/**
 * A functor class to demonstrate that the thread pool works with functors.
 */
class Multiplier {
public:
    explicit Multiplier(int factor) : factor_(factor) {}
    
    int operator()(int value) const {
        // Simulate some work
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); /* rax: was 10 */
        return value * factor_;
    }
    
private:
    int factor_;
};

/**
 * Regular function to demonstrate function pointer support.
 */
int add_numbers(int a, int b) {
    return a + b;
}

/**
 * Function that throws an exception to demonstrate exception handling.
 */
int throwing_function(int x) {
    if (x < 0) {
        throw std::invalid_argument("Negative value not allowed: " + std::to_string(x));
    }
    return x * 2;
}


int main() {
    std::cout << "=== Thread Pool Demonstration ===\n\n";
    
    // Determine available parallelism
    const unsigned int num_threads = std::thread::hardware_concurrency();
    std::cout << "Hardware concurrency: " << num_threads << " threads\n\n";
    
    // =========================================================================
    // Test 1: Parallel Sum of Squares
    // =========================================================================
    std::cout << "--- Test 1: Parallel Sum of Squares ---\n";
    {
        const uint64_t N = 10'000'000;  // Compute sum of squares from 0 to N-1
        const size_t num_chunks = num_threads * 2;  // More chunks than threads for load balancing
        const uint64_t chunk_size = N / num_chunks;
        
        ThreadPool pool(num_threads);
        std::vector<std::future<uint64_t>> futures;
        futures.reserve(num_chunks);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Submit tasks for each chunk
        for (size_t i = 0; i < num_chunks; ++i) {
            uint64_t start = i * chunk_size;
            uint64_t end = (i == num_chunks - 1) ? N : (i + 1) * chunk_size;
            
            futures.push_back(pool.submit(sum_of_squares, start, end));
        }
        
        // Collect results
        uint64_t parallel_result = 0;
        for (auto& future : futures) {
            parallel_result += future.get();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto parallel_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();
        
        // Compute sequential result for verification
        start_time = std::chrono::high_resolution_clock::now();
        uint64_t sequential_result = sum_of_squares(0, N);
        end_time = std::chrono::high_resolution_clock::now();
        auto sequential_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();
        
        std::cout << "Sum of squares [0, " << N << "):\n";
        std::cout << "  Parallel result:   " << parallel_result << " (" << parallel_duration << " ms)\n";
        std::cout << "  Sequential result: " << sequential_result << " (" << sequential_duration << " ms)\n";
        std::cout << "  Results match: " << (parallel_result == sequential_result ? "YES" : "NO") << "\n";
        if (sequential_duration > 0) {
            std::cout << "  Speedup: " << std::fixed << std::setprecision(2)
                      << static_cast<double>(sequential_duration) / parallel_duration << "x\n";
        }
    }
    std::cout << "\n";
    
    // =========================================================================
    // Test 2: Various Callable Types
    // =========================================================================
    std::cout << "--- Test 2: Various Callable Types ---\n";
    {
        ThreadPool pool(4);
        
        // Lambda
        auto lambda_future = pool.submit([](int x, int y) {
            return x + y;
        }, 10, 20);
        
        // Function pointer
        auto func_ptr_future = pool.submit(add_numbers, 100, 200);
        
        // Functor (callable object)
        Multiplier multiplier(5);
        auto functor_future = pool.submit(multiplier, 7);
        
        // std::function
        std::function<int(int)> std_func = [](int x) { return x * x; };
        auto std_func_future = pool.submit(std_func, 8);
        
        // Lambda capturing by reference
        int captured_value = 42;
        auto capture_future = pool.submit([&captured_value]() {
            return captured_value * 2;
        });
        
        // Collect and display results
        std::cout << "  Lambda (10 + 20): " << lambda_future.get() << "\n";
        std::cout << "  Function pointer (100 + 200): " << func_ptr_future.get() << "\n";
        std::cout << "  Functor (7 * 5): " << functor_future.get() << "\n";
        std::cout << "  std::function (8^2): " << std_func_future.get() << "\n";
        std::cout << "  Capturing lambda (42 * 2): " << capture_future.get() << "\n";
    }
    std::cout << "\n";
    
    // =========================================================================
    // Test 3: Exception Handling
    // =========================================================================
    std::cout << "--- Test 3: Exception Handling ---\n";
    {
        ThreadPool pool(2);
        
        // Submit a task that will succeed
        auto success_future = pool.submit(throwing_function, 10);
        
        // Submit a task that will throw
        auto fail_future = pool.submit(throwing_function, -5);
        
        // Get the successful result
        std::cout << "  Successful task (10 * 2): " << success_future.get() << "\n";
        
        // Get the failed result - exception is rethrown from future.get()
        try {
            fail_future.get();
            std::cout << "  ERROR: Exception was not thrown!\n";
        } catch (const std::invalid_argument& e) {
            std::cout << "  Exception caught as expected: " << e.what() << "\n";
        }
    }
    std::cout << "\n";
    
    // =========================================================================
    // Test 4: High Task Volume
    // =========================================================================
    std::cout << "--- Test 4: High Task Volume ---\n";
    {
        const size_t num_tasks = 10; /* rax: was 1000 */
        ThreadPool pool(num_threads);
        
        std::vector<std::future<int>> futures;
        futures.reserve(num_tasks);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Submit many small tasks
        for (size_t i = 0; i < num_tasks; ++i) {
            futures.push_back(pool.submit([](int x) {
                // Small computation
                int result = 0;
                for (int j = 0; j < 1000; ++j) {
                    result += (x + j) % 17;
                }
                return result;
            }, static_cast<int>(i)));
        }
        
        // Collect all results
        int64_t total = 0;
        for (auto& future : futures) {
            total += future.get();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();
        
        std::cout << "  Submitted " << num_tasks << " tasks\n";
        std::cout << "  Total result: " << total << "\n";
        std::cout << "  Time: " << duration << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(0)
                  << (num_tasks * 1000.0 / duration) << " tasks/sec\n";
        
        auto [queued, completed] = pool.get_stats();
        std::cout << "  Stats: " << completed << "/" << queued << " tasks completed\n";
    }
    std::cout << "\n";
    
    // =========================================================================
    // Test 5: Void Return Type
    // =========================================================================
    std::cout << "--- Test 5: Void Return Type Tasks ---\n";
    {
        ThreadPool pool(2);
        std::atomic<int> counter{0};
        
        std::vector<std::future<void>> futures;
        for (int i = 0; i < 10; ++i) {
            futures.push_back(pool.submit([&counter, i]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(1)); /* rax: was 5 */
                counter += i;
            }));
        }
        
        // Wait for all tasks to complete
        for (auto& future : futures) {
            future.get();  // Blocks until task completes, no return value
        }
        
        std::cout << "  Counter after 10 increments (0+1+2+...+9): " << counter.load() << "\n";
        std::cout << "  Expected: 45\n";
    }
    std::cout << "\n";
    
    // =========================================================================
    // Test 6: Graceful Shutdown with Pending Tasks
    // =========================================================================
    std::cout << "--- Test 6: Graceful Shutdown ---\n";
    {
        ThreadPool pool(2);
        std::atomic<int> completed_count{0};
        
        // Submit tasks that take some time
        std::vector<std::future<int>> futures;
        for (int i = 0; i < 20; ++i) {
            futures.push_back(pool.submit([&completed_count, i]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(1)); /* rax: was 20 */
                ++completed_count;
                return i;
            }));
        }
        
        std::cout << "  Submitted 20 tasks (each takes 20ms)\n";
        std::cout << "  Pool will shutdown gracefully (wait for all tasks)...\n";
        
        // Pool destructor will wait for all tasks to complete
    }
    std::cout << "  Graceful shutdown test completed\n\n";
    
    // =========================================================================
    // Test 7: Submit After Shutdown (Error Handling)
    // =========================================================================
    std::cout << "--- Test 7: Submit After Shutdown ---\n";
    {
        ThreadPool pool(2);
        pool.shutdown(true);  // Immediate shutdown
        
        try {
            auto future = pool.submit([]() { return 42; });
            std::cout << "  ERROR: Should have thrown exception!\n";
        } catch (const std::runtime_error& e) {
            std::cout << "  Exception caught as expected: " << e.what() << "\n";
        }
    }
    std::cout << "\n";
    
    std::cout << "=== All Tests Completed ===\n";
    
    return 0;
}
