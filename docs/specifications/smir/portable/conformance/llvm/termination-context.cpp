/* Controlled native-host oracle. Source compiler/runtime recorded separately. */
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <cstring>

struct Cause {};
struct CopyFailure {};
struct CopySource {
    CopySource() = default;
    CopySource(const CopySource&) { throw CopyFailure{}; }
};
static const char* selected;
[[noreturn]] static void report(int exit_code) noexcept {
    const int count = std::uncaught_exceptions();
    const std::exception_ptr owner = std::current_exception();
    int kind = 0;
    if (owner) {
        try { std::rethrow_exception(owner); }
        catch (const Cause&) { kind = 1; }
        catch (const CopyFailure&) { kind = 2; }
        catch (const CopySource&) { kind = 3; }
        catch (...) { kind = 4; }
    }
    std::printf("case=%s uncaught=%d current=%d kind=%d\n", selected, count,
                static_cast<bool>(owner), kind);
    std::fflush(stdout);
    std::_Exit(exit_code);
}
[[noreturn]] static void handler() noexcept { report(73); }
[[noreturn]] static void other_handler() noexcept { report(74); }
[[noreturn]] static void no_throw() noexcept { throw Cause{}; }
[[noreturn]] static void dynamic_rethrow() { throw; }
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    selected = argv[1];
    std::set_terminate(handler);
    if (std::strcmp(selected, "terminate_in_catch") == 0) {
        try { throw Cause{}; }
        catch (...) { std::set_terminate(other_handler); std::terminate(); }
    }
    if (std::strcmp(selected, "bare_rethrow_after_change") == 0) {
        try { throw Cause{}; }
        catch (...) {
            std::set_terminate(other_handler);
            try { dynamic_rethrow(); }
            catch (...) { std::terminate(); }
        }
    }
    if (std::strcmp(selected, "owner_rethrow_after_change") == 0) {
        try { throw Cause{}; }
        catch (...) {
            auto owner = std::current_exception();
            std::set_terminate(other_handler);
            try { std::rethrow_exception(owner); }
            catch (...) { std::terminate(); }
        }
    }
    if (std::strcmp(selected, "rethrow_empty") == 0) dynamic_rethrow();
    if (std::strcmp(selected, "unhandled") == 0) throw Cause{};
    if (std::strcmp(selected, "noexcept") == 0) no_throw();
    if (std::strcmp(selected, "catch_copy") == 0) {
        try { throw CopySource{}; }
        catch (CopySource copied) { (void)copied; }
    }
    return 3;
}
