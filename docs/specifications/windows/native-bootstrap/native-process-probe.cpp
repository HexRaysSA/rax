#include <assist/emulation/rax/rax_process.hpp>
#include <fstream>
#include <cstdio>
using namespace assist::emulation::rax;
int main() {
    RaxApi api{}; api.version=&rax_version; api.strerror=&rax_strerror;
    api.process_open_image=&rax_process_open_image; api.process_close=&rax_process_close;
    api.process_run=&rax_process_run; api.process_set_cancelled=&rax_process_set_cancelled;
    api.process_info_json=&rax_process_info_json; api.process_last_error=&rax_process_last_error;
    api.process_mem_read=&rax_process_mem_read; api.process_mem_write=&rax_process_mem_write;
    api.process_context_read=&rax_process_context_read; api.process_context_write=&rax_process_context_write;
    api.process_stdin_feed=&rax_process_stdin_feed; api.process_output_read=&rax_process_output_read;
    for (const char* path : {
      "C:/Windows/Temp/assist-native-rax-20261010/src/tests/fixtures/user/windows/bin/arm64/smoke.exe",
      "C:/Windows/Temp/assist-native-rax-20261010/src/tests/fixtures/user/windows/crt_stdio/bin/arm64/msvcrt/streams.exe",
      "C:/Windows/Temp/assist-native-rax-20261010/src/tests/fixtures/user/windows/crt_stdio/bin/arm64/ucrtbase/streams.exe",
      "C:/Windows/System32/whoami.exe"}) {
        std::printf("program %s\n",path);
        try {
            std::ifstream input(path,std::ios::binary);
            if (!input) throw std::runtime_error("probe input missing");
            std::vector<std::uint8_t> image(std::istreambuf_iterator<char>(input),{});
            RaxProcess process(&api,image,{{"native_runtime",true},{"guest_path","C:\\app\\probe.exe"},{"memory_bytes",268435456},{"slice_instructions",4096}});
            auto before=process.info();std::printf("opened modules=%zu\n",before["modules"].size());
            auto run=process.run(1000000,5000);auto state=process.info();
            std::printf("run reason=%u exit=%u diagnostic=%s\n",run.reason,run.exit_code,state.value("diagnostic",nlohmann::json()).dump().c_str());
            std::printf("threads=%s\nmodules=%s\n",state["threads"].dump().c_str(),state["modules"].dump().c_str());
        } catch (const std::exception& e) { std::printf("refused %s\n",e.what()); }
    }
}
