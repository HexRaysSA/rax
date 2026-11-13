cmake_minimum_required(VERSION 3.20)
project(rax_instruction_cache_controls LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Instruction-cache controls require native Windows and MSVC")
endif()
add_executable(native_instruction_cache native-oracle-v2.c)
set_target_properties(native_instruction_cache PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES
    MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_options(native_instruction_cache PRIVATE /W4 /WX)
target_link_libraries(native_instruction_cache PRIVATE kernel32)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-path-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:native_instruction_cache>\n")
