cmake_minimum_required(VERSION 3.20)
project(rax_local_settings_controls LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Local Settings controls require native Windows and MSVC")
endif()
add_executable(local_settings_native "probe-v1.c")
set_target_properties(local_settings_native PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_definitions(local_settings_native PRIVATE _WIN32_WINNT=0x0601)
target_compile_options(local_settings_native PRIVATE /W4 /WX)
target_link_libraries(local_settings_native PRIVATE ntdll kernel32 advapi32 crypt32)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:local_settings_native>\n")
