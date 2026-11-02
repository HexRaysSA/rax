cmake_minimum_required(VERSION 3.20)
project(rax_invalid_key_class_control LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Native Windows and MSVC are required")
endif()
add_executable(nls_key_query_probe probe-v1.c)
set_target_properties(nls_key_query_probe PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES
    MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_options(nls_key_query_probe PRIVATE /W4 /WX /GS- /Zl /Oi)
target_link_options(nls_key_query_probe PRIVATE /NODEFAULTLIB /ENTRY:entry)
target_link_libraries(nls_key_query_probe PRIVATE kernel32)
file(GENERATE OUTPUT "probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:nls_key_query_probe>\n")
