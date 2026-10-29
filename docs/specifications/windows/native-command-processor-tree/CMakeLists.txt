cmake_minimum_required(VERSION 3.20)
project(rax_command_processor_tree_controls LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "The Command Processor controls require native Windows and MSVC")
endif()
add_executable(cmd_tree tree-v1.c)
set_target_properties(cmd_tree PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES
    MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_options(cmd_tree PRIVATE /W4 /WX)
target_link_libraries(cmd_tree PRIVATE ntdll kernel32 advapi32)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:cmd_tree>\n")
