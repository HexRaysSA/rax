cmake_minimum_required(VERSION 3.20)
project(rax_command_processor_controls LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "The Command Processor controls require native Windows and MSVC")
endif()
foreach(kind IN ITEMS absolute relative family physical graph physical-relative)
    add_executable(cmd_${kind} "${kind}-v1.c")
    set_target_properties(cmd_${kind} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES
        MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_compile_options(cmd_${kind} PRIVATE /W4 /WX)
    target_link_libraries(cmd_${kind} PRIVATE ntdll kernel32 advapi32)
endforeach()
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:cmd_absolute>\n$<TARGET_FILE:cmd_relative>\n$<TARGET_FILE:cmd_family>\n$<TARGET_FILE:cmd_physical>\n$<TARGET_FILE:cmd_graph>\n$<TARGET_FILE:cmd_physical-relative>\n")
