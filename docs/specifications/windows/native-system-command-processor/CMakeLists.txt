cmake_minimum_required(VERSION 3.20)
project(rax_system_command_processor_controls LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "The System Command Processor controls require native Windows and MSVC")
endif()
foreach(kind IN ITEMS system system-relative system-parent system-parent-relative system-parent-graph)
    add_executable(cmd_${kind} "${kind}-v1.c")
    set_target_properties(cmd_${kind} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES
        MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_compile_options(cmd_${kind} PRIVATE /W4 /WX)
    target_link_libraries(cmd_${kind} PRIVATE ntdll kernel32 advapi32)
endforeach()
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:cmd_system>\n$<TARGET_FILE:cmd_system-relative>\n$<TARGET_FILE:cmd_system-parent>\n$<TARGET_FILE:cmd_system-parent-relative>\n$<TARGET_FILE:cmd_system-parent-graph>\n")
