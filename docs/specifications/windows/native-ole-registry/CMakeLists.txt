cmake_minimum_required(VERSION 3.20)
project(rax_ole_registry_controls LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "The OLE registry controls require native Windows and MSVC")
endif()
foreach(kind IN ITEMS absolute missing relative tree)
    add_executable(ole_${kind} "${kind}-v1.c")
    set_target_properties(ole_${kind} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES
        MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_compile_options(ole_${kind} PRIVATE /W4 /WX)
    target_link_libraries(ole_${kind} PRIVATE ntdll kernel32 advapi32)
endforeach()
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:ole_absolute>\n$<TARGET_FILE:ole_missing>\n$<TARGET_FILE:ole_relative>\n$<TARGET_FILE:ole_tree>\n")
