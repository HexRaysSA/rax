cmake_minimum_required(VERSION 3.20)
project(rax_machine_hive_controls LANGUAGES C)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "The MACHINE-root controls require native Windows and MSVC")
endif()

foreach(kind IN ITEMS absolute relative)
    if(kind STREQUAL "absolute")
        set(source probe-v1.c)
    else()
        set(source probe-relative-v1.c)
    endif()
    add_executable(machine_${kind} "${source}")
    set_target_properties(machine_${kind} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES
        MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_compile_options(machine_${kind} PRIVATE /W4 /WX)
    target_link_libraries(machine_${kind} PRIVATE ntdll kernel32)
endforeach()

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:machine_absolute>\n$<TARGET_FILE:machine_relative>\n")
