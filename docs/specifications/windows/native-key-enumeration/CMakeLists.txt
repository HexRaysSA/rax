cmake_minimum_required(VERSION 3.20)
project(rax_key_enumeration_controls LANGUAGES C)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "The key-enumeration controls require native Windows and MSVC")
endif()

foreach(kind IN ITEMS probe fault)
    add_executable(enumeration_${kind} "${kind}-v1.c")
    set_target_properties(enumeration_${kind} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES
        MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_compile_options(enumeration_${kind} PRIVATE /W4 /WX)
    target_link_libraries(enumeration_${kind} PRIVATE ntdll kernel32 advapi32)
endforeach()

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:enumeration_probe>\n$<TARGET_FILE:enumeration_fault>\n")
