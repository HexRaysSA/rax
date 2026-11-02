cmake_minimum_required(VERSION 3.20)
project(rax_native_query_multiple_values C)
if(NOT WIN32)
    message(FATAL_ERROR "Native query controls require Windows")
endif()
add_executable(rax_native_query_multiple_values probe-v1.c)
set_target_properties(rax_native_query_multiple_values PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(rax_native_query_multiple_values PRIVATE advapi32 psapi)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/probe-paths-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:rax_native_query_multiple_values>\n")
