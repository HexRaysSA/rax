cmake_minimum_required(VERSION 3.20)
project(rax_native_file_state_set_control LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "Native controls require a Windows/MSVC-compatible target")
endif()
set(CMAKE_C_STANDARD_LIBRARIES "")
add_executable(file_state_scalars scalars-v1.c)
set_target_properties(file_state_scalars PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED YES MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_options(file_state_scalars PRIVATE /O2 /W4 /WX /GS- /Zl)
target_link_options(file_state_scalars PRIVATE /nodefaultlib /entry:entry /subsystem:console)
target_link_libraries(file_state_scalars PRIVATE kernel32)

add_executable(file_state_faults faults-v1.c)
set_target_properties(file_state_faults PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED YES MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_options(file_state_faults PRIVATE /O2 /W4 /WX /GS- /Zl)
target_link_options(file_state_faults PRIVATE /nodefaultlib /entry:entry /subsystem:console)
target_link_libraries(file_state_faults PRIVATE kernel32)
