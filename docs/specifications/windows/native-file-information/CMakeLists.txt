cmake_minimum_required(VERSION 3.20)
project(rax_native_file_information_control LANGUAGES C)
if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "Native controls require a Windows/MSVC-compatible target")
endif()
set(CMAKE_C_STANDARD_LIBRARIES "")
add_executable(file_information_profile profile-v1.c)
set_target_properties(file_information_profile PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED YES MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_options(file_information_profile PRIVATE /O2 /W4 /WX /GS- /Zl)
target_link_options(file_information_profile PRIVATE
  /nodefaultlib /entry:entry /subsystem:console)
target_link_libraries(file_information_profile PRIVATE kernel32)

add_executable(file_information_faults faults-v1.c)
set_target_properties(file_information_faults PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED YES MSVC_RUNTIME_LIBRARY MultiThreaded)
target_compile_options(file_information_faults PRIVATE /O2 /W4 /WX /GS- /Zl)
target_link_options(file_information_faults PRIVATE
  /nodefaultlib /entry:entry /subsystem:console)
target_link_libraries(file_information_faults PRIVATE kernel32)
