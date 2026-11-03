cmake_minimum_required(VERSION 3.20)
project(rax_native_system_policy LANGUAGES CXX)
if(NOT WIN32)
  message(FATAL_ERROR "These independent native probes require Windows")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
foreach(probe IN ITEMS abi pointer)
  add_executable(native-system-policy-${probe}
    native-policy-${probe}-v1.cpp entry-shim.cpp)
  target_compile_definitions(native-system-policy-${probe} PRIVATE UNICODE _UNICODE)
  target_link_libraries(native-system-policy-${probe} PRIVATE kernel32)
  if(MSVC)
    target_compile_options(native-system-policy-${probe} PRIVATE /W4 /GS-)
  endif()
endforeach()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
foreach(mode IN ITEMS response input)
  set(generated "${CMAKE_CURRENT_BINARY_DIR}/native-cipher-${mode}-generated.cpp")
  add_custom_command(OUTPUT "${generated}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/generate-cipher-probe.py"
      "${mode}" --output "${generated}"
    DEPENDS generate-cipher-probe.py "cipher-${mode}-v1.cpp.in"
      "cipher-${mode}-requests-v1.json" probe-source-bindings-v1.json
    VERBATIM)
  add_executable(native-system-policy-cipher-${mode} "${generated}")
  target_link_libraries(native-system-policy-cipher-${mode} PRIVATE kernel32 advapi32)
endforeach()
