cmake_minimum_required(VERSION 4.0)
project(tarako-tls-attester VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

# Select archive dependencies and include their private link flags.
set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
add_link_options(-static)
find_package(PkgConfig REQUIRED)
list(APPEND PKG_CONFIG_ARGN --static)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET libtarako libnghttp2)

foreach(binary IN ITEMS tarako-tls-attester tarako-tls-attester-test tarako-tdx-attester)
  add_executable(${binary} main.c)
  target_link_libraries(${binary} PRIVATE PkgConfig::DEPS)
  install(TARGETS ${binary} RUNTIME DESTINATION bin)
endforeach()
target_compile_definitions(tarako-tls-attester-test PRIVATE TARAKO_TEST)
target_compile_definitions(tarako-tdx-attester PRIVATE TARAKO_TDX)
