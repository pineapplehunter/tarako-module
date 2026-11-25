cmake_minimum_required(VERSION 4.0)
project(tarako-tls-client VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET libtarako libnghttp2)

foreach(binary IN ITEMS tarako-tls-client tarako-tdx-client)
  add_executable(${binary} main.c)
  target_link_libraries(${binary} PRIVATE PkgConfig::DEPS)
  install(TARGETS ${binary} RUNTIME DESTINATION bin)
endforeach()
target_compile_definitions(tarako-tdx-client PRIVATE TARAKO_TDX)
