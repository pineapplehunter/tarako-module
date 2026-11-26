cmake_minimum_required(VERSION 4.0)
project(tarako-tdx-client VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET libtarako libnghttp2)

add_executable(tarako-tdx-client main.c)
target_link_libraries(tarako-tdx-client PRIVATE PkgConfig::DEPS)
install(TARGETS tarako-tdx-client RUNTIME DESTINATION bin)
