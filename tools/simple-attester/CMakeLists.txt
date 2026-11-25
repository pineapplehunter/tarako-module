cmake_minimum_required(VERSION 4.0)
project(tarako-simple-attester VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

# Select archive dependencies and include their private link flags.
set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
add_link_options(-static)
find_package(PkgConfig REQUIRED)
list(APPEND PKG_CONFIG_ARGN --static)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET libtarako libevent)

add_executable(tarako-simple-attester main.c)
target_link_libraries(tarako-simple-attester PRIVATE PkgConfig::DEPS)
install(TARGETS tarako-simple-attester RUNTIME DESTINATION bin)
