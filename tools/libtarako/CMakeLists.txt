cmake_minimum_required(VERSION 4.0)
project(libtarako VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

include(GNUInstallDirs)
find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET openssl libcurl json-c)

add_library(tarako STATIC tarako.c evidence.c early_tls.c tdx_quote.c)
set_target_properties(tarako PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(tarako PUBLIC PkgConfig::DEPS)

configure_file(libtarako.pc.in libtarako.pc @ONLY)
install(TARGETS tarako ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES tarako.h evidence.h early_tls.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tarako)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libtarako.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
