cmake_minimum_required(VERSION 3.10)
project(async_netconf_client C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(ancc async_netconf_client.c)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSSH REQUIRED libssh)
pkg_check_modules(LIBUV REQUIRED libuv)

include_directories(
    ${LIBSSH_INCLUDE_DIRS}
    ${LIBUV_INCLUDE_DIRS}
)

target_link_libraries(ancc
    ${LIBSSH_LIBRARIES}
    ${LIBUV_LIBRARIES}
)

target_compile_options(ancc PRIVATE
    ${LIBSSH_CFLAGS_OTHER}
    ${LIBUV_CFLAGS_OTHER}
)
