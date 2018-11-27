cmake_minimum_required(VERSION 2.8)
project(sm2)

set(CMAKE_VERBOSE_MAKEFILE on )

add_compile_options(-std=c99 -Wall)

include_directories(include)
add_subdirectory(src)
add_executable(sm2 src/sm2.c)


target_link_libraries(sm2 sm2lib ssl crypto)