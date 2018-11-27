cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/include)
aux_source_directory(. DIRSRCS)

add_library(sm2lib SHARED ${DIRSRCS})