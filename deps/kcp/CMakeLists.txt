cmake_minimum_required(VERSION 2.8.8)

project(kcp)

add_library(kcp STATIC ikcp.c ikcp.h)

add_executable(kcp_test test.cpp test.h)
target_link_libraries(kcp_test kcp)