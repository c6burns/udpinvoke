cmake_minimum_required(VERSION 3.02)
project(udp_in_ur_cornflakes LANGUAGES C CXX)
set(UDP_LINK_LIBS "")

if (NOT WIN32)
	set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -fPIC")
	set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -pie")
endif()


#
# argparse dependency
include_directories(${CMAKE_SOURCE_DIR}/deps/argparse)
add_subdirectory(${CMAKE_SOURCE_DIR}/deps/argparse)
list(APPEND UDP_LINK_LIBS argparse)


#
# libuv dependencyudp
set(BUILD_TESTING OFF)
include_directories(${CMAKE_SOURCE_DIR}/deps/libuv/include)
add_subdirectory(${CMAKE_SOURCE_DIR}/deps/libuv)
list(APPEND UDP_LINK_LIBS uv_a)


#
# aws-c-common dependency
include_directories(${CMAKE_SOURCE_DIR}/deps/aws-c-common/include)
include_directories(${CMAKE_BINARY_DIR}/deps/aws-c-common/generated/include)
add_subdirectory(${CMAKE_SOURCE_DIR}/deps/aws-c-common)
list(APPEND UDP_LINK_LIBS aws-c-common)


#
# build udp_in_ur_cornflakes library
include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
set(UDP_LIBRARY_SRCS
	src/log.c
	include/udp/log.h
	src/bufferpool.c
	include/udp/bufferpool.h
	src/endpoint.c
	include/udp/endpoint.h
	src/uuid.c
	include/udp/uuid.h
	src/allocator.c
	include/udp/allocator.h
	src/thread.c
	include/udp/thread.h
	src/udp_connection.c
	include/udp/udp_connection.h
	src/udp_context.c
	include/udp/udp_context.h
	include/udp/error.h
)
add_library(udp_in_ur_cornflakes ${UDP_LIBRARY_SRCS})
target_link_libraries(udp_in_ur_cornflakes ${UDP_LINK_LIBS})
list(APPEND UDP_LINK_LIBS udp_in_ur_cornflakes)



#
# build test executables
# TODO: make a cache variable to turn tests on/off
add_executable(udp_test tests/test.c)
target_link_libraries(udp_test ${UDP_LINK_LIBS})



#
# build tcploadgen executable
set(UDP_LOADGEN_SRCS
	src/udplg/udplg.c
	include/udplg/cmdargs.h
)
#add_executable(udplg ${UDP_LOADGEN_SRCS})
#target_link_libraries(udplg ${UDP_LINK_LIBS})


#
# build tcpserver executable
set(UDP_SERVER_SRCS
	src/udpserv/udpserv.c
	include/udpserv/udpserv.h
)
add_executable(udpserv ${UDP_SERVER_SRCS})
target_link_libraries(udpserv ${UDP_LINK_LIBS})


#
# build unity plugin
include_directories(${CMAKE_SOURCE_DIR}/deps/unity)
set(UDP_PLUGIN_SRCS
	src/unity/udp_unity.c
)
add_library(udp_unity SHARED ${UDP_PLUGIN_SRCS})
target_link_libraries(udp_unity ${UDP_LINK_LIBS})
add_custom_command(
    TARGET udp_unity 
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:udp_unity>
        ${CMAKE_SOURCE_DIR}/UnityProject/Assets/Plugins/x86_64/$<TARGET_FILE_NAME:udp_unity>
)
