cmake_minimum_required(VERSION 3.8)
project(PA3)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        include/author.h
        include/connection_manager.h
        include/control_handler.h
        include/control_header_lib.h
        include/global.h
        include/network_util.h
        src/author.c
        src/connection_manager.c
        src/control_handler.c
        src/control_header_lib.c
        src/network_util.c
        src/vijayaha_assignment3.c)

add_executable(PA3 ${SOURCE_FILES})