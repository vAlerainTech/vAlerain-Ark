cmake_minimum_required(VERSION 3.21)
project(vAlerain_Ark)

set(CMAKE_CXX_STANDARD 14)

# 添加头文件目录
include_directories(Header-file)
include_directories(Header-file/sys)

#解决兼容方法
set(CMAKE_EXE_LINKER_FLAGS -static)

# 添加可执行文件目标
add_executable(main
        Source-code/debug/main.cpp
        cmake-build-debug/ico.o
)
