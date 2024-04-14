cmake_minimum_required(VERSION 3.21)
project(vAlerain_Ark)

set(CMAKE_CXX_STANDARD 14)

# 添加头文件目录
include_directories(Header-file)
include_directories(Header-file/sys)

# 添加可执行文件目标
add_executable(my_target
        Preview-version/1.0.0.1/main.cpp)


