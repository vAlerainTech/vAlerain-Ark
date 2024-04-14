cmake_minimum_required(VERSION 3.27)
project(vAlerain_Ark)

set(CMAKE_CXX_STANDARD 14)

include_directories(Header-file)
include_directories(Header-file/sys)

add_executable(vAlerain_Ark
        Header-file/sys/cdefs.h
        Header-file/sys/fcntl.h
        Header-file/sys/file.h
        Header-file/sys/locking.h
        Header-file/sys/param.h
        Header-file/sys/stat.h
        Header-file/sys/time.h
        Header-file/sys/timeb.h
        Header-file/sys/types.h
        Header-file/sys/unistd.h
        Header-file/sys/utime.h
        Header-file/DataVault.h
        Preview-version/main.cpp
        Source-code/1.0.0.0/main.cpp
        Source-code/1.0.0.1/main.cpp
        Source-code/1.0.0.2/main.cpp
        Preview-version/1.0.0.1/main.cpp
        Preview-version/1.0.0.1/main.cpp)
