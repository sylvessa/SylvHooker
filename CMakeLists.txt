cmake_minimum_required(VERSION 3.5)
project(SylvHooker)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_library(SylvHooker STATIC src/SylvHooker.cpp)

target_include_directories(SylvHooker PUBLIC include)
