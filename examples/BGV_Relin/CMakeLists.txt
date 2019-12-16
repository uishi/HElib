cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

## Use -std=c++11 as default.
set(CMAKE_CXX_STANDARD 11)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug)

project(BGV_general_example
       	LANGUAGES CXX)

find_package(helib 1.0.0 EXACT REQUIRED)

add_executable(relin relin.cpp)

target_link_libraries(relin helib)

