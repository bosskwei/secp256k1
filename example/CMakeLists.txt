# Minimal version of CMake
cmake_minimum_required (VERSION 3.7)

# Flags
set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_COMPILER /usr/bin/clang++-6.0)

# set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_BUILD_TYPE Release)
 
# Define project name
project (OpenCL_Example)

#
find_package(Threads)
find_package(OpenCL REQUIRED)

#
include_directories(${OPENCL_INCLUDE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

# Set up executable
add_executable (deqp-vk src/main.cpp)
target_link_libraries(deqp-vk ${CMAKE_THREAD_LIBS_INIT} ${OpenCL_LIBRARY})
