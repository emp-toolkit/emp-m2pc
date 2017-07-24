cmake_minimum_required (VERSION 2.8.11)
project (emp-m2pc)

if(POLICY CMP0042)
  cmake_policy(SET CMP0042 NEW) # use rpath on macOS
endif()

include_directories(${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} cmake/)
set(CMAKE_C_FLAGS "-pthread -Wall -march=native -O3 -maes")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++0x")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

macro (add_test _name)
	add_executable(${_name} "test/${_name}.cpp" ${sources})
	target_link_libraries(${_name} ${EMP-OT_LIBRARIES}) 
endmacro()

add_test (sha1)
add_test (mal)
add_test (kot)
add_test (vot)
add_test (sha256)
add_test (mal2pc)
add_test (mal2pc_other)
add_test (mal_decompose)
add_test (mal2pc-comb)
add_test (xor-tree)
add_test (ot_xor_tree)
