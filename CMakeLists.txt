cmake_minimum_required (VERSION 2.8.11)
project (emp-m2pc)

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

# Test cases
macro (add_test _name)
	add_test_with_lib(${_name} ${EMP-OT_LIBRARIES})
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
