cmake_minimum_required(VERSION 3.20)
project(daahe_core VERSION 0.1.0 LANGUAGES C)
add_library(daahe_core STATIC daahe_core.c)
target_include_directories(daahe_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(daahe_core PUBLIC c_std_99)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(daahe_core PRIVATE -Wall -Wextra -Wconversion -Werror)
endif()

