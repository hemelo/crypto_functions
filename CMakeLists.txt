cmake_minimum_required(VERSION 3.25)
project(crypto_functions)

set(CMAKE_CXX_STANDARD 11)

add_library(crypto_functions hashing.cpp ByteUtils.h HashingUtils.h)
