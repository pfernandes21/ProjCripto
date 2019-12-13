# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEALExamples VERSION 3.4.4 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY .)
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(election Election.cpp)
target_sources(election
    PRIVATE
        Admin.cpp
        Voter.cpp
        Tally.cpp
        Counter.cpp
)

# Import Microsoft SEAL
find_package(SEAL 3.4.4 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${SEALExamples_SOURCE_DIR}/../src/cmake
)

# Link Microsoft SEAL
target_link_libraries(election SEAL::seal)
target_link_libraries(election OpenSSL::Crypto)
