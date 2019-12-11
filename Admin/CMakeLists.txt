# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEALExamples VERSION 3.4.4 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY)

add_executable(admin Admin.cpp)

# Import OpenSSL
find_package(OpenSSL REQUIRED)

# Import Microsoft SEAL
find_package(SEAL 3.4.4 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${SEALExamples_SOURCE_DIR}/../src/cmake
)

# Link Microsoft SEAL && OpenSSL
target_link_libraries(admin SEAL::seal OpenSSL::SSL OpenSSL::Crypto)