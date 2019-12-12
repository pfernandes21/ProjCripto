cmake_minimum_required(VERSION 3.12)

project(SEALExamples VERSION 3.4.4 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../)

add_executable(voterApp Voter.cpp)

# Import OpenSSL
find_package(OpenSSL REQUIRED)

# Import Microsoft SEAL
find_package(SEAL 3.4.4 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${SEALExamples_SOURCE_DIR}/../src/cmake
)

# Link Microsoft SEAL && OpenSSL
target_link_libraries(voterApp SEAL::seal OpenSSL:SSL)