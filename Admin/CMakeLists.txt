cmake_minimum_required(VERSION 3.12)

project(SEALExamples VERSION 3.4.4 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../)

add_executable(adminApp Admin.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.4.4 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${SEALExamples_SOURCE_DIR}/../src/cmake
)

# Link Microsoft SEAL
target_link_libraries(adminApp SEAL::seal)