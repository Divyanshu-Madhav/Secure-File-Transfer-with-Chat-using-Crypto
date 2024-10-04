# Minimum CMake version
cmake_minimum_required(VERSION 3.10)

# Project name
project(SecureFileTransfer)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)

# Manually set the include directory for Crypto++ (update to your local path)
include_directories(${CMAKE_SOURCE_DIR}/cryptopp-CRYPTOPP_8_7_0)

# Manually set the library path for Crypto++
link_directories(${CMAKE_SOURCE_DIR}/cryptopp-CRYPTOPP_8_7_0)

# Add the executables for server and client
add_executable(server server/server.cpp)
add_executable(client client/client.cpp)

# Link the Crypto++ library with the executables
target_link_libraries(server cryptopp)
target_link_libraries(client cryptopp)
