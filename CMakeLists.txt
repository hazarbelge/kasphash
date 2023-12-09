cmake_minimum_required(VERSION 3.17)
project(kasphash)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
endif()

add_executable(kasphash main.cpp)
target_link_libraries(kasphash ${OPENSSL_LIBRARIES})
