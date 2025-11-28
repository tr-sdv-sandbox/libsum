# libsum-common - Shared code between backend and client

cmake_minimum_required(VERSION 3.16)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Protobuf REQUIRED)

# Generate protobuf C++ code
set(PROTO_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/manifest.proto
)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

# Common library (static, linked by backend and client)
add_library(sum-common STATIC
    src/manifest.cpp
    src/x509_extension.cpp
    src/crypto_ed25519.cpp
    src/crypto_x25519.cpp
    src/crypto_keys.cpp
    src/crypto_sha256_streaming.cpp
    src/crypto_aes.cpp
    src/crypto_aes_streaming.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

target_include_directories(sum-common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(sum-common PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(sum-common PUBLIC
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    glog::glog
    protobuf::libprotobuf
)

# Tests for common library
if(BUILD_TESTS)
    add_executable(sum-common-tests
        tests/crypto_test.cpp
        tests/certificate_test.cpp
        tests/manifest_test.cpp
    )

    target_link_libraries(sum-common-tests PRIVATE
        sum-common
        GTest::gtest
        GTest::gtest_main
    )

    add_test(NAME CommonTests COMMAND sum-common-tests)
endif()
