# libsum-backend - Certificate generation (server-side)

cmake_minimum_required(VERSION 3.16)

# Backend library (static)
add_library(sum-backend STATIC
    src/manifest_builder.cpp
)

target_include_directories(sum-backend PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(sum-backend PRIVATE
    ${CMAKE_SOURCE_DIR}/common/src
)

target_link_libraries(sum-backend PUBLIC
    sum-common
)

# CLI Tools
if(BUILD_TOOLS)
    # sum-keygen: Key generation tool
    add_executable(sum-keygen
        tools/sum_keygen.cpp
    )
    target_link_libraries(sum-keygen PRIVATE
        sum-common
        glog::glog
    )
    install(TARGETS sum-keygen DESTINATION bin)

    # sum-generate: Certificate generation tool
    add_executable(sum-generate
        tools/sum_generate.cpp
    )
    target_link_libraries(sum-generate PRIVATE
        sum-backend
        glog::glog
    )
    install(TARGETS sum-generate DESTINATION bin)

    # sum-create-ca: CA certificate creation tool
    add_executable(sum-create-ca
        tools/sum_create_ca.cpp
    )
    target_link_libraries(sum-create-ca PRIVATE
        sum-backend
        glog::glog
    )
    install(TARGETS sum-create-ca DESTINATION bin)

    # sum-build-manifest: Multi-artifact manifest builder with JSON workflow
    add_executable(sum-build-manifest
        tools/sum_build_manifest.cpp
    )
    target_link_libraries(sum-build-manifest PRIVATE
        sum-backend
        glog::glog
        nlohmann_json::nlohmann_json
        OpenSSL::Crypto
    )
    install(TARGETS sum-build-manifest DESTINATION bin)
endif()

# Examples
if(BUILD_EXAMPLES)
    add_executable(keygen-example
        examples/keygen_example.cpp
    )
    target_link_libraries(keygen-example PRIVATE
        sum-common
        glog::glog
    )

    add_executable(generator-example
        examples/generator_example.cpp
    )
    target_link_libraries(generator-example PRIVATE
        sum-backend
        glog::glog
    )
endif()

# Tests for backend library
if(BUILD_TESTS)
    add_executable(sum-backend-tests
        tests/manifest_builder_test.cpp
        tests/update_certificate_test.cpp
    )

    target_link_libraries(sum-backend-tests PRIVATE
        sum-backend
        sum-common
        GTest::gtest
        GTest::gtest_main
        OpenSSL::Crypto
    )

    add_test(NAME BackendTests COMMAND sum-backend-tests)
endif()
