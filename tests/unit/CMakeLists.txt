# Copy test data to build directory
file(COPY ${CMAKE_SOURCE_DIR}/tests/testdata
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/../)

# Unit test executables
add_executable(crypto_test
    crypto_test.cpp
)

target_link_libraries(crypto_test
    PRIVATE
        sum
        GTest::GTest
        GTest::Main
)

add_executable(manifest_test
    manifest_test.cpp
)

target_link_libraries(manifest_test
    PRIVATE
        sum
        GTest::GTest
        GTest::Main
)

# Register tests
include(GoogleTest)
gtest_discover_tests(crypto_test)
gtest_discover_tests(manifest_test)
