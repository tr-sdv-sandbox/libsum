# Integration test executables (backend + client)

add_executable(backend-client-test
    backend_client_test.cpp
)

target_link_libraries(backend-client-test PRIVATE
    sum-backend
    sum-client
    GTest::gtest
    GTest::gtest_main
)

# Register tests
include(GoogleTest)
gtest_discover_tests(backend-client-test)

# Add tools integration test (shell script)
add_test(
    NAME ToolsIntegrationTest
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools_end_to_end_test.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
