# libsum-client - Certificate validation (device-side, C++)

cmake_minimum_required(VERSION 3.16)

# Client library (static)
add_library(sum-client STATIC
    src/validator.cpp
)

target_include_directories(sum-client PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(sum-client PRIVATE
    ${CMAKE_SOURCE_DIR}/common/src
)

target_link_libraries(sum-client PUBLIC
    sum-common
)

# CLI Tools
if(BUILD_TOOLS)
    # sum-verify: Certificate verification tool
    add_executable(sum-verify
        tools/sum_verify.cpp
    )
    target_link_libraries(sum-verify PRIVATE
        sum-client
        glog::glog
    )
    install(TARGETS sum-verify DESTINATION bin)

    # sum-inspect: Certificate inspection tool
    add_executable(sum-inspect
        tools/sum_inspect.cpp
    )
    target_link_libraries(sum-inspect PRIVATE
        sum-client
        glog::glog
    )
    install(TARGETS sum-inspect DESTINATION bin)
endif()

# Examples
if(BUILD_EXAMPLES)
    add_executable(validator-example
        examples/validator_example.cpp
    )
    target_link_libraries(validator-example PRIVATE
        sum-client
        glog::glog
    )
endif()
