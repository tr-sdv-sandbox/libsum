# libsum - Secure Update Manifest
# Reorganized into: common (shared), backend (generation), client (validation)

cmake_minimum_required(VERSION 3.14)
project(libsum VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_BACKEND "Build backend library (certificate generation)" ON)
option(BUILD_CLIENT "Build client library (validation)" ON)
option(BUILD_COMMON "Build common library (shared code)" ON)
option(BUILD_TOOLS "Build CLI tools" ON)
option(BUILD_EXAMPLES "Build examples" OFF)
option(BUILD_TESTS "Build tests" ON)
option(SUM_ENABLE_COVERAGE "Enable coverage reporting" OFF)

# Dependencies
find_package(OpenSSL 3.0 REQUIRED)
find_package(glog REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(Protobuf REQUIRED)

if(BUILD_TESTS)
    find_package(GTest REQUIRED)
    enable_testing()
endif()

# Common library (required by both backend and client)
if(BUILD_COMMON)
    add_subdirectory(common)
endif()

# Backend library (certificate generation)
if(BUILD_BACKEND)
    add_subdirectory(backend)
endif()

# Client library (validation)
if(BUILD_CLIENT)
    add_subdirectory(client)
endif()

# Integration tests (requires both backend and client)
if(BUILD_TESTS AND BUILD_BACKEND AND BUILD_CLIENT)
    add_subdirectory(tests)
endif()

# Installation
include(GNUInstallDirs)

# Install headers
install(DIRECTORY common/include/sum
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
if(BUILD_BACKEND)
    install(DIRECTORY backend/include/sum
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()
if(BUILD_CLIENT)
    install(DIRECTORY client/include/sum
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

# Install libraries
if(BUILD_COMMON)
    install(TARGETS sum-common
        EXPORT sumTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
if(BUILD_BACKEND)
    install(TARGETS sum-backend
        EXPORT sumTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
if(BUILD_CLIENT)
    install(TARGETS sum-client
        EXPORT sumTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

# Export targets
install(EXPORT sumTargets
    FILE sumTargets.cmake
    NAMESPACE sum::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sum
)

# Package config
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/sumConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sumConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sum
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/sumConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/sumConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/sumConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sum
)

# Summary
message(STATUS "")
message(STATUS "═══════════════════════════════════════")
message(STATUS "  libsum v${PROJECT_VERSION} Configuration")
message(STATUS "═══════════════════════════════════════")
message(STATUS "  Build common:   ${BUILD_COMMON}")
message(STATUS "  Build backend:  ${BUILD_BACKEND}")
message(STATUS "  Build client:   ${BUILD_CLIENT}")
message(STATUS "  Build tools:    ${BUILD_TOOLS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Build tests:    ${BUILD_TESTS}")
message(STATUS "═══════════════════════════════════════")
message(STATUS "")
