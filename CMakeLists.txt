cmake_minimum_required(VERSION 3.16)
project(GordianNet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD   99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── libjuice (ICE/STUN — fetched automatically) ────────────────────────────
include(FetchContent)
FetchContent_Declare(
    libjuice
    GIT_REPOSITORY https://github.com/paullouisageneau/libjuice.git
    GIT_TAG        v1.7.0
)
set(NO_SERVER ON  CACHE BOOL "" FORCE)   # skip juice server binary
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(libjuice)

# ── mbedTLS (system — headers at /usr/include/mbedtls, libs in /usr/lib) ──
find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h
    PATHS /usr/include /usr/local/include
    REQUIRED)
find_library(MBEDTLS_LIB    mbedtls    PATHS /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib REQUIRED)
find_library(MBEDX509_LIB   mbedx509   PATHS /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib REQUIRED)
find_library(MBEDCRYPTO_LIB mbedcrypto PATHS /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib REQUIRED)

message(STATUS "mbedTLS include : ${MBEDTLS_INCLUDE_DIR}")
message(STATUS "mbedTLS libs    : ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB}")

# ── libgordian_net (shared library) ────────────────────────────────────────
add_library(gordian_net SHARED
    src/gordian_node.cpp
    vendor/ikcp.c
)

target_include_directories(gordian_net
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/vendor
        ${MBEDTLS_INCLUDE_DIR}
)

target_compile_options(gordian_net PRIVATE
    -Wall -Wextra
    # ikcp.c uses old-style C; silence its warnings when compiled as C99
    $<$<COMPILE_LANGUAGE:C>:-Wno-unused-parameter>
)

target_link_libraries(gordian_net
    PRIVATE
        juice-static
        ${MBEDTLS_LIB}
        ${MBEDX509_LIB}
        ${MBEDCRYPTO_LIB}
)

# ── gordian_chat CLI ───────────────────────────────────────────────────────
add_executable(gordian_chat
    cli/main.cpp
)

target_include_directories(gordian_chat
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(gordian_chat
    PRIVATE
        gordian_net
)

# ── Tests ──────────────────────────────────────────────────────────────────
enable_testing()

add_executable(loopback_test
    tests/loopback_test.cpp
)

target_include_directories(loopback_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(loopback_test
    PRIVATE
        gordian_net
)

add_test(NAME loopback
    COMMAND loopback_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# 45 s hard timeout — ICE over loopback is fast
set_tests_properties(loopback PROPERTIES TIMEOUT 45)

# ── Install rules ──────────────────────────────────────────────────────────
install(TARGETS gordian_net gordian_chat
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES include/gordian_net.h DESTINATION include)

# ── Summary ────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "GordianNet configuration (libjuice + mbedTLS + KCP)")
message(STATUS "  Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C standard  : ${CMAKE_C_STANDARD}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "")
