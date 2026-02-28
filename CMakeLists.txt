cmake_minimum_required(VERSION 3.16)
project(GordianNet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD   99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Options ───────────────────────────────────────────────────────────────
option(GORDIAN_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(GORDIAN_SANITIZER "" CACHE STRING "Sanitizer: address, thread, or undefined")

# ── Sanitizer support ─────────────────────────────────────────────────────
if(GORDIAN_SANITIZER)
    set(SAN_FLAGS "-fsanitize=${GORDIAN_SANITIZER} -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${SAN_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SAN_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS} ${SAN_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${SAN_FLAGS}")
    message(STATUS "Sanitizer enabled: ${GORDIAN_SANITIZER}")
endif()

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

# ── Compiler hardening flags ──────────────────────────────────────────────
set(GORDIAN_COMMON_FLAGS
    -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security
    -fstack-protector-strong
)
if(GORDIAN_WARNINGS_AS_ERRORS)
    list(APPEND GORDIAN_COMMON_FLAGS -Werror)
endif()

# ── libgordian_net (shared library) ────────────────────────────────────────
add_library(gordian_net SHARED
    src/gordian_node.cpp
    vendor/ikcp.c
)

set_target_properties(gordian_net PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION 0
    CXX_VISIBILITY_PRESET hidden
    C_VISIBILITY_PRESET   hidden
)

target_compile_definitions(gordian_net PRIVATE GORDIAN_NET_BUILDING)

# _FORTIFY_SOURCE only in Release/RelWithDebInfo (requires -O1+)
target_compile_definitions(gordian_net PRIVATE
    $<$<CONFIG:Release>:_FORTIFY_SOURCE=2>
    $<$<CONFIG:RelWithDebInfo>:_FORTIFY_SOURCE=2>
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
    ${GORDIAN_COMMON_FLAGS}
    # ikcp.c uses old-style C; silence its warnings when compiled as C99
    $<$<COMPILE_LANGUAGE:C>:-Wno-unused-parameter>
)

target_link_options(gordian_net PRIVATE
    "LINKER:-z,relro,-z,now"
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

target_compile_options(gordian_chat PRIVATE ${GORDIAN_COMMON_FLAGS})

target_link_libraries(gordian_chat
    PRIVATE
        gordian_net
)

# ── Tests ──────────────────────────────────────────────────────────────────
enable_testing()

# Helper: add a test executable linked to gordian_net
function(gordian_add_test NAME SOURCE TIMEOUT_S)
    add_executable(${NAME} ${SOURCE})
    target_include_directories(${NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_options(${NAME} PRIVATE ${GORDIAN_COMMON_FLAGS})
    target_link_libraries(${NAME} PRIVATE gordian_net)
    add_test(NAME ${NAME}
        COMMAND ${NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(${NAME} PROPERTIES TIMEOUT ${TIMEOUT_S})
endfunction()

gordian_add_test(loopback_test     tests/loopback_test.cpp      45)
gordian_add_test(framing_test      tests/framing_test.cpp       60)
gordian_add_test(error_path_test   tests/error_path_test.cpp    30)
gordian_add_test(concurrent_send_test tests/concurrent_send_test.cpp 60)
gordian_add_test(shutdown_test     tests/shutdown_test.cpp       60)

# ── pkg-config ─────────────────────────────────────────────────────────────
configure_file(gordian_net.pc.in gordian_net.pc @ONLY)

# ── Install rules ──────────────────────────────────────────────────────────
install(TARGETS gordian_net gordian_chat
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES include/gordian_net.h DESTINATION include)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gordian_net.pc
    DESTINATION lib/pkgconfig
)

# ── Summary ────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "GordianNet configuration (libjuice + mbedTLS + KCP)")
message(STATUS "  Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C standard  : ${CMAKE_C_STANDARD}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Sanitizer   : ${GORDIAN_SANITIZER}")
message(STATUS "  Werror      : ${GORDIAN_WARNINGS_AS_ERRORS}")
message(STATUS "")
