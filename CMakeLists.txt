project(dnsblocker)

cmake_minimum_required(VERSION 2.8)

set(DNSB_MAJOR_VERSION 0)
set(DNSB_MINOR_VERSION 14)
set(DNSB_PATCH_VERSION 1)

add_definitions(-DDNSB_VERSION="${DNSB_MAJOR_VERSION}.${DNSB_MINOR_VERSION}.${DNSB_PATCH_VERSION}")

set(CMAKE_BUILD_TYPE "Release"  CACHE STRING  "Specify the build type")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")

set(ENABLE_DNS_CONSOLE true CACHE BOOLEAN "Enable to manage the server using commands in DNS messages")


if (CMAKE_BUILD_TYPE STREQUAL "")
    message(STATUS "No build type selected, default to 'Release'")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DNSB_BUILD_DEBUG 1)
else()
    set(DNSB_BUILD_RELEASE 1)
endif()


if (UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=c++11 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type")
    set(CMAKE_CXX_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g -O0")
endif()

if (MSVC)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()


find_package(Threads)


configure_file("source/defs.hh.in" "${CMAKE_CURRENT_LIST_DIR}/source/defs.hh")

add_executable(dnsblocker
    "source/socket.cc"
	"source/main.cc"
    "source/nodes.cc"
    "source/log.cc"
    "source/buffer.cc"
    "source/process.cc"
    "source/dns.cc")
target_include_directories(dnsblocker
    PUBLIC "include")
target_compile_definitions(dnsblocker PRIVATE _DEFAULT_SOURCE)
target_link_libraries(dnsblocker ${CMAKE_THREAD_LIBS_INIT})
set_target_properties(dnsblocker PROPERTIES
    OUTPUT_NAME "dnsblocker"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )

add_executable(optimize
    "source/optimize.cc"
    "source/nodes.cc")
target_include_directories(optimize
    PUBLIC "include")
target_compile_definitions(optimize PRIVATE _DEFAULT_SOURCE)
target_link_libraries(optimize ${CMAKE_THREAD_LIBS_INIT})
set_target_properties(optimize PROPERTIES
    OUTPUT_NAME "optimize"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )

install(TARGETS dnsblocker DESTINATION bin)
