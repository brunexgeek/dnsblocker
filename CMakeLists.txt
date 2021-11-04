project(dnsblocker)

cmake_minimum_required(VERSION 2.8)

set(DNSB_MAJOR_VERSION 0)
set(DNSB_MINOR_VERSION 19)
set(DNSB_PATCH_VERSION 0)

add_definitions(-DDNSB_VERSION="${DNSB_MAJOR_VERSION}.${DNSB_MINOR_VERSION}.${DNSB_PATCH_VERSION}")

set(CMAKE_BUILD_TYPE "Release"  CACHE STRING  "Specify the build type")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
set(ENABLE_DNS_CONSOLE TRUE CACHE BOOL "Enable to manage the server using HTTP REST")
set(ENABLE_IPV6 FALSE CACHE BOOL "Enable support for IPv6")

if (CMAKE_BUILD_TYPE STREQUAL "")
    message(STATUS "No build type selected, default to 'Release'")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DNSB_BUILD_DEBUG 1)
else()
    set(DNSB_BUILD_RELEASE 1)
endif()

set(GIT_IGNORE_UNTRACKED TRUE)
set(PRE_CONFIGURE_FILE "source/git.hh.in")
set(POST_CONFIGURE_FILE "${CMAKE_BINARY_DIR}/__include/git.hh")
include(cmake/git_watcher.cmake)

if (UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=c++17 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type -Werror=init-self")
    set(CMAKE_CXX_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -g -O3")
    set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g -O0")
endif()

if (MSVC)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

find_package(Threads)

configure_file("source/defs.hh.in" "__include/defs.hh")

include(cmake/bin2h.cmake)
bin2h(SOURCE_FILE "source/log-header.html" HEADER_FILE "${CMAKE_BINARY_DIR}/__include/html1.hh" VARIABLE_NAME "HTML_HEADER" NULL_TERMINATE)
bin2h(SOURCE_FILE "source/log-footer.html" HEADER_FILE "${CMAKE_BINARY_DIR}/__include/html2.hh" VARIABLE_NAME "HTML_FOOTER" NULL_TERMINATE)

add_executable(dnsblocker
    "source/socket.cc"
	"source/main.cc"
    "source/nodes.cc"
    "source/log.cc"
    "source/buffer.cc"
    "source/process.cc"
    "source/console.cc"
    "source/webster.cc"
    "source/dns.cc")
target_include_directories(dnsblocker
    PUBLIC "include"
    PRIVATE "${CMAKE_BINARY_DIR}/__include/")
target_compile_definitions(dnsblocker PRIVATE _DEFAULT_SOURCE)
target_link_libraries(dnsblocker ${CMAKE_THREAD_LIBS_INIT})
add_dependencies(dnsblocker check_git)
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
