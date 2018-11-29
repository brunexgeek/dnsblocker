project(dnsblocker)

cmake_minimum_required(VERSION 2.8)

set(DNSB_MAJOR_VERSION 0)
set(DNSB_MINOR_VERSION 6)
set(DNSB_PATCH_VERSION 0)

set(LIBRARY_TYPE "SHARED" CACHE STRING "Specify the type of binary to be generated")
set_property(CACHE LIBRARY_TYPE PROPERTY STRINGS "STATIC" "SHARED")

set(CMAKE_BUILD_TYPE "Release"  CACHE STRING  "Specify the build type")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")

set(ENABLE_RECURSIVE_DNS false CACHE BOOLEAN "Enable resursive query using fallback DNS")
set(ENABLE_TIMESTAMP true CACHE BOOLEAN "Enable timestamp in log entries")

if (UNIX)
    set(CMAKE_BUILD_PLATFORM "auto"  CACHE STRING  "Target platform which the binaries will be generated")
    set_property(CACHE CMAKE_BUILD_PLATFORM PROPERTY STRINGS "auto" "x86_64" "x86")

    if (NOT CMAKE_BUILD_PLATFORM STREQUAL "auto" AND
        NOT CMAKE_BUILD_PLATFORM STREQUAL "x86" AND
        NOT CMAKE_BUILD_PLATFORM STREQUAL "x86_64")
        set(CMAKE_BUILD_PLATFORM "auto")
    endif()
endif()

if (NOT CMAKE_BUILD_PLATFORM OR "${CMAKE_BUILD_PLATFORM}" STREQUAL "auto")
    if (${CMAKE_SIZEOF_VOID_P} EQUAL 4)
        set(CMAKE_BUILD_PLATFORM "x86")
    elseif(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        set(CMAKE_BUILD_PLATFORM "x86_64")
    endif()
endif()


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
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=c++11 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=int-conversion -Werror=return-type -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Werror=discarded-qualifiers")
    set(CMAKE_CXX_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g -O0")

    if(CMAKE_BUILD_PLATFORM STREQUAL "x86")
        set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32" )
        set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" )
        set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32" )
        set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32" )
    elseif(CMAKE_BUILD_PLATFORM STREQUAL "x86_64")
        set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64" )
        set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64" )
        set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m64" )
        set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64" )
    endif()
endif()


configure_file("config.hh.in" "${CMAKE_CURRENT_LIST_DIR}/config.hh")

add_executable(dnsblocker
    "${CMAKE_CURRENT_LIST_DIR}/main.cc"
    "${CMAKE_CURRENT_LIST_DIR}/nodes.cc"
    "${CMAKE_CURRENT_LIST_DIR}/log.cc"
    "${CMAKE_CURRENT_LIST_DIR}/buffer.cc"
    "${CMAKE_CURRENT_LIST_DIR}/dns.cc")
target_compile_definitions(dnsblocker PRIVATE _DEFAULT_SOURCE)
set_target_properties(dnsblocker PROPERTIES
    OUTPUT_NAME "dnsblocker"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )

install(TARGETS dnsblocker DESTINATION bin)
