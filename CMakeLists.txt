#[[  This file is part of steamstub_unpack.

     steamstub_unpack is free software: you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
     OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
     LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  #]]

cmake_minimum_required(VERSION 3.14)

project(steamstub_unpack CXX)

include(ExternalProject)
include(cmake/FetchCPM.cmake)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libcryptopp REQUIRED libcryptopp)

CPMAddPackage("gh:zyantific/zydis#master")

CPMAddPackage(
        NAME LIEF_SRC
        GIT_TAG master
        GITHUB_REPOSITORY lief-project/LIEF
        DOWNLOAD_ONLY YES
)

if (LIEF_SRC_ADDED)
    set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
    set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
    set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

    set(LIEF_LIBRARIES
            "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}"
    )

    set(LIEF_CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DLIEF_DOC=off
            -DLIEF_PYTHON_API=off
            -DLIEF_EXAMPLES=off
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    )

    ExternalProject_Add(LIEF
            PREFIX           "${LIEF_PREFIX}"
            SOURCE_DIR       ${LIEF_SRC_SOURCE_DIR}
            INSTALL_DIR      ${LIEF_INSTALL_DIR}
            CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
            BUILD_BYPRODUCTS ${LIEF_LIBRARIES}
            UPDATE_COMMAND   ""
    )
endif()

message(STATUS "LIEF include directory: ${LIEF_INCLUDE_DIRS}")
message(STATUS "LIEF library: ${LIEF_LIBRARIES}")

CPMAddPackage(
        NAME PPK_ASSERT
        GIT_TAG master
        GITHUB_REPOSITORY gpakosz/PPK_ASSERT
        DOWNLOAD_ONLY YES
)

if (PPK_ASSERT_ADDED)
    add_library(PPK_ASSERT STATIC
            ${PPK_ASSERT_SOURCE_DIR}/src/ppk_assert.cpp
            ${PPK_ASSERT_SOURCE_DIR}/src/ppk_assert.h
    )

    target_compile_definitions(PPK_ASSERT PUBLIC
            -DPPK_ASSERT_ENABLED=1
    )

    target_include_directories(PPK_ASSERT PUBLIC
            $<BUILD_INTERFACE:${PPK_ASSERT_SOURCE_DIR}/src/>
    )
endif()

CPMAddPackage(
        NAME mio
        GIT_TAG master
        GITHUB_REPOSITORY mandreyel/mio
)

add_executable(steamstub_unpack
        src/main.cc
)

add_dependencies(steamstub_unpack LIEF)

target_compile_features(steamstub_unpack PRIVATE cxx_std_17)

target_include_directories(steamstub_unpack PRIVATE
        ${libcryptopp_INCLUDE_DIRS}
        ${LIEF_INCLUDE_DIRS}
)

target_link_libraries(steamstub_unpack PRIVATE
        ${libcryptopp_LIBRARIES}
        ${LIEF_LIBRARIES}
        mio
        PPK_ASSERT
        Zydis
)

install(TARGETS steamstub_unpack)
