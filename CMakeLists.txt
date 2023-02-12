cmake_minimum_required(VERSION 3.0.0)
project(cryptoapi-samples VERSION 0.1.0)

#
# Global config
#
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#
# Basic common directories
#
set(CAS_ROOT			${CMAKE_SOURCE_DIR})
set(CAS_COMMON			${CAS_ROOT}/common)
set(CAS_COMMON_INCLUDE	${CAS_COMMON}/include)
set(CAS_CRYPTOPROVIDERS	${CAS_ROOT}/cryptoproviders)
set(CAS_SECURE_CHANNEL	${CAS_ROOT}/secure-channel)

#
# Generic include directories
#
set(CAS_GENERIC_INCLUDE_DIRECTORIES ${CAS_COMMON_INCLUDE})

include_directories(${CAS_GENERIC_INCLUDE_DIRECTORIES})

#
# Preprocessor definitions
#
add_compile_definitions(UNICODE)  # Build with unicode characters (wchar_t)

#
# Projects
#
add_subdirectory(common)
add_subdirectory(cryptoproviders)
add_subdirectory(secure-channel)
