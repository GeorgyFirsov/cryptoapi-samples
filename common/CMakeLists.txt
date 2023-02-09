#
# Directories
#
set(CAS_COMMON_INCLUDE_ROOT	${CAS_COMMON}/include)
set(CAS_COMMON_SOURCE_ROOT	${CAS_COMMON}/src)

#
# Sources and headers
#
set(CAS_COMMON_SOURCE_FILES	${CAS_COMMON_SOURCE_ROOT}/common.cpp)

set(CAS_COMMON_HEADER_FILES	${CAS_COMMON_INCLUDE_ROOT}/common.hpp)

set(CAS_COMMON_SOURCES		${CAS_COMMON_SOURCE_FILES}
							${CAS_COMMON_HEADER_FILES})

#
# Library itself
#
add_library(common	${CAS_COMMON_SOURCES})
